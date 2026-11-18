// API de CuántoLaVenta: cuentas con Google, lotes guardados y seguimiento.
// Necesita un binding D1 llamado DB en el proyecto de Cloudflare Pages.
// El ID de cliente de Google es público (no es una clave secreta).
const GOOGLE_CLIENT_ID = "";               // se completa al crear el cliente OAuth en Google Cloud
const GRATIS_HASTA = "2026-12-31";         // todo gratis durante 2026
const ADMINS = ["franciscocamyausan@gmail.com"];
const SESION_DIAS = 60;
const COOKIE = "clv_s";

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS usuarios (id INTEGER PRIMARY KEY AUTOINCREMENT, google_sub TEXT UNIQUE NOT NULL, email TEXT, nombre TEXT, foto TEXT, plan TEXT NOT NULL DEFAULT 'gratis', creado TEXT NOT NULL, ultimo_ingreso TEXT)`,
  `CREATE TABLE IF NOT EXISTS sesiones (token_hash TEXT PRIMARY KEY, usuario_id INTEGER NOT NULL, expira TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS lotes (id INTEGER PRIMARY KEY AUTOINCREMENT, usuario_id INTEGER NOT NULL, nombre TEXT NOT NULL, parametros TEXT NOT NULL, notas TEXT DEFAULT '', creado TEXT NOT NULL, actualizado TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS valuaciones (id INTEGER PRIMARY KEY AUTOINCREMENT, lote_id INTEGER NOT NULL, fecha TEXT NOT NULL, cabezas REAL, peso REAL, total REAL, por_cabeza REAL, por_kilo REAL, certeza TEXT, fuentes INTEGER, precios_al TEXT, nota TEXT DEFAULT '')`,
  `CREATE INDEX IF NOT EXISTS idx_lotes_usuario ON lotes(usuario_id)`,
  `CREATE INDEX IF NOT EXISTS idx_val_lote ON valuaciones(lote_id)`
];
let schemaListo = false;

const json = (data, status = 200, extra = {}) => new Response(JSON.stringify(data), {status, headers: {"Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...extra}});
const ahora = () => new Date().toISOString();

async function sha256(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function tokenAleatorio() {
  const a = new Uint8Array(32); crypto.getRandomValues(a);
  return [...a].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function leerCookie(req, name) {
  const m = (req.headers.get("Cookie") || "").match(new RegExp("(?:^|;\\s*)" + name + "=([a-f0-9]{64})"));
  return m ? m[1] : null;
}
async function asegurarSchema(db) {
  if (schemaListo) return;
  await db.batch(SCHEMA.map((s) => db.prepare(s)));
  schemaListo = true;
}
async function usuarioActual(req, db) {
  const tok = leerCookie(req, COOKIE);
  if (!tok) return null;
  const h = await sha256(tok);
  return await db.prepare(`SELECT u.id, u.email, u.nombre, u.foto, u.plan, u.creado FROM sesiones s JOIN usuarios u ON u.id = s.usuario_id WHERE s.token_hash = ? AND s.expira > ?`).bind(h, ahora()).first();
}
const num = (v) => (v === null || v === undefined || v === "" || !isFinite(Number(v))) ? null : Number(v);
const txt = (v, max = 200) => String(v ?? "").slice(0, max);

function planInfo(u) {
  const gratis = new Date().toISOString().slice(0, 10) <= GRATIS_HASTA;
  return {plan: u ? u.plan : "gratis", gratisHasta: GRATIS_HASTA, periodoGratis: gratis};
}

async function valuacionDesde(body) {
  const v = body || {};
  return {
    fecha: txt(v.fecha || ahora(), 40), cabezas: num(v.cabezas), peso: num(v.peso), total: num(v.total),
    por_cabeza: num(v.por_cabeza), por_kilo: num(v.por_kilo), certeza: txt(v.certeza, 20), fuentes: num(v.fuentes),
    precios_al: txt(v.precios_al, 20), nota: txt(v.nota, 500)
  };
}
function insertarValuacion(db, loteId, v) {
  return db.prepare(`INSERT INTO valuaciones (lote_id, fecha, cabezas, peso, total, por_cabeza, por_kilo, certeza, fuentes, precios_al, nota) VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
    .bind(loteId, v.fecha, v.cabezas, v.peso, v.total, v.por_cabeza, v.por_kilo, v.certeza, v.fuentes, v.precios_al, v.nota);
}

export async function onRequest({request, env}) {
  const url = new URL(request.url);
  const ruta = url.pathname.replace(/^\/api\/?/, "").replace(/\/$/, "");
  const metodo = request.method;

  if (ruta === "config") {
    return json({googleClientId: GOOGLE_CLIENT_ID, baseDatos: !!env.DB, ...planInfo(null)});
  }
  if (!env.DB) return json({error: "La base de datos todavía no está conectada."}, 503);
  const db = env.DB;
  await asegurarSchema(db);

  // Protección básica contra pedidos de otros sitios en acciones que cambian datos
  if (metodo !== "GET" && request.headers.get("X-CLV") !== "1") return json({error: "Pedido no válido."}, 403);

  // ---- Ingreso con Google ----
  if (ruta === "auth/google" && metodo === "POST") {
    if (!GOOGLE_CLIENT_ID) return json({error: "El ingreso con Google todavía no está configurado."}, 503);
    const {credential} = await request.json().catch(() => ({}));
    if (!credential) return json({error: "Falta la credencial de Google."}, 400);
    const r = await fetch("https://oauth2.googleapis.com/tokeninfo?id_token=" + encodeURIComponent(credential));
    if (!r.ok) return json({error: "Google no validó el ingreso."}, 401);
    const t = await r.json();
    const okIss = t.iss === "accounts.google.com" || t.iss === "https://accounts.google.com";
    if (t.aud !== GOOGLE_CLIENT_ID || !okIss || Number(t.exp) * 1000 < Date.now() || String(t.email_verified) !== "true") {
      return json({error: "El ingreso con Google no es válido."}, 401);
    }
    const ts = ahora();
    await db.prepare(`INSERT INTO usuarios (google_sub, email, nombre, foto, creado, ultimo_ingreso) VALUES (?,?,?,?,?,?)
      ON CONFLICT(google_sub) DO UPDATE SET email=excluded.email, nombre=excluded.nombre, foto=excluded.foto, ultimo_ingreso=excluded.ultimo_ingreso`)
      .bind(t.sub, t.email || "", t.name || "", t.picture || "", ts, ts).run();
    const u = await db.prepare(`SELECT id, email, nombre, foto, plan, creado FROM usuarios WHERE google_sub = ?`).bind(t.sub).first();
    const tok = tokenAleatorio();
    const expira = new Date(Date.now() + SESION_DIAS * 864e5).toISOString();
    await db.prepare(`INSERT INTO sesiones (token_hash, usuario_id, expira) VALUES (?,?,?)`).bind(await sha256(tok), u.id, expira).run();
    await db.prepare(`DELETE FROM sesiones WHERE expira < ?`).bind(ts).run();
    return json({usuario: {...u, esAdmin: ADMINS.includes(u.email)}, ...planInfo(u)}, 200, {
      "Set-Cookie": `${COOKIE}=${tok}; Path=/; Max-Age=${SESION_DIAS * 86400}; HttpOnly; Secure; SameSite=Lax`
    });
  }

  if (ruta === "auth/salir" && metodo === "POST") {
    const tok = leerCookie(request, COOKIE);
    if (tok) await db.prepare(`DELETE FROM sesiones WHERE token_hash = ?`).bind(await sha256(tok)).run();
    return json({ok: true}, 200, {"Set-Cookie": `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`});
  }

  const u = await usuarioActual(request, db);

  if (ruta === "yo") return json({usuario: u ? {...u, esAdmin: ADMINS.includes(u.email)} : null, ...planInfo(u)});
  if (!u) return json({error: "Tenés que ingresar con tu cuenta de Google."}, 401);

  // ---- Lotes ----
  if (ruta === "lotes" && metodo === "GET") {
    const lotes = (await db.prepare(`SELECT id, nombre, parametros, notas, creado, actualizado FROM lotes WHERE usuario_id = ? ORDER BY actualizado DESC`).bind(u.id).all()).results;
    const ids = lotes.map((l) => l.id);
    let vals = [];
    if (ids.length) {
      vals = (await db.prepare(`SELECT * FROM valuaciones WHERE lote_id IN (${ids.map(() => "?").join(",")}) ORDER BY fecha ASC`).bind(...ids).all()).results;
    }
    return json({lotes: lotes.map((l) => ({...l, parametros: JSON.parse(l.parametros), valuaciones: vals.filter((v) => v.lote_id === l.id)})), ...planInfo(u)});
  }

  if (ruta === "lotes" && metodo === "POST") {
    const b = await request.json().catch(() => ({}));
    const nombre = txt(b.nombre, 80).trim() || "Mi lote";
    const params = JSON.stringify(b.parametros || {}).slice(0, 4000);
    const ts = ahora();
    const r = await db.prepare(`INSERT INTO lotes (usuario_id, nombre, parametros, notas, creado, actualizado) VALUES (?,?,?,?,?,?)`).bind(u.id, nombre, params, txt(b.notas, 2000), ts, ts).run();
    const id = r.meta.last_row_id;
    if (b.valuacion) await insertarValuacion(db, id, await valuacionDesde(b.valuacion)).run();
    return json({id});
  }

  const m = ruta.match(/^lotes\/(\d+)(\/valuaciones)?$/);
  if (m) {
    const id = Number(m[1]);
    const lote = await db.prepare(`SELECT id FROM lotes WHERE id = ? AND usuario_id = ?`).bind(id, u.id).first();
    if (!lote) return json({error: "No encontramos ese lote."}, 404);

    if (m[2] && metodo === "POST") {
      const b = await request.json().catch(() => ({}));
      await db.batch([
        insertarValuacion(db, id, await valuacionDesde(b)),
        db.prepare(`UPDATE lotes SET actualizado = ? WHERE id = ?`).bind(ahora(), id)
      ]);
      return json({ok: true});
    }
    if (!m[2] && metodo === "PATCH") {
      const b = await request.json().catch(() => ({}));
      const sets = [], vals = [];
      if (b.nombre !== undefined) { sets.push("nombre = ?"); vals.push(txt(b.nombre, 80).trim() || "Mi lote"); }
      if (b.notas !== undefined) { sets.push("notas = ?"); vals.push(txt(b.notas, 2000)); }
      if (b.parametros !== undefined) { sets.push("parametros = ?"); vals.push(JSON.stringify(b.parametros).slice(0, 4000)); }
      sets.push("actualizado = ?"); vals.push(ahora());
      await db.prepare(`UPDATE lotes SET ${sets.join(", ")} WHERE id = ?`).bind(...vals, id).run();
      return json({ok: true});
    }
    if (!m[2] && metodo === "DELETE") {
      await db.batch([
        db.prepare(`DELETE FROM valuaciones WHERE lote_id = ?`).bind(id),
        db.prepare(`DELETE FROM lotes WHERE id = ?`).bind(id)
      ]);
      return json({ok: true});
    }
  }

  // ---- Resumen para el dueño (para planear la monetización) ----
  if (ruta === "admin/resumen" && metodo === "GET") {
    if (!ADMINS.includes(u.email)) return json({error: "Sin permiso."}, 403);
    const q = async (s) => (await db.prepare(s).first()).n;
    return json({
      usuarios: await q(`SELECT COUNT(*) n FROM usuarios`),
      usuariosUltimos7Dias: await q(`SELECT COUNT(*) n FROM usuarios WHERE ultimo_ingreso > datetime('now','-7 days')`),
      lotes: await q(`SELECT COUNT(*) n FROM lotes`),
      valuaciones: await q(`SELECT COUNT(*) n FROM valuaciones`),
      cabezasGuardadas: (await db.prepare(`SELECT COALESCE(SUM(cabezas),0) n FROM (SELECT v.cabezas FROM valuaciones v JOIN (SELECT lote_id, MAX(id) mid FROM valuaciones GROUP BY lote_id) x ON v.id = x.mid)`).first()).n
    });
  }

  return json({error: "Ruta no encontrada."}, 404);
}
