// Protege /panel con contraseña. Acá solo se guarda un hash doble de la contraseña:
// la cookie lleva sha256(contraseña) y el servidor compara sha256(cookie) con PANEL_HASH.
const PANEL_HASH = "1eaebe28bedcf08e1e9d73ad3c7784b044ce2d441137103072762882b5f470b6";
const COOKIE = "clv_panel";

async function sha256(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function getCookie(req, name) {
  const c = req.headers.get("Cookie") || "";
  const m = c.match(new RegExp("(?:^|;\\s*)" + name + "=([a-f0-9]{64})"));
  return m ? m[1] : null;
}

function loginPage(error) {
  return new Response(`<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex"><title>Panel · CuántoLaVenta</title>
<style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:linear-gradient(135deg,#0b2e22,#17573f);padding:16px}
.box{background:#fff;border-radius:18px;padding:28px 24px;width:100%;max-width:360px;box-shadow:0 20px 50px rgba(0,0,0,.25)}
h1{margin:0 0 4px;font-size:21px;color:#0b2e22}p{margin:0 0 18px;color:#5b7368;font-size:14px}
input{width:100%;padding:13px 14px;border:1.5px solid #d6e7dd;border-radius:11px;font-size:16px;outline:none}input:focus{border-color:#2e9466}
button{width:100%;margin-top:12px;padding:13px;border:0;border-radius:11px;background:#17573f;color:#fff;font-size:16px;font-weight:700;cursor:pointer}
.err{color:#b3261e;font-size:13.5px;margin-top:10px}</style></head><body>
<form class="box" method="POST" action="/panel/login"><h1>Panel CuántoLaVenta</h1><p>Ingresá la contraseña para ver el panel semanal.</p>
<input type="password" name="password" placeholder="Contraseña" autocomplete="current-password" autofocus required>
<button type="submit">Entrar</button>${error ? '<div class="err">Contraseña incorrecta.</div>' : ""}</form></body></html>`,
    {status: error ? 401 : 200, headers: {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Robots-Tag": "noindex"}});
}

export async function onRequest(context) {
  const {request, next} = context;
  const url = new URL(request.url);
  const path = url.pathname;
  if (!(path === "/panel" || path.startsWith("/panel/") || path === "/panel.html")) return next();

  if (path === "/panel/login" && request.method === "POST") {
    const form = await request.formData();
    const h1 = await sha256(String(form.get("password") || ""));
    if ((await sha256(h1)) !== PANEL_HASH) return loginPage(true);
    return new Response(null, {status: 303, headers: {
      "Location": "/panel/",
      "Set-Cookie": `${COOKIE}=${h1}; Path=/panel; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax`,
      "Cache-Control": "no-store"
    }});
  }

  if (path === "/panel/salir") {
    return new Response(null, {status: 303, headers: {"Location": "/panel/", "Set-Cookie": `${COOKIE}=; Path=/panel; Max-Age=0; HttpOnly; Secure; SameSite=Lax`}});
  }

  const tok = getCookie(request, COOKIE);
  if (!tok || (await sha256(tok)) !== PANEL_HASH) return loginPage(false);

  const res = await next();
  const out = new Response(res.body, res);
  out.headers.set("Cache-Control", "no-store");
  out.headers.set("X-Robots-Tag", "noindex");
  return out;
}
