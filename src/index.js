const enc = new TextEncoder();
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64 = s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return Uint8Array.from(atob(s), c => c.charCodeAt(0)); };
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const q = encodeURIComponent;
const money = c => (c / 100).toLocaleString('es-VE', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const fecha = s => { const d = new Date(s); return isNaN(d) ? '' : d.toLocaleString('es-VE', { timeZone: 'America/Caracas', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }); };
const eq = (a, b) => { if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; };

async function hmac(secret, data) {
  const k = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64(await crypto.subtle.sign('HMAC', k, enc.encode(data)));
}
async function hashPw(pw, salt) {
  salt = salt || crypto.getRandomValues(new Uint8Array(16));
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, k, 256);
  return 'pbkdf2$' + b64(salt) + '$' + b64(bits);
}
async function checkPw(pw, stored) {
  const p = String(stored).split('$');
  if (p.length !== 3) return false;
  return eq(await hashPw(pw, unb64(p[1])), stored);
}

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32enc(bytes) {
  let bits = 0, val = 0, out = '';
  for (const b of bytes) { val = (val << 8) | b; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += B32[(val << (5 - bits)) & 31];
  return out;
}
function b32dec(s) {
  let bits = 0, val = 0; const out = [];
  for (const ch of s.replace(/[\s=]/g, '').toUpperCase()) {
    const i = B32.indexOf(ch); if (i < 0) continue;
    val = (val << 5) | i; bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}
async function totp(secret, step) {
  const key = await crypto.subtle.importKey('raw', b32dec(secret), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const buf = new ArrayBuffer(8), dv = new DataView(buf);
  dv.setUint32(0, Math.floor(step / 4294967296)); dv.setUint32(4, step >>> 0);
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, buf));
  const o = h[19] & 15;
  const n = ((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 1000000).padStart(6, '0');
}
async function checkTotp(secret, code, last) {
  code = String(code).replace(/\s/g, '');
  if (!/^\d{6}$/.test(code)) return 0;
  const now = Math.floor(Date.now() / 30000);
  for (const d of [0, -1, 1]) {
    const st = now + d;
    if (st <= last) continue;
    if (eq(await totp(secret, st), code)) return st;
  }
  return 0;
}

async function sb(env, method, path, body, prefer) {
  const h = { apikey: env.SUPABASE_KEY, 'Content-Type': 'application/json' };
  if (env.SUPABASE_KEY.startsWith('eyJ')) h.Authorization = 'Bearer ' + env.SUPABASE_KEY;
  if (prefer) h.Prefer = prefer;
  const r = await fetch(env.SUPABASE_URL + '/rest/v1/' + path, { method, headers: h, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text();
  let data = null;
  try { data = t ? JSON.parse(t) : null; } catch (e) { }
  return { ok: r.ok, status: r.status, data };
}
const audit = (env, actor, accion, detalle = '') => sb(env, 'POST', 'auditoria', { actor, accion, detalle });
async function saldo(env, uid) {
  const r = await sb(env, 'GET', `libro?user_id=eq.${uid}&select=centavos`);
  return r.ok ? r.data.reduce((s, x) => s + x.centavos, 0) : 0;
}
function cents(s) {
  const t = s.trim().replace(',', '.');
  if (!/^\d{1,7}(\.\d{1,2})?$/.test(t)) return null;
  const c = Math.round(parseFloat(t) * 100);
  return c > 0 && c <= 100000000 ? c : null;
}
async function loadUser(env, id) {
  const r = await sb(env, 'GET', `usuarios?id=eq.${Number(id)}&select=*`);
  return (r.ok && r.data[0]) || null;
}
async function readCookie(req, env) {
  const c = (req.headers.get('Cookie') || '').match(/(?:^|; )s=([^;]+)/);
  if (!c) return null;
  const [p, sig] = c[1].split('.');
  if (!p || !sig || !eq(sig, await hmac(env.SESSION_SECRET, p))) return null;
  try { const d = JSON.parse(new TextDecoder().decode(unb64(p))); return d.e > Date.now() ? d : null; } catch (e) { return null; }
}
async function cookie(env, uid, kind) {
  const age = kind === 'pre' ? 300 : 28800;
  const p = b64(enc.encode(JSON.stringify({ u: uid, k: kind, e: Date.now() + age * 1000 })));
  return `s=${p}.${await hmac(env.SESSION_SECRET, p)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${age}`;
}
const CLEAR = 's=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0';
async function bloqueado(env, email) {
  const desde = new Date(Date.now() - 10 * 60e3).toISOString();
  const n = await sb(env, 'GET', `auditoria?accion=eq.LOGIN_FALLO&detalle=eq.${q(email)}&creado=gte.${q(desde)}&select=id`);
  return n.ok && n.data.length >= 5;
}

const H = { 'Content-Type': 'text/html; charset=utf-8', 'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'self' 'unsafe-inline'; base-uri 'none'; form-action 'self'", 'Referrer-Policy': 'same-origin', 'Cache-Control': 'no-store' };
const html = (b, status = 200) => new Response(b, { status, headers: H });
const go = (to, ck) => new Response(null, { status: 303, headers: { Location: to, ...(ck ? { 'Set-Cookie': ck } : {}) } });

const CSS = `:root{--bg:#0e1113;--card:#171c20;--line:#232a30;--tx:#e8edf0;--mu:#8b98a3;--g:#2ecc8f;--g2:#1f9d6b;--au:#d4af37}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--tx);min-height:100vh;overflow-x:hidden}
body:before,body:after{content:"";position:fixed;z-index:-1;border-radius:50%;filter:blur(90px);animation:fl 14s ease-in-out infinite alternate}
body:before{width:420px;height:420px;background:#1f9d6b;opacity:.35;top:-140px;left:-120px}
body:after{width:360px;height:360px;background:#d4af37;opacity:.12;bottom:-140px;right:-100px;animation-delay:-6s}
@keyframes fl{to{transform:translate(40px,60px) scale(1.15)}}
@keyframes up{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes pop{from{opacity:0;transform:translate(-50%,-10px)}to{opacity:1;transform:translate(-50%,0)}}
.wrap{max-width:960px;margin:auto;padding:14px}
.auth{min-height:100vh;display:grid;place-items:center;padding:16px}
.box{width:100%;max-width:400px;animation:up .5s both}
.logo{display:flex;align-items:center;gap:10px;font-weight:700;font-size:20px}.logo svg{width:34px;height:34px}
.card{background:linear-gradient(180deg,rgba(255,255,255,.035),rgba(255,255,255,.01)),var(--card);border:1px solid var(--line);border-radius:18px;padding:18px;margin:14px 0;animation:up .5s both;box-shadow:0 10px 30px rgba(0,0,0,.25)}
h1{font-size:24px;margin:.2em 0 .1em}h2{font-size:13px;margin:0 0 6px;color:var(--mu);font-weight:600;text-transform:uppercase;letter-spacing:.07em}
p.s{color:var(--mu);margin:0 0 10px;font-size:14px}
label{display:block;font-size:13px;color:var(--mu);margin:12px 0 4px}
input,select{width:100%;padding:13px 14px;border-radius:12px;border:1px solid var(--line);background:#0f1316;color:var(--tx);font:inherit;transition:border .2s,box-shadow .2s}
input:focus{outline:0;border-color:var(--g);box-shadow:0 0 0 3px rgba(46,204,143,.18)}
button,.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;width:100%;padding:13px 16px;margin-top:14px;border:0;border-radius:12px;background:linear-gradient(135deg,var(--g),var(--g2));color:#04140d;font:inherit;font-weight:600;cursor:pointer;transition:transform .15s,filter .2s,box-shadow .2s;text-decoration:none}
button:hover,.btn:hover{filter:brightness(1.08);box-shadow:0 6px 20px rgba(46,204,143,.25)}button:active{transform:scale(.98)}button:disabled{opacity:.6;cursor:wait}
.sm{width:auto;margin:0;padding:8px 14px;font-size:14px}
.ghost{background:transparent;color:var(--tx);border:1px solid var(--line)}.ghost:hover{background:rgba(255,255,255,.05);box-shadow:none}
.danger{background:rgba(229,72,77,.14);color:#ff8b8f;border:1px solid rgba(229,72,77,.35)}
.spin{width:16px;height:16px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:spin .7s linear infinite}
.top{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:6px 0}
.chip{display:flex;align-items:center;gap:10px}.chip form{margin:0}
.av{width:38px;height:38px;flex:none;border-radius:50%;display:grid;place-items:center;background:linear-gradient(135deg,var(--au),#8a6d12);color:#1b1500;font-weight:700}
.hero{background:radial-gradient(120% 140% at 0 0,#1f9d6b 0,#0f5a40 45%,#101a16 100%);border:1px solid rgba(46,204,143,.35)}
.hero small{color:#bfe9d6}.bal{font-size:40px;font-weight:800;letter-spacing:-.5px}
.grid{display:grid;gap:14px}@media(min-width:760px){.g2{grid-template-columns:1fr 1fr}}
.row{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:12px 0;border-bottom:1px solid var(--line);animation:up .4s both}.row:last-child{border:0}
.item{padding:12px 0;border-bottom:1px solid var(--line);animation:up .4s both}.item:last-child{border:0}
.acts{display:flex;gap:8px;margin-top:10px}.acts form{flex:1;margin:0}.acts button{flex:1;margin:0;width:100%}
.mu{color:var(--mu);font-size:13px}
.badge{display:inline-block;font-size:12px;padding:3px 9px;border-radius:99px;font-weight:600}
.PENDIENTE{background:rgba(245,165,36,.14);color:#f5a524}.APROBADO,.APROBADA{background:rgba(46,204,143,.14);color:var(--g)}.RECHAZADO,.RECHAZADA{background:rgba(229,72,77,.14);color:#ff8b8f}
.pos{color:var(--g)}.neg{color:#ff8b8f}
.seg{display:grid;grid-template-columns:1fr 1fr;gap:6px;background:#0f1316;border:1px solid var(--line);border-radius:12px;padding:4px}
.seg input{position:absolute;opacity:0;width:0;height:0}
.seg label{margin:0;text-align:center;padding:10px;border-radius:9px;cursor:pointer;color:var(--mu);transition:.2s}
.seg input:checked+label{background:var(--g2);color:#fff}
.amt{position:relative}.amt span{position:absolute;left:14px;top:50%;transform:translateY(-50%);color:var(--mu)}.amt input{padding-left:30px;font-size:20px;font-weight:600}
.toast{position:fixed;left:50%;top:14px;transform:translateX(-50%);z-index:9;background:#1d2428;border:1px solid var(--line);padding:11px 16px;border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,.4);animation:pop .3s both;max-width:92vw;text-align:center}
.empty{text-align:center;color:var(--mu);padding:18px 0;font-size:14px}
.key{font-family:ui-monospace,monospace;font-size:17px;letter-spacing:2px;word-break:break-all;background:#0f1316;border:1px dashed var(--au);border-radius:12px;padding:12px;margin:8px 0}
.stats{display:grid;grid-template-columns:1fr 1fr;gap:12px}.stats .card{margin:8px 0}.stats b{font-size:30px;display:block}
.pw{position:relative}.pw button{position:absolute;right:6px;top:50%;transform:translateY(-50%);width:auto;margin:0;padding:6px 10px;font-size:13px;background:transparent;color:var(--mu);box-shadow:none}
.code{text-align:center;font-size:28px;letter-spacing:10px;font-weight:700}
a{color:var(--g)}details summary{cursor:pointer;color:var(--mu);padding:4px 0}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}`;

const JS = `document.querySelectorAll('form').forEach(function(f){f.addEventListener('submit',function(e){if(f.dataset.s){e.preventDefault();return}f.dataset.s=1;var b=e.submitter||f.querySelector('button:not([type=button])');setTimeout(function(){if(b){b.disabled=true;b.insertAdjacentHTML('afterbegin','<i class="spin"></i>')}},0)})});
document.querySelectorAll('[data-pw]').forEach(function(b){b.addEventListener('click',function(){var i=b.previousElementSibling;i.type=i.type==='password'?'text':'password';b.textContent=i.type==='password'?'Ver':'Ocultar'})});
document.querySelectorAll('[data-copy]').forEach(function(b){b.addEventListener('click',function(){if(navigator.clipboard)navigator.clipboard.writeText(b.dataset.copy);b.textContent='Copiado'})});
document.querySelectorAll('[data-n]').forEach(function(el){var t=+el.dataset.n,s=performance.now();(function f(n){var p=Math.min((n-s)/900,1),v=Math.round(t*(1-Math.pow(1-p,3)));el.textContent=(v/100).toLocaleString('es-VE',{minimumFractionDigits:2,maximumFractionDigits:2});if(p<1)requestAnimationFrame(f)})(s)});
setTimeout(function(){document.querySelectorAll('.toast').forEach(function(t){t.style.transition='opacity .4s';t.style.opacity=0})},3500);
window.addEventListener('pageshow',function(e){if(e.persisted)location.reload()});`;

const MSG = { bloq: 'Demasiados intentos. Espera 10 minutos.', mal: 'Datos incorrectos.', cod: 'Código incorrecto o vencido.', reg: 'Solicitud recibida. Tu cuenta queda pendiente de aprobación.', adm: 'Administrador creado. Ahora inicia sesión.', inv: 'Datos inválidos.', saldo: 'Saldo insuficiente.', sol: 'Solicitud enviada, pendiente de aprobación.', bye: 'Sesión cerrada.' };
const LOGO = `<svg viewBox="0 0 32 32" fill="none"><defs><linearGradient id="lg" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#2ecc8f"/><stop offset="1" stop-color="#d4af37"/></linearGradient></defs><path d="M16 3l11 4v8c0 7-5 12-11 14C10 27 5 22 5 15V7l11-4z" fill="url(#lg)"/><path d="M11 16l4 4 7-8" stroke="#04140d" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
const shell = (body, m) => `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#0e1113"><title>Proyecto-12</title><style>${CSS}</style></head><body>${MSG[m] ? `<div class="toast" role="status">${MSG[m]}</div>` : ''}${body}<script>${JS}</script></body></html>`;
const auth = (t, s, inner, m) => shell(`<main class="auth"><div class="box"><div class="logo">${LOGO}Proyecto-12</div><div class="card"><h1>${t}</h1><p class="s">${s}</p>${inner}</div></div></main>`, m);
const field = (n, l, t = 'text', x = '') => `<label for="${n}">${l}</label><input id="${n}" name="${n}" type="${t}" ${x} required>`;
const pwf = (n, l, x = '') => `<label for="${n}">${l}</label><div class="pw"><input id="${n}" name="${n}" type="password" ${x} required><button type="button" data-pw>Ver</button></div>`;
const EM = 'autocomplete="username" autocapitalize="none" spellcheck="false"';

const loginP = m => auth('Bienvenido', 'Ingresa con tu correo y contraseña', `<form method="post">${field('email', 'Correo', 'email', EM)}${pwf('pw', 'Contraseña', 'autocomplete="current-password"')}<button>Entrar</button></form><p class="mu" style="text-align:center;margin:16px 0 0">¿No tienes cuenta? <a href="/registro">Solicítala</a></p>`, m);
const regP = m => auth('Crear cuenta', 'Un administrador revisará tu solicitud', `<form method="post">${field('nombre', 'Nombre completo', 'text', 'autocomplete="name" maxlength="80"')}${field('cedula', 'Cédula', 'text', 'maxlength="20"')}${field('email', 'Correo', 'email', EM)}${pwf('pw', 'Contraseña (mínimo 10 caracteres)', 'autocomplete="new-password" minlength="10"')}<button>Solicitar cuenta</button></form><p class="mu" style="text-align:center;margin:16px 0 0"><a href="/login">Ya tengo cuenta</a></p>`, m);
const setupP = m => auth('Crear administrador', 'Solo se puede hacer una vez', `<form method="post">${field('nombre', 'Nombre', 'text', 'maxlength="80"')}${field('email', 'Correo', 'email', EM)}${pwf('pw', 'Contraseña (mínimo 10 caracteres)', 'autocomplete="new-password" minlength="10"')}${pwf('token', 'Código de instalación', 'autocomplete="off"')}<button>Crear administrador</button></form>`, m);
function twoP(u, secret, m) {
  const uri = `otpauth://totp/Proyecto-12:${q(u.email)}?secret=${secret}&issuer=Proyecto-12`;
  const setup = !u.totp_ok;
  const head = setup ? `<a class="btn ghost" href="${esc(uri)}">Abrir mi app autenticadora</a><p class="mu" style="margin:12px 0 0">Si no se abre, agrega esta clave a mano en Google Authenticator u otra app:</p><div class="key">${secret}</div><button type="button" class="ghost sm" data-copy="${secret}">Copiar clave</button>` : '';
  return auth('Verificación en dos pasos', setup ? 'Primera vez: activa la protección de tu cuenta' : 'Ingresa el código de 6 dígitos de tu app', `${head}<form method="post"><label for="code">Código</label><input class="code" id="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="7" pattern="[0-9 ]*" required><button>${setup ? 'Activar y entrar' : 'Verificar'}</button></form>`, m);
}
const top = (me, tag) => `<header class="top"><div class="logo">${LOGO}<span>Proyecto-12</span></div><div class="chip">${tag || ''}<div class="av" title="${esc(me.nombre)}">${esc((me.nombre || '?').trim().charAt(0).toUpperCase())}</div><form method="post" action="/salir"><button class="sm ghost">Salir</button></form></div></header>`;
const solRow = (r, i) => `<div class="row" style="animation-delay:${i * 40}ms"><div><b>${r.tipo === 'DEPOSITO' ? 'Depósito' : 'Retiro'}</b><div class="mu">${fecha(r.creado)}</div></div><div style="text-align:right"><div>$ ${money(r.centavos)}</div><span class="badge ${esc(r.estado)}">${esc(r.estado)}</span></div></div>`;
const movRow = (r, i) => `<div class="row" style="animation-delay:${i * 40}ms"><div><b>${r.centavos > 0 ? 'Ingreso' : 'Egreso'}</b><div class="mu">${fecha(r.creado)}</div></div><b class="${r.centavos > 0 ? 'pos' : 'neg'}">${r.centavos > 0 ? '+' : '−'}$ ${money(Math.abs(r.centavos))}</b></div>`;
const list = (a, fn, vacio) => a.length ? a.map(fn).join('') : `<div class="empty">${vacio}</div>`;

function panelP(me, s, sols, mov, m) {
  const first = esc((me.nombre || '').trim().split(' ')[0]);
  if (me.estado !== 'APROBADO') return shell(`<div class="wrap">${top(me)}<div class="card"><h1>Hola, ${first}</h1><p class="s">Estado de tu cuenta: <span class="badge ${esc(me.estado)}">${esc(me.estado)}</span></p><p>${me.estado === 'RECHAZADO' ? 'Tu solicitud no fue aprobada. Comunícate con la administración.' : 'Un administrador está revisando tu solicitud. Normalmente se aprueba en 12 a 24 horas.'}</p></div></div>`, m);
  return shell(`<div class="wrap">${top(me)}
<section class="card hero"><small>Hola, ${first} · Saldo disponible</small><div class="bal">$ <span data-n="${s}">${money(s)}</span></div></section>
<section class="card"><h2>Nueva solicitud</h2><form method="post" action="/solicitar"><div class="seg"><input type="radio" id="t1" name="tipo" value="DEPOSITO" checked><label for="t1">Depósito</label><input type="radio" id="t2" name="tipo" value="RETIRO"><label for="t2">Retiro</label></div>
<label for="monto">Monto</label><div class="amt"><span>$</span><input id="monto" name="monto" inputmode="decimal" placeholder="0,00" autocomplete="off" required></div>
<label for="ref">Referencia (opcional)</label><input id="ref" name="referencia" maxlength="60" autocomplete="off"><button>Enviar solicitud</button></form></section>
<div class="grid g2"><section class="card"><h2>Solicitudes</h2>${list(sols, solRow, 'Aún no hay solicitudes')}</section><section class="card"><h2>Movimientos</h2>${list(mov, movRow, 'Aún no hay movimientos')}</section></div></div>`, m);
}
const acts = (path) => `<form method="post" action="${path}" class="acts" style="display:flex"><button class="sm" name="a" value="aprobar">Aprobar</button><button class="sm danger" name="a" value="rechazar" onclick="return confirm('¿Rechazar?')">Rechazar</button></form>`;
function adminP(me, users, sols, logs, m) {
  return shell(`<div class="wrap">${top(me, '<span class="badge APROBADO">Admin</span>')}
<div class="stats"><div class="card"><h2>Cuentas</h2><b>${users.length}</b><span class="mu">por aprobar</span></div><div class="card"><h2>Solicitudes</h2><b>${sols.length}</b><span class="mu">por aprobar</span></div></div>
<div class="grid g2"><section class="card"><h2>Cuentas por aprobar</h2>${list(users, (x, i) => `<div class="item" style="animation-delay:${i * 40}ms"><b>${esc(x.nombre)}</b><div class="mu">${esc(x.cedula)} · ${esc(x.email)}</div>${acts('/admin/usuario/' + x.id)}</div>`, 'Nada pendiente')}</section>
<section class="card"><h2>Solicitudes por aprobar</h2>${list(sols, (x, i) => `<div class="item" style="animation-delay:${i * 40}ms"><div class="row" style="padding:0;border:0"><div><b>${esc(x.usuarios?.nombre)}</b><div class="mu">${esc(x.referencia)}</div></div><div style="text-align:right"><b>$ ${money(x.centavos)}</b><div class="mu">${x.tipo === 'DEPOSITO' ? 'Depósito' : 'Retiro'}</div></div></div>${acts('/admin/solicitud/' + x.id)}</div>`, 'Nada pendiente')}</section></div>
<section class="card"><details><summary>Auditoría (últimos 30 eventos)</summary>${list(logs, l => `<div class="row"><div><b>${esc(l.accion)}</b> <span class="mu">${esc(l.detalle)}</span><div class="mu">${esc(l.actor)}</div></div><span class="mu">${fecha(l.creado)}</span></div>`, 'Sin eventos')}</details></section></div>`, m);
}

async function route(req, env) {
  const u = new URL(req.url), path = u.pathname, post = req.method === 'POST';
  const m = u.searchParams.get('m');
  if (post && req.headers.get('Origin') !== u.origin) return new Response('Origen no permitido', { status: 403 });
  const form = post ? await req.formData() : null;
  const f = k => String(form.get(k) ?? '');
  const ses = await readCookie(req, env);
  const me = ses && ses.k === 'full' ? await loadUser(env, ses.u) : null;

  if (path === '/') return go(me ? (me.rol === 'admin' ? '/admin' : '/panel') : '/login');

  if (path === '/login') {
    if (!post) return html(loginP(m));
    const email = f('email').trim().toLowerCase().slice(0, 120);
    if (await bloqueado(env, email)) return go('/login?m=bloq');
    const r = await sb(env, 'GET', `usuarios?email=eq.${q(email)}&select=*`);
    const usr = r.ok && r.data[0];
    if (usr && await checkPw(f('pw'), usr.pw)) {
      if (usr.rol === 'admin') return go('/2fa', await cookie(env, usr.id, 'pre'));
      await audit(env, email, 'LOGIN');
      return go('/panel', await cookie(env, usr.id, 'full'));
    }
    if (!usr) await hashPw('relleno');
    await audit(env, email, 'LOGIN_FALLO', email);
    return go('/login?m=mal');
  }

  if (path === '/2fa') {
    if (!ses || ses.k !== 'pre') return go('/login');
    const usr = await loadUser(env, ses.u);
    if (!usr || usr.rol !== 'admin') return go('/login');
    if (!usr.totp_secret) {
      const sec = b32enc(crypto.getRandomValues(new Uint8Array(20)));
      await sb(env, 'PATCH', `usuarios?id=eq.${usr.id}`, { totp_secret: sec });
      usr.totp_secret = sec;
    }
    if (!post) return html(twoP(usr, usr.totp_secret, m));
    if (await bloqueado(env, usr.email)) return go('/login?m=bloq', CLEAR);
    const st = await checkTotp(usr.totp_secret, f('code'), Number(usr.totp_last) || 0);
    if (!st) { await audit(env, usr.email, 'LOGIN_FALLO', usr.email); return go('/2fa?m=cod'); }
    await sb(env, 'PATCH', `usuarios?id=eq.${usr.id}`, { totp_ok: true, totp_last: st });
    await audit(env, usr.email, 'LOGIN');
    return go('/admin', await cookie(env, usr.id, 'full'));
  }

  if (path === '/registro') {
    if (!post) return html(regP(m));
    const nombre = f('nombre').trim().slice(0, 80), cedula = f('cedula').trim().slice(0, 20);
    const email = f('email').trim().toLowerCase().slice(0, 120), pw = f('pw');
    if (!nombre || !cedula || !email.includes('@') || pw.length < 10) return go('/registro?m=inv');
    const r = await sb(env, 'POST', 'usuarios', { nombre, cedula, email, pw: await hashPw(pw) });
    if (r.ok) await audit(env, email, 'REGISTRO');
    return go('/login?m=reg');
  }

  if (path === '/crear-admin') {
    const ex = await sb(env, 'GET', 'usuarios?rol=eq.admin&select=id&limit=1');
    if (!env.SETUP_TOKEN || !ex.ok || ex.data.length) return new Response('No encontrado', { status: 404 });
    if (!post) return html(setupP(m));
    const nombre = f('nombre').trim().slice(0, 80), email = f('email').trim().toLowerCase().slice(0, 120), pw = f('pw');
    if (f('token').trim() !== String(env.SETUP_TOKEN).trim() || !nombre || !email.includes('@') || pw.length < 10) return go('/crear-admin?m=mal');
    const r = await sb(env, 'POST', 'usuarios', { nombre, cedula: '-', email, pw: await hashPw(pw), rol: 'admin', estado: 'APROBADO', totp_secret: b32enc(crypto.getRandomValues(new Uint8Array(20))) });
    if (r.ok) await audit(env, email, 'ADMIN_CREADO');
    return go(r.ok ? '/login?m=adm' : '/crear-admin?m=inv');
  }

  if (path === '/salir' && post) return go('/login?m=bye', CLEAR);
  if (!me) return go('/login');

  if (path === '/panel' && !post) {
    if (me.rol === 'admin') return go('/admin');
    const [sols, mov] = await Promise.all([
      sb(env, 'GET', `solicitudes?user_id=eq.${me.id}&order=id.desc&limit=20&select=*`),
      sb(env, 'GET', `libro?user_id=eq.${me.id}&order=id.desc&limit=20&select=*`)]);
    return html(panelP(me, await saldo(env, me.id), sols.data || [], mov.data || [], m));
  }

  if (path === '/solicitar' && post) {
    if (me.rol !== 'cliente' || me.estado !== 'APROBADO') return new Response('Prohibido', { status: 403 });
    const tipo = f('tipo'), c = cents(f('monto'));
    if (!['DEPOSITO', 'RETIRO'].includes(tipo) || c === null) return go('/panel?m=inv');
    if (tipo === 'RETIRO') {
      const p = await sb(env, 'GET', `solicitudes?user_id=eq.${me.id}&tipo=eq.RETIRO&estado=eq.PENDIENTE&select=centavos`);
      const pend = (p.data || []).reduce((s, x) => s + x.centavos, 0);
      if (c + pend > await saldo(env, me.id)) return go('/panel?m=saldo');
    }
    await sb(env, 'POST', 'solicitudes', { user_id: me.id, tipo, centavos: c, referencia: f('referencia').slice(0, 60) });
    await audit(env, me.email, 'SOLICITUD_' + tipo, String(c));
    return go('/panel?m=sol');
  }

  if (me.rol !== 'admin') return new Response('Prohibido', { status: 403 });

  if (path === '/admin' && !post) {
    const [us, so, lg] = await Promise.all([
      sb(env, 'GET', 'usuarios?estado=eq.PENDIENTE&rol=eq.cliente&order=id&select=*'),
      sb(env, 'GET', 'solicitudes?estado=eq.PENDIENTE&order=id&select=*,usuarios(nombre)'),
      sb(env, 'GET', 'auditoria?order=id.desc&limit=30&select=*')]);
    return html(adminP(me, us.data || [], so.data || [], lg.data || [], m));
  }

  let x;
  if (post && (x = path.match(/^\/admin\/usuario\/(\d+)$/))) {
    const nuevo = { aprobar: 'APROBADO', rechazar: 'RECHAZADO' }[f('a')];
    if (!nuevo) return go('/admin?m=inv');
    const r = await sb(env, 'PATCH', `usuarios?id=eq.${x[1]}&estado=eq.PENDIENTE&rol=eq.cliente`, { estado: nuevo }, 'return=representation');
    if (r.ok && r.data.length) await audit(env, me.email, 'USUARIO_' + nuevo, 'id=' + x[1]);
    return go('/admin');
  }
  if (post && (x = path.match(/^\/admin\/solicitud\/(\d+)$/))) {
    const a = f('a');
    if (!['aprobar', 'rechazar'].includes(a)) return go('/admin?m=inv');
    const r = await sb(env, 'POST', 'rpc/resolver_solicitud', { p_id: Number(x[1]), p_accion: a, p_admin: me.id });
    if (r.ok && r.data === 'SALDO_INSUFICIENTE') return go('/admin?m=saldo');
    if (r.ok && r.data === 'OK') await audit(env, me.email, 'SOLICITUD_' + a.toUpperCase(), 'id=' + x[1]);
    return go('/admin');
  }
  return new Response('No encontrado', { status: 404 });
}

export default {
  async fetch(req, env) {
    try { return await route(req, env); }
    catch (e) { console.log('error', e.message); return html(shell('<main class="auth"><div class="card">Error interno. Intenta de nuevo.</div></main>'), 500); }
  }
};
