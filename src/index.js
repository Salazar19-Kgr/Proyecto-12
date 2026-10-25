const enc = new TextEncoder();
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64 = s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return Uint8Array.from(atob(s), c => c.charCodeAt(0)); };
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const q = encodeURIComponent;
const money = c => (c / 100).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const fecha = s => String(s).slice(0, 16).replace('T', ' ');
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
  const p = stored.split('$');
  if (p.length !== 3) return false;
  return eq(await hashPw(pw, unb64(p[1])), stored);
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
async function getUser(req, env) {
  const c = (req.headers.get('Cookie') || '').match(/(?:^|; )s=([^;]+)/);
  if (!c) return null;
  const [p, sig] = c[1].split('.');
  if (!p || !sig || !eq(sig, await hmac(env.SESSION_SECRET, p))) return null;
  let d;
  try { d = JSON.parse(new TextDecoder().decode(unb64(p))); } catch (e) { return null; }
  if (!d.u || d.e < Date.now()) return null;
  const r = await sb(env, 'GET', `usuarios?id=eq.${Number(d.u)}&select=*`);
  return (r.ok && r.data[0]) || null;
}
async function setCookie(env, uid) {
  const p = b64(enc.encode(JSON.stringify({ u: uid, e: Date.now() + 8 * 3600e3 })));
  return `s=${p}.${await hmac(env.SESSION_SECRET, p)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=28800`;
}

const H = { 'Content-Type': 'text/html; charset=utf-8', 'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'self' 'unsafe-inline'", 'Referrer-Policy': 'same-origin', 'Cache-Control': 'no-store' };
const html = (b, status = 200) => new Response(b, { status, headers: H });
const go = (to, cookie) => new Response(null, { status: 303, headers: { Location: to, ...(cookie ? { 'Set-Cookie': cookie } : {}) } });

const CSS = `body{font-family:sans-serif;background:#16181a;color:#eee;margin:auto;padding:12px;max-width:720px}a{color:#2ecc8f}input,select,button{width:100%;padding:10px;margin:4px 0;border-radius:8px;border:1px solid #333;background:#22262a;color:#eee;box-sizing:border-box}button{background:#1f9d6b;border:0;font-weight:bold}.c{background:#1e2226;padding:12px;border-radius:12px;margin:10px 0}.m{color:#d4af37}.b{display:inline-block;width:auto;padding:6px 10px}.r{background:#a33}table{width:100%;font-size:14px}.f{background:#2a2f33;padding:8px;border-radius:8px;margin:6px 0}`;
const MSG = { bloq: 'Demasiados intentos. Espera 10 minutos.', mal: 'Datos incorrectos.', reg: 'Solicitud recibida. Tu cuenta queda pendiente de aprobación.', adm: 'Administrador creado. Ya puedes entrar.', inv: 'Datos inválidos.', saldo: 'Saldo insuficiente.', sol: 'Solicitud enviada, pendiente de aprobación.', bye: 'Sesión cerrada.' };
const page = (body, m) => `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Proyecto-12</title><style>${CSS}</style></head><body><h2><a href="/" style="text-decoration:none">Proyecto-12</a></h2>${MSG[m] ? `<div class="f">${MSG[m]}</div>` : ''}${body}</body></html>`;
const salir = `<form method="post" action="/salir"><button class="b">Salir</button></form>`;
const inp = (n, ph, t = 'text') => `<input name="${n}" type="${t}" placeholder="${ph}" required>`;

const loginP = m => page(`<div class="c"><form method="post">${inp('email', 'Correo', 'email')}${inp('pw', 'Contraseña', 'password')}<button>Entrar</button></form><a href="/registro">Crear cuenta</a></div>`, m);
const regP = m => page(`<div class="c"><form method="post">${inp('nombre', 'Nombre completo')}${inp('cedula', 'Cédula')}${inp('email', 'Correo', 'email')}${inp('pw', 'Contraseña (mín. 10)', 'password')}<button>Solicitar cuenta</button></form><a href="/login">Ya tengo cuenta</a></div>`, m);
const setupP = m => page(`<div class="c"><b>Crear administrador (una sola vez)</b><form method="post">${inp('nombre', 'Nombre')}${inp('email', 'Correo', 'email')}${inp('pw', 'Contraseña (mín. 10)', 'password')}${inp('token', 'Código de instalación', 'password')}<button>Crear</button></form></div>`, m);

function panelP(me, s, sols, mov, m) {
  let b = `<div class="c">Hola, ${esc(me.nombre)} — Estado: <b>${esc(me.estado)}</b>${salir}</div>`;
  if (me.estado === 'APROBADO') {
    b += `<div class="c">Saldo disponible: <b class="m">$ ${money(s)}</b></div>
<div class="c"><form method="post" action="/solicitar"><select name="tipo"><option>DEPOSITO</option><option>RETIRO</option></select><input name="monto" placeholder="Monto (ej. 25.50)" required><input name="referencia" placeholder="Referencia (opcional)"><button>Enviar solicitud</button></form></div>
<div class="c"><b>Solicitudes</b><table>${sols.map(r => `<tr><td>${esc(r.tipo)}</td><td>${money(r.centavos)}</td><td>${esc(r.estado)}</td></tr>`).join('')}</table></div>
<div class="c"><b>Movimientos</b><table>${mov.map(r => `<tr><td>${fecha(r.creado)}</td><td>${money(r.centavos)}</td></tr>`).join('')}</table></div>`;
  } else b += `<div class="c">Tu cuenta está en revisión o fue rechazada. Un administrador debe aprobarla.</div>`;
  return page(b, m);
}
const btns = `<button class="b" name="a" value="aprobar">Aprobar</button> <button class="b r" name="a" value="rechazar">Rechazar</button>`;
function adminP(me, users, sols, logs, m) {
  return page(`<div class="c">Administrador: ${esc(me.nombre)}${salir}</div>
<div class="c"><b>Cuentas por aprobar</b>${users.map(x => `<div class="f">${esc(x.nombre)}<br>${esc(x.cedula)} · ${esc(x.email)}<form method="post" action="/admin/usuario/${x.id}">${btns}</form></div>`).join('') || '<p>Nada pendiente</p>'}</div>
<div class="c"><b>Solicitudes por aprobar</b>${sols.map(x => `<div class="f">${esc(x.usuarios?.nombre)}: ${esc(x.tipo)} $ ${money(x.centavos)} <small>${esc(x.referencia)}</small><form method="post" action="/admin/solicitud/${x.id}">${btns}</form></div>`).join('') || '<p>Nada pendiente</p>'}</div>
<div class="c"><b>Auditoría</b><table>${logs.map(l => `<tr><td>${fecha(l.creado)}</td><td>${esc(l.actor)}</td><td>${esc(l.accion)} ${esc(l.detalle)}</td></tr>`).join('')}</table></div>`, m);
}

async function route(req, env) {
  const u = new URL(req.url), path = u.pathname, post = req.method === 'POST';
  const m = u.searchParams.get('m');
  if (post && req.headers.get('Origin') !== u.origin) return new Response('Origen no permitido', { status: 403 });
  const form = post ? await req.formData() : null;
  const f = k => String(form.get(k) ?? '');
  const me = await getUser(req, env);

  if (path === '/') return go(me ? (me.rol === 'admin' ? '/admin' : '/panel') : '/login');

  if (path === '/login') {
    if (!post) return html(loginP(m));
    const email = f('email').trim().toLowerCase().slice(0, 120);
    const desde = new Date(Date.now() - 10 * 60e3).toISOString();
    const n = await sb(env, 'GET', `auditoria?accion=eq.LOGIN_FALLO&detalle=eq.${q(email)}&creado=gte.${q(desde)}&select=id`);
    if (n.ok && n.data.length >= 5) return go('/login?m=bloq');
    const r = await sb(env, 'GET', `usuarios?email=eq.${q(email)}&select=*`);
    const usr = r.ok && r.data[0];
    if (usr && await checkPw(f('pw'), usr.pw)) {
      await audit(env, email, 'LOGIN');
      return go(usr.rol === 'admin' ? '/admin' : '/panel', await setCookie(env, usr.id));
    }
    if (!usr) await hashPw('relleno');
    await audit(env, email, 'LOGIN_FALLO', email);
    return go('/login?m=mal');
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
    if (!eq(f('token'), env.SETUP_TOKEN) || !nombre || !email.includes('@') || pw.length < 10) return go('/crear-admin?m=mal');
    const r = await sb(env, 'POST', 'usuarios', { nombre, cedula: '-', email, pw: await hashPw(pw), rol: 'admin', estado: 'APROBADO' });
    if (r.ok) await audit(env, email, 'ADMIN_CREADO');
    return go('/login?m=adm');
  }

  if (path === '/salir' && post) return go('/login?m=bye', 's=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0');
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
    catch (e) { console.log('error', e.message); return html(page('<div class="c">Error interno.</div>'), 500); }
  }
};
