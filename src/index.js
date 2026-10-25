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
async function authCall(env, path, body) {
  if (!env.SUPABASE_ANON) return { ok: false, status: 0, data: 'falta SUPABASE_ANON' };
  const r = await fetch(env.SUPABASE_URL + '/auth/v1/' + path, { method: 'POST', headers: { apikey: env.SUPABASE_ANON, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  let data = null;
  try { data = await r.json(); } catch (e) { }
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
async function cookie(env, data, age) {
  const p = b64(enc.encode(JSON.stringify({ ...data, e: Date.now() + age * 1000 })));
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

const NAME = 'Plataforma Bancaria de Ahorros';
const CSS = `@property --ang{syntax:'<angle>';inherits:false;initial-value:0deg}
:root{--bg:#07061a;--b1:#2b1a7a;--b2:#4c1d95;--tx:#f1efff;--mu:#9a95c4;--card:rgba(255,255,255,.05);--line:rgba(255,255,255,.1);--inp:rgba(0,0,0,.32);--a1:#a78bfa;--a2:#7c3aed;--on:#fff;--glow:124,58,237;--c1:#3b1d9e;--c2:#6d28d9;--c3:#1b1060;--ok:#34d399;--bad:#fb7185;--warn:#fbbf24;--pt:167,139,250}
[data-t=oceano]{--bg:#04121a;--b1:#0b4a6f;--b2:#0e7490;--a1:#22d3ee;--a2:#0ea5e9;--on:#03212b;--glow:14,165,233;--c1:#0b4a6f;--c2:#0e7490;--c3:#062a3d;--pt:34,211,238;--mu:#8fb3c4}
[data-t=rubi]{--bg:#14060b;--b1:#6b0f2a;--b2:#9f1239;--a1:#fb7185;--a2:#e11d48;--on:#fff;--glow:225,29,72;--c1:#7f1230;--c2:#be123c;--c3:#3b0818;--pt:251,113,133;--mu:#c49aa6}
[data-t=oro]{--bg:#0a0a12;--b1:#16245a;--b2:#3b2a08;--a1:#f2c14e;--a2:#d9961a;--on:#2a1c00;--glow:242,193,78;--c1:#1a2f8f;--c2:#2742bd;--c3:#0f1b5a;--pt:242,193,78;--mu:#98a0bd}
[data-t=claro]{--bg:#f3f5fb;--b1:#c7d2fe;--b2:#ddd6fe;--tx:#12162b;--mu:#5b6486;--card:rgba(255,255,255,.78);--line:rgba(20,30,80,.13);--inp:#fff;--a1:#6366f1;--a2:#4f46e5;--on:#fff;--glow:79,70,229;--c1:#312e81;--c2:#4f46e5;--c3:#1e1b4b;--ok:#059669;--bad:#e11d48;--warn:#d97706;--pt:79,70,229}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:var(--tx);min-height:100vh;overflow-x:hidden;background:radial-gradient(900px 600px at 12% -10%,var(--b1),transparent 62%),radial-gradient(800px 520px at 105% 110%,var(--b2),transparent 58%),var(--bg);background-attachment:fixed;transition:background .5s,color .3s}
#bg{position:fixed;inset:0;width:100%;height:100%;z-index:-1;pointer-events:none}
.gridbg{position:fixed;inset:0;z-index:-1;pointer-events:none;background-image:linear-gradient(var(--line) 1px,transparent 1px),linear-gradient(90deg,var(--line) 1px,transparent 1px);background-size:44px 44px;-webkit-mask-image:radial-gradient(ellipse at 50% 30%,#000 0,transparent 70%);mask-image:radial-gradient(ellipse at 50% 30%,#000 0,transparent 70%);opacity:.55;animation:grid 22s linear infinite}
@keyframes grid{to{background-position:44px 44px}}
.orb{position:fixed;border-radius:50%;filter:blur(70px);z-index:-1;pointer-events:none;animation:fl 14s ease-in-out infinite alternate;background:rgb(var(--glow))}
.o1{width:360px;height:360px;opacity:.4;top:-110px;right:-90px}.o2{width:300px;height:300px;opacity:.25;bottom:-100px;left:-80px;animation-delay:-6s}.o3{width:200px;height:200px;opacity:.2;top:42%;left:55%;animation-delay:-3s}
@keyframes fl{to{transform:translate(-50px,60px) scale(1.18)}}
@keyframes up{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:none}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes pop{from{opacity:0;transform:translate(-50%,-12px)}to{opacity:1;transform:translate(-50%,0)}}
@keyframes shine{50%,100%{transform:translateX(120%)}}
@keyframes draw{to{stroke-dashoffset:0}}@keyframes fade{to{opacity:1}}
@keyframes rot{to{--ang:360deg}}
.wrap{max-width:980px;margin:auto;padding:14px}
.auth{min-height:calc(100vh - 110px);display:grid;place-items:center;padding:16px}
.box{width:100%;max-width:420px;animation:up .6s cubic-bezier(.2,.8,.2,1) both}
.pitch{display:none}
@media(min-width:900px){.auth{grid-template-columns:1fr 420px;gap:70px;max-width:1040px;margin:auto;place-items:center stretch}.pitch{display:block;animation:up .7s both}.pitch h1{font-size:46px;line-height:1.1;margin:0 0 14px}.pitch ul{list-style:none;padding:0;margin:22px 0 0}.pitch li{display:flex;gap:12px;align-items:center;margin:14px 0;color:var(--mu)}}
.brand{display:flex;align-items:center;gap:11px;margin-bottom:6px}.brand svg{width:42px;height:42px;flex:none}.brand b{display:block;font-size:16px;line-height:1.15}
.brand small,.brand a.tag{display:block;color:var(--a1);font-size:11px;letter-spacing:.16em;text-transform:uppercase;text-decoration:none;font-weight:600}.brand a.tag:hover{text-decoration:underline}
.card{background:var(--card);-webkit-backdrop-filter:blur(14px);backdrop-filter:blur(14px);border:1px solid var(--line);border-radius:20px;padding:18px;margin:14px 0;animation:up .6s cubic-bezier(.2,.8,.2,1) both;box-shadow:0 12px 40px rgba(0,0,0,.3)}
.glow{position:relative}
.glow:after{content:"";position:absolute;inset:-1px;border-radius:21px;padding:1px;background:conic-gradient(from var(--ang),transparent 0 60%,var(--a1) 82%,transparent);-webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);mask-composite:exclude;animation:rot 5s linear infinite;pointer-events:none}
h1{font-size:25px;margin:.2em 0 .1em;letter-spacing:-.3px}h2{font-size:12px;margin:0 0 8px;color:var(--mu);font-weight:600;text-transform:uppercase;letter-spacing:.12em}
p.s{color:var(--mu);margin:0 0 10px;font-size:14px}
label{display:block;font-size:13px;color:var(--mu);margin:14px 0 5px}
input{width:100%;padding:14px;border-radius:13px;border:1px solid var(--line);background:var(--inp);color:var(--tx);font:inherit;transition:border .2s,box-shadow .2s}
input:focus{outline:0;border-color:var(--a1);box-shadow:0 0 0 3px rgba(var(--glow),.25)}
button,.btn{position:relative;overflow:hidden;display:inline-flex;align-items:center;justify-content:center;gap:8px;width:100%;padding:14px 16px;margin-top:16px;border:0;border-radius:14px;background:linear-gradient(135deg,var(--a1),var(--a2));color:var(--on);font:inherit;font-weight:700;cursor:pointer;transition:transform .15s,box-shadow .25s;text-decoration:none;box-shadow:0 8px 24px rgba(var(--glow),.3)}
button:before,.btn:before{content:"";position:absolute;inset:0;background:linear-gradient(110deg,transparent 30%,rgba(255,255,255,.4) 50%,transparent 70%);transform:translateX(-120%);transition:transform .6s}
button:hover:before{transform:translateX(120%)}button:hover{transform:translateY(-1px);box-shadow:0 12px 30px rgba(var(--glow),.45)}button:active{transform:scale(.98)}button:disabled{opacity:.65;cursor:wait}
.sm{width:auto;margin:0;padding:9px 15px;font-size:14px;border-radius:12px}
.ghost{background:var(--card);color:var(--tx);border:1px solid var(--line);box-shadow:none}.ghost:before{display:none}.ghost:hover{box-shadow:none;background:var(--line)}
.danger{background:rgba(251,113,133,.12);color:var(--bad);border:1px solid rgba(251,113,133,.4);box-shadow:none}.danger:before{display:none}.danger:hover{box-shadow:none}
.spin{width:16px;height:16px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:spin .7s linear infinite}
.top{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:8px 0}.top .brand{margin:0}
.chip{display:flex;align-items:center;gap:10px}.chip form{margin:0}
.av{width:40px;height:40px;flex:none;border-radius:50%;display:grid;place-items:center;background:linear-gradient(135deg,var(--a1),var(--a2));color:var(--on);font-weight:800}
.vcard{position:relative;overflow:hidden;border:0;padding:22px;color:#fff;background:linear-gradient(135deg,var(--c1),var(--c2) 50%,var(--c3));box-shadow:0 20px 50px rgba(var(--glow),.35)}
.vcard:before{content:"";position:absolute;width:280px;height:280px;border-radius:50%;background:radial-gradient(circle,rgba(var(--glow),.55),transparent 65%);top:-120px;right:-90px}
.vcard:after{content:"";position:absolute;inset:0;background:linear-gradient(115deg,transparent 35%,rgba(255,255,255,.18) 50%,transparent 65%);transform:translateX(-120%);animation:shine 6s ease-in-out infinite}
.vcard>*{position:relative;z-index:1}.vrow{display:flex;justify-content:space-between;align-items:center;gap:10px}
.lab{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:rgba(255,255,255,.75)}
.bal{font-size:clamp(34px,10vw,48px);font-weight:800;letter-spacing:-1px;font-variant-numeric:tabular-nums;line-height:1.1;margin-top:4px}
.holder{font-size:13px;letter-spacing:.12em;text-transform:uppercase;color:rgba(255,255,255,.88)}
.spark{width:100%;height:70px;margin-top:12px;display:block}.ln{fill:none;stroke:#fff;stroke-width:2.5;stroke-linecap:round;stroke-linejoin:round;stroke-dasharray:1;stroke-dashoffset:1;vector-effect:non-scaling-stroke;animation:draw 1.6s .3s ease forwards}.ar{opacity:0;animation:fade 1s 1.2s forwards}
.grid{display:grid;gap:14px}@media(min-width:760px){.g2{grid-template-columns:1fr 1fr}}
.row{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:13px 0;border-bottom:1px solid var(--line);animation:up .45s both}.row:last-child{border:0}
.item{padding:14px 0;border-bottom:1px solid var(--line);animation:up .45s both}.item:last-child{border:0}.who{display:flex;gap:12px;align-items:center}
.acts{display:flex;gap:8px;margin:12px 0 0}.acts button{flex:1;margin:0;width:auto}
.mu{color:var(--mu);font-size:13px}
.badge{display:inline-block;font-size:12px;padding:3px 10px;border-radius:99px;font-weight:700}
.PENDIENTE{background:rgba(251,191,36,.16);color:var(--warn)}.APROBADO,.APROBADA{background:rgba(52,211,153,.16);color:var(--ok)}.RECHAZADO,.RECHAZADA{background:rgba(251,113,133,.16);color:var(--bad)}
.pos{color:var(--ok)}.neg{color:var(--bad)}
.seg{position:relative;display:grid;grid-template-columns:1fr 1fr;gap:6px;background:var(--inp);border:1px solid var(--line);border-radius:14px;padding:4px}
.seg input{position:absolute;opacity:0;pointer-events:none}.seg label{margin:0;text-align:center;padding:11px;border-radius:10px;cursor:pointer;color:var(--mu);transition:.25s}
.seg input:checked+label{background:linear-gradient(135deg,var(--a1),var(--a2));color:var(--on);font-weight:700}
.amt{position:relative}.amt span{position:absolute;left:15px;top:50%;transform:translateY(-50%);color:var(--a1);font-weight:700}.amt input{padding-left:32px;font-size:22px;font-weight:700}
.toast{position:fixed;left:50%;top:14px;transform:translateX(-50%);z-index:9;background:rgba(20,18,50,.96);color:#fff;border:1px solid rgba(255,255,255,.15);padding:12px 18px;border-radius:14px;box-shadow:0 10px 40px rgba(0,0,0,.5);animation:pop .35s both;max-width:92vw;text-align:center}
.empty{text-align:center;color:var(--mu);padding:20px 0;font-size:14px}
.stats{display:grid;grid-template-columns:1fr 1fr;gap:12px}.stats .card{margin:8px 0}.stats b{font-size:34px;display:block;line-height:1.2}
.pw{position:relative}.pw button{position:absolute;right:6px;top:50%;transform:translateY(-50%);width:auto;margin:0;padding:6px 10px;font-size:13px;background:transparent;color:var(--mu);box-shadow:none}.pw button:before{display:none}
.code{text-align:center;font-size:30px;letter-spacing:10px;font-weight:700}
a{color:var(--a1)}details summary{cursor:pointer;color:var(--mu);padding:4px 0}
.foot{text-align:center;color:var(--mu);font-size:12px;padding:18px 12px 26px}
.themes{display:flex;gap:12px;justify-content:center;margin-top:12px}
.tdot{width:28px;height:28px;min-width:0;padding:0;margin:0;border-radius:50%;border:2px solid var(--line);box-shadow:none}.tdot:before{display:none}.tdot:hover{transform:scale(1.18);box-shadow:none}.tdot.on{border-color:var(--tx);transform:scale(1.15)}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}.ln{stroke-dashoffset:0}.ar{opacity:1}}`;

const CSS2 = `html{scroll-behavior:smooth}
:root{--navbg:rgba(8,8,24,.88)}
[data-t=claro]{--navbg:rgba(255,255,255,.92)}
[data-t=esmeralda]{--bg:#050b09;--b1:#0b3d2e;--b2:#134e3a;--a1:#34e3a0;--a2:#16a974;--on:#032016;--glow:22,169,116;--c1:#0f5c43;--c2:#16a974;--c3:#06261c;--pt:52,227,160;--mu:#8fb5a6}
select{width:100%;padding:14px;border-radius:13px;border:1px solid var(--line);background:var(--inp);color:var(--tx);font:inherit}
select:focus{outline:0;border-color:var(--a1);box-shadow:0 0 0 3px rgba(var(--glow),.25)}
option{background:#14122e;color:#fff}
.ic{width:22px;height:22px;flex:none}
.app{min-height:100vh}.side{display:none}
.mainc{max-width:1120px;margin:auto;padding:12px 14px 30px}
.bnav{position:fixed;left:0;right:0;bottom:0;z-index:20;display:flex;justify-content:space-around;padding:8px 6px calc(8px + env(safe-area-inset-bottom));background:var(--navbg);-webkit-backdrop-filter:blur(16px);backdrop-filter:blur(16px);border-top:1px solid var(--line)}
.bnav a{display:flex;flex-direction:column;align-items:center;gap:2px;flex:1;font-size:11px;color:var(--mu);text-decoration:none;padding:5px 2px;border-radius:12px;transition:.2s}
.bnav a.on{color:var(--a1);background:rgba(var(--glow),.14)}
.foot{padding-bottom:90px}
@media(min-width:900px){.app{display:grid;grid-template-columns:250px 1fr}.side{display:flex;flex-direction:column;gap:6px;position:sticky;top:0;height:100vh;padding:20px 14px;border-right:1px solid var(--line);background:rgba(0,0,0,.18);-webkit-backdrop-filter:blur(14px);backdrop-filter:blur(14px)}.side a{display:flex;align-items:center;gap:12px;padding:12px 14px;border-radius:14px;color:var(--mu);text-decoration:none;font-weight:600;transition:.2s}.side a:hover{background:var(--card)}.side a.on{background:rgba(var(--glow),.16);color:var(--a1)}.side .sp{flex:1}.bnav{display:none}.app .top{display:none}.mainc{padding:24px 30px 40px}.foot{padding-bottom:26px}}
.hello h1{margin:.1em 0}
.kpis{display:grid;grid-template-columns:1fr 1fr;gap:12px}@media(min-width:900px){.kpis{grid-template-columns:repeat(4,1fr)}}
.kpi{padding:14px;margin:0!important}
.kpi .k{display:flex;align-items:center;gap:8px;color:var(--mu);font-size:12px}
.kpi b{display:block;font-size:22px;font-variant-numeric:tabular-nums;margin-top:8px}
.kic{width:30px;height:30px;border-radius:10px;display:grid;place-items:center;background:rgba(var(--glow),.18);color:var(--a1)}.kic .ic{width:18px;height:18px}
.card.kpi.hi{background:linear-gradient(135deg,var(--a1),var(--a2));border:0;color:var(--on);box-shadow:0 14px 36px rgba(var(--glow),.35)}.kpi.hi .k{color:var(--on);opacity:.85}.kpi.hi .kic{background:rgba(0,0,0,.18);color:var(--on)}
.donut{display:flex;align-items:center;gap:16px}.donut svg{width:130px;height:130px;flex:none}.leg{flex:1}.leg div{display:flex;align-items:center;gap:8px;font-size:13px;margin:7px 0;flex-wrap:wrap}.dot{width:10px;height:10px;border-radius:50%;flex:none}
.rg{animation:ringin 1.4s ease both}@keyframes ringin{from{stroke-dasharray:0 100}}
.chart{width:100%;height:150px;display:block}.chart .ln{stroke:var(--a1)}.ar2{fill:rgba(var(--glow),.2)}
.bar{height:8px;border-radius:99px;background:var(--line);overflow:hidden;margin-top:6px}.bar i{display:block;height:100%;width:0;border-radius:99px;background:linear-gradient(90deg,var(--a1),var(--a2));animation:grow 1.2s .2s cubic-bezier(.2,.8,.2,1) forwards}@keyframes grow{to{width:var(--w)}}
.goal{padding:12px 0 4px;animation:up .4s both}
.scroll{overflow-x:auto}.tbl{width:100%;border-collapse:collapse;font-size:14px}.tbl td{padding:11px 6px;border-top:1px solid var(--line);vertical-align:top}.tbl tr:first-child td{border-top:0}.tr{text-align:right;white-space:nowrap}
.opt{display:block;position:relative;cursor:pointer;margin:10px 0;color:var(--tx);font-size:inherit}.opt input{position:absolute;opacity:0;pointer-events:none}
.acct{border:1px solid var(--line);border-radius:16px;padding:14px;background:rgba(var(--glow),.06);transition:.2s}.opt input:checked+.acct{border-color:var(--a1);box-shadow:0 0 0 2px rgba(var(--glow),.35)}
.acct .num{font-family:ui-monospace,monospace;font-size:18px;letter-spacing:1px;word-break:break-all;margin:8px 0}
.row2{display:grid;grid-template-columns:92px 1fr;gap:10px}
.detail{margin-top:10px;font-size:13px;line-height:1.7;background:rgba(0,0,0,.18);border:1px solid var(--line);border-radius:12px;padding:10px;word-break:break-word}
.pv{margin-top:8px;font-size:15px;font-weight:700;color:var(--a1);min-height:1.3em}
.rate{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:9px 12px;border-radius:12px;background:rgba(var(--glow),.13);font-size:13px;margin:6px 0 10px}.rate .ic{width:18px;height:18px}
.warnb{background:rgba(251,191,36,.15);color:var(--warn);padding:9px 12px;border-radius:12px;font-size:13px;margin:6px 0 10px}
.inline{display:flex;gap:8px;align-items:flex-start;margin-top:8px}.inline .amt{flex:1}.inline button{margin-top:0;width:auto;padding:14px 18px;flex:none}
.amt.bs input{padding-left:46px}
@media print{body{background:#fff!important;color:#000!important}.noprint,.bnav,.side,#bg,.gridbg,.orb,.foot{display:none!important}.card{box-shadow:none!important;background:#fff!important;border:1px solid #999!important;color:#000!important}.mu{color:#444!important}}`;

const JS = `window.applyTheme=function(t){document.documentElement.dataset.t=t;try{localStorage.setItem('t',t)}catch(e){}document.querySelectorAll('.tdot').forEach(function(b){b.classList.toggle('on',b.dataset.t===t)});window.dispatchEvent(new Event('theme'))};
document.querySelectorAll('.tdot').forEach(function(b){b.addEventListener('click',function(){applyTheme(b.dataset.t)})});
(function(){var t=document.documentElement.dataset.t||'violeta';document.querySelectorAll('.tdot').forEach(function(b){b.classList.toggle('on',b.dataset.t===t)})})();
document.querySelectorAll('form').forEach(function(f){f.addEventListener('submit',function(e){if(f.dataset.s){e.preventDefault();return}f.dataset.s=1;var b=e.submitter||f.querySelector('button:not([type=button])');setTimeout(function(){if(b){b.disabled=true;b.insertAdjacentHTML('afterbegin','<i class="spin"></i>')}},0)})});
document.querySelectorAll('[data-pw]').forEach(function(b){b.addEventListener('click',function(){var i=b.previousElementSibling;i.type=i.type==='password'?'text':'password';b.textContent=i.type==='password'?'Ver':'Ocultar'})});
document.querySelectorAll('[data-copy]').forEach(function(b){b.addEventListener('click',function(){if(navigator.clipboard)navigator.clipboard.writeText(b.dataset.copy);b.textContent='Copiado';setTimeout(function(){b.textContent='Copiar'},1800)})});
document.querySelectorAll('[data-conv]').forEach(function(i){var o=document.getElementById(i.dataset.out),t=+i.dataset.t4,m=i.dataset.conv;function u(){var v=parseFloat(String(i.value).replace(',','.'));if(!(v>0)||!t){o.textContent='';return}var c=Math.round(v*100);if(m==='dep'){o.textContent='Recibirás $ '+(Math.floor(c*10000/t)/100).toLocaleString('es-VE',{minimumFractionDigits:2,maximumFractionDigits:2})}else{o.textContent='Recibirás Bs '+(Math.round(c*t/10000)/100).toLocaleString('es-VE',{minimumFractionDigits:2,maximumFractionDigits:2})}}i.addEventListener('input',u)});
document.querySelectorAll('[data-n]').forEach(function(el){var t=+el.dataset.n,s=performance.now();(function f(n){var p=Math.min((n-s)/900,1),v=Math.round(t*(1-Math.pow(1-p,3)));el.textContent=(v/100).toLocaleString('es-VE',{minimumFractionDigits:2,maximumFractionDigits:2});if(p<1)requestAnimationFrame(f)})(s)});
document.querySelectorAll('[data-i]').forEach(function(el){var t=+el.dataset.i,s=performance.now();(function f(n){var p=Math.min((n-s)/700,1);el.textContent=Math.round(t*p);if(p<1)requestAnimationFrame(f)})(s)});
setTimeout(function(){document.querySelectorAll('.toast').forEach(function(t){t.style.transition='opacity .4s';t.style.opacity=0})},3800);
window.addEventListener('pageshow',function(e){if(e.persisted)location.reload()});
(function(){var c=document.getElementById('bg');if(!c||matchMedia('(prefers-reduced-motion:reduce)').matches)return;var x=c.getContext('2d'),w=0,h=0,P=[],rgb='167,139,250';
function col(){rgb=getComputedStyle(document.documentElement).getPropertyValue('--pt').trim()||rgb}
function rs(){var nw=innerWidth,nh=innerHeight;if(P.length&&nw===w){h=c.height=nh;return}w=c.width=nw;h=c.height=nh;var n=Math.min(55,Math.round(w*h/14000));P=[];for(var i=0;i<n;i++)P.push({x:Math.random()*w,y:Math.random()*h,vx:(Math.random()-.5)*.4,vy:(Math.random()-.5)*.4,r:Math.random()*1.6+.7})}
function f(){x.clearRect(0,0,w,h);for(var i=0;i<P.length;i++){var p=P[i];p.x+=p.vx;p.y+=p.vy;if(p.x<0||p.x>w)p.vx*=-1;if(p.y<0||p.y>h)p.vy*=-1;x.fillStyle='rgba('+rgb+',.75)';x.beginPath();x.arc(p.x,p.y,p.r,0,6.283);x.fill();for(var j=i+1;j<P.length;j++){var q=P[j],dx=p.x-q.x,dy=p.y-q.y,d=dx*dx+dy*dy;if(d<16900){x.strokeStyle='rgba('+rgb+','+(0.3*(1-d/16900))+')';x.lineWidth=1;x.beginPath();x.moveTo(p.x,p.y);x.lineTo(q.x,q.y);x.stroke()}}}requestAnimationFrame(f)}
col();rs();f();addEventListener('resize',rs);addEventListener('theme',col)})();`;

const MSG = { bloq: 'Demasiados intentos. Espera 10 minutos.', mal: 'Datos incorrectos.', cod: 'Código incorrecto o vencido.', espera: 'Espera un minuto antes de pedir otro código.', envio: 'No se pudo enviar el código. Revisa la configuración de correo.', noadmin: 'Ese correo no es de un administrador.', reg: 'Solicitud recibida. Tu cuenta queda pendiente de aprobación.', adm: 'Administrador creado. Ingresa tu correo para recibir el código.', inv: 'Revisa los datos del formulario.', saldo: 'Saldo insuficiente.', disp: 'No tienes saldo disponible suficiente (los fondos de metas están bloqueados).', exc: 'El abono supera lo que falta para completar la meta.', abono: 'Abono realizado. Esos fondos quedan bloqueados hasta completar la meta.', metaf: 'No puedes eliminar una meta con fondos sin completar.', notasa: 'Aún no hay tasa del día publicada.', tasa: 'Tasa del día actualizada.', dep: 'Depósito registrado. Un administrador verificará tu pago.', ret: 'Retiro solicitado. Se procesará cuando sea aprobado.', ref: 'Esa referencia de pago ya fue registrada.', nocta: 'No hay una cuenta de cobro disponible.', meta: 'Meta creada.', metax: 'Meta eliminada.', metal: 'Máximo 10 metas.', cta: 'Cuenta de cobro guardada.', ctat: 'Cuenta de cobro actualizada.', bye: 'Sesión cerrada.' };
const LOGO = `<svg viewBox="0 0 40 40" fill="none"><path d="M20 3l14 5v10c0 9-6 15-14 19C12 33 6 27 6 18V8l14-5z" style="fill:var(--a1)"/><path d="M13 24l5-6 4 4 6-8" style="stroke:var(--on)" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg>`;
const CHECK = `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" style="flex:none"><circle cx="12" cy="12" r="11" style="stroke:var(--a1);fill:rgba(var(--glow),.15)"/><path d="M7 12.5l3.2 3.2L17 9" style="stroke:var(--a1)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
const brand = link => `<div class="brand">${LOGO}<div><b>Plataforma Bancaria</b>${link ? '<a class="tag" href="/admin">Ahorros Venezolanos</a>' : '<small>Ahorros Venezolanos</small>'}</div></div>`;
const THEMES = [['violeta', '#a78bfa', '#7c3aed'], ['esmeralda', '#34e3a0', '#16a974'], ['oceano', '#22d3ee', '#0ea5e9'], ['rubi', '#fb7185', '#e11d48'], ['oro', '#f2c14e', '#d9961a'], ['claro', '#e5e7eb', '#6366f1']];
const DOTS = THEMES.map(([t, a, b]) => `<button type="button" class="tdot" data-t="${t}" title="${t}" aria-label="Tema ${t}" style="background:linear-gradient(135deg,${a},${b})"></button>`).join('');
const shell = (body, m) => `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#060912"><title>${NAME}</title><script>try{var t=localStorage.getItem('t');if(t)document.documentElement.dataset.t=t}catch(e){}</script><style>${CSS}${CSS2}</style></head><body><canvas id="bg"></canvas><i class="gridbg"></i><i class="orb o1"></i><i class="orb o2"></i><i class="orb o3"></i>${MSG[m] ? `<div class="toast" role="status">${MSG[m]}</div>` : ''}${body}<footer class="foot"><div>Uso interno · ${NAME}</div><div class="themes">${DOTS}</div></footer><script>${JS}</script></body></html>`;
const pitch = `<section class="pitch"><div class="brand" style="margin-bottom:26px">${LOGO}<div><b>${NAME}</b></div></div><h1>Ahorra con orden<br>y total claridad</h1><p class="s" style="font-size:17px">Gestiona tus depósitos, retiros y movimientos en un solo lugar.</p><ul>${['Cuentas verificadas por la administración', 'Cada movimiento queda registrado', 'Tu saldo se calcula solo con movimientos aprobados'].map(t => `<li>${CHECK}${t}</li>`).join('')}</ul></section>`;
const auth = (t, s, inner, m, link = true) => shell(`<main class="auth">${pitch}<div class="box">${brand(link)}<div class="card glow"><h1>${t}</h1><p class="s">${s}</p>${inner}</div></div></main>`, m);
const field = (n, l, t = 'text', x = '') => `<label for="${n}">${l}</label><input id="${n}" name="${n}" type="${t}" ${x} required>`;
const pwf = (n, l, x = '') => `<label for="${n}">${l}</label><div class="pw"><input id="${n}" name="${n}" type="password" ${x} required><button type="button" data-pw>Ver</button></div>`;
const EM = 'autocomplete="username" autocapitalize="none" spellcheck="false"';
const arr = r => Array.isArray(r.data) ? r.data : [];
const list = (a, fn, vacio) => a.length ? a.map(fn).join('') : `<div class="empty">${vacio}</div>`;
const initial = n => esc((n || '?').trim().charAt(0).toUpperCase());
function centsMax(s, max) {
  const t = s.trim().replace(',', '.');
  if (!/^\d{1,10}(\.\d{1,2})?$/.test(t)) return null;
  const c = Math.round(parseFloat(t) * 100);
  return c > 0 && c <= max ? c : null;
}
const tasaTxt = t4 => (t4 / 10000).toLocaleString('es-VE', { minimumFractionDigits: 2, maximumFractionDigits: 4 });

const BANCOS = [['0102', 'Banco de Venezuela'], ['0104', 'Venezolano de Crédito'], ['0105', 'Mercantil'], ['0108', 'Provincial'], ['0114', 'Bancaribe'], ['0115', 'Exterior'], ['0128', 'Caroní'], ['0134', 'Banesco'], ['0137', 'Sofitasa'], ['0138', 'Plaza'], ['0151', 'BFC'], ['0156', '100% Banco'], ['0157', 'DelSur'], ['0163', 'Banco del Tesoro'], ['0166', 'Agrícola de Venezuela'], ['0168', 'Bancrecer'], ['0169', 'Mi Banco'], ['0171', 'Activo'], ['0172', 'Bancamiga'], ['0174', 'Banplus'], ['0175', 'Bicentenario'], ['0177', 'Banfanb'], ['0191', 'BNC'], ['0000', 'Otro banco']];
const okBanco = c => BANCOS.some(b => b[0] === c);
const bancoNombre = c => { const b = BANCOS.find(x => x[0] === c); return b ? `${b[1]} (${b[0]})` : esc(c || '—'); };
const bancoOpts = sel => BANCOS.map(([c, n]) => `<option value="${c}"${c === sel ? ' selected' : ''}>${c} · ${n}</option>`).join('');

const ic = p => `<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${p}</svg>`;
const I = {
  home: ic('<path d="M3 11l9-8 9 8v10a1 1 0 0 1-1 1h-5v-7H9v7H4a1 1 0 0 1-1-1z"/>'),
  dep: ic('<path d="M12 3v12m0 0l-4-4m4 4l4-4M4 20h16"/>'),
  ret: ic('<path d="M12 16V4m0 0L8 8m4-4l4 4M4 20h16"/>'),
  goal: ic('<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/>'),
  users: ic('<circle cx="9" cy="8" r="4"/><path d="M2 21c0-4 3-6 7-6s7 2 7 6M17 4a4 4 0 0 1 0 8M22 21c0-3-2-5-4-5.6"/>'),
  bank: ic('<path d="M3 10l9-6 9 6M5 10v8M9 10v8M15 10v8M19 10v8M3 21h18"/>'),
  out: ic('<path d="M9 21H5V3h4M16 17l5-5-5-5M21 12H9"/>'),
  wallet: ic('<path d="M3 7h16a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2zM3 7l2-3h12M16 14h.01"/>'),
  up: ic('<path d="M7 17L17 7M9 7h8v8"/>'),
  down: ic('<path d="M17 7L7 17M15 17H7V9"/>'),
  clock: ic('<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>'),
  lock: ic('<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>'),
  alert: ic('<path d="M12 3l10 18H2zM12 10v5M12 18h.01"/>'),
};
const rateBar = t => t ? `<div class="rate">${I.clock}<span>Tasa del día: <b>Bs ${tasaTxt(t.tasa4)}</b> por $ 1</span><span class="mu">${fecha(t.creado)}</span></div>` : '<div class="warnb">Aún no hay tasa del día publicada.</div>';
const NAV_C = [['/panel', 'Resumen', I.home], ['/depositar', 'Depositar', I.dep], ['/retirar', 'Retirar', I.ret], ['/metas', 'Metas', I.goal]];
const NAV_A = [['/admin', 'Resumen', I.home], ['/admin#cola', 'Cuentas', I.users], ['/admin#solicitudes', 'Pagos', I.wallet], ['/admin#tasa', 'Tasa', I.clock], ['/admin#cobro', 'Cobro', I.bank]];
function layout(me, nav, active, content, m) {
  const links = nav.map(([h, l, i]) => `<a href="${h}" class="${h === active ? 'on' : ''}">${i}<span>${l}</span></a>`).join('');
  return shell(`<div class="app"><aside class="side">${brand(false)}<div style="height:14px"></div>${links}<div class="sp"></div><div class="chip" style="padding:8px"><div class="av">${initial(me.nombre)}</div><div style="font-size:14px">${esc(me.nombre)}</div></div><form method="post" action="/salir"><button class="sm ghost" style="width:100%">${I.out}<span>Salir</span></button></form></aside><div class="mainc"><header class="top">${brand(false)}<div class="chip"><div class="av">${initial(me.nombre)}</div><form method="post" action="/salir"><button class="sm ghost">Salir</button></form></div></header>${content}</div></div><nav class="bnav">${links}</nav>`, m);
}
const top = me => `<header class="top noprint" style="display:flex">${brand(false)}<div class="chip"><div class="av">${initial(me.nombre)}</div><form method="post" action="/salir"><button class="sm ghost">Salir</button></form></div></header>`;
const kpi = (cls, ico, lab, val, extra = '') => `<div class="card kpi ${cls}"><div class="k"><span class="kic">${ico}</span>${lab}</div><b>${val}</b>${extra}</div>`;

const loginP = m => auth('Bienvenido', 'Ingresa con tu correo y contraseña', `<form method="post">${field('email', 'Correo', 'email', EM)}${pwf('pw', 'Contraseña', 'autocomplete="current-password"')}<button>Entrar</button></form><p class="mu" style="text-align:center;margin:16px 0 0">¿No tienes cuenta? <a href="/registro">Solicítala</a></p>`, m);
const regP = m => auth('Crear cuenta', 'Un administrador revisará tu solicitud', `<form method="post">${field('nombre', 'Nombre completo', 'text', 'autocomplete="name" maxlength="80"')}${field('cedula', 'Cédula', 'text', 'maxlength="20"')}${field('email', 'Correo', 'email', EM)}${pwf('pw', 'Contraseña (mínimo 10 caracteres)', 'autocomplete="new-password" minlength="10"')}<button>Solicitar cuenta</button></form><p class="mu" style="text-align:center;margin:16px 0 0"><a href="/login">Ya tengo cuenta</a></p>`, m);
const setupP = m => auth('Crear administrador', 'Solo se puede hacer una vez', `<form method="post">${field('nombre', 'Nombre', 'text', 'maxlength="80"')}${field('email', 'Correo donde recibirás los códigos', 'email', EM)}${pwf('token', 'Código de instalación', 'autocomplete="off"')}<button>Crear administrador</button></form>`, m, false);
const adminLoginP = m => auth('Acceso administrativo', 'Te enviaremos un código a tu correo', `<form method="post" action="/acceso">${field('email', 'Correo de administrador', 'email', EM)}<button>Enviar código</button></form><p class="mu" style="text-align:center;margin:16px 0 0"><a href="/login">Volver al inicio</a></p>`, m, false);
const codeP = (email, m) => auth('Revisa tu correo', `Enviamos un código a <b>${esc(email)}</b>. Revisa también la carpeta de spam.`, `<form method="post"><label for="code">Código</label><input class="code" id="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="10" pattern="[0-9 ]*" required autofocus><button>Verificar</button></form><p class="mu" style="text-align:center;margin:16px 0 0"><a href="/admin">Usar otro correo</a></p>`, m, false);

const pendP = (me, m) => shell(`<div class="wrap">${top(me)}<div class="card"><h1>Hola, ${esc((me.nombre || '').trim().split(' ')[0])}</h1><p class="s">Estado de tu cuenta: <span class="badge ${esc(me.estado)}">${esc(me.estado)}</span></p><p>${me.estado === 'RECHAZADO' ? 'Tu solicitud no fue aprobada. Comunícate con la administración.' : 'Un administrador está revisando tu solicitud. Te avisaremos cuando esté aprobada.'}</p></div></div>`, m);

const donut = (p, label) => `<svg viewBox="0 0 120 120"><circle cx="60" cy="60" r="46" fill="none" style="stroke:var(--line)" stroke-width="12"/><circle class="rg" cx="60" cy="60" r="46" fill="none" style="stroke:var(--a1)" stroke-width="12" stroke-linecap="round" pathLength="100" stroke-dasharray="${p.toFixed(1)} 100" transform="rotate(-90 60 60)"/><text x="60" y="64" text-anchor="middle" style="fill:var(--tx);font-size:20px;font-weight:700">${Math.round(p)}%</text><text x="60" y="80" text-anchor="middle" style="fill:var(--mu);font-size:9px">${label}</text></svg>`;
function chart(mov, s) {
  if (mov.length < 2) return '<div class="empty">Aún no hay suficientes movimientos para la gráfica</div>';
  const pts = [s]; let cur = s;
  for (const r of mov) { cur -= r.centavos; pts.push(cur); }
  pts.reverse();
  const mn = Math.min(...pts), mx = Math.max(...pts), rg = mx - mn || 1;
  const d = pts.map((v, i) => (i ? 'L' : 'M') + ((i / (pts.length - 1)) * 300).toFixed(1) + ' ' + (105 - ((v - mn) / rg) * 90).toFixed(1)).join('');
  return `<svg class="chart" viewBox="0 0 300 120" preserveAspectRatio="none"><path d="M0 30H300M0 60H300M0 90H300" style="stroke:var(--line);stroke-width:1;fill:none;vector-effect:non-scaling-stroke"/><path class="ar ar2" d="${d}L300 120L0 120Z"/><path class="ln" pathLength="1" d="${d}"/></svg>`;
}
const goalRow = (g, i) => {
  const p = Math.max(0, Math.min(100, g.ahorrado / g.objetivo * 100)), done = g.ahorrado >= g.objetivo;
  return `<div class="goal" style="animation-delay:${i * 45}ms"><div class="vrow"><b>${esc(g.nombre)}</b><span class="badge ${done ? 'APROBADA' : 'PENDIENTE'}">${done ? 'Completada' : 'Bloqueada'}</span></div><div class="mu">$ ${money(g.ahorrado)} de $ ${money(g.objetivo)} · ${Math.round(p)}%</div><div class="bar"><i style="--w:${p.toFixed(1)}%"></i></div></div>`;
};
const actRow = r => { const dep = r.tipo === 'DEPOSITO'; return `<tr><td><b>${dep ? 'Depósito' : 'Retiro'}</b><div class="mu">${fecha(r.creado)}</div></td><td><span class="badge ${esc(r.estado)}">${esc(r.estado)}</span></td><td class="tr ${dep ? 'pos' : 'neg'}">${dep ? '+' : '−'}$ ${money(r.centavos)}${r.estado === 'APROBADA' ? `<div><a class="mu" href="/comprobante/${r.id}">Comprobante</a></div>` : ''}</td></tr>`; };

function panelP(me, d, m) {
  const first = esc((me.nombre || '').trim().split(' ')[0]);
  const pct = d.ing > 0 ? Math.min(100, d.egr / d.ing * 100) : 0;
  return layout(me, NAV_C, '/panel', `<div class="hello"><h1>Hola, ${first}</h1><p class="s">Cuenta de ahorro N.º PB-${String(me.id).padStart(6, '0')} · saldo en dólares</p></div>${rateBar(d.tasa)}
<div class="kpis">${kpi('hi', I.wallet, 'Saldo total', `$ <span data-n="${d.s}">${money(d.s)}</span>`)}${kpi('', I.down, 'Disponible para retirar', '$ ' + money(d.s - d.bloq))}${kpi('', I.lock, 'Bloqueado en metas', '$ ' + money(d.bloq))}${kpi('', I.clock, 'En revisión', `<span data-i="${d.pend}">${d.pend}</span>`, '<div class="mu">solicitudes</div>')}</div>
<div class="grid g2" style="margin-top:14px"><section class="card"><h2>Flujo de caja</h2><div class="donut">${donut(pct, 'retirado')}<div class="leg"><div><i class="dot" style="background:var(--a1)"></i>Ingresos <b>$ ${money(d.ing)}</b></div><div><i class="dot" style="background:var(--mu)"></i>Egresos <b>$ ${money(d.egr)}</b></div></div></div></section>
<section class="card"><h2>Evolución del saldo</h2>${chart(d.mov, d.s)}</section></div>
<div class="grid g2"><section class="card"><h2>Actividad reciente</h2>${d.sols.length ? `<div class="scroll"><table class="tbl"><tbody>${d.sols.map(actRow).join('')}</tbody></table></div>` : '<div class="empty">Aún no hay actividad. Haz tu primer depósito.</div>'}</section>
<section class="card"><h2>Metas de ahorro</h2>${list(d.metas.slice(0, 3), goalRow, 'Crea tu primera meta de ahorro')}<a class="btn ghost sm" style="margin-top:12px" href="/metas">Ver todas</a></section></div>`, m);
}
function depositP(me, cuentas, tasa, m) {
  const opts = cuentas.map((c, i) => `<label class="opt"><input type="radio" name="cuenta" value="${c.id}"${i === 0 ? ' checked' : ''}><div class="acct"><b>${esc(c.banco)} <span class="mu">${esc(c.codigo)}</span></b><div class="mu">${esc(c.tipo)} · ${esc(c.titular)} · ${esc(c.doc)}</div><div class="num">${esc(c.numero)}</div><button type="button" class="sm ghost" data-copy="${esc(c.numero)}">Copiar</button></div></label>`).join('');
  const body = !tasa ? '<div class="empty">Aún no hay tasa del día publicada. Intenta más tarde.</div>' : !cuentas.length ? '<div class="empty">El administrador aún no ha configurado una cuenta de cobro.</div>' : `<form method="post" action="/depositar"><h2>1 · Transfiere a la cuenta de la plataforma</h2>${opts}<h2 style="margin-top:20px">2 · Registra tu pago</h2>
<label for="monto">Monto transferido en bolívares</label><div class="amt bs"><span>Bs</span><input id="monto" name="monto" inputmode="decimal" placeholder="0,00" autocomplete="off" data-conv="dep" data-out="o1" data-t4="${tasa.tasa4}" required></div><div class="pv" id="o1"></div>
<label for="banco">Banco desde el que pagaste</label><select id="banco" name="banco">${bancoOpts('')}</select>
<label for="titular">Nombre del titular de la cuenta</label><input id="titular" name="titular" value="${esc(me.nombre)}" maxlength="80" required>
<label>Documento del titular</label><div class="row2"><select name="doc_tipo"><option>V</option><option>E</option><option>J</option><option>P</option></select><input name="doc_numero" inputmode="numeric" placeholder="Número" maxlength="10" required></div>
<label for="ref">Número de referencia</label><input id="ref" name="referencia" maxlength="30" placeholder="Ej. 00123456" autocomplete="off" required>
<button>Registrar depósito</button></form>`;
  return layout(me, NAV_C, '/depositar', `<div class="hello"><h1>Depositar</h1><p class="s">Tus bolívares se convierten a dólares con la tasa del día, así tu ahorro no se devalúa. Un administrador verifica el pago en el banco antes de acreditarlo.</p></div>${rateBar(tasa)}<section class="card">${body}</section>`, m);
}
const withdrawP = (me, disp, bloq, tasa, m) => layout(me, NAV_C, '/retirar', `<div class="hello"><h1>Retirar</h1><p class="s">Disponible para retirar: <b>$ ${money(disp)}</b>${bloq ? ` · En metas (bloqueado): <b>$ ${money(bloq)}</b>` : ''}</p></div>${rateBar(tasa)}<section class="card">${tasa ? `<form method="post" action="/retirar">
<label for="monto">Monto a retirar en dólares</label><div class="amt"><span>$</span><input id="monto" name="monto" inputmode="decimal" placeholder="0,00" autocomplete="off" data-conv="ret" data-out="o2" data-t4="${tasa.tasa4}" required></div><div class="pv" id="o2"></div>
<label for="banco">Banco donde recibirás los bolívares</label><select id="banco" name="banco">${bancoOpts('')}</select>
<label for="num">Número de cuenta (20 dígitos)</label><input id="num" name="num_cuenta" inputmode="numeric" maxlength="20" pattern="[0-9]{20}" placeholder="01341234561234567890" autocomplete="off" required>
<label for="titular">Nombre del titular</label><input id="titular" name="titular" value="${esc(me.nombre)}" maxlength="80" required>
<label>Documento del titular</label><div class="row2"><select name="doc_tipo"><option>V</option><option>E</option><option>J</option><option>P</option></select><input name="doc_numero" inputmode="numeric" placeholder="Número" maxlength="10" required></div>
<button>Solicitar retiro</button></form>` : '<div class="empty">Aún no hay tasa del día publicada.</div>'}</section>`, m);
const goalsP = (me, disp, metas, m) => layout(me, NAV_C, '/metas', `<div class="hello"><h1>Metas de ahorro</h1><p class="s">Disponible para abonar: <b>$ ${money(disp)}</b>. El dinero que abones a una meta queda <b>bloqueado</b> hasta completarla.</p></div>
<div class="grid g2"><section class="card"><h2>Nueva meta</h2><form method="post" action="/metas"><label for="n">Nombre</label><input id="n" name="nombre" maxlength="40" placeholder="Ej. Vacaciones" required><label for="o">Monto objetivo en dólares</label><div class="amt"><span>$</span><input id="o" name="objetivo" inputmode="decimal" placeholder="0,00" autocomplete="off" required></div><button>Crear meta</button></form></section>
<section class="card"><h2>Mis metas</h2>${list(metas, (g, i) => { const done = g.ahorrado >= g.objetivo; return goalRow(g, i) + (done ? '' : `<form method="post" action="/metas/abonar/${g.id}" class="inline"><div class="amt"><span>$</span><input name="monto" inputmode="decimal" placeholder="Abonar" autocomplete="off" required></div><button class="sm">Abonar</button></form>`) + (g.ahorrado === 0 || done ? `<form method="post" action="/metas/borrar/${g.id}"><button class="sm ghost" style="margin-top:8px" onclick="return confirm('¿Eliminar esta meta?')">Eliminar</button></form>` : ''); }, 'Aún no tienes metas')}</section></div>`, m);
function receiptP(me, x) {
  const dep = x.tipo === 'DEPOSITO';
  const r = (k, v) => `<div class="row"><span class="mu">${k}</span><b style="text-align:right">${v}</b></div>`;
  return shell(`<div class="wrap" style="max-width:640px">${top(me)}<section class="card"><div class="mu">Comprobante</div><h1>PB-${String(x.id).padStart(6, '0')}</h1>
${r('Tipo', dep ? 'Depósito' : 'Retiro')}${r('Monto en dólares', '$ ' + money(x.centavos))}${x.monto_bs ? r('Monto en bolívares', 'Bs ' + money(x.monto_bs)) + r('Tasa aplicada', 'Bs ' + tasaTxt(x.tasa4) + ' por $ 1') : ''}${r('Estado', `<span class="badge ${esc(x.estado)}">${esc(x.estado)}</span>`)}${r('Fecha', fecha(x.creado))}${r('Cliente', esc(x.usuarios?.nombre))}${r('Banco', bancoNombre(x.banco))}${r('Titular', esc(x.titular))}${r('Documento', esc((x.doc_tipo || '') + '-' + (x.doc_numero || '')))}${dep ? r('Referencia', esc(x.referencia)) + r('Cuenta destino', esc(x.cuentas_pago?.banco) + ' ' + esc(x.cuentas_pago?.numero)) : r('Cuenta de destino', esc(x.num_cuenta))}
<div class="noprint" style="margin-top:14px"><button onclick="window.print()">Imprimir o guardar PDF</button><a class="btn ghost" style="margin-top:10px" href="${me.rol === 'admin' ? '/admin' : '/panel'}">Volver</a></div></section></div>`);
}

const acts = path => `<form method="post" action="${path}" class="acts"><button class="sm" name="a" value="aprobar">Aprobar</button><button class="sm danger" name="a" value="rechazar" onclick="return confirm('¿Rechazar?')">Rechazar</button></form>`;
const solItem = (x, i) => {
  const dep = x.tipo === 'DEPOSITO';
  const conv = x.monto_bs ? (dep ? `<div>Pagó <b>Bs ${money(x.monto_bs)}</b> a ${tasaTxt(x.tasa4)} → acreditar <b>$ ${money(x.centavos)}</b></div>` : `<div>Retira <b>$ ${money(x.centavos)}</b> a ${tasaTxt(x.tasa4)} → transferir <b>Bs ${money(x.monto_bs)}</b></div>`) : '';
  return `<div class="item" style="animation-delay:${i * 45}ms"><div class="vrow"><div class="who"><div class="av">${initial(x.usuarios?.nombre)}</div><div><b>${esc(x.usuarios?.nombre)}</b><div class="mu">${esc(x.usuarios?.email)}</div></div></div><div style="text-align:right"><b class="${dep ? 'pos' : 'neg'}">$ ${money(x.centavos)}</b><div class="mu">${dep ? 'Depósito' : 'Retiro'}</div></div></div>
<div class="detail">${conv}<div>Banco: ${bancoNombre(x.banco)}</div><div>Titular: ${esc(x.titular)} · ${esc((x.doc_tipo || '') + '-' + (x.doc_numero || ''))}</div>${dep ? `<div>Referencia: <b>${esc(x.referencia)}</b></div><div>Destino: ${esc(x.cuentas_pago?.banco)} ${esc(x.cuentas_pago?.numero)}</div>` : `<div>Cuenta destino: <b>${esc(x.num_cuenta)}</b></div>`}<div>${fecha(x.creado)}</div></div>${acts('/admin/solicitud/' + x.id)}</div>`;
};
const ctaRow = (c, i) => `<div class="item" style="animation-delay:${i * 45}ms"><div class="vrow"><div><b>${esc(c.banco)} <span class="mu">${esc(c.codigo)}</span></b><div class="mu">${esc(c.tipo)} · ${esc(c.titular)} · ${esc(c.doc)}</div><div style="font-family:ui-monospace,monospace">${esc(c.numero)}</div></div><span class="badge ${c.activo ? 'APROBADO' : 'RECHAZADO'}">${c.activo ? 'Activa' : 'Inactiva'}</span></div><form method="post" action="/admin/cuenta/${c.id}"><input type="hidden" name="v" value="${c.activo ? 0 : 1}"><button class="sm ghost" style="margin-top:10px">${c.activo ? 'Desactivar' : 'Activar'}</button></form></div>`;
function adminP(me, d, m) {
  const total = d.clientes.length, apr = d.clientes.filter(u => u.estado === 'APROBADO').length;
  const pu = d.clientes.filter(u => u.estado === 'PENDIENTE'), rech = total - apr - pu.length;
  const pct = total ? apr / total * 100 : 0;
  const sla = d.sols.filter(x => Date.now() - new Date(x.creado) > 864e5).length;
  const t = d.tasas[0], stale = !t || Date.now() - new Date(t.creado) > 864e5;
  const n = v => `<span data-i="${v}">${v}</span>`;
  return layout(me, NAV_A, '/admin', `<div class="hello"><h1>Centro de administración</h1><p class="s">Verificación de cuentas y control de pagos</p></div>
<div class="kpis">${kpi('hi', I.users, 'Clientes', n(total))}${kpi('', I.users, 'Verificados', n(apr))}${kpi('', I.clock, 'Cuentas pendientes', n(pu.length))}${kpi('', I.wallet, 'Pagos pendientes', n(d.sols.length))}</div>
<div class="grid g2" style="margin-top:14px"><section class="card"><h2>Estado de verificación</h2><div class="donut">${donut(pct, 'verificados')}<div class="leg"><div><i class="dot" style="background:var(--a1)"></i>Aprobados <b>${apr}</b></div><div><i class="dot" style="background:var(--warn)"></i>Pendientes <b>${pu.length}</b></div><div><i class="dot" style="background:var(--bad)"></i>Rechazados <b>${rech}</b></div></div></div></section>
<section class="card"><h2>Alertas</h2><div class="row"><span style="display:flex;gap:8px;align-items:center">${I.alert} Inicios fallidos (24 h)</span><b class="${d.fallos ? 'neg' : 'pos'}">${d.fallos}</b></div><div class="row"><span style="display:flex;gap:8px;align-items:center">${I.clock} Pagos con más de 24 h</span><b class="${sla ? 'neg' : 'pos'}">${sla}</b></div><div class="row"><span style="display:flex;gap:8px;align-items:center">${I.alert} Tasa del día</span><b class="${stale ? 'neg' : 'pos'}">${stale ? 'Desactualizada' : 'Vigente'}</b></div></section></div>
<section class="card" id="cola"><h2>Cola de verificación</h2>${list(pu, (x, i) => `<div class="item" style="animation-delay:${i * 45}ms"><div class="who"><div class="av">${initial(x.nombre)}</div><div><b>${esc(x.nombre)}</b><div class="mu">${esc(x.cedula)} · ${esc(x.email)}</div><div class="mu">${fecha(x.creado)}</div></div></div>${acts('/admin/usuario/' + x.id)}</div>`, 'Nada pendiente')}</section>
<section class="card" id="solicitudes"><h2>Pagos por aprobar</h2><p class="mu">Antes de aprobar un depósito, confirma el pago en el estado de cuenta del banco. Al aprobar un retiro, ya debes haber transferido los bolívares indicados.</p>${list(d.sols, solItem, 'Nada pendiente')}</section>
<section class="card" id="tasa"><h2>Tasa del día (Bs por $ 1)</h2>${rateBar(t)}${stale ? '<div class="warnb">La tasa no existe o tiene más de 24 horas. Actualízala antes de recibir o aprobar pagos.</div>' : ''}
<form method="post" action="/admin/tasa"><label for="tasa">Nueva tasa en bolívares por 1 dólar</label><input id="tasa" name="tasa" inputmode="decimal" placeholder="900,00" autocomplete="off" required><button>Publicar tasa</button></form>
${d.tasas.length ? `<h2 style="margin-top:16px">Historial</h2>${d.tasas.map(x => `<div class="row"><span class="mu">${fecha(x.creado)} · ${esc(x.por)}</span><b>Bs ${tasaTxt(x.tasa4)}</b></div>`).join('')}` : ''}</section>
<section class="card" id="cobro"><h2>Cuentas de cobro de la plataforma</h2>${list(d.cuentas, ctaRow, 'Aún no hay cuentas de cobro. Agrega la cuenta de la plataforma para recibir depósitos.')}
<form method="post" action="/admin/cuenta" style="margin-top:16px"><h2>Agregar cuenta</h2><label for="cb">Banco</label><select id="cb" name="banco">${bancoOpts('')}</select><label for="ct">Tipo</label><select id="ct" name="tipo"><option>Corriente</option><option>Ahorro</option></select><label for="cn">Número de cuenta (20 dígitos)</label><input id="cn" name="numero" inputmode="numeric" maxlength="20" pattern="[0-9]{20}" required><label for="cti">Titular</label><input id="cti" name="titular" maxlength="80" required><label for="cd">Documento o RIF del titular</label><input id="cd" name="doc" maxlength="20" placeholder="J-123456789" required><button>Guardar cuenta</button></form></section>
<section class="card" id="auditoria"><details><summary>Auditoría (últimos 30 eventos)</summary>${list(d.logs, l => `<div class="row"><div><b>${esc(l.accion)}</b> <span class="mu">${esc(l.detalle)}</span><div class="mu">${esc(l.actor)}</div></div><span class="mu">${fecha(l.creado)}</span></div>`, 'Sin eventos')}</details></section>`, m);
}

async function getTasa(env) { const r = await sb(env, 'GET', 'tasas?order=id.desc&limit=1&select=*'); return arr(r)[0] || null; }
async function enMetas(env, uid) { const r = await sb(env, 'GET', `metas?user_id=eq.${uid}&select=ahorrado,objetivo`); return arr(r).filter(g => g.ahorrado < g.objetivo).reduce((a, g) => a + g.ahorrado, 0); }

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
    if (usr && usr.rol !== 'admin' && await checkPw(f('pw'), usr.pw)) {
      await audit(env, email, 'LOGIN');
      return go('/panel', await cookie(env, { u: usr.id, k: 'full' }, 28800));
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
    const nombre = f('nombre').trim().slice(0, 80), email = f('email').trim().toLowerCase().slice(0, 120);
    if (f('token').trim() !== String(env.SETUP_TOKEN).trim() || !nombre || !email.includes('@')) return go('/crear-admin?m=mal');
    const r = await sb(env, 'POST', 'usuarios', { nombre, cedula: '-', email, pw: '!', rol: 'admin', estado: 'APROBADO' });
    if (r.ok) await audit(env, email, 'ADMIN_CREADO');
    return go(r.ok ? '/admin?m=adm' : '/crear-admin?m=inv');
  }

  if (path === '/acceso') {
    if (!post) return go('/admin');
    const email = f('email').trim().toLowerCase().slice(0, 120);
    if (await bloqueado(env, email)) return go('/admin?m=bloq');
    const r = await sb(env, 'GET', `usuarios?email=eq.${q(email)}&rol=eq.admin&select=id`);
    if (r.ok && r.data.length) {
      const a = await authCall(env, 'otp', { email, create_user: true });
      if (a.status === 429) return go('/admin?m=espera');
      if (!a.ok) { console.log('otp error', a.status, JSON.stringify(a.data)); return go('/admin?m=envio'); }
      await audit(env, email, 'OTP_ENVIO');
    } else return go('/admin?m=noadmin');
    return go('/codigo', await cookie(env, { k: 'otp', m: email }, 600));
  }

  if (path === '/codigo') {
    if (!ses || ses.k !== 'otp') return go('/admin');
    if (!post) return html(codeP(ses.m, m));
    if (await bloqueado(env, ses.m)) return go('/admin?m=bloq', CLEAR);
    const code = f('code').replace(/\s/g, '');
    let ok = false;
    if (/^\d{4,10}$/.test(code)) {
      for (const t of ['email', 'signup']) {
        const v = await authCall(env, 'verify', { type: t, email: ses.m, token: code });
        if (v.ok) { ok = true; break; }
      }
    }
    const adm = ok ? await sb(env, 'GET', `usuarios?email=eq.${q(ses.m)}&rol=eq.admin&select=id`) : null;
    if (ok && adm.ok && adm.data.length) {
      await audit(env, ses.m, 'LOGIN');
      return go('/admin', await cookie(env, { u: adm.data[0].id, k: 'full' }, 28800));
    }
    await audit(env, ses.m, 'LOGIN_FALLO', ses.m);
    return go('/codigo?m=cod');
  }

  if (path === '/salir' && post) return go('/login?m=bye', CLEAR);
  if (path === '/admin' && !post && !me) return html(adminLoginP(m));
  if (!me) return go('/login');

  const cli = me.rol === 'cliente' && me.estado === 'APROBADO';
  const NO = () => new Response('Prohibido', { status: 403 });
  let x;

  if (path === '/panel' && !post) {
    if (me.rol === 'admin') return go('/admin');
    if (me.estado !== 'APROBADO') return html(pendP(me, m));
    const [lb, so, pe, mt, ta] = await Promise.all([
      sb(env, 'GET', `libro?user_id=eq.${me.id}&order=id.desc&select=centavos,creado`),
      sb(env, 'GET', `solicitudes?user_id=eq.${me.id}&order=id.desc&limit=8&select=*`),
      sb(env, 'GET', `solicitudes?user_id=eq.${me.id}&estado=eq.PENDIENTE&select=id`),
      sb(env, 'GET', `metas?user_id=eq.${me.id}&order=id&select=*`),
      getTasa(env)]);
    const rows = arr(lb), metas = arr(mt);
    let s = 0, ing = 0, egr = 0;
    for (const r of rows) { s += r.centavos; if (r.centavos > 0) ing += r.centavos; else egr -= r.centavos; }
    const bloq = metas.filter(g => g.ahorrado < g.objetivo).reduce((a, g) => a + g.ahorrado, 0);
    return html(panelP(me, { s, ing, egr, bloq, mov: rows.slice(0, 25), sols: arr(so), pend: arr(pe).length, metas, tasa: ta }, m));
  }

  if (path === '/depositar') {
    if (!cli) return NO();
    if (!post) {
      const [ct, ta] = await Promise.all([sb(env, 'GET', 'cuentas_pago?activo=eq.true&order=id&select=*'), getTasa(env)]);
      return html(depositP(me, arr(ct), ta, m));
    }
    const bs = centsMax(f('monto'), 1e10), cuenta = Number(f('cuenta')), banco = f('banco');
    const titular = f('titular').trim().slice(0, 80), dt = f('doc_tipo'), dn = f('doc_numero').trim();
    const ref = f('referencia').trim().toUpperCase().slice(0, 30);
    if (bs === null || !okBanco(banco) || titular.length < 3 || !['V', 'E', 'J', 'P'].includes(dt) || !/^\d{5,10}$/.test(dn) || !/^[A-Z0-9-]{4,30}$/.test(ref)) return go('/depositar?m=inv');
    const t = await getTasa(env);
    if (!t) return go('/depositar?m=notasa');
    const usd = Math.floor(bs * 10000 / t.tasa4);
    if (usd < 1) return go('/depositar?m=inv');
    const ct = await sb(env, 'GET', `cuentas_pago?id=eq.${cuenta}&activo=eq.true&select=id`);
    if (!arr(ct).length) return go('/depositar?m=nocta');
    const dup = await sb(env, 'GET', `solicitudes?tipo=eq.DEPOSITO&banco=eq.${q(banco)}&referencia=eq.${q(ref)}&estado=neq.RECHAZADA&select=id&limit=1`);
    if (arr(dup).length) return go('/depositar?m=ref');
    const r = await sb(env, 'POST', 'solicitudes', { user_id: me.id, tipo: 'DEPOSITO', centavos: usd, monto_bs: bs, tasa4: t.tasa4, referencia: ref, banco, titular, doc_tipo: dt, doc_numero: dn, cuenta_id: cuenta });
    if (!r.ok) { console.log('dep error', r.status, JSON.stringify(r.data)); return go('/depositar?m=inv'); }
    await audit(env, me.email, 'SOLICITUD_DEPOSITO', `Bs ${bs} tasa ${t.tasa4}`);
    return go('/panel?m=dep');
  }

  if (path === '/retirar') {
    if (!cli) return NO();
    if (!post) {
      const [sd, bl, ta] = await Promise.all([saldo(env, me.id), enMetas(env, me.id), getTasa(env)]);
      return html(withdrawP(me, sd - bl, bl, ta, m));
    }
    const c = cents(f('monto')), banco = f('banco'), num = f('num_cuenta').replace(/\s/g, '');
    const titular = f('titular').trim().slice(0, 80), dt = f('doc_tipo'), dn = f('doc_numero').trim();
    if (c === null || !okBanco(banco) || !/^\d{20}$/.test(num) || titular.length < 3 || !['V', 'E', 'J', 'P'].includes(dt) || !/^\d{5,10}$/.test(dn)) return go('/retirar?m=inv');
    const [sd, bl, t, p] = await Promise.all([saldo(env, me.id), enMetas(env, me.id), getTasa(env), sb(env, 'GET', `solicitudes?user_id=eq.${me.id}&tipo=eq.RETIRO&estado=eq.PENDIENTE&select=centavos`)]);
    if (!t) return go('/retirar?m=notasa');
    const pend = arr(p).reduce((s, y) => s + y.centavos, 0);
    if (c + pend > sd - bl) return go('/retirar?m=disp');
    const bs = Math.round(c * t.tasa4 / 10000);
    const r = await sb(env, 'POST', 'solicitudes', { user_id: me.id, tipo: 'RETIRO', centavos: c, monto_bs: bs, tasa4: t.tasa4, banco, num_cuenta: num, titular, doc_tipo: dt, doc_numero: dn });
    if (!r.ok) { console.log('ret error', r.status, JSON.stringify(r.data)); return go('/retirar?m=inv'); }
    await audit(env, me.email, 'SOLICITUD_RETIRO', `USD ${c} tasa ${t.tasa4}`);
    return go('/panel?m=ret');
  }

  if (path === '/metas') {
    if (!cli) return NO();
    if (!post) {
      const [mt, sd] = await Promise.all([sb(env, 'GET', `metas?user_id=eq.${me.id}&order=id&select=*`), saldo(env, me.id)]);
      const metas = arr(mt);
      const bl = metas.filter(g => g.ahorrado < g.objetivo).reduce((a, g) => a + g.ahorrado, 0);
      return html(goalsP(me, sd - bl, metas, m));
    }
    const nombre = f('nombre').trim().slice(0, 40), obj = cents(f('objetivo'));
    if (nombre.length < 2 || obj === null) return go('/metas?m=inv');
    const n = await sb(env, 'GET', `metas?user_id=eq.${me.id}&select=id`);
    if (arr(n).length >= 10) return go('/metas?m=metal');
    await sb(env, 'POST', 'metas', { user_id: me.id, nombre, objetivo: obj });
    return go('/metas?m=meta');
  }
  if (post && (x = path.match(/^\/metas\/abonar\/(\d+)$/))) {
    if (!cli) return NO();
    const c = cents(f('monto'));
    if (c === null) return go('/metas?m=inv');
    const r = await sb(env, 'POST', 'rpc/abonar_meta', { p_user: me.id, p_meta: Number(x[1]), p_monto: c });
    const res = r.ok ? r.data : '';
    if (res === 'OK') { await audit(env, me.email, 'META_ABONO', String(c)); return go('/metas?m=abono'); }
    return go('/metas?m=' + ({ SALDO_INSUFICIENTE: 'disp', EXCEDE_META: 'exc' }[res] || 'inv'));
  }
  if (post && (x = path.match(/^\/metas\/borrar\/(\d+)$/))) {
    if (!cli) return NO();
    const g = arr(await sb(env, 'GET', `metas?id=eq.${x[1]}&user_id=eq.${me.id}&select=*`))[0];
    if (!g) return go('/metas');
    if (g.ahorrado > 0 && g.ahorrado < g.objetivo) return go('/metas?m=metaf');
    await sb(env, 'DELETE', `metas?id=eq.${g.id}&user_id=eq.${me.id}&ahorrado=eq.${g.ahorrado}`);
    return go('/metas?m=metax');
  }

  if (!post && (x = path.match(/^\/comprobante\/(\d+)$/))) {
    const r = await sb(env, 'GET', `solicitudes?id=eq.${x[1]}&estado=eq.APROBADA&select=*,usuarios!solicitudes_user_id_fkey(nombre),cuentas_pago(banco,numero)`);
    const s = arr(r)[0];
    if (!s || (me.rol !== 'admin' && s.user_id !== me.id)) return new Response('No encontrado', { status: 404 });
    return html(receiptP(me, s));
  }

  if (me.rol !== 'admin') return NO();

  if (path === '/admin' && !post) {
    const desde = new Date(Date.now() - 864e5).toISOString();
    const [cl, so, ct, lg, fa, ts] = await Promise.all([
      sb(env, 'GET', 'usuarios?rol=eq.cliente&order=id&select=id,nombre,cedula,email,estado,creado'),
      sb(env, 'GET', 'solicitudes?estado=eq.PENDIENTE&order=id&select=*,usuarios!solicitudes_user_id_fkey(nombre,email),cuentas_pago(banco,numero)'),
      sb(env, 'GET', 'cuentas_pago?order=id&select=*'),
      sb(env, 'GET', 'auditoria?order=id.desc&limit=30&select=*'),
      sb(env, 'GET', `auditoria?accion=eq.LOGIN_FALLO&creado=gte.${q(desde)}&select=id`),
      sb(env, 'GET', 'tasas?order=id.desc&limit=5&select=*')]);
    return html(adminP(me, { clientes: arr(cl), sols: arr(so), cuentas: arr(ct), logs: arr(lg), fallos: arr(fa).length, tasas: arr(ts) }, m));
  }

  if (post && (x = path.match(/^\/admin\/usuario\/(\d+)$/))) {
    const nuevo = { aprobar: 'APROBADO', rechazar: 'RECHAZADO' }[f('a')];
    if (!nuevo) return go('/admin?m=inv');
    const r = await sb(env, 'PATCH', `usuarios?id=eq.${x[1]}&estado=eq.PENDIENTE&rol=eq.cliente`, { estado: nuevo }, 'return=representation');
    if (r.ok && arr(r).length) await audit(env, me.email, 'USUARIO_' + nuevo, 'id=' + x[1]);
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
  if (post && path === '/admin/tasa') {
    const t = f('tasa').trim().replace(',', '.');
    if (!/^\d{1,7}(\.\d{1,4})?$/.test(t)) return go('/admin?m=inv');
    const t4 = Math.round(parseFloat(t) * 10000);
    if (t4 < 1) return go('/admin?m=inv');
    const r = await sb(env, 'POST', 'tasas', { tasa4: t4, por: me.email });
    if (r.ok) await audit(env, me.email, 'TASA_PUBLICADA', t);
    return go(r.ok ? '/admin?m=tasa' : '/admin?m=inv');
  }
  if (post && path === '/admin/cuenta') {
    const banco = f('banco'), numero = f('numero').replace(/\s/g, ''), titular = f('titular').trim().slice(0, 80), doc = f('doc').trim().slice(0, 20);
    const tipo = f('tipo') === 'Ahorro' ? 'Ahorro' : 'Corriente';
    const b = BANCOS.find(y => y[0] === banco);
    if (!b || !/^\d{20}$/.test(numero) || titular.length < 3 || doc.length < 5) return go('/admin?m=inv');
    const r = await sb(env, 'POST', 'cuentas_pago', { banco: b[1], codigo: b[0], tipo, numero, titular, doc });
    if (r.ok) await audit(env, me.email, 'CUENTA_COBRO_NUEVA', b[0]);
    return go(r.ok ? '/admin?m=cta' : '/admin?m=inv');
  }
  if (post && (x = path.match(/^\/admin\/cuenta\/(\d+)$/))) {
    const on = f('v') === '1';
    const r = await sb(env, 'PATCH', `cuentas_pago?id=eq.${x[1]}`, { activo: on });
    if (r.ok) await audit(env, me.email, on ? 'CUENTA_ACTIVADA' : 'CUENTA_DESACTIVADA', 'id=' + x[1]);
    return go('/admin?m=ctat');
  }
  return new Response('No encontrado', { status: 404 });
}

export default {
  async fetch(req, env) {
    try { return await route(req, env); }
    catch (e) { console.log('error', e.message); return html(shell('<main class="auth"><div class="card">Error interno. Intenta de nuevo.</div></main>'), 500); }
  }
};
