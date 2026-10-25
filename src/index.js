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

const JS = `window.applyTheme=function(t){document.documentElement.dataset.t=t;try{localStorage.setItem('t',t)}catch(e){}document.querySelectorAll('.tdot').forEach(function(b){b.classList.toggle('on',b.dataset.t===t)});window.dispatchEvent(new Event('theme'))};
document.querySelectorAll('.tdot').forEach(function(b){b.addEventListener('click',function(){applyTheme(b.dataset.t)})});
(function(){var t=document.documentElement.dataset.t||'violeta';document.querySelectorAll('.tdot').forEach(function(b){b.classList.toggle('on',b.dataset.t===t)})})();
document.querySelectorAll('form').forEach(function(f){f.addEventListener('submit',function(e){if(f.dataset.s){e.preventDefault();return}f.dataset.s=1;var b=e.submitter||f.querySelector('button:not([type=button])');setTimeout(function(){if(b){b.disabled=true;b.insertAdjacentHTML('afterbegin','<i class="spin"></i>')}},0)})});
document.querySelectorAll('[data-pw]').forEach(function(b){b.addEventListener('click',function(){var i=b.previousElementSibling;i.type=i.type==='password'?'text':'password';b.textContent=i.type==='password'?'Ver':'Ocultar'})});
document.querySelectorAll('[data-n]').forEach(function(el){var t=+el.dataset.n,s=performance.now();(function f(n){var p=Math.min((n-s)/900,1),v=Math.round(t*(1-Math.pow(1-p,3)));el.textContent=(v/100).toLocaleString('es-VE',{minimumFractionDigits:2,maximumFractionDigits:2});if(p<1)requestAnimationFrame(f)})(s)});
document.querySelectorAll('[data-i]').forEach(function(el){var t=+el.dataset.i,s=performance.now();(function f(n){var p=Math.min((n-s)/700,1);el.textContent=Math.round(t*p);if(p<1)requestAnimationFrame(f)})(s)});
setTimeout(function(){document.querySelectorAll('.toast').forEach(function(t){t.style.transition='opacity .4s';t.style.opacity=0})},3800);
window.addEventListener('pageshow',function(e){if(e.persisted)location.reload()});
(function(){var c=document.getElementById('bg');if(!c||matchMedia('(prefers-reduced-motion:reduce)').matches)return;var x=c.getContext('2d'),w=0,h=0,P=[],rgb='167,139,250';
function col(){rgb=getComputedStyle(document.documentElement).getPropertyValue('--pt').trim()||rgb}
function rs(){var nw=innerWidth,nh=innerHeight;if(P.length&&nw===w){h=c.height=nh;return}w=c.width=nw;h=c.height=nh;var n=Math.min(55,Math.round(w*h/14000));P=[];for(var i=0;i<n;i++)P.push({x:Math.random()*w,y:Math.random()*h,vx:(Math.random()-.5)*.4,vy:(Math.random()-.5)*.4,r:Math.random()*1.6+.7})}
function f(){x.clearRect(0,0,w,h);for(var i=0;i<P.length;i++){var p=P[i];p.x+=p.vx;p.y+=p.vy;if(p.x<0||p.x>w)p.vx*=-1;if(p.y<0||p.y>h)p.vy*=-1;x.fillStyle='rgba('+rgb+',.75)';x.beginPath();x.arc(p.x,p.y,p.r,0,6.283);x.fill();for(var j=i+1;j<P.length;j++){var q=P[j],dx=p.x-q.x,dy=p.y-q.y,d=dx*dx+dy*dy;if(d<16900){x.strokeStyle='rgba('+rgb+','+(0.3*(1-d/16900))+')';x.lineWidth=1;x.beginPath();x.moveTo(p.x,p.y);x.lineTo(q.x,q.y);x.stroke()}}}requestAnimationFrame(f)}
col();rs();f();addEventListener('resize',rs);addEventListener('theme',col)})();`;

const MSG = { bloq: 'Demasiados intentos. Espera 10 minutos.', mal: 'Datos incorrectos.', cod: 'Código incorrecto o vencido.', espera: 'Espera un minuto antes de pedir otro código.', envio: 'No se pudo enviar el código. Revisa la configuración de correo.', reg: 'Solicitud recibida. Tu cuenta queda pendiente de aprobación.', adm: 'Administrador creado. Ingresa tu correo para recibir el código.', inv: 'Datos inválidos.', saldo: 'Saldo insuficiente.', sol: 'Solicitud enviada, pendiente de aprobación.', bye: 'Sesión cerrada.' };
const LOGO = `<svg viewBox="0 0 40 40" fill="none"><path d="M20 3l14 5v10c0 9-6 15-14 19C12 33 6 27 6 18V8l14-5z" style="fill:var(--a1)"/><path d="M13 24l5-6 4 4 6-8" style="stroke:var(--on)" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg>`;
const CHECK = `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" style="flex:none"><circle cx="12" cy="12" r="11" style="stroke:var(--a1);fill:rgba(var(--glow),.15)"/><path d="M7 12.5l3.2 3.2L17 9" style="stroke:var(--a1)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
const CHIP = `<svg width="38" height="28" viewBox="0 0 38 28"><rect x="1" y="1" width="36" height="26" rx="6" fill="#f2c14e"/><path d="M1 10h36M1 18h36M14 1v26M24 1v26" stroke="#8a5e08" stroke-width="1.2" opacity=".55"/></svg>`;
const brand = link => `<div class="brand">${LOGO}<div><b>Plataforma Bancaria</b>${link ? '<a class="tag" href="/admin">Ahorros Venezolanos</a>' : '<small>Ahorros Venezolanos</small>'}</div></div>`;
const THEMES = [['violeta', '#a78bfa', '#7c3aed'], ['oceano', '#22d3ee', '#0ea5e9'], ['rubi', '#fb7185', '#e11d48'], ['oro', '#f2c14e', '#d9961a'], ['claro', '#e5e7eb', '#6366f1']];
const DOTS = THEMES.map(([t, a, b]) => `<button type="button" class="tdot" data-t="${t}" title="${t}" aria-label="Tema ${t}" style="background:linear-gradient(135deg,${a},${b})"></button>`).join('');
const shell = (body, m) => `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${NAME}</title><script>try{var t=localStorage.getItem('t');if(t)document.documentElement.dataset.t=t}catch(e){}</script><style>${CSS}</style></head><body><canvas id="bg"></canvas><i class="gridbg"></i><i class="orb o1"></i><i class="orb o2"></i><i class="orb o3"></i>${MSG[m] ? `<div class="toast" role="status">${MSG[m]}</div>` : ''}${body}<footer class="foot"><div>Uso interno · ${NAME}</div><div class="themes">${DOTS}</div></footer><script>${JS}</script></body></html>`;
const pitch = `<section class="pitch"><div class="brand" style="margin-bottom:26px">${LOGO}<div><b>${NAME}</b></div></div><h1>Ahorra con orden<br>y total claridad</h1><p class="s" style="font-size:17px">Gestiona tus depósitos, retiros y movimientos en un solo lugar.</p><ul>${['Cuentas verificadas por la administración', 'Cada movimiento queda registrado', 'Tu saldo se calcula solo con movimientos aprobados'].map(t => `<li>${CHECK}${t}</li>`).join('')}</ul></section>`;
const auth = (t, s, inner, m, link = true) => shell(`<main class="auth">${pitch}<div class="box">${brand(link)}<div class="card glow"><h1>${t}</h1><p class="s">${s}</p>${inner}</div></div></main>`, m);
const field = (n, l, t = 'text', x = '') => `<label for="${n}">${l}</label><input id="${n}" name="${n}" type="${t}" ${x} required>`;
const pwf = (n, l, x = '') => `<label for="${n}">${l}</label><div class="pw"><input id="${n}" name="${n}" type="password" ${x} required><button type="button" data-pw>Ver</button></div>`;
const EM = 'autocomplete="username" autocapitalize="none" spellcheck="false"';

const loginP = m => auth('Bienvenido', 'Ingresa con tu correo y contraseña', `<form method="post">${field('email', 'Correo', 'email', EM)}${pwf('pw', 'Contraseña', 'autocomplete="current-password"')}<button>Entrar</button></form><p class="mu" style="text-align:center;margin:16px 0 0">¿No tienes cuenta? <a href="/registro">Solicítala</a></p>`, m);
const regP = m => auth('Crear cuenta', 'Un administrador revisará tu solicitud', `<form method="post">${field('nombre', 'Nombre completo', 'text', 'autocomplete="name" maxlength="80"')}${field('cedula', 'Cédula', 'text', 'maxlength="20"')}${field('email', 'Correo', 'email', EM)}${pwf('pw', 'Contraseña (mínimo 10 caracteres)', 'autocomplete="new-password" minlength="10"')}<button>Solicitar cuenta</button></form><p class="mu" style="text-align:center;margin:16px 0 0"><a href="/login">Ya tengo cuenta</a></p>`, m);
const setupP = m => auth('Crear administrador', 'Solo se puede hacer una vez', `<form method="post">${field('nombre', 'Nombre', 'text', 'maxlength="80"')}${field('email', 'Correo donde recibirás los códigos', 'email', EM)}${pwf('token', 'Código de instalación', 'autocomplete="off"')}<button>Crear administrador</button></form>`, m, false);
const adminLoginP = m => auth('Acceso administrativo', 'Te enviaremos un código a tu correo', `<form method="post" action="/acceso">${field('email', 'Correo de administrador', 'email', EM)}<button>Enviar código</button></form><p class="mu" style="text-align:center;margin:16px 0 0"><a href="/login">Volver al inicio</a></p>`, m, false);
const codeP = (email, m) => auth('Revisa tu correo', `Enviamos un código a <b>${esc(email)}</b>. Revisa también la carpeta de spam.`, `<form method="post"><label for="code">Código</label><input class="code" id="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="10" pattern="[0-9 ]*" required autofocus><button>Verificar</button></form><p class="mu" style="text-align:center;margin:16px 0 0"><a href="/admin">Usar otro correo</a></p>`, m, false);

const top = (me, tag) => `<header class="top">${brand(false)}<div class="chip">${tag || ''}<div class="av" title="${esc(me.nombre)}">${esc((me.nombre || '?').trim().charAt(0).toUpperCase())}</div><form method="post" action="/salir"><button class="sm ghost">Salir</button></form></div></header>`;
const solRow = (r, i) => `<div class="row" style="animation-delay:${i * 45}ms"><div><b>${r.tipo === 'DEPOSITO' ? 'Depósito' : 'Retiro'}</b><div class="mu">${fecha(r.creado)}</div></div><div style="text-align:right"><div>$ ${money(r.centavos)}</div><span class="badge ${esc(r.estado)}">${esc(r.estado)}</span></div></div>`;
const movRow = (r, i) => `<div class="row" style="animation-delay:${i * 45}ms"><div><b>${r.centavos > 0 ? 'Ingreso' : 'Egreso'}</b><div class="mu">${fecha(r.creado)}</div></div><b class="${r.centavos > 0 ? 'pos' : 'neg'}">${r.centavos > 0 ? '+' : '−'}$ ${money(Math.abs(r.centavos))}</b></div>`;
const list = (a, fn, vacio) => a.length ? a.map(fn).join('') : `<div class="empty">${vacio}</div>`;
function spark(mov, s) {
  if (mov.length < 2) return '';
  const pts = [s]; let cur = s;
  for (const r of mov) { cur -= r.centavos; pts.push(cur); }
  pts.reverse();
  const mn = Math.min(...pts), mx = Math.max(...pts), rg = mx - mn || 1;
  const d = pts.map((v, i) => (i ? 'L' : 'M') + ((i / (pts.length - 1)) * 300).toFixed(1) + ' ' + (65 - ((v - mn) / rg) * 55).toFixed(1)).join('');
  return `<svg class="spark" viewBox="0 0 300 70" preserveAspectRatio="none"><path class="ar" d="${d}L300 70L0 70Z" fill="rgba(255,255,255,.14)"/><path class="ln" pathLength="1" d="${d}"/></svg>`;
}
function panelP(me, s, sols, mov, m) {
  const first = esc((me.nombre || '').trim().split(' ')[0]);
  if (me.estado !== 'APROBADO') return shell(`<div class="wrap">${top(me)}<div class="card"><h1>Hola, ${first}</h1><p class="s">Estado de tu cuenta: <span class="badge ${esc(me.estado)}">${esc(me.estado)}</span></p><p>${me.estado === 'RECHAZADO' ? 'Tu solicitud no fue aprobada. Comunícate con la administración.' : 'Un administrador está revisando tu solicitud. Te avisaremos cuando esté aprobada.'}</p></div></div>`, m);
  return shell(`<div class="wrap">${top(me)}
<section class="card vcard"><div class="vrow"><span class="lab">Cuenta de ahorro</span>${CHIP}</div><div class="lab" style="margin-top:20px">Saldo disponible</div><div class="bal">$ <span data-n="${s}">${money(s)}</span></div>${spark(mov, s)}<div class="vrow" style="margin-top:12px"><span class="holder">${esc(me.nombre)}</span><span class="badge APROBADO">Activa</span></div></section>
<section class="card"><h2>Nueva solicitud</h2><form method="post" action="/solicitar"><div class="seg"><input type="radio" id="t1" name="tipo" value="DEPOSITO" checked><label for="t1">Depósito</label><input type="radio" id="t2" name="tipo" value="RETIRO"><label for="t2">Retiro</label></div>
<label for="monto">Monto</label><div class="amt"><span>$</span><input id="monto" name="monto" inputmode="decimal" placeholder="0,00" autocomplete="off" required></div>
<label for="ref">Referencia (opcional)</label><input id="ref" name="referencia" maxlength="60" autocomplete="off"><button>Enviar solicitud</button></form></section>
<div class="grid g2"><section class="card"><h2>Solicitudes</h2>${list(sols, solRow, 'Aún no hay solicitudes')}</section><section class="card"><h2>Movimientos</h2>${list(mov, movRow, 'Aún no hay movimientos')}</section></div></div>`, m);
}
const acts = path => `<form method="post" action="${path}" class="acts"><button class="sm" name="a" value="aprobar">Aprobar</button><button class="sm danger" name="a" value="rechazar" onclick="return confirm('¿Rechazar?')">Rechazar</button></form>`;
function adminP(me, users, sols, logs, m) {
  const ini = n => esc((n || '?').trim().charAt(0).toUpperCase());
  return shell(`<div class="wrap">${top(me, '<span class="badge APROBADO">Admin</span>')}
<div class="stats"><div class="card"><div class="mu">Cuentas por aprobar</div><b data-i="${users.length}">${users.length}</b></div><div class="card"><div class="mu">Solicitudes por aprobar</div><b data-i="${sols.length}">${sols.length}</b></div></div>
<div class="grid g2"><section class="card"><h2>Cuentas por aprobar</h2>${list(users, (x, i) => `<div class="item" style="animation-delay:${i * 45}ms"><div class="who"><div class="av">${ini(x.nombre)}</div><div><b>${esc(x.nombre)}</b><div class="mu">${esc(x.cedula)} · ${esc(x.email)}</div></div></div>${acts('/admin/usuario/' + x.id)}</div>`, 'Nada pendiente')}</section>
<section class="card"><h2>Solicitudes por aprobar</h2>${list(sols, (x, i) => `<div class="item" style="animation-delay:${i * 45}ms"><div class="vrow"><div class="who"><div class="av">${ini(x.usuarios?.nombre)}</div><div><b>${esc(x.usuarios?.nombre)}</b><div class="mu">${esc(x.referencia)}</div></div></div><div style="text-align:right"><b>$ ${money(x.centavos)}</b><div class="mu">${x.tipo === 'DEPOSITO' ? 'Depósito' : 'Retiro'}</div></div></div>${acts('/admin/solicitud/' + x.id)}</div>`, 'Nada pendiente')}</section></div>
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
    }
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
