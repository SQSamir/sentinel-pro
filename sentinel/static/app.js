let token = sessionStorage.getItem('sentinel_token') || null;
let role = null;
const view = document.getElementById('view');

const pages = { dashboard, jails, bans, whitelist, config, logs, audit, sessions, health };

async function tryRefreshToken() {
  const r = await fetch('/auth/refresh', { method: 'POST' });
  if (!r.ok) return false;
  const j = await r.json();
  if (!j?.access_token) return false;
  token = j.access_token;
  sessionStorage.setItem('sentinel_token', token);
  return true;
}

async function api(path, opts = {}, retried = false) {
  opts.headers = opts.headers || {};
  if (token) opts.headers['Authorization'] = `Bearer ${token}`;
  const r = await fetch(path, opts);
  if (r.status === 401) {
    if (!retried && await tryRefreshToken()) return api(path, opts, true);
    sessionStorage.removeItem('sentinel_token');
    token = null;
    await showLogin();
    return null;
  }
  const ct = r.headers.get('content-type') || '';
  const body = ct.includes('application/json') ? await r.json() : await r.text();
  if (!r.ok) throw new Error(body.detail || body || `HTTP ${r.status}`);
  return body;
}

function esc(s){return (s||'').toString().replace(/[&<>]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[m]));}

function setActive(btn){
  document.querySelectorAll('.nav-btn').forEach(x=>x.classList.remove('active'));
  if(btn) btn.classList.add('active');
}

async function showLogin() {
  view.innerHTML = `<div class='card' style='max-width:420px'>
    <h3>Login</h3>
    <div class='row' style='grid-template-columns:1fr'>
      <input id='u' placeholder='username' value='admin'>
      <input id='p' placeholder='password' type='password'>
      <button class='action' id='l'>Sign in</button>
    </div>
  </div>`;
  document.getElementById('who').textContent = 'guest';
  document.getElementById('ws').textContent = 'WS: disconnected';
  document.getElementById('l').onclick = async () => {
    const username = document.getElementById('u').value.trim();
    const password = document.getElementById('p').value;
    const r = await fetch('/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username, password }) });
    const j = await r.json();
    if (!r.ok) return alert(j.detail || 'login failed');
    token = j.access_token; role = j.role;
    sessionStorage.setItem('sentinel_token', token);
    await me();
    await dashboard();
    connectWS();
  };
}

async function me() {
  const m = await api('/auth/me');
  if(!m) return;
  role = m.role;
  document.getElementById('who').textContent = `${m.username} (${m.role})`;
}

async function dashboard() {
  const s = await api('/f2b/stats');
  if(!s) return;
  view.innerHTML = `<div class='card'><h3>Dashboard</h3><pre class='mono'>${esc(JSON.stringify(s, null, 2))}</pre></div>`;
}

async function jails() {
  const j = await api('/f2b/jails');
  if(!j) return;
  view.innerHTML = `<div class='card'><h3>Jails</h3><pre class='mono'>${esc(j.raw || '')}</pre></div>`;
}

async function bans() {
  const jailResp = await api('/f2b/jails');
  if (!jailResp) return;
  const jails = Array.isArray(jailResp.jails) ? jailResp.jails : [];

  const options = jails.length
    ? jails.map(j => `<option value="${esc(j)}">${esc(j)}</option>`).join('')
    : `<option value="">(no jails found)</option>`;

  view.innerHTML = `<div class='card'><h3>Ban / Unban</h3>
    <div class='row'>
      <select id='jail'>${options}</select>
      <input id='ip' placeholder='IP'>
      <button class='action danger' id='ban'>Ban</button>
      <button class='action warn' id='unban'>Unban</button>
    </div>
  </div>`;

  document.getElementById('ban').onclick = async () => {
    const jail = document.getElementById('jail').value.trim();
    const ip = document.getElementById('ip').value.trim();
    if (!jail || !ip) return alert('Jail və IP daxil et');
    try {
      await api('/f2b/bans', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jail, ip }) });
      alert('Banned');
    } catch (e) { alert(e.message); }
  };

  document.getElementById('unban').onclick = async () => {
    const jail = document.getElementById('jail').value.trim();
    const ip = document.getElementById('ip').value.trim();
    if (!jail || !ip) return alert('Jail və IP daxil et');
    try {
      await api(`/f2b/bans/${encodeURIComponent(jail)}/${encodeURIComponent(ip)}`, { method: 'DELETE' });
      alert('Unbanned');
    } catch (e) { alert(e.message); }
  };
}

async function whitelist() {
  const items = await api('/f2b/whitelist') || [];
  view.innerHTML = `<div class='card'><h3>Whitelist</h3>
    <div class='row'>
      <input id='entry' placeholder='IP/CIDR'>
      <input id='note' placeholder='note'>
      <button class='action' id='add'>Add</button>
      <div></div>
    </div>
    <pre class='mono'>${esc(JSON.stringify(items, null, 2))}</pre>
  </div>`;
  document.getElementById('add').onclick = async () => {
    const entry = document.getElementById('entry').value.trim();
    const note = document.getElementById('note').value.trim();
    try {
      await api('/f2b/whitelist', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ entry, note }) });
      await whitelist();
    } catch (e) { alert(e.message); }
  };
}

async function config() {
  const c = await api('/f2b/config');
  if(!c) return;
  view.innerHTML = `<div class='card'><h3>Config Editor (${esc(c.path)})</h3>
    <textarea id='cfg' rows='20'>${esc(c.content || '')}</textarea><br><br>
    <button class='action' id='save'>Save</button>
  </div>`;

  document.getElementById('save').onclick = async () => {
    try {
      await api('/f2b/config', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ content: document.getElementById('cfg').value }) });
      alert('Saved');
    } catch (e) { alert(e.message); }
  };
}

async function logs() {
  const l = await api('/f2b/logs?limit=300');
  if(!l) return;
  view.innerHTML = `<div class='card'><h3>Log Analyzer</h3>
    <a href='/f2b/logs/export' target='_blank'>Export logs</a>
    <pre class='mono'>${esc((l.items || []).join('\n'))}</pre>
  </div>`;
}

async function audit() {
  const a = await api('/audit?limit=300');
  if(!a) return;
  view.innerHTML = `<div class='card'><h3>Audit Log</h3>
    <a href='/audit/export' target='_blank'>Export NDJSON</a>
    <pre class='mono'>${esc(JSON.stringify(a, null, 2))}</pre>
  </div>`;
}

async function sessions() {
  const s = await api('/auth/sessions');
  if(!s) return;
  view.innerHTML = `<div class='card'><h3>Sessions</h3>
    <button class='action warn' id='lo'>Logout all sessions</button>
    <pre class='mono'>${esc(JSON.stringify(s, null, 2))}</pre>
  </div>`;
  document.getElementById('lo').onclick = async () => {
    await api('/auth/logout-all', { method: 'POST' });
    alert('All sessions revoked');
  };
}

async function health() {
  const h = await api('/system/health');
  if(!h) return;
  view.innerHTML = `<div class='card'><h3>System Health</h3><pre class='mono'>${esc(JSON.stringify(h, null, 2))}</pre></div>`;
}

function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/ws/events?token=${encodeURIComponent(token)}`);
  ws.onopen = () => document.getElementById('ws').textContent = 'WS: connected';
  ws.onclose = () => document.getElementById('ws').textContent = 'WS: disconnected';
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.type === 'log') {
      const pre = document.querySelector('#view pre.mono');
      if (pre && pre.textContent.length < 200000) pre.textContent += `\n${msg.line}`;
    }
  };
}

document.querySelectorAll('[data-view]').forEach(b => {
  b.onclick = async () => {
    setActive(b);
    const fn = pages[b.dataset.view];
    if (fn) await fn();
  };
});

document.getElementById('logout').onclick = async () => {
  await fetch('/auth/logout', { method: 'POST' });
  token = null;
  role = null;
  sessionStorage.removeItem('sentinel_token');
  await showLogin();
};

(async () => {
  if (!token) await tryRefreshToken();
  if (token) {
    await me();
    await dashboard();
    connectWS();
  } else {
    await showLogin();
  }
})();
