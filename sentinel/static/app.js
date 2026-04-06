let token = null;
let role = null;
const view = document.getElementById('view');

async function api(path, opts = {}) {
  opts.headers = opts.headers || {};
  if (token) opts.headers['Authorization'] = `Bearer ${token}`;
  const r = await fetch(path, opts);
  if (r.status === 401) {
    await showLogin();
    return null;
  }
  const ct = r.headers.get('content-type') || '';
  const body = ct.includes('application/json') ? await r.json() : await r.text();
  if (!r.ok) throw new Error(body.detail || body || `HTTP ${r.status}`);
  return body;
}

function esc(s){return (s||'').replace(/[&<>]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[m]));}

async function showLogin() {
  view.innerHTML = `<div class='card'><h3>Login</h3><input id='u' placeholder='username' value='admin'><br><br><input id='p' placeholder='password' type='password'><br><br><button id='l'>Login</button></div>`;
  document.getElementById('l').onclick = async () => {
    const username = document.getElementById('u').value;
    const password = document.getElementById('p').value;
    const r = await fetch('/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username, password }) });
    const j = await r.json();
    if (!r.ok) return alert(j.detail || 'login failed');
    token = j.access_token; role = j.role;
    await me();
    dashboard();
    connectWS();
  }
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
  view.innerHTML = `<div class='card'><h3>Stats</h3><pre class='mono'>${esc(JSON.stringify(s, null, 2))}</pre></div>`;
}

async function jails() {
  const j = await api('/f2b/jails');
  if(!j) return;
  view.innerHTML = `<div class='card'><h3>Jails</h3><pre class='mono'>${esc(j.raw || '')}</pre></div>`;
}

async function bans() {
  view.innerHTML = `<div class='card'><h3>Ban / Unban</h3>
  <input id='jail' placeholder='jail'> <input id='ip' placeholder='ip'>
  <button id='ban'>Ban</button> <button id='unban'>Unban</button></div>`;
  document.getElementById('ban').onclick = async () => {
    try { await api('/f2b/bans', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jail: jail.value, ip: ip.value }) }); alert('banned'); } catch (e) { alert(e.message); }
  };
  document.getElementById('unban').onclick = async () => {
    try { await api(`/f2b/bans/${encodeURIComponent(jail.value)}/${encodeURIComponent(ip.value)}`, { method: 'DELETE' }); alert('unbanned'); } catch (e) { alert(e.message); }
  };
}

async function whitelist() {
  const items = await api('/f2b/whitelist') || [];
  view.innerHTML = `<div class='card'><h3>Whitelist</h3>
    <input id='entry' placeholder='IP/CIDR'> <input id='note' placeholder='note'> <button id='add'>Add</button>
    <pre class='mono'>${esc(JSON.stringify(items, null, 2))}</pre></div>`;
  document.getElementById('add').onclick = async () => {
    try { await api('/f2b/whitelist', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ entry: entry.value, note: note.value }) }); whitelist(); } catch (e) { alert(e.message); }
  };
}

async function config() {
  const c = await api('/f2b/config');
  if(!c) return;
  view.innerHTML = `<div class='card'><h3>Config: ${esc(c.path)}</h3><textarea id='cfg' rows='18'>${esc(c.content || '')}</textarea><br><button id='save'>Save</button></div>`;
  document.getElementById('save').onclick = async () => {
    try { await api('/f2b/config', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ content: document.getElementById('cfg').value }) }); alert('saved'); } catch (e) { alert(e.message); }
  };
}

async function logs() {
  const l = await api('/f2b/logs?limit=300');
  if(!l) return;
  view.innerHTML = `<div class='card'><h3>Logs</h3><a href='/f2b/logs/export' target='_blank'>Export logs</a><pre class='mono'>${esc((l.items || []).join('\n'))}</pre></div>`;
}

async function audit() {
  const a = await api('/audit?limit=300');
  if(!a) return;
  view.innerHTML = `<div class='card'><h3>Audit</h3><a href='/audit/export' target='_blank'>Export NDJSON</a><pre class='mono'>${esc(JSON.stringify(a, null, 2))}</pre></div>`;
}

async function sessions() {
  const s = await api('/auth/sessions');
  if(!s) return;
  view.innerHTML = `<div class='card'><h3>Sessions</h3><button id='lo'>Logout all sessions</button><pre class='mono'>${esc(JSON.stringify(s, null, 2))}</pre></div>`;
  document.getElementById('lo').onclick = async () => { await api('/auth/logout-all', { method: 'POST' }); alert('revoked all'); };
}

async function health() {
  const h = await api('/system/health');
  if(!h) return;
  view.innerHTML = `<div class='card'><h3>Health</h3><pre class='mono'>${esc(JSON.stringify(h, null, 2))}</pre></div>`;
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
      if (pre && pre.textContent.length < 100000) pre.textContent += `\n${msg.line}`;
    }
  };
}

document.querySelectorAll('[data-view]').forEach(b => b.onclick = () => ({ dashboard, jails, bans, whitelist, config, logs, audit, sessions, health }[b.dataset.view]()));
document.getElementById('logout').onclick = async () => { await fetch('/auth/logout', { method: 'POST' }); token = null; showLogin(); };
showLogin();
