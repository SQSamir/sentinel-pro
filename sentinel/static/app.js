let token = null;
const view = document.getElementById('view');

async function api(path, opts={}){
  opts.headers = opts.headers || {};
  if(token) opts.headers['Authorization'] = `Bearer ${token}`;
  const r = await fetch(path, opts);
  if(r.status===401) return showLogin();
  const ct = r.headers.get('content-type')||'';
  return ct.includes('application/json') ? r.json() : r.text();
}

async function showLogin(){
  view.innerHTML = `<div class='card'><h3>Login</h3><input id='u' placeholder='username'><br><br><input id='p' placeholder='password' type='password'><br><br><button id='l'>Login</button></div>`;
  document.getElementById('l').onclick = async ()=>{
    const username=document.getElementById('u').value;
    const password=document.getElementById('p').value;
    const r = await fetch('/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username,password})});
    const j = await r.json();
    if(!r.ok){ alert(j.detail||'login failed'); return; }
    token = j.access_token;
    await me();
    dashboard();
    connectWS();
  }
}

async function me(){
  const m = await api('/auth/me');
  document.getElementById('who').textContent = `${m.username} (${m.role})`;
}

async function dashboard(){
  const s = await api('/f2b/stats');
  view.innerHTML = `<div class='card'><h3>Stats</h3><pre class='mono'>${JSON.stringify(s,null,2)}</pre></div>`;
}

async function jails(){
  const j = await api('/f2b/jails');
  view.innerHTML = `<div class='card'><h3>Jails</h3><pre class='mono'>${j.raw||''}</pre></div>`;
}

function connectWS(){
  const proto = location.protocol==='https:'?'wss':'ws';
  const ws = new WebSocket(`${proto}://${location.host}/ws/events`);
  ws.onopen = ()=>document.getElementById('ws').textContent='WS: connected';
  ws.onclose= ()=>document.getElementById('ws').textContent='WS: disconnected';
  ws.onmessage = (ev)=>console.log('WS',ev.data);
}

document.querySelectorAll('[data-view]').forEach(b=>b.onclick=()=>({dashboard,jails,stats:dashboard}[b.dataset.view]()));
document.getElementById('logout').onclick=async()=>{await fetch('/auth/logout',{method:'POST'}); token=null; showLogin();};
showLogin();
