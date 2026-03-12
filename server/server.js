const express  = require('express');
const { WebSocketServer } = require('ws');
const { Client: SSHClient } = require('ssh2');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cors    = require('cors');
const http    = require('http');
const path    = require('path');
const crypto  = require('crypto');
const db      = require('./db');

const PORT = process.env.PORT || 3000;
const app  = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'client')));

// ─── Auth middleware ──────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  if (db.setting('auth_enabled') !== '1') return next();
  const token = req.headers['x-auth-token'] || req.query.token;
  if (token && token === db.setting('auth_token')) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

// ─── Telegram helper ──────────────────────────────────────────────────────────
async function sendTelegram(message) {
  const token = db.setting('telegram_token');
  const chatId = db.setting('telegram_chat_id');
  if (!token || !chatId) return;
  try {
    await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text: message, parse_mode: 'HTML' })
    });
  } catch(e) { console.error('[telegram]', e.message); }
}

// ─── SSH exec helper ──────────────────────────────────────────────────────────
function sshExec(router, command) {
  return new Promise((resolve, reject) => {
    const conn = new SSHClient();
    let output = '';
    conn.on('ready', () => {
      conn.exec(command, (err, stream) => {
        if (err) { conn.end(); return reject(err); }
        stream.on('data', d => output += d.toString());
        stream.stderr.on('data', d => output += d.toString());
        stream.on('close', () => { conn.end(); resolve(output); });
      });
    });
    conn.on('error', reject);
    conn.connect({ host: router.ip, port: router.ssh_port||22, username: router.ssh_user||'root', password: router.ssh_pass||'', readyTimeout: 8000 });
  });
}

// ─── Auth ─────────────────────────────────────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const { password } = req.body;
  if (password === db.setting('admin_password')) {
    res.json({ ok: true, token: db.setting('auth_token') });
  } else {
    res.status(401).json({ error: 'Неверный пароль' });
  }
});

app.get('/api/auth/status', (req, res) => {
  res.json({ auth_enabled: db.setting('auth_enabled') === '1' });
});

// ─── Settings ─────────────────────────────────────────────────────────────────
app.get('/api/settings', authMiddleware, (req, res) => {
  const rows = db.all('SELECT key,value FROM settings');
  const obj  = {};
  rows.forEach(r => obj[r.key] = r.value);
  delete obj.auth_token;
  delete obj.admin_password;
  res.json(obj);
});

app.put('/api/settings', authMiddleware, (req, res) => {
  const safe = ['theme','language','grid_columns','telegram_token','telegram_chat_id',
                'heartbeat_interval','offline_timeout','backup_interval','app_name','auth_enabled'];
  Object.entries(req.body).forEach(([k,v]) => { if (safe.includes(k)) db.setSetting(k, v); });
  res.json({ ok: true });
});

app.put('/api/settings/password', authMiddleware, (req, res) => {
  const { current, next } = req.body;
  if (current !== db.setting('admin_password')) return res.status(400).json({ error: 'Неверный текущий пароль' });
  db.setSetting('admin_password', next);
  const newToken = crypto.randomBytes(32).toString('hex');
  db.setSetting('auth_token', newToken);
  res.json({ ok: true, token: newToken });
});

// ─── Groups ───────────────────────────────────────────────────────────────────
app.get('/api/groups', authMiddleware, (req, res) => res.json(db.all('SELECT * FROM groups ORDER BY name')));

app.post('/api/groups', authMiddleware, (req, res) => {
  const { name, city, lat, lng } = req.body;
  const id = db.run('INSERT INTO groups (name,city,lat,lng) VALUES (?,?,?,?)', [name, city||'', lat||null, lng||null]);
  res.json({ id, name, city, lat, lng });
});

app.put('/api/groups/:id', authMiddleware, (req, res) => {
  const { name, city, lat, lng } = req.body;
  db.run('UPDATE groups SET name=?,city=?,lat=?,lng=? WHERE id=?', [name, city, lat, lng, req.params.id]);
  res.json({ ok: true });
});

app.delete('/api/groups/:id', authMiddleware, (req, res) => {
  db.run('UPDATE routers SET group_id=NULL WHERE group_id=?', [req.params.id]);
  db.run('DELETE FROM groups WHERE id=?', [req.params.id]);
  res.json({ ok: true });
});

// ─── Routers CRUD ─────────────────────────────────────────────────────────────
app.get('/api/routers', authMiddleware, (req, res) => res.json(db.all('SELECT * FROM routers ORDER BY name')));

app.post('/api/routers', authMiddleware, (req, res) => {
  const { name, ip, location, model, tags, ssh_user, ssh_pass, ssh_port, lat, lng, group_id } = req.body;
  if (!name || !ip) return res.status(400).json({ error: 'name and ip required' });
  const id = db.run(
    `INSERT INTO routers (name,ip,location,model,tags,ssh_user,ssh_pass,ssh_port,lat,lng,group_id,status,created_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,'unknown',datetime('now'))`,
    [name, ip, location||'', model||'', JSON.stringify(tags||[]), ssh_user||'root', ssh_pass||'', ssh_port||22, lat||null, lng||null, group_id||null]
  );
  res.json({ id, name, ip, status: 'unknown' });
});

app.put('/api/routers/:id', authMiddleware, (req, res) => {
  const { name, ip, location, model, tags, ssh_user, ssh_pass, ssh_port, lat, lng, group_id } = req.body;
  db.run(
    `UPDATE routers SET name=?,ip=?,location=?,model=?,tags=?,ssh_user=?,ssh_pass=?,ssh_port=?,lat=?,lng=?,group_id=? WHERE id=?`,
    [name, ip, location, model, JSON.stringify(tags||[]), ssh_user, ssh_pass, ssh_port||22, lat||null, lng||null, group_id||null, req.params.id]
  );
  res.json({ ok: true });
});

app.delete('/api/routers/:id', authMiddleware, (req, res) => {
  db.run('DELETE FROM routers WHERE id=?', [req.params.id]);
  res.json({ ok: true });
});

// ─── Register & Heartbeat ─────────────────────────────────────────────────────
app.post('/api/routers/register', (req, res) => {
  const { name, ip, model, firmware, mac } = req.body;
  if (!ip) return res.status(400).json({ error: 'ip required' });
  const existing = db.get('SELECT * FROM routers WHERE ip=?', [ip]);
  if (existing) return res.json({ id: existing.id, registered: false });
  const id = db.run(
    `INSERT INTO routers (name,ip,model,firmware,mac,tags,ssh_user,ssh_port,status,created_at)
     VALUES (?,?,?,?,?,'[]','root',22,'online',datetime('now'))`,
    [name||ip, ip, model||'', firmware||'', mac||'']
  );
  db.run(`INSERT INTO events (router_id,router_name,type,message) VALUES (?,?,?,?)`,
    [id, name||ip, 'online', `Роутер ${name||ip} зарегистрирован`]);
  console.log(`[register] ${name} (${ip})`);
  res.json({ id, registered: true });
});

app.post('/api/routers/:id/heartbeat', (req, res) => {
  const { cpu, ram, clients, uptime_sec, firmware, load } = req.body;
  const router = db.get('SELECT status FROM routers WHERE id=?', [req.params.id]);
  if (!router) return res.status(404).json({ error: 'not found' });

  const wasOffline = router.status !== 'online';
  db.run(
    `UPDATE routers SET status='online',cpu=?,ram=?,clients=?,uptime_sec=?,firmware=COALESCE(?,firmware),load=?,last_seen=datetime('now') WHERE id=?`,
    [cpu||0, ram||0, clients||0, uptime_sec||0, firmware, load||'', req.params.id]
  );

  // Store metrics history (every heartbeat)
  db.run(`INSERT INTO metrics_history (router_id,cpu,ram,clients) VALUES (?,?,?,?)`,
    [req.params.id, cpu||0, ram||0, clients||0]);

  // Cleanup old metrics (keep 7 days)
  db.run(`DELETE FROM metrics_history WHERE router_id=? AND recorded_at < datetime('now','-7 days')`, [req.params.id]);

  if (wasOffline) {
    const r = db.get('SELECT name FROM routers WHERE id=?', [req.params.id]);
    db.run(`INSERT INTO events (router_id,router_name,type,message) VALUES (?,?,?,?)`,
      [req.params.id, r.name, 'online', `Роутер ${r.name} снова онлайн`]);
    sendTelegram(`✅ <b>${r.name}</b> снова онлайн`);
  }

  res.json({ ok: true });
});

// ─── Actions ──────────────────────────────────────────────────────────────────
app.post('/api/routers/:id/ping', authMiddleware, async (req, res) => {
  const router = db.get('SELECT * FROM routers WHERE id=?', [req.params.id]);
  if (!router) return res.status(404).json({ error: 'not found' });
  const net = require('net'), start = Date.now();
  const socket = new net.Socket();
  socket.setTimeout(3000);
  socket.connect(router.ssh_port||22, router.ip, () => { socket.destroy(); res.json({ ok: true, ms: Date.now()-start }); });
  socket.on('error', () => res.json({ ok: false, ms: null }));
  socket.on('timeout', () => { socket.destroy(); res.json({ ok: false, ms: null }); });
});

app.post('/api/routers/:id/reboot', authMiddleware, async (req, res) => {
  const router = db.get('SELECT * FROM routers WHERE id=?', [req.params.id]);
  if (!router) return res.status(404).json({ error: 'not found' });
  try {
    await sshExec(router, 'reboot &');
    db.run(`UPDATE routers SET status='rebooting' WHERE id=?`, [router.id]);
    db.run(`INSERT INTO events (router_id,router_name,type,message) VALUES (?,?,?,?)`,
      [router.id, router.name, 'reboot', `Роутер ${router.name} перезагружен`]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── Stats for monitoring ─────────────────────────────────────────────────────
app.get('/api/stats', authMiddleware, (req, res) => {
  const routers = db.all('SELECT * FROM routers');
  const online  = routers.filter(r=>r.status==='online');
  const totalClients = online.reduce((s,r)=>s+r.clients,0);
  const avgCpu = online.length ? (online.reduce((s,r)=>s+r.cpu,0)/online.length).toFixed(1) : 0;
  const avgRam = online.length ? (online.reduce((s,r)=>s+r.ram,0)/online.length).toFixed(1) : 0;
  const highCpu = online.filter(r=>r.cpu>85);
  const highRam = online.filter(r=>r.ram>90);
  res.json({
    total: routers.length,
    online: online.length,
    offline: routers.filter(r=>r.status==='offline').length,
    warning: routers.filter(r=>r.status==='warning').length,
    totalClients, avgCpu, avgRam,
    highCpu: highCpu.map(r=>r.name),
    highRam: highRam.map(r=>r.name),
  });
});

// ─── Metrics history for charts ───────────────────────────────────────────────
app.get('/api/metrics/:id', authMiddleware, (req, res) => {
  const hours = parseInt(req.query.hours)||24;
  const rows = db.all(
    `SELECT cpu,ram,clients,recorded_at FROM metrics_history
     WHERE router_id=? AND recorded_at > datetime('now','-${hours} hours')
     ORDER BY recorded_at ASC LIMIT 500`,
    [req.params.id]
  );
  res.json(rows);
});

// ─── Events ───────────────────────────────────────────────────────────────────
app.get('/api/events', authMiddleware, (req, res) => {
  const limit = parseInt(req.query.limit)||100;
  res.json(db.all(`SELECT * FROM events ORDER BY created_at DESC LIMIT ?`, [limit]));
});

// ─── Snapshots ────────────────────────────────────────────────────────────────
app.get('/api/snapshots', authMiddleware, (req, res) => {
  res.json(db.all('SELECT id,router_id,router_name,label,created_at FROM snapshots ORDER BY created_at DESC'));
});

app.post('/api/snapshots/:id', authMiddleware, async (req, res) => {
  const router = db.get('SELECT * FROM routers WHERE id=?', [req.params.id]);
  if (!router) return res.status(404).json({ error: 'not found' });
  try {
    const content = await sshExec(router, 'uci export');
    const label   = req.body.label || new Date().toLocaleString('ru');
    const snapId  = db.run(
      'INSERT INTO snapshots (router_id,router_name,label,content) VALUES (?,?,?,?)',
      [router.id, router.name, label, content]
    );
    db.run(`INSERT INTO events (router_id,router_name,type,message) VALUES (?,?,?,?)`,
      [router.id, router.name, 'snapshot', `Снапшот конфига: ${label}`]);
    res.json({ ok: true, id: snapId, label });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/snapshots/:id/content', authMiddleware, (req, res) => {
  const snap = db.get('SELECT * FROM snapshots WHERE id=?', [req.params.id]);
  if (!snap) return res.status(404).json({ error: 'not found' });
  res.json(snap);
});

app.delete('/api/snapshots/:id', authMiddleware, (req, res) => {
  db.run('DELETE FROM snapshots WHERE id=?', [req.params.id]);
  res.json({ ok: true });
});

// ─── Push config ──────────────────────────────────────────────────────────────
app.post('/api/push-config', authMiddleware, async (req, res) => {
  const { router_ids, commands } = req.body;
  if (!router_ids?.length || !commands) return res.status(400).json({ error: 'router_ids and commands required' });
  const results = [];
  for (const id of router_ids) {
    const router = db.get('SELECT * FROM routers WHERE id=?', [id]);
    if (!router) { results.push({ id, ok: false, error: 'not found' }); continue; }
    try {
      const out = await sshExec(router, commands);
      db.run(`INSERT INTO events (router_id,router_name,type,message) VALUES (?,?,?,?)`,
        [router.id, router.name, 'config', `Push конфига выполнен`]);
      results.push({ id, name: router.name, ok: true, output: out });
    } catch(e) {
      results.push({ id, name: router.name, ok: false, error: e.message });
    }
  }
  res.json({ results });
});

// ─── Package update ───────────────────────────────────────────────────────────
app.post('/api/routers/:id/opkg-update', authMiddleware, async (req, res) => {
  const router = db.get('SELECT * FROM routers WHERE id=?', [req.params.id]);
  if (!router) return res.status(404).json({ error: 'not found' });
  try {
    const out = await sshExec(router, 'opkg update 2>&1 | tail -5');
    db.run(`INSERT INTO events (router_id,router_name,type,message) VALUES (?,?,?,?)`,
      [router.id, router.name, 'update', `opkg update выполнен`]);
    res.json({ ok: true, output: out });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/routers/:id/packages', authMiddleware, async (req, res) => {
  const router = db.get('SELECT * FROM routers WHERE id=?', [req.params.id]);
  if (!router) return res.status(404).json({ error: 'not found' });
  try {
    const out = await sshExec(router, 'opkg list-upgradable 2>/dev/null');
    const packages = out.trim().split('\n').filter(Boolean).map(line => {
      const parts = line.split(' - ');
      return { name: parts[0], from: parts[1]||'', to: parts[2]||'' };
    });
    res.json({ packages });
  } catch(e) { res.status(500).json({ error: e.message, packages: [] }); }
});

// ─── Update history ───────────────────────────────────────────────────────────
app.get('/api/update-history', authMiddleware, (req, res) => {
  res.json(db.all('SELECT * FROM update_history ORDER BY created_at DESC LIMIT 100'));
});

// ─── System info ──────────────────────────────────────────────────────────────
app.get('/api/system', authMiddleware, (req, res) => {
  const fs = require('fs');
  let dbSize = 0;
  try { dbSize = fs.statSync(process.env.DB_PATH || path.join(__dirname, 'netctrl.db')).size; } catch(e) {}
  res.json({
    version:  '1.0.0',
    name:     db.setting('app_name'),
    uptime:   Math.floor(process.uptime()),
    dbSize:   dbSize,
    routers:  db.get('SELECT COUNT(*) as n FROM routers').n,
    events:   db.get('SELECT COUNT(*) as n FROM events').n,
    snapshots:db.get('SELECT COUNT(*) as n FROM snapshots').n,
    nodeVersion: process.version,
  });
});

// ─── DB Backup ────────────────────────────────────────────────────────────────
app.get('/api/backup/download', authMiddleware, (req, res) => {
  const dbPath = process.env.DB_PATH || path.join(__dirname, 'netctrl.db');
  res.download(dbPath, `netctrl-backup-${new Date().toISOString().slice(0,10)}.db`);
});

// ─── Telegram test ────────────────────────────────────────────────────────────
app.post('/api/telegram/test', authMiddleware, async (req, res) => {
  try {
    await sendTelegram('✅ OpenWRT NetCtrl: тестовое уведомление работает!');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── LuCI Auto-login ─────────────────────────────────────────────────────────
app.get('/luci-login/:id', async (req, res) => {
  const router = db.get('SELECT * FROM routers WHERE id=?', [req.params.id]);
  if (!router) return res.status(404).send('Router not found');

  try {
    const rpcResp = await fetch(`http://${router.ip}/cgi-bin/luci/rpc/auth`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: 1, method: 'login', params: [router.ssh_user || 'root', router.ssh_pass || ''] })
    });
    const rpcData = await rpcResp.json();
    const token = rpcData.result;
    if (!token || token === '0000000000000000000000000000000000000000') {
      throw new Error('Invalid token');
    }

    // Return HTML form that auto-submits POST to LuCI with token
    res.send(`
<!DOCTYPE html>
<html>
<head><title>Redirecting to LuCI...</title></head>
<body>
  <form id="luciForm" method="post" action="http://${router.ip}/cgi-bin/luci/">
    <input type="hidden" name="luci_username" value="${router.ssh_user || 'root'}">
    <input type="hidden" name="luci_password" value="${router.ssh_pass || ''}">
    <input type="hidden" name="auth" value="${token}">
  </form>
  <script>document.getElementById('luciForm').submit();</script>
</body>
</html>
    `);
  } catch (e) {
    console.error('[luci-login]', e.message);
    res.redirect(`http://${router.ip}/cgi-bin/luci/`);
  }
});

// ─── LuCI Proxy ───────────────────────────────────────────────────────────────
app.use('/proxy/:id', (req, res, next) => {
  const router = db.get('SELECT * FROM routers WHERE id=?', [req.params.id]);
  if (!router) return res.status(404).send('Router not found');
  const proxy = createProxyMiddleware({
    target: `http://${router.ip}`,
    changeOrigin: true,
    followRedirects: true,
    pathRewrite: { [`^/proxy/${req.params.id}`]: '' },
    on: {
      proxyReq: (proxyReq) => {
        proxyReq.removeHeader('x-forwarded-host');
        proxyReq.setHeader('Origin', `http://${router.ip}`);
        proxyReq.setHeader('Referer', `http://${router.ip}/cgi-bin/luci/`);
      },
      error: (err, req, res) => res.status(502).send(`Cannot connect to LuCI: ${err.message}`)
    }
  });
  proxy(req, res, next);
});

// ─── Agent installer ──────────────────────────────────────────────────────────
app.get('/agent/install.sh', (req, res) => {
  const serverUrl = `http://${req.hostname}:${PORT}`;
  res.setHeader('Content-Type', 'text/plain');
  res.send(`#!/bin/sh
SERVER="${serverUrl}"
AGENT_FILE="/usr/bin/netctrl-agent"
wget -q "$SERVER/agent/netctrl-agent.sh" -O "$AGENT_FILE"
chmod +x "$AGENT_FILE"
if ! grep -q netctrl-agent /etc/rc.local 2>/dev/null; then
  echo "NETCTRL_SERVER=$SERVER $AGENT_FILE &" >> /etc/rc.local
fi
NETCTRL_SERVER=$SERVER $AGENT_FILE &
echo "NetCtrl agent started. Server: $SERVER"
`);
});
app.get('/agent/netctrl-agent.sh', (req, res) => res.sendFile(path.join(__dirname, 'agent/netctrl-agent.sh')));

// ─── SPA fallback ─────────────────────────────────────────────────────────────
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'client/index.html')));

// ─── HTTP + WebSocket ─────────────────────────────────────────────────────────
const server = http.createServer(app);
const wss    = new WebSocketServer({ server, path: '/ws/ssh' });

// Offline checker
setInterval(() => {
  const timeout = parseInt(db.setting('offline_timeout'))||120;
  const rows = db.all(
    `SELECT id,name FROM routers WHERE status='online' AND last_seen < datetime('now','-${timeout} seconds')`
  );
  rows.forEach(r => {
    db.run(`UPDATE routers SET status='offline' WHERE id=?`, [r.id]);
    db.run(`INSERT INTO events (router_id,router_name,type,message) VALUES (?,?,?,?)`,
      [r.id, r.name, 'offline', `Роутер ${r.name} недоступен`]);
    sendTelegram(`🔴 <b>${r.name}</b> недоступен`);
  });
}, 60*1000);

// ─── WebSocket SSH proxy ──────────────────────────────────────────────────────
wss.on('connection', (ws, req) => {
  const url = new URL(req.url, 'http://localhost');
  const routerId = url.searchParams.get('id');
  if (!routerId) { ws.close(1008,'Missing router id'); return; }
  const router = db.get('SELECT * FROM routers WHERE id=?', [routerId]);
  if (!router) { ws.close(1008,'Router not found'); return; }
  console.log(`[ssh] ${router.name} (${router.ip})`);
  const conn = new SSHClient();
  let stream = null, cols = 80, rows = 24;
  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data);
      if (msg.type==='resize') { cols=msg.cols||80; rows=msg.rows||24; if(stream) stream.setWindow(rows,cols,0,0); return; }
      if (msg.type==='data' && stream) { stream.write(msg.data); return; }
    } catch {}
    if (stream) stream.write(data);
  });
  conn.on('ready', () => {
    conn.shell({ term:'xterm-256color', cols, rows }, (err, s) => {
      if (err) { ws.send(JSON.stringify({type:'error',message:err.message})); ws.close(); return; }
      stream = s;
      stream.on('data', d => { if(ws.readyState===ws.OPEN) ws.send(d); });
      stream.stderr.on('data', d => { if(ws.readyState===ws.OPEN) ws.send(d); });
      stream.on('close', () => { ws.close(); conn.end(); });
    });
  });
  conn.on('error', err => { if(ws.readyState===ws.OPEN){ ws.send(`\r\nSSH Error: ${err.message}\r\n`); ws.close(); } });
  ws.on('close', () => { if(stream) stream.close(); conn.end(); });
  conn.connect({ host:router.ip, port:router.ssh_port||22, username:router.ssh_user||'root', password:router.ssh_pass||'', readyTimeout:8000 });
});

server.listen(PORT, () => {
  console.log(`\n✓ OpenWRT NetCtrl running at http://localhost:${PORT}`);
  console.log(`✓ WebSocket SSH at ws://localhost:${PORT}/ws/ssh`);
  console.log(`✓ Agent installer: http://localhost:${PORT}/agent/install.sh\n`);
});
