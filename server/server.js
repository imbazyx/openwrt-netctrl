const express  = require('express');
const { WebSocketServer } = require('ws');
const { Client: SSHClient } = require('ssh2');
const { createProxyMiddleware } = require('http-proxy-middleware');
const http    = require('http');
const path    = require('path');
const fs      = require('fs');
const crypto  = require('crypto');
const db      = require('./db');

const PORT = process.env.PORT || 3000;
const app  = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});
// Клиент лежит рядом с server/ в репозитории, но Dockerfile кладёт его в server/client
const CLIENT_DIR = [
  path.join(__dirname, '..', 'client'),
  path.join(__dirname, 'client'),
].find(p => fs.existsSync(path.join(p, 'index.html'))) || path.join(__dirname, '..', 'client');
app.use(express.static(CLIENT_DIR));

// ─── Auth middleware ──────────────────────────────────────────────────────────
const safeEqual = (a, b) => {
  const ba = Buffer.from(String(a || ''), 'utf8');
  const bb = Buffer.from(String(b || ''), 'utf8');
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
};

function authEnabled() { return db.setting('auth_enabled') === '1'; }

function authMiddleware(req, res, next) {
  if (!authEnabled()) return next();
  const token = req.headers['x-auth-token'];
  if (safeEqual(token, db.setting('auth_token'))) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

// Токен в query убран намеренно: он утекает в логи, историю и Referer.
// WebSocket браузеру не умеет слать заголовки — там query остаётся.

// Опциональныйfleet-wide секрет для /register: пусто = открыто (типичная LAN),
// задать → никто чужой не зарегистрирует роутер в панели.
function agentAuth(req, res, next) {
  const key = db.setting('agent_key');
  if (!key) return next();
  if (safeEqual(req.headers['x-agent-key'], key)) return next();
  res.status(401).json({ error: 'bad agent key' });
}

// ─── Rate limit (in-memory) ───────────────────────────────────────────────────
const buckets = new Map();
function rateLimit({ windowMs, max, key = req => req.ip }) {
  return (req, res, next) => {
    const k = key(req);
    const now = Date.now();
    const hits = (buckets.get(k) || []).filter(t => now - t < windowMs);
    if (hits.length >= max) return res.status(429).json({ error: 'Too many requests' });
    hits.push(now);
    buckets.set(k, hits);
    if (buckets.size > 5000) for (const [bk, v] of buckets) if (!v.some(t => now - t < windowMs)) buckets.delete(bk);
    next();
  };
}

// ─── Telegram helper ──────────────────────────────────────────────────────────
const escapeHtml = s => String(s ?? '').replace(/[&<>"']/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

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
const SSH_EXEC_TIMEOUT_MS = +(process.env.SSH_TIMEOUT_MS || 20000);
const SSH_MAX_OUTPUT     = 256 * 1024;

function sshExec(router, command, timeoutMs = SSH_EXEC_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const conn = new SSHClient();
    let output = '';
    let settled = false;
    const done = (fn, arg) => { if (settled) return; settled = true; clearTimeout(timer); try { conn.end(); } catch {} fn(arg); };
    const timer = setTimeout(() => done(reject, new Error(`SSH timeout ${timeoutMs}ms`)), timeoutMs);

    conn.on('ready', () => {
      conn.exec(command, (err, stream) => {
        if (err) return done(reject, err);
        stream.on('data', d => { if (output.length < SSH_MAX_OUTPUT) output += d.toString(); });
        stream.stderr.on('data', d => { if (output.length < SSH_MAX_OUTPUT) output += d.toString(); });
        stream.on('close', () => done(resolve, output));
        stream.on('error', e => done(reject, e));
      });
    });
    conn.on('error', e => done(reject, e));
    conn.connect({ host: router.ip, port: router.ssh_port||22, username: router.ssh_user||'root', password: router.ssh_pass||'', readyTimeout: 8000 });
  });
}

// ─── Auth ─────────────────────────────────────────────────────────────────────
app.post('/api/auth/login', rateLimit({ windowMs: 60_000, max: 10 }), (req, res) => {
  const { password } = req.body || {};
  if (safeEqual(password, db.setting('admin_password'))) {
    res.json({ ok: true, token: db.setting('auth_token') });
  } else {
    res.status(401).json({ error: 'Неверный пароль' });
  }
});

app.get('/api/auth/status', (req, res) => {
  res.json({ auth_enabled: authEnabled() });
});

// ─── Settings ─────────────────────────────────────────────────────────────────
const SETTING_DEFAULTS = {
  theme:'dark', language:'ru', grid_columns:'3', telegram_token:'', telegram_chat_id:'',
  heartbeat_interval:'30', offline_timeout:'120', backup_interval:'weekly',
  app_name:'OpenWRT NetCtrl', auth_enabled:'1', agent_key:'',
};
const SETTING_MAX_LEN = 2000;

app.get('/api/settings', authMiddleware, (req, res) => {
  const obj = {};
  db.all('SELECT key,value FROM settings').forEach(r => obj[r.key] = r.value);
  delete obj.auth_token;
  delete obj.admin_password;
  res.json(obj);
});

app.put('/api/settings', authMiddleware, (req, res) => {
  const errors = [];
  Object.entries(req.body || {}).forEach(([k, v]) => {
    if (!(k in SETTING_DEFAULTS)) return;
    // В SQLite уходит только скаляр — объекты/массивы роняли запрос 500-й ошибкой
    if (v === null || typeof v === 'object') { errors.push(`${k}: expected scalar`); return; }
    const s = String(v).slice(0, SETTING_MAX_LEN);
    if (k === 'offline_timeout' && !(parseInt(s) >= 30 && parseInt(s) <= 86400)) { errors.push('offline_timeout: 30..86400'); return; }
    if (k === 'heartbeat_interval' && !(parseInt(s) >= 10 && parseInt(s) <= 3600)) { errors.push('heartbeat_interval: 10..3600'); return; }
    if (k === 'grid_columns' && !(parseInt(s) >= 1 && parseInt(s) <= 12)) { errors.push('grid_columns: 1..12'); return; }
    db.setSetting(k, s);
  });
  if (errors.length) return res.status(400).json({ error: errors.join('; ') });
  res.json({ ok: true });
});

app.put('/api/settings/password', authMiddleware, rateLimit({ windowMs: 60_000, max: 10 }), (req, res) => {
  const { current, next } = req.body || {};
  if (!safeEqual(current, db.setting('admin_password'))) return res.status(400).json({ error: 'Неверный текущий пароль' });
  if (typeof next !== 'string' || next.length < 8) return res.status(400).json({ error: 'Пароль должен быть не короче 8 символов' });
  db.setSetting('admin_password', next);
  const newToken = crypto.randomBytes(32).toString('hex');
  db.setSetting('auth_token', newToken);
  res.json({ ok: true, token: newToken });
});

// ─── Groups ───────────────────────────────────────────────────────────────────
app.get('/api/groups', authMiddleware, (req, res) => res.json(db.all('SELECT * FROM groups ORDER BY name')));

app.post('/api/groups', authMiddleware, (req, res) => {
  const { name, city, lat, lng } = req.body || {};
  if (!name || typeof name !== 'string') return res.status(400).json({ error: 'name required' });
  const id = db.run('INSERT INTO groups (name,city,lat,lng) VALUES (?,?,?,?)', [name, city||'', lat||null, lng||null]);
  res.json({ id, name, city, lat, lng });
});

app.put('/api/groups/:id', authMiddleware, (req, res) => {
  const { name, city, lat, lng } = req.body || {};
  db.run('UPDATE groups SET name=?,city=?,lat=?,lng=? WHERE id=?', [name, city, lat, lng, req.params.id]);
  res.json({ ok: true });
});

app.delete('/api/groups/:id', authMiddleware, (req, res) => {
  db.run('UPDATE routers SET group_id=NULL WHERE group_id=?', [req.params.id]);
  db.run('DELETE FROM groups WHERE id=?', [req.params.id]);
  res.json({ ok: true });
});

// ─── Routers CRUD ─────────────────────────────────────────────────────────────
// ssh_pass никогда не отдаётся наружу: вместо него ssh_pass_set.
const publicRouter = r => { const { ssh_pass, ...rest } = r; return { ...rest, ssh_pass_set: !!ssh_pass }; };
const isIP = s => typeof s === 'string' && /^[0-9a-fA-F.:]{3,45}$/.test(s) && !s.includes(' ');

app.get('/api/routers', authMiddleware, (req, res) =>
  res.json(db.all('SELECT * FROM routers ORDER BY name').map(publicRouter)));

app.post('/api/routers', authMiddleware, (req, res) => {
  const { name, ip, location, model, tags, ssh_user, ssh_pass, ssh_port, lat, lng, group_id } = req.body || {};
  if (!name || !ip) return res.status(400).json({ error: 'name and ip required' });
  if (!isIP(ip)) return res.status(400).json({ error: 'invalid ip' });
  const id = db.run(
    `INSERT INTO routers (name,ip,location,model,tags,ssh_user,ssh_pass,ssh_port,lat,lng,group_id,status,created_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,'unknown',datetime('now'))`,
    [String(name), String(ip), location||'', model||'', JSON.stringify(tags||[]), ssh_user||'root', ssh_pass||'', ssh_port||22, lat||null, lng||null, group_id||null]
  );
  res.json({ id, name, ip, status: 'unknown' });
});

app.put('/api/routers/:id', authMiddleware, (req, res) => {
  const { name, ip, location, model, tags, ssh_user, ssh_pass, ssh_port, lat, lng, group_id } = req.body || {};
  if (ip !== undefined && !isIP(ip)) return res.status(400).json({ error: 'invalid ip' });
  const cur = db.get('SELECT * FROM routers WHERE id=?', [req.params.id]);
  if (!cur) return res.status(404).json({ error: 'not found' });
  db.run(
    `UPDATE routers SET name=?,ip=?,location=?,model=?,tags=?,ssh_user=?,ssh_pass=?,ssh_port=?,lat=?,lng=?,group_id=? WHERE id=?`,
    [name ?? cur.name, ip ?? cur.ip, location ?? '', model ?? '', JSON.stringify(tags||[]),
     ssh_user || 'root', ssh_pass || cur.ssh_pass, ssh_port || 22,
     lat ?? null, lng ?? null, group_id ?? null, req.params.id]
  );
  res.json({ ok: true });
});

app.delete('/api/routers/:id', authMiddleware, (req, res) => {
  db.run('DELETE FROM routers WHERE id=?', [req.params.id]);
  res.json({ ok: true });
});

// ─── Register & Heartbeat ─────────────────────────────────────────────────────
app.post('/api/routers/register', agentAuth, rateLimit({ windowMs: 60_000, max: 30 }), (req, res) => {
  const { name, ip, model, firmware, mac } = req.body || {};
  if (!ip || !isIP(ip)) return res.status(400).json({ error: 'ip required' });
  const existing = db.get('SELECT id,agent_key FROM routers WHERE ip=?', [ip]);
  if (existing) {
    if (!existing.agent_key) db.run('UPDATE routers SET agent_key=? WHERE id=?', [crypto.randomBytes(24).toString('hex'), existing.id]);
    return res.json({ id: existing.id, key: db.get('SELECT agent_key FROM routers WHERE id=?', [existing.id]).agent_key, registered: false });
  }
  // Свой ключ на роутер: по нему роутер шлёт heartbeat, чужим id подделать метрики нельзя
  const key = crypto.randomBytes(24).toString('hex');
  const id = db.run(
    `INSERT INTO routers (name,ip,model,firmware,mac,tags,ssh_user,ssh_port,agent_key,status,created_at)
     VALUES (?,?,?,?,?,'[]','root',22,?,'online',datetime('now'))`,
    [String(name||ip), String(ip), model||'', firmware||'', mac||'', key]
  );
  db.run(`INSERT INTO events (router_id,router_name,type,message) VALUES (?,?,?,?)`,
    [id, name||ip, 'online', `Роутер ${name||ip} зарегистрирован`]);
  console.log(`[register] ${name} (${ip})`);
  res.json({ id, key, registered: true });
});

app.post('/api/routers/:id/heartbeat', (req, res) => {
  const { cpu, ram, clients, uptime_sec, firmware, load } = req.body || {};
  const router = db.get('SELECT status,agent_key,name FROM routers WHERE id=?', [req.params.id]);
  if (!router) return res.status(404).json({ error: 'not found' });

  // Legacy-роутеры (созданные до этой версии) без ключа: принимаем один раз и выдаём ключ
  let key = router.agent_key;
  if (!key) {
    key = crypto.randomBytes(24).toString('hex');
    db.run('UPDATE routers SET agent_key=? WHERE id=?', [key, req.params.id]);
    return res.json({ ok: true, key });
  }
  if (!safeEqual(req.headers['x-router-key'], key)) {
    return res.status(401).json({ error: 'bad router key' });
  }

  const wasOffline = router.status !== 'online';
  const num = (v, max) => Math.min(Math.max(Number(v) || 0, 0), max);
  db.run(
    `UPDATE routers SET status='online',cpu=?,ram=?,clients=?,uptime_sec=?,firmware=COALESCE(?,firmware),load=?,last_seen=datetime('now') WHERE id=?`,
    [num(cpu, 100), num(ram, 100), num(clients, 10000), num(uptime_sec, 1e12), firmware || null, String(load||'').slice(0,200), req.params.id]
  );

  // Store metrics history (every heartbeat)
  db.run(`INSERT INTO metrics_history (router_id,cpu,ram,clients) VALUES (?,?,?,?)`,
    [req.params.id, num(cpu,100), num(ram,100), num(clients,10000)]);

  // Cleanup old metrics (keep 7 days)
  db.run(`DELETE FROM metrics_history WHERE router_id=? AND recorded_at < datetime('now','-7 days')`, [req.params.id]);

  if (wasOffline) {
    db.run(`INSERT INTO events (router_id,router_name,type,message) VALUES (?,?,?,?)`,
      [req.params.id, router.name, 'online', `Роутер ${router.name} снова онлайн`]);
    sendTelegram(`✅ <b>${escapeHtml(router.name)}</b> снова онлайн`);
  }

  res.json({ ok: true, interval: parseInt(db.setting('heartbeat_interval')) || 30 });
});

// ─── Actions ──────────────────────────────────────────────────────────────────
app.post('/api/routers/:id/ping', authMiddleware, async (req, res) => {
  const router = db.get('SELECT * FROM routers WHERE id=?', [req.params.id]);
  if (!router) return res.status(404).json({ error: 'not found' });
  const net = require('net'), start = Date.now();
  const socket = new net.Socket();
  let answered = false;
  const reply = (payload) => { if (answered) return; answered = true; socket.destroy(); res.json(payload); };
  socket.setTimeout(3000);
  socket.on('error', () => reply({ ok: false, ms: null }));
  socket.on('timeout', () => reply({ ok: false, ms: null }));
  socket.connect(router.ssh_port||22, router.ip, () => reply({ ok: true, ms: Date.now()-start }));
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
    rebooting: routers.filter(r=>r.status==='rebooting').length,
    unknown: routers.filter(r=>r.status==='unknown').length,
    totalClients, avgCpu, avgRam,
    highCpu: highCpu.map(r=>r.name),
    highRam: highRam.map(r=>r.name),
  });
});

// ─── Metrics history for charts ───────────────────────────────────────────────
const clamp = (v, lo, hi, dflt) => { const n = parseInt(v, 10); return Number.isFinite(n) ? Math.min(Math.max(n, lo), hi) : dflt; };

app.get('/api/metrics/:id', authMiddleware, (req, res) => {
  const hours = clamp(req.query.hours, 1, 24*30, 24);
  const rows = db.all(
    `SELECT cpu,ram,clients,recorded_at FROM metrics_history
     WHERE router_id=? AND recorded_at > datetime('now','-${hours} hours')
     ORDER BY recorded_at ASC LIMIT 2000`,
    [req.params.id]
  );
  res.json(rows);
});

// ─── Events ───────────────────────────────────────────────────────────────────
app.get('/api/events', authMiddleware, (req, res) => {
  const limit = clamp(req.query.limit, 1, 1000, 100);
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
  const { router_ids, commands } = req.body || {};
  if (!Array.isArray(router_ids) || !router_ids.length || typeof commands !== 'string' || !commands.trim())
    return res.status(400).json({ error: 'router_ids and commands required' });
  if (commands.length > 4000) return res.status(400).json({ error: 'command too long' });
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

// Версия — из package.json, чтобы /api/system и npm-версия не расходились
const VERSION = require('./package.json').version;

// ─── System info ──────────────────────────────────────────────────────────────
app.get('/api/system', authMiddleware, (req, res) => {
  let dbSize = 0;
  try { dbSize = fs.statSync(process.env.DB_PATH || path.join(__dirname, 'netctrl.db')).size; } catch(e) {}
  res.json({
    version:  VERSION,
    name:     db.setting('app_name'),
    uptime:   Math.floor(process.uptime()),
    dbSize:   dbSize,
    routers:  db.get('SELECT COUNT(*) as n FROM routers').n,
    events:   db.get('SELECT COUNT(*) as n FROM events').n,
    snapshots:db.get('SELECT COUNT(*) as n FROM snapshots').n,
    nodeVersion: process.version,
  });
});

// Ключ, которым роутеры доказывают регистрацию. Отдаём только владельцу панели.
app.get('/api/agent-key', authMiddleware, (req, res) => {
  const key = db.setting('agent_key') || crypto.randomBytes(24).toString('hex');
  if (!db.setting('agent_key')) db.setSetting('agent_key', key);
  res.json({ agent_key: key });
});

// ─── DB Backup ────────────────────────────────────────────────────────────────
app.get('/api/backup/download', authMiddleware, (req, res) => {
  const dbPath = process.env.DB_PATH || path.join(__dirname, 'netctrl.db');
  if (!fs.existsSync(dbPath)) return res.status(404).json({ error: 'db not found' });
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
app.get('/luci-login/:id', authMiddleware, async (req, res) => {
  const router = db.get('SELECT * FROM routers WHERE id=?', [req.params.id]);
  if (!router) return res.status(404).send('Router not found');

  const luciBase = `http://${router.ip}`;
  try {
    const rpcResp = await fetch(`${luciBase}/cgi-bin/luci/rpc/auth`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: 1, method: 'login', params: [router.ssh_user || 'root', router.ssh_pass || ''] }),
      signal: AbortSignal.timeout(8000)
    });
    const rpcData = await rpcResp.json();
    const token = rpcData.result;
    if (!token || token === '0000000000000000000000000000000000000000') {
      throw new Error('Invalid token');
    }

    // LuCI этой версии принимает логин/пароль формой; значения экранируем.
    const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
      ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));
    res.setHeader('Cache-Control', 'no-store');
    res.send(`<!DOCTYPE html>
<html>
<head><title>Redirecting to LuCI...</title></head>
<body>
  <form id="luciForm" method="post" action="${esc(luciBase)}/cgi-bin/luci/">
    <input type="hidden" name="luci_username" value="${esc(router.ssh_user || 'root')}">
    <input type="hidden" name="luci_password" value="${esc(router.ssh_pass || '')}">
    <input type="hidden" name="auth" value="${esc(token)}">
  </form>
  <script>document.getElementById('luciForm').submit();</script>
</body>
</html>`);
  } catch (e) {
    console.error('[luci-login]', e.message);
    res.redirect(`${luciBase}/cgi-bin/luci/`);
  }
});

// ─── LuCI Proxy ───────────────────────────────────────────────────────────────
app.use('/proxy/:id', authMiddleware, (req, res, next) => {
  const router = db.get('SELECT * FROM routers WHERE id=?', [req.params.id]);
  if (!router) return res.status(404).send('Router not found');
  const proxy = createProxyMiddleware({
    target: `http://${router.ip}`,
    changeOrigin: true,
    followRedirects: true,
    proxyTimeout: 20000,
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
app.get('/agent/install.sh', authMiddleware, (req, res) => {
  const serverUrl = `http://${req.hostname}:${PORT}`;
  const agentKey  = db.setting('agent_key') || '';
  res.setHeader('Content-Type', 'text/plain');
  // Хост в shell-скрипт подставляется как есть — это наш собственный Host.
  res.send(`#!/bin/sh
# NetCtrl agent installer
SERVER="${serverUrl}"
AGENT_KEY="${agentKey}"
[ -z "$AGENT_KEY" ] && { echo "agent_key is empty in panel settings; run 'Generate' first"; exit 1; }
AGENT_FILE="/usr/bin/netctrl-agent"
INIT_FILE="/etc/init.d/netctrl"

wget -O "$AGENT_FILE" "$SERVER/agent/netctrl-agent.sh" || { echo "download failed"; exit 1; }
chmod +x "$AGENT_FILE"

cat > "$INIT_FILE" <<EOF
#!/bin/sh /etc/rc.common
START=99
USE_PROCD=1
PROG=$AGENT_FILE
EXTRA_ARGS="server=$SERVER key=$AGENT_KEY"
start() {
  procd_open_instance
  procd_set_param command $AGENT_FILE "\\$EXTRA_ARGS"
  procd_set_param respawn
  procd_set_param stderr 1
  procd_close_instance
}
stop() { killall $(basename $AGENT_FILE); }
EOF
chmod +x "$INIT_FILE"
/etc/init.d/netctrl enable
/etc/init.d/netctrl restart
echo "NetCtrl agent installed and started. Server: $SERVER"
`);
});
app.get('/agent/netctrl-agent.sh', (req, res) => res.sendFile(path.join(__dirname, '../agent/netctrl-agent.sh')));

// ─── SPA fallback ─────────────────────────────────────────────────────────────
// Только для навигации панели: неизвестный /api/* обязан отдавать JSON 404,
// иначе клиенты молча парсят HTML.
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(CLIENT_DIR, 'index.html'), err => err && next(err));
});
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// ─── Error handler: наружу не отдаём стек-трейсы (обязан быть последним) ───────
app.use((err, req, res, next) => {
  console.error('[error]', req.method, req.path, err.message);
  if (res.headersSent) return next(err);
  const duplicate = String(err.code || '').startsWith('SQLITE_CONSTRAINT');
  const code = duplicate ? 409 : (err.status || err.statusCode || 500);
  res.status(code).json({ error: code === 500 ? 'Внутренняя ошибка сервера' : err.message });
});

// ─── HTTP + WebSocket ─────────────────────────────────────────────────────────
const server = http.createServer(app);
const wss    = new WebSocketServer({ noServer: true, maxPayload: 256 * 1024 });

// Токен проверяется на этапе upgrade: неавторизованный клиент получает 401
// в рукопожатии, а не «открытое» соединение, которое закроется через мгновение.
// Браузер не умеет слать заголовки в WS, поэтому токен приходит в query.
server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname !== '/ws/ssh') return socket.destroy();
  if (authEnabled() && !safeEqual(url.searchParams.get('token'), db.setting('auth_token'))) {
    socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    return socket.destroy();
  }
  wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws, req));
});

// Offline checker. 'rebooting' тоже должен уходить в offline — иначе роутер
//, который не перезагрузился, навсегда остаётся в статусе 'rebooting'.
setInterval(() => {
  const timeout = clamp(db.setting('offline_timeout'), 30, 86400, 120);
  const rows = db.all(
    `SELECT id,name FROM routers WHERE status IN ('online','rebooting')
     AND (last_seen IS NULL OR last_seen < datetime('now','-${timeout} seconds'))`
  );
  rows.forEach(r => {
    db.run(`UPDATE routers SET status='offline' WHERE id=?`, [r.id]);
    db.run(`INSERT INTO events (router_id,router_name,type,message) VALUES (?,?,?,?)`,
      [r.id, r.name, 'offline', `Роутер ${r.name} недоступен`]);
    sendTelegram(`🔴 <b>${escapeHtml(r.name)}</b> недоступен`);
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
