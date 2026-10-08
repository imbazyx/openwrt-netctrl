const Database = require('better-sqlite3');
const path = require('path');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'netctrl.db');
const db = new Database(DB_PATH);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS routers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    ip          TEXT NOT NULL UNIQUE,
    location    TEXT DEFAULT '',
    model       TEXT DEFAULT '',
    firmware    TEXT DEFAULT '',
    mac         TEXT DEFAULT '',
    tags        TEXT DEFAULT '[]',
    ssh_user    TEXT DEFAULT 'root',
    ssh_pass    TEXT DEFAULT '',
    ssh_port    INTEGER DEFAULT 22,
    status      TEXT DEFAULT 'unknown',
    cpu         REAL DEFAULT 0,
    ram         REAL DEFAULT 0,
    clients     INTEGER DEFAULT 0,
    uptime_sec  INTEGER DEFAULT 0,
    load        TEXT DEFAULT '',
    lat         REAL DEFAULT NULL,
    lng         REAL DEFAULT NULL,
    group_id    INTEGER DEFAULT NULL,
    agent_key   TEXT DEFAULT NULL,
    last_seen   TEXT,
    created_at  TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS metrics_history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    router_id  INTEGER NOT NULL,
    cpu        REAL DEFAULT 0,
    ram        REAL DEFAULT 0,
    clients    INTEGER DEFAULT 0,
    recorded_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (router_id) REFERENCES routers(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    router_id  INTEGER,
    router_name TEXT DEFAULT '',
    type       TEXT NOT NULL,
    message    TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS snapshots (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    router_id  INTEGER NOT NULL,
    router_name TEXT DEFAULT '',
    label      TEXT DEFAULT '',
    content    TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (router_id) REFERENCES routers(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS groups (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    city       TEXT DEFAULT '',
    lat        REAL DEFAULT NULL,
    lng        REAL DEFAULT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT DEFAULT ''
  );

  CREATE TABLE IF NOT EXISTS update_history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    router_id  INTEGER,
    router_name TEXT DEFAULT '',
    action     TEXT NOT NULL,
    from_ver   TEXT DEFAULT '',
    to_ver     TEXT DEFAULT '',
    status     TEXT DEFAULT 'ok',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_metrics_router ON metrics_history(router_id, recorded_at);
  CREATE INDEX IF NOT EXISTS idx_events_router  ON events(router_id, created_at);
`);

// Миграции для баз, созданных прошлыми версиями
const cols = new Set(db.prepare('PRAGMA table_info(routers)').all().map(c => c.name));
if (!cols.has('agent_key')) db.exec('ALTER TABLE routers ADD COLUMN agent_key TEXT DEFAULT NULL');

// Default settings
const defaults = {
  auth_enabled:      '1',
  admin_password:    'admin',
  app_name:          'OpenWRT NetCtrl',
  theme:             'dark',
  language:          'ru',
  telegram_token:    '',
  telegram_chat_id:  '',
  heartbeat_interval:'30',
  offline_timeout:   '120',
  grid_columns:      '3',
  backup_interval:   'weekly',
  agent_key:         '',
  auth_token:        require('crypto').randomBytes(32).toString('hex'),
};
const insSet = db.prepare('INSERT OR IGNORE INTO settings (key,value) VALUES (?,?)');
Object.entries(defaults).forEach(([k,v]) => insSet.run(k,v));

// Default groups for Taganrog
const gc = db.prepare('SELECT COUNT(*) as n FROM groups').get();
if (gc.n === 0) {
  db.prepare('INSERT INTO groups (name,city,lat,lng) VALUES (?,?,?,?)').run('Таганрог', 'Таганрог', 47.2083, 38.8869);
  db.prepare('INSERT INTO groups (name,city,lat,lng) VALUES (?,?,?,?)').run('Неклиновский р-н', 'Таганрог', 47.15, 38.75);
  db.prepare('INSERT INTO groups (name,city,lat,lng) VALUES (?,?,?,?)').run('Матвеев-Курган', 'Матвеев-Курган', 47.57, 38.85);
}

module.exports = {
  all:  (sql, p=[]) => db.prepare(sql).all(...p),
  get:  (sql, p=[]) => db.prepare(sql).get(...p),
  run:  (sql, p=[]) => { const r = db.prepare(sql).run(...p); return r.lastInsertRowid; },
  setting: (key) => { const r = db.prepare('SELECT value FROM settings WHERE key=?').get(key); return r ? r.value : null; },
  // better-sqlite3 падает на object/array/undefined — приводим к строке на границе
  setSetting: (key, value) => {
    const v = (value === null || value === undefined) ? '' : (typeof value === 'object' ? JSON.stringify(value) : String(value));
    return db.prepare('INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)').run(key, v);
  },
};
