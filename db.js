// db.js — Database Setup & Schema
// Uses SQLite via better-sqlite3 (no separate DB server needed)

const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

// ── Persistent DB path resolution ─────────────────────────────────────────
// Priority:
//   1. DB_PATH env var (explicit override)
//   2. A writable /data dir → the Railway Volume mount convention. Once a
//      volume is attached at /data in the Railway dashboard, the DB lives
//      there and SURVIVES redeploys — no env var needed.
//   3. Local file next to the code (dev, or prod without a volume = EPHEMERAL)
function resolveDbPath() {
  if (process.env.DB_PATH) return process.env.DB_PATH;
  try {
    if (fs.existsSync('/data')) {
      fs.accessSync('/data', fs.constants.W_OK);
      return '/data/grand_furniture.db';
    }
  } catch (_) { /* /data not writable — fall through */ }
  return path.join(__dirname, 'grand_furniture.db');
}

const DB_PATH = resolveDbPath();
const DB_PERSISTENT = !!process.env.DB_PATH || DB_PATH.startsWith('/data');

function initializeDatabase() {
  const db = new Database(DB_PATH);

  // Enable WAL mode for better performance
  db.pragma('journal_mode = WAL');

  // ── Table 1: Raw Events ────────────────────────────────────────────────
  // Every webhook call from ManyChat stores one row here.
  // event_id: persistent unique identifier — used for DB-level idempotency (Phase 2).
  // Declared UNIQUE so a duplicate INSERT attempt is detectable before it happens.
  db.exec(`
    CREATE TABLE IF NOT EXISTS events (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      event_id      TEXT UNIQUE,
      user_id       TEXT NOT NULL,
      first_name    TEXT,
      event_type    TEXT NOT NULL,
      event_value   TEXT,
      score_delta   INTEGER DEFAULT 0,
      session_count INTEGER DEFAULT 0,
      current_score INTEGER DEFAULT 0,
      branch        TEXT,
      product_id    TEXT,
      raw_payload   TEXT,
      created_at    DATETIME DEFAULT (datetime('now'))
    )
  `);

  // ── Phase 2 Migration — add event_id to existing events table ─────────
  // ALTER TABLE fails silently if the column already exists (caught below).
  // This makes the migration safe to run on every startup against an existing DB.
  try {
    db.exec(`ALTER TABLE events ADD COLUMN event_id TEXT`);
    console.log('✅ Migration: event_id column added to events table');
  } catch (e) {
    if (!e.message.includes('duplicate column name')) throw e;
  }

  // ── Category Migration — per-event product category ───────────────────
  // Stores the furniture category (غرف النوم / السفرة / الانتريهات / الأطفال)
  // on EVERY product_details & category_request event so analytics can break
  // demand down per category instead of mixing all products together.
  try {
    db.exec(`ALTER TABLE events ADD COLUMN category TEXT`);
    console.log('✅ Migration: category column added to events table');
  } catch (e) {
    if (!e.message.includes('duplicate column name')) throw e;
  }
  // Composite index powers the per-user "already scored this product/category"
  // dedup lookups in POST /api/events without a full table scan.
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_events_user_type_prod
      ON events(user_id, event_type, product_id);
    CREATE INDEX IF NOT EXISTS idx_events_user_type_cat
      ON events(user_id, event_type, category);
    CREATE INDEX IF NOT EXISTS idx_events_category
      ON events(category);
  `);

  // ── Table 2: Lead Profiles ─────────────────────────────────────────────
  // One row per user — updated on every event.
  // visit_at: timestamp of the first confirmed showroom visit (Phase 3).
  db.exec(`
    CREATE TABLE IF NOT EXISTS lead_profiles (
      user_id            TEXT PRIMARY KEY,
      first_name         TEXT,
      total_score        INTEGER DEFAULT 0,
      lead_class         TEXT DEFAULT 'cold',
      preferred_branch   TEXT,
      last_product       TEXT,
      product_view_count INTEGER DEFAULT 0,
      session_count      INTEGER DEFAULT 0,
      visit_confirmed    INTEGER DEFAULT 0,
      location_requested INTEGER DEFAULT 0,
      visit_at           DATETIME,
      last_activity      DATETIME DEFAULT (datetime('now')),
      created_at         DATETIME DEFAULT (datetime('now'))
    )
  `);

  // ── Phase 3 Migration — add visit_at to existing lead_profiles table ───
  // Same safe try/catch pattern as the event_id migration above.
  // Existing rows get NULL — correct, as they have not confirmed a visit.
  try {
    db.exec(`ALTER TABLE lead_profiles ADD COLUMN visit_at DATETIME`);
    console.log('✅ Migration: visit_at column added to lead_profiles table');
  } catch (e) {
    if (!e.message.includes('duplicate column name')) throw e;
  }

  // ── Indexes for fast dashboard queries ────────────────────────────────
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_events_user_id    ON events(user_id);
    CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
    CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);
    CREATE INDEX IF NOT EXISTS idx_leads_lead_class  ON lead_profiles(lead_class);
    CREATE INDEX IF NOT EXISTS idx_leads_branch      ON lead_profiles(preferred_branch);
  `);

  // ── Phase 2: Unique index on event_id ─────────────────────────────────
  // Partial WHERE event_id IS NOT NULL ensures existing NULL rows (from
  // the ALTER TABLE path) are excluded — avoids false UNIQUE violations.
  db.exec(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_events_event_id ON events(event_id)
    WHERE event_id IS NOT NULL
  `);

  // ── Phase 3: Index on visit_at for fast visit metric queries ──────────
  // Used by visits_today and visits_this_week dashboard queries.
  // Partial WHERE visit_at IS NOT NULL skips the majority of rows that
  // have never confirmed a visit, keeping the index tight.
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_leads_visit_at ON lead_profiles(visit_at)
    WHERE visit_at IS NOT NULL
  `);

  // ── RBAC: assigned_rep migration ─────────────────────────────────────────
  // Stores the name of the sales rep this lead is assigned to.
  // NULL = unassigned (admin sees all; reps only see their assigned leads).
  try {
    db.exec(`ALTER TABLE lead_profiles ADD COLUMN assigned_rep TEXT`);
    console.log('✅ Migration: assigned_rep column added to lead_profiles');
  } catch (e) {
    if (!e.message.includes('duplicate column name')) throw e;
  }

  // ── O2O Attribution Migrations ────────────────────────────────────────────
  // campaign_source: which Meta/ManyChat campaign brought this lead
  // ad_id:           specific ad creative ID for deeper ROI analysis
  // visit_code:      short unique code the receptionist enters to confirm arrival
  // purchased_at:    timestamp of first recorded offline purchase
  const o2oColumns = [
    { col: 'campaign_source',         type: 'TEXT'     },
    { col: 'ad_id',                   type: 'TEXT'     },
    { col: 'visit_code',              type: 'TEXT'     },
    { col: 'purchased_at',            type: 'DATETIME' },
    { col: 'location_reminder_sent',  type: 'DATETIME' },
    { col: 'last_category',           type: 'TEXT'     }, // product category from ManyChat
    { col: 'phone',                   type: 'TEXT'     }, // normalized phone → reception lookup
  ];
  for (const { col, type } of o2oColumns) {
    try {
      db.exec(`ALTER TABLE lead_profiles ADD COLUMN ${col} ${type}`);
      console.log(`✅ Migration: ${col} column added to lead_profiles`);
    } catch (e) {
      if (!e.message.includes('duplicate column name')) throw e;
    }
  }

  // Unique partial index on visit_code — skips NULLs so old rows are unaffected
  db.exec(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_lead_profiles_visit_code
    ON lead_profiles(visit_code)
    WHERE visit_code IS NOT NULL
  `);

  // Non-unique index on phone — reception looks leads up by phone. NOT unique
  // because two FB users could share a phone (family); we match the most recent.
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_lead_profiles_phone
    ON lead_profiles(phone)
    WHERE phone IS NOT NULL
  `);

  // purchases: one row per offline sale, linked by user_id
  db.exec(`
    CREATE TABLE IF NOT EXISTS purchases (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id     TEXT NOT NULL,
      product_id  TEXT,
      price       REAL,
      branch      TEXT,
      notes       TEXT,
      rep         TEXT,
      created_at  DATETIME NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_purchases_user    ON purchases(user_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_purchases_product ON purchases(product_id);
  `);

  // ── Intelligence layer — additive tables ─────────────────────────────────
  // messages_sent: every ManyChat flow we trigger is recorded here for audit
  // and to drive the weekly send counter. Joined back to lead_profiles by user_id.
  db.exec(`
    CREATE TABLE IF NOT EXISTS messages_sent (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id      TEXT NOT NULL,
      sent_by_rep  TEXT,
      action_type  TEXT NOT NULL,
      flow_id      TEXT,
      message_text TEXT,
      sent_at      DATETIME NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_messages_sent_user ON messages_sent(user_id, sent_at DESC);
  `);

  // tasks: rep follow-up reminders. due_at is a plain YYYY-MM-DD (showroom
  // reps think in days, not timestamps). status: 'pending' | 'done'.
  db.exec(`
    CREATE TABLE IF NOT EXISTS tasks (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      lead_id      TEXT NOT NULL,
      lead_name    TEXT,
      rep_name     TEXT NOT NULL,
      due_at       TEXT NOT NULL,
      note         TEXT,
      source       TEXT NOT NULL DEFAULT 'manual',
      status       TEXT NOT NULL DEFAULT 'pending',
      created_at   DATETIME NOT NULL DEFAULT (datetime('now')),
      completed_at DATETIME
    );
    CREATE INDEX IF NOT EXISTS idx_tasks_rep    ON tasks(rep_name, status, due_at);
    CREATE INDEX IF NOT EXISTS idx_tasks_lead   ON tasks(lead_id);
  `);

  // lead_phones: EVERY phone a customer ever gave (they may have several, or
  // re-enter a different one). Never overwritten — reception can match ANY.
  db.exec(`
    CREATE TABLE IF NOT EXISTS lead_phones (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    TEXT NOT NULL,
      phone      TEXT NOT NULL,
      created_at DATETIME NOT NULL DEFAULT (datetime('now')),
      UNIQUE(user_id, phone)
    );
    CREATE INDEX IF NOT EXISTS idx_lead_phones_phone ON lead_phones(phone);
    CREATE INDEX IF NOT EXISTS idx_lead_phones_user  ON lead_phones(user_id);
  `);

  // lead_visits: one row per branch the customer actually visited. Visiting
  // فيصل then later picking حلوان must NOT erase the فيصل visit.
  db.exec(`
    CREATE TABLE IF NOT EXISTS lead_visits (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    TEXT NOT NULL,
      branch     TEXT,
      visited_at DATETIME NOT NULL DEFAULT (datetime('now')),
      UNIQUE(user_id, branch)
    );
    CREATE INDEX IF NOT EXISTS idx_lead_visits_user ON lead_visits(user_id);
  `);

  // sales_rep — the showroom salesperson reception attached to this visit
  try {
    db.exec(`ALTER TABLE lead_visits ADD COLUMN sales_rep TEXT`);
    console.log('✅ Migration: sales_rep column added to lead_visits');
  } catch (e) {
    if (!e.message.includes('duplicate column name')) throw e;
  }
  db.exec(`CREATE INDEX IF NOT EXISTS idx_lead_visits_sales ON lead_visits(sales_rep)`);

  // branch_customer_followups: tracks whether a branch manager has followed up
  // with a specific customer. One row per (branch, user_id) pair.
  db.exec(`
    CREATE TABLE IF NOT EXISTS branch_customer_followups (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      branch        TEXT NOT NULL,
      user_id       TEXT NOT NULL,
      followed_up   INTEGER NOT NULL DEFAULT 0,
      followed_up_at DATETIME,
      followed_up_by TEXT,
      UNIQUE(branch, user_id)
    );
    CREATE INDEX IF NOT EXISTS idx_bcf_branch ON branch_customer_followups(branch);
  `);

  // follow_up_state: per-lead weekly send counter.
  // week_anchor is the ISO date of the Monday the counter belongs to;
  // the scheduler resets sends_this_week to 0 when week_anchor < this week's Monday.
  db.exec(`
    CREATE TABLE IF NOT EXISTS follow_up_state (
      user_id          TEXT PRIMARY KEY,
      sends_this_week  INTEGER NOT NULL DEFAULT 0,
      week_anchor      TEXT,
      last_sent_at     DATETIME
    );
  `);

  // ── Users & Settings (auth layer) ────────────────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      name          TEXT NOT NULL,
      email         TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role          TEXT NOT NULL DEFAULT 'rep',
      created_at    TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS settings (
      key        TEXT PRIMARY KEY,
      value      TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  // users.branch — which branch a "reception" account belongs to
  // (NULL for admin/rep). Migration is idempotent.
  try {
    db.exec(`ALTER TABLE users ADD COLUMN branch TEXT`);
    console.log('✅ Migration: branch column added to users');
  } catch (e) {
    if (!e.message.includes('duplicate column name')) throw e;
  }

  // New performance indexes
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_events_type_date ON events(event_type, created_at);
    CREATE INDEX IF NOT EXISTS idx_purchases_created ON purchases(created_at);
    CREATE INDEX IF NOT EXISTS idx_events_branch_type ON events(branch, event_type);
  `);

  // ── Seed default admin (idempotent) ───────────────────────────────────────
  const existingAdmin = db.prepare(`SELECT id FROM users WHERE email = ?`)
    .get('admin@grandfurniture.eg');
  if (!existingAdmin) {
    db.prepare(
      `INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)`
    ).run('مدير النظام', 'admin@grandfurniture.eg', bcrypt.hashSync('Grand@2025', 10), 'admin');
    console.log('✅ Seed: admin user created');
  }

  // ── Seed default settings (idempotent) ────────────────────────────────────
  const defaultSettings = [
    ['company_name',           'Grand Furniture'],
    ['active_branches',        '[{"id":"nasr_city","name":"نصر سيتي"},{"id":"maadi","name":"المعادي"},{"id":"new_cairo","name":"القاهرة الجديدة"},{"id":"october","name":"أكتوبر"},{"id":"alexandria","name":"الإسكندرية"}]'],
    ['weekly_message_limit',   '2'],
    ['manychat_api_key',           ''],
    ['manychat_page_id',           ''],
    // Event-triggered flows (fired automatically on lead state changes)
    ['manychat_visit_flow',        ''],
    ['manychat_purchase_flow',     ''],
    ['manychat_reminder_flow',     ''],
    // Intelligent trigger flows (fired by /api/trigger-message decision engine)
    ['manychat_flow_immediate',    ''],   // hot lead — active in last 6 hours
    ['manychat_flow_branch_info',  ''],   // confirmed visit or location request
    ['manychat_flow_offer',        ''],   // recent product_details event
    ['manychat_flow_reengage',     ''],   // warm/hot lead inactive ≥ 3 days
    ['openai_api_key',             ''],
    ['facebook_pixel_id',      ''],
    ['scoring_hot_threshold',  '40'],
    ['scoring_warm_threshold', '15'],
    ['lead_expiry_days',       '30'],
    // Webhook security — secret is auto-generated below; enforcement is opt-in
    // so existing ManyChat setups don't break the moment this ships.
    ['webhook_enforce',        'false'],
    // Auto-assign a lead to the least-loaded rep when it first turns warm.
    ['auto_assign_enabled',    'true'],
  ];
  const insertSetting = db.prepare(
    `INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)`
  );
  for (const [key, value] of defaultSettings) {
    insertSetting.run(key, value);
  }

  // Auto-generate a strong webhook secret once (free, no env var needed).
  // Shown read-only in the dashboard so the admin can paste it into ManyChat.
  const whRow = db.prepare(`SELECT value FROM settings WHERE key = 'webhook_secret'`).get();
  if (!whRow || !whRow.value) {
    const wh = crypto.randomBytes(24).toString('hex');
    db.prepare(`
      INSERT INTO settings (key, value, updated_at)
      VALUES ('webhook_secret', ?, datetime('now'))
      ON CONFLICT(key) DO UPDATE SET value = excluded.value
    `).run(wh);
    console.log('🔐 Generated webhook secret (stored in settings)');
  }

  // ── Migrate active_branches: string[] → {id,name}[] ──────────────────────
  // Old format was '["nasr_city","maadi",...]'. Upgrade to [{id,name}] objects.
  const branchFallbackNames = {
    nasr_city:  'نصر سيتي',
    maadi:      'المعادي',
    new_cairo:  'القاهرة الجديدة',
    october:    'أكتوبر',
    alexandria: 'الإسكندرية',
    helwan:     'حلوان',
    faisal:     'فيصل',
    ain_shams:  'عين شمس',
  };
  const branchRow = db.prepare(`SELECT value FROM settings WHERE key = 'active_branches'`).get();
  if (branchRow) {
    try {
      const parsed = JSON.parse(branchRow.value);
      // If first element is a string, it's the old format — upgrade it
      if (Array.isArray(parsed) && parsed.length > 0 && typeof parsed[0] === 'string') {
        const upgraded = parsed.map(id => ({
          id,
          name: branchFallbackNames[id] || id,
        }));
        db.prepare(
          `UPDATE settings SET value = ?, updated_at = datetime('now') WHERE key = 'active_branches'`
        ).run(JSON.stringify(upgraded));
        console.log('✅ Migrated active_branches to {id,name}[] format');
      }
    } catch (_) {}
  }

  console.log('✅ Database initialized at:', DB_PATH);
  if (DB_PERSISTENT) {
    console.log('💾 Storage: PERSISTENT — data survives redeploys ✅');
  } else {
    console.warn('⚠️  Storage: EPHEMERAL — data is WIPED on every redeploy.');
    console.warn('⚠️  Fix (free): Railway → service → Variables/Volumes → add a Volume mounted at /data, then redeploy.');
  }
  return db;
}

// Singleton pattern — same DB instance across app
let dbInstance = null;

function getDb() {
  if (!dbInstance) {
    dbInstance = initializeDatabase();
  }
  return dbInstance;
}

module.exports = { getDb };
