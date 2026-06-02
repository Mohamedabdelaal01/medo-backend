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

function initializeDatabase(dbPath = DB_PATH) {
  const db = new Database(dbPath);

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

  // ── ManyChat enrichment columns ────────────────────────────────────────
  // These hold the extra profile fields ManyChat can attach to events
  // (some are already sent, others become available once the admin adds
  // them to the External Request payload — see ManyChat setup guide).
  for (const col of [
    `last_name        TEXT`,
    `gender           TEXT`,
    `locale           TEXT`,
    `timezone         TEXT`,
    `last_input_text  TEXT`,
    `subscribed_at    DATETIME`,
    `growth_tool_id   TEXT`,
    `manychat_source  TEXT`,   // 'manychat' channel marker
    `extra_fields     TEXT`,   // JSON dump of anything new ManyChat sends
  ]) {
    try {
      db.exec(`ALTER TABLE lead_profiles ADD COLUMN ${col}`);
    } catch (e) {
      if (!e.message.includes('duplicate column name')) throw e;
    }
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
    // Re-visit follow-up — for customers who visited but did NOT buy.
    { col: 'revisit_status',          type: 'TEXT'     }, // NULL=pending re-followup, 'lost'=closed
    { col: 'revisit_note',            type: 'TEXT'     }, // free-text reason when closed
    { col: 'revisit_updated_by',      type: 'TEXT'     },
    { col: 'revisit_updated_at',      type: 'DATETIME' },
    // platform: which ManyChat channel the lead first contacted us on
    // ('instagram' | 'facebook'). Set once on first event and preserved.
    { col: 'platform',                type: 'TEXT'     },
  ];
  for (const { col, type } of o2oColumns) {
    try {
      db.exec(`ALTER TABLE lead_profiles ADD COLUMN ${col} ${type}`);
      console.log(`✅ Migration: ${col} column added to lead_profiles`);
    } catch (e) {
      if (!e.message.includes('duplicate column name')) throw e;
    }
  }

  // ── One-time backfill: existing leads predate the Instagram flow, so all
  // historic ManyChat leads came from Facebook. Idempotent — only fills NULLs.
  // Walk-ins (manychat_source = 'walkin') are skipped so they stay platform-less.
  const backfill = db.prepare(`
    UPDATE lead_profiles
    SET    platform = 'facebook'
    WHERE  platform IS NULL
      AND  (manychat_source IS NULL OR manychat_source != 'walkin')
  `).run();
  if (backfill.changes > 0) {
    console.log(`✅ Backfill: ${backfill.changes} legacy leads marked as platform='facebook'`);
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

  // purchases.contract_number — the paper/contract reference for the sale.
  try {
    db.exec(`ALTER TABLE purchases ADD COLUMN contract_number TEXT`);
    console.log('✅ Migration: contract_number column added to purchases');
  } catch (e) {
    if (!e.message.includes('duplicate column name')) throw e;
  }

  // ── Product catalog — categories + products + per-purchase line items ────
  // The catalog is admin/branch-manager managed. Sales reps pick from it when
  // recording a purchase. A single contract can include multiple products, so
  // purchase_items is a many-to-many join between purchases and products.
  db.exec(`
    CREATE TABLE IF NOT EXISTS product_categories (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      name        TEXT NOT NULL,
      sort_order  INTEGER NOT NULL DEFAULT 0,
      active      INTEGER NOT NULL DEFAULT 1,
      created_at  DATETIME NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS products (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      category_id  INTEGER NOT NULL,
      name         TEXT NOT NULL,
      active       INTEGER NOT NULL DEFAULT 1,
      created_at   DATETIME NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (category_id) REFERENCES product_categories(id)
    );
    CREATE INDEX IF NOT EXISTS idx_products_category ON products(category_id);

    CREATE TABLE IF NOT EXISTS purchase_items (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      purchase_id   INTEGER NOT NULL,
      product_id    INTEGER NOT NULL,
      created_at    DATETIME NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (purchase_id) REFERENCES purchases(id) ON DELETE CASCADE,
      FOREIGN KEY (product_id)  REFERENCES products(id)
    );
    CREATE INDEX IF NOT EXISTS idx_purchase_items_purchase ON purchase_items(purchase_id);
    CREATE INDEX IF NOT EXISTS idx_purchase_items_product  ON purchase_items(product_id);
  `);

  // ── One-time seed: backfill catalog from historical events ───────────────
  // The events table has been tracking (category, event_value=product name)
  // pairs from ManyChat product views for months — that's the merchant's
  // implicit catalog. Hydrate the new explicit tables from it on first run
  // so the admin doesn't have to retype everything. Idempotent: only inserts
  // names that aren't already there.
  const catalogIsEmpty = db.prepare(`SELECT COUNT(*) AS n FROM product_categories`).get().n === 0;
  if (catalogIsEmpty) {
    const distinctCats = db.prepare(`
      SELECT category, COUNT(*) AS n
      FROM events
      WHERE event_type IN ('product_details', 'category_request')
        AND category IS NOT NULL AND category != ''
      GROUP BY category
      ORDER BY n DESC
    `).all();

    const seed = db.transaction(() => {
      const insertCat = db.prepare(`
        INSERT INTO product_categories (name, sort_order) VALUES (?, ?)
      `);
      const insertProd = db.prepare(`
        INSERT INTO products (category_id, name) VALUES (?, ?)
      `);

      let totalCats = 0, totalProducts = 0;
      let sortOrder = 0;
      for (const { category } of distinctCats) {
        const catResult = insertCat.run(category, sortOrder++);
        totalCats++;
        const catId = catResult.lastInsertRowid;

        const products = db.prepare(`
          SELECT event_value, COUNT(*) AS n
          FROM events
          WHERE event_type = 'product_details'
            AND category = ?
            AND event_value IS NOT NULL AND event_value != ''
          GROUP BY event_value
          ORDER BY n DESC
        `).all(category);

        for (const { event_value } of products) {
          insertProd.run(catId, event_value);
          totalProducts++;
        }
      }
      return { totalCats, totalProducts };
    });

    const { totalCats, totalProducts } = seed();
    if (totalCats > 0) {
      console.log(`✅ Catalog seed: ${totalCats} categories + ${totalProducts} products imported from events history`);
    }
  }

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

  // pre_visit_rep — the rep who followed the lead up ONLINE before the visit
  // (may differ from sales_rep, the showroom rep who actually served them).
  try {
    db.exec(`ALTER TABLE lead_visits ADD COLUMN pre_visit_rep TEXT`);
    console.log('✅ Migration: pre_visit_rep column added to lead_visits');
  } catch (e) {
    if (!e.message.includes('duplicate column name')) throw e;
  }
  db.exec(`CREATE INDEX IF NOT EXISTS idx_lead_visits_prerep ON lead_visits(pre_visit_rep)`);

  // branch_customer_followups: live follow-up state per (branch, user_id).
  // The branch manager assigns the customer to a sales rep; that sales rep
  // (or the manager) then marks the follow-up done and writes a call summary.
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

  // Assignment + call-summary columns (idempotent migration).
  // assigned_sales: the sales rep the manager handed this customer to.
  // auto_assigned : 1 → reception auto-assigned (the rep stood with the customer
  //                 in the showroom before the manager distributed). 0 → manual.
  for (const { col, type } of [
    { col: 'assigned_sales', type: 'TEXT'                       },
    { col: 'assigned_at',    type: 'DATETIME'                   },
    { col: 'assigned_by',    type: 'TEXT'                       },
    { col: 'call_summary',   type: 'TEXT'                       },
    { col: 'auto_assigned',  type: 'INTEGER NOT NULL DEFAULT 0' },
    // sent: the rep ticked "بعت" — they sent the first outreach message (e.g.
    // WhatsApp) to this customer. A lightweight step BEFORE a full "تابعت", so
    // the rep can see who they've already messaged vs not. Distinct from followed_up.
    { col: 'sent',           type: 'INTEGER NOT NULL DEFAULT 0' },
    { col: 'sent_at',        type: 'DATETIME'                   },
  ]) {
    try {
      db.exec(`ALTER TABLE branch_customer_followups ADD COLUMN ${col} ${type}`);
      console.log(`✅ Migration: ${col} added to branch_customer_followups`);
    } catch (e) {
      if (!e.message.includes('duplicate column name')) throw e;
    }
  }
  db.exec(`CREATE INDEX IF NOT EXISTS idx_bcf_assigned ON branch_customer_followups(assigned_sales)`);

  // Backfill — for any customer whose reception linked them to a sales rep
  // (lead_visits.sales_rep) but the branch manager never distributed them,
  // create a branch_customer_followups row flagged auto_assigned=1 so the
  // manager sees the auto-assignment tag instead of "مش متوزّع".
  try {
    const backfilled = db.prepare(`
      INSERT INTO branch_customer_followups
        (branch, user_id, assigned_sales, assigned_at, assigned_by, auto_assigned)
      SELECT v.branch, v.user_id, v.sales_rep,
             COALESCE(v.visited_at, datetime('now')),
             'reception_backfill', 1
      FROM lead_visits v
      WHERE v.sales_rep IS NOT NULL
        AND v.branch    IS NOT NULL
        AND NOT EXISTS (
          SELECT 1 FROM branch_customer_followups f
          WHERE f.branch = v.branch AND f.user_id = v.user_id
        )
    `).run();
    if (backfilled.changes > 0) {
      console.log(`✅ Backfill: ${backfilled.changes} reception-assigned customers auto-distributed`);
    }
  } catch (e) {
    console.warn('[backfill auto_assigned] skipped:', e.message);
  }

  // ── Backfill: heal branch-less contracts ────────────────────────────────
  // A purchase recorded without a branch is invisible to every branch manager.
  // Derive it from the rep's current branch, else the customer's latest visit
  // branch, else their preferred branch. Idempotent (only touches NULL/empty).
  try {
    const healed = db.prepare(`
      UPDATE purchases
      SET branch = COALESCE(
        (SELECT u.branch FROM users u WHERE TRIM(u.name) = TRIM(purchases.rep) AND u.branch IS NOT NULL LIMIT 1),
        (SELECT v.branch FROM lead_visits v WHERE v.user_id = purchases.user_id AND v.branch IS NOT NULL ORDER BY v.visited_at DESC LIMIT 1),
        (SELECT lp.preferred_branch FROM lead_profiles lp WHERE lp.user_id = purchases.user_id)
      )
      WHERE (branch IS NULL OR TRIM(branch) = '')
        AND COALESCE(
          (SELECT u.branch FROM users u WHERE TRIM(u.name) = TRIM(purchases.rep) AND u.branch IS NOT NULL LIMIT 1),
          (SELECT v.branch FROM lead_visits v WHERE v.user_id = purchases.user_id AND v.branch IS NOT NULL ORDER BY v.visited_at DESC LIMIT 1),
          (SELECT lp.preferred_branch FROM lead_profiles lp WHERE lp.user_id = purchases.user_id)
        ) IS NOT NULL
    `).run();
    if (healed.changes > 0) {
      console.log(`✅ Backfill: ${healed.changes} branch-less contract(s) assigned a branch`);
    }
  } catch (e) {
    console.warn('[backfill purchase branch] skipped:', e.message);
  }

  // followup_log: append-only history. One row per COMPLETED follow-up so
  // reassigning a customer to another sales rep never erases what was done
  // before — the old call summaries stay visible in the customer profile.
  db.exec(`
    CREATE TABLE IF NOT EXISTS followup_log (
      id             INTEGER PRIMARY KEY AUTOINCREMENT,
      branch         TEXT NOT NULL,
      user_id        TEXT NOT NULL,
      sales          TEXT,
      call_summary   TEXT,
      followed_up_at DATETIME NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_fulog_user ON followup_log(user_id, followed_up_at DESC);
  `);

  // revisit_followups: append-only log of re-visit follow-up attempts for
  // customers who visited but didn't buy — so we can see WHEN and HOW MANY
  // times a customer was followed up, and who did it.
  db.exec(`
    CREATE TABLE IF NOT EXISTS revisit_followups (
      id             INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id        TEXT NOT NULL,
      followed_up_by TEXT,
      note           TEXT,
      created_at     DATETIME NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_revisit_fu_user ON revisit_followups(user_id, created_at DESC);
  `);

  // system_audit_log: an undo ledger for admin/manager assignment actions.
  // old_state stores the pre-change row as JSON so the action can be reverted.
  db.exec(`
    CREATE TABLE IF NOT EXISTS system_audit_log (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      operator_name TEXT,
      action_type   TEXT,
      target_id     TEXT,
      old_state     TEXT,
      created_at    DATETIME DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_audit_created ON system_audit_log(created_at DESC);
  `);
  // reverted — 1 once the action has been undone (so the UI can show it).
  try {
    db.exec(`ALTER TABLE system_audit_log ADD COLUMN reverted INTEGER NOT NULL DEFAULT 0`);
  } catch (e) {
    if (!e.message.includes('duplicate column name')) throw e;
  }

  // notifications: backend-generated alerts. audience = role bucket ('admin').
  db.exec(`
    CREATE TABLE IF NOT EXISTS notifications (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      audience    TEXT NOT NULL,
      type        TEXT,
      message     TEXT NOT NULL,
      read        INTEGER NOT NULL DEFAULT 0,
      created_at  DATETIME DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_notif_audience ON notifications(audience, created_at DESC);
  `);

  // sales_targets: MONTHLY revenue goals per branch / per sales rep.
  // scope_type = 'branch' | 'sales_rep' ; scope_name = branch / rep name ;
  // target_month = 'YYYY-MM'. One target per (scope, month).
  db.exec(`
    CREATE TABLE IF NOT EXISTS sales_targets (
      scope_type    TEXT,
      scope_name    TEXT,
      target_month  TEXT,
      target_amount REAL,
      PRIMARY KEY (scope_type, scope_name, target_month)
    );
  `);

  // Migrate a pre-monthly sales_targets table (no target_month column) →
  // recreate with the monthly schema, stamping old rows with the current month.
  try {
    const stCols = db.prepare(`PRAGMA table_info(sales_targets)`).all().map(c => c.name);
    if (!stCols.includes('target_month')) {
      const curMonth = new Date().toISOString().slice(0, 7); // YYYY-MM
      db.exec(`ALTER TABLE sales_targets RENAME TO sales_targets_legacy`);
      db.exec(`
        CREATE TABLE sales_targets (
          scope_type    TEXT,
          scope_name    TEXT,
          target_month  TEXT,
          target_amount REAL,
          PRIMARY KEY (scope_type, scope_name, target_month)
        );
      `);
      const legacy = db.prepare(
        `SELECT scope_type, scope_name, target_amount FROM sales_targets_legacy`
      ).all();
      const ins = db.prepare(`
        INSERT OR REPLACE INTO sales_targets (scope_type, scope_name, target_month, target_amount)
        VALUES (?, ?, ?, ?)
      `);
      for (const r of legacy) ins.run(r.scope_type, r.scope_name, curMonth, r.target_amount);
      db.exec(`DROP TABLE sales_targets_legacy`);
      console.log(`✅ Migration: sales_targets → monthly schema (${legacy.length} rows kept)`);
    }
  } catch (e) {
    console.error('[migration] sales_targets monthly:', e.message);
  }

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

  // achievement_badges: persisted recognitions for sales reps and branches.
  // entity_type = 'sales' (sales_rep name) or 'branch' (branch id).
  // badge_code is unique per (entity_type, entity_id) — re-awarding the same
  // weekly trophy to the same person is idempotent.
  db.exec(`
    CREATE TABLE IF NOT EXISTS achievement_badges (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      entity_type TEXT NOT NULL CHECK (entity_type IN ('sales','branch')),
      entity_id   TEXT NOT NULL,
      badge_code  TEXT NOT NULL,
      badge_label TEXT NOT NULL,
      earned_at   DATETIME NOT NULL DEFAULT (datetime('now')),
      score       REAL,
      UNIQUE(entity_type, entity_id, badge_code)
    );
    CREATE INDEX IF NOT EXISTS idx_badges_entity
      ON achievement_badges(entity_type, entity_id);
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

  // users.active — 1 = can log in, 0 = disabled (kept for history but blocked
  // at login). Existing rows default to 1 so nobody is locked out by the migration.
  try {
    db.exec(`ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1`);
    console.log('✅ Migration: active column added to users');
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
    // Achievement scoring weights (must sum to 100). Editable from Settings.
    ['achievement_followup_weight', '30'],
    ['achievement_visit_weight',    '30'],
    ['achievement_close_weight',    '40'],
    // Visit forecast — expected % of customers who picked a branch and
    // will actually show up, split by whether they shared a phone number.
    ['forecast_with_phone_weight',    '80'],
    ['forecast_without_phone_weight', '35'],
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

  console.log('✅ Database initialized at:', dbPath);
  if (DB_PERSISTENT) {
    console.log('💾 Storage: PERSISTENT — data survives redeploys ✅');
  } else {
    console.warn('⚠️  Storage: EPHEMERAL — data is WIPED on every redeploy.');
    console.warn('⚠️  Fix (free): Railway → service → Variables/Volumes → add a Volume mounted at /data, then redeploy.');
  }
  return db;
}

// ── Account-based cloned sandbox ─────────────────────────────────────────────
// Two physical DBs: production (grand_furniture.db) and a sandbox clone
// (grand_furniture_demo.db). Routing is PER REQUEST via AsyncLocalStorage —
// a request runs in the demo context only when the logged-in user's name
// starts with `demo_`. Webhooks / background jobs / startup have no context
// and always hit production. Existing getDb() call sites need no changes.
const { AsyncLocalStorage } = require('async_hooks');
const dbContext = new AsyncLocalStorage();

const DEMO_DB_PATH = path.join(path.dirname(DB_PATH), 'grand_furniture_demo.db');

let liveDbInstance = null;
let demoDbInstance = null;

function getLiveDb() {
  if (!liveDbInstance) liveDbInstance = initializeDatabase(DB_PATH);
  return liveDbInstance;
}

function getDemoDb() {
  if (!demoDbInstance) demoDbInstance = initializeDatabase(DEMO_DB_PATH);
  return demoDbInstance;
}

// getDb() — argument-free. Reads the per-request context set by requireAuth.
function getDb() {
  const store = dbContext.getStore();
  return store && store.demo ? getDemoDb() : getLiveDb();
}

// Runs `fn` (the rest of a request) inside a live/demo DB context.
function runWithDbContext(isDemo, fn) {
  return dbContext.run({ demo: !!isDemo }, fn);
}

// Releases the cached demo handle + deletes its files (.db / -wal / -shm).
function wipeDemoDb() {
  if (demoDbInstance) { try { demoDbInstance.close(); } catch (_) {} demoDbInstance = null; }
  for (const suffix of ['', '-wal', '-shm']) {
    try { if (fs.existsSync(DEMO_DB_PATH + suffix)) fs.rmSync(DEMO_DB_PATH + suffix); }
    catch (_) { /* best-effort */ }
  }
}

// Clones a fresh snapshot of production into the demo DB file.
async function cloneLiveToDemo() {
  wipeDemoDb();                       // release handle + remove stale files
  const live = getLiveDb();
  await live.backup(DEMO_DB_PATH);    // online backup — safe while live is in use
}

module.exports = {
  getDb, getLiveDb, getDemoDb, runWithDbContext,
  wipeDemoDb, cloneLiveToDemo, DEMO_DB_PATH,
};
