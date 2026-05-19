// server.js — Grand Furniture Backend
// Receives ManyChat webhooks, scores leads, feeds dashboard API
// Node.js + Express + SQLite — beginner-friendly & production-ready

require('dotenv').config();
const express  = require('express');
const cors     = require('cors');
const crypto   = require('crypto'); // built-in — no install needed
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const { getDb }            = require('./db');
const { processScore }     = require('./scoring');
const { canSend, recordSend, getStateRotated, getWeeklyLimit } = require('./services/scheduler');
const { predict }          = require('./services/prediction');
const { decide, flowIdFor }= require('./services/nextAction');
const { syncLeadClass }    = require('./services/tagging');
const { getManyChatClient }= require('./manychat/client');
const { requireAuth, requireRole, getJwtSecret } = require('./middleware/auth');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Settings helper ───────────────────────────────────────────────────────────
// Small reader used by security middleware & integration status. Never throws.
function getSetting(key, fallback = null) {
  try {
    const row = getDb().prepare(`SELECT value FROM settings WHERE key = ?`).get(key);
    return row && row.value != null ? row.value : fallback;
  } catch (_) {
    return fallback;
  }
}

// ── Phone normalization ───────────────────────────────────────────────────────
// Collapses every way an Egyptian number can be typed/sent to ONE canonical
// local form (01XXXXXXXXX), so the phone the customer types in ManyChat and
// the phone the receptionist types both match the same stored value.
//   "+20 101 234 5678" / "00201012345678" / "201012345678" / "01012345678"
//   → all become "01012345678"
function normalizePhone(raw) {
  if (raw == null) return null;
  let d = String(raw).replace(/\D/g, '');          // digits only
  if (!d) return null;
  d = d.replace(/^00/, '');                          // drop intl "00" prefix
  if (d.startsWith('20') && d.length >= 11) d = d.slice(2); // drop EG country code
  if (d.length === 10 && d[0] !== '0') d = '0' + d;  // 1012345678 → 01012345678
  return d;
}

// ── Auto-assignment ───────────────────────────────────────────────────────────
// Assigns an unassigned lead to the rep with the FEWEST active leads
// (active = not purchased/converted). Returns the rep name or null.
// Safe & best-effort: never throws into the webhook path.
function autoAssignLead(db, userId, leadName) {
  try {
    const pick = db.prepare(`
      SELECT u.name AS rep,
        (SELECT COUNT(*) FROM lead_profiles lp
           WHERE lp.assigned_rep = u.name
             AND lp.lead_class NOT IN ('purchased','converted')) AS load
      FROM users u
      WHERE u.role != 'admin'
      ORDER BY load ASC, u.name ASC
      LIMIT 1
    `).get();

    if (!pick || !pick.rep) return null; // no reps exist yet

    db.prepare(`UPDATE lead_profiles SET assigned_rep = ? WHERE user_id = ?`)
      .run(pick.rep, userId);
    console.log(`👤 AUTO-ASSIGN: ${leadName || userId} → ${pick.rep} (load was ${pick.load})`);
    return pick.rep;
  } catch (e) {
    console.warn('[auto-assign] failed:', e.message);
    return null;
  }
}

// ── API Protection Layer — In-Memory State ────────────────────────────────────
// All state is intentionally in-memory:
//   - No DB schema changes
//   - Resets on deploy (acceptable — Railway restarts are infrequent)
//   - Safe for single-instance Railway deployments

// Rate limiting: one entry per user_id
// Shape: Map<userId, { count: number, windowStart: number }>
const rateLimitMap = new Map();
const RATE_LIMIT_MAX    = 20;          // max events allowed per window
const RATE_LIMIT_WINDOW = 60 * 1000;  // 60-second rolling window (ms)

// Phase 1 Idempotency: tracks recently seen event hashes to reject duplicates
// Fast path — caught before any DB read. Complements Phase 2 DB-level check.
// Shape: Map<hash, expiresAt (ms timestamp)>
const seenEvents   = new Map();
const DEDUP_WINDOW = 10 * 1000; // 10-second dedup window (ms)

// Periodic cleanup — prevents unbounded memory growth on Railway long-running instances.
// Runs every 60 s, removes expired entries from both maps.
setInterval(() => {
  const now = Date.now();
  for (const [hash, expiresAt] of seenEvents) {
    if (now > expiresAt) seenEvents.delete(hash);
  }
  for (const [userId, state] of rateLimitMap) {
    if (now - state.windowStart > RATE_LIMIT_WINDOW) rateLimitMap.delete(userId);
  }
}, 60 * 1000);

// ── Middleware ─────────────────────────────────────────────────────────────
// CORS locked to known origins. Vercel preview deployments use dynamic
// subdomains, so we allow the project's *.vercel.app pattern + localhost dev.
// FRONTEND_URL env var can add an extra explicit origin if ever needed.
const ALLOWED_ORIGINS = [
  'https://dashboard-frontend-last.vercel.app',
  'http://localhost:5173',
  'http://localhost:3000',
  process.env.FRONTEND_URL,
].filter(Boolean);

app.use(cors({
  origin(origin, cb) {
    // No origin = same-origin / server-to-server (ManyChat webhook, curl) → allow
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    // Allow Vercel preview builds of this project (dashboard-frontend-last-*.vercel.app)
    if (/^https:\/\/dashboard-frontend-last[\w-]*\.vercel\.app$/.test(origin)) {
      return cb(null, true);
    }
    return cb(new Error('Not allowed by CORS'));
  },
  credentials: true,
}));
app.use(express.json());

// Request logger — skip health checks (Railway pings them constantly) and
// stay quiet in production to avoid log bloat. Set LOG_REQUESTS=1 to force on.
const LOG_REQUESTS = process.env.LOG_REQUESTS === '1' || process.env.NODE_ENV !== 'production';
app.use((req, res, next) => {
  if (LOG_REQUESTS && req.path !== '/health') {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  }
  next();
});

// ── Webhook Security — Secret Validation ─────────────────────────────────────
// Checks x-webhook-secret header against WEBHOOK_SECRET env var.
// Returns 403 (not 401) — this is authorization, not authentication.
// Falls through silently if WEBHOOK_SECRET is not set (dev / staging without secret).
// ManyChat supports custom headers — set x-webhook-secret in webhook settings.
function validateSecret(req, res, next) {
  // Secret comes from env (highest priority) or the auto-generated DB value.
  const secret = process.env.WEBHOOK_SECRET || getSetting('webhook_secret');
  // Enforcement is opt-in (admin toggles it in Settings) so going live with
  // this code doesn't instantly break an already-running ManyChat setup.
  const enforce = getSetting('webhook_enforce', 'false') === 'true';

  if (!enforce || !secret) return next(); // not enforced — accept (legacy behavior)

  const incoming = req.headers['x-webhook-secret'];
  if (!incoming || incoming !== secret) {
    return res.status(403).json({ success: false, error: 'forbidden' });
  }
  next();
}

// ── Request Payload Validation ────────────────────────────────────────────────
// Runs after validateSecret, before rate limiter and business logic.
// Enforces required fields and type safety on event_value.
function validatePayload(req, res, next) {
  const { user_id, event_type, event_value } = req.body || {};

  if (!user_id || typeof user_id !== 'string' || user_id.trim() === '') {
    return res.status(400).json({ success: false, error: 'missing_required_fields' });
  }

  if (!event_type || typeof event_type !== 'string' || event_type.trim() === '') {
    return res.status(400).json({ success: false, error: 'missing_required_fields' });
  }

  // event_value is optional — but if present it must be a string
  if (event_value !== undefined && event_value !== null && typeof event_value !== 'string') {
    return res.status(400).json({ success: false, error: 'missing_required_fields' });
  }

  next();
}

// ── Per-User Rate Limiter ─────────────────────────────────────────────────────
// Runs after validatePayload (user_id is guaranteed to be a valid string here).
// Uses a sliding-window counter stored in rateLimitMap.
// Rejects the request if count exceeds RATE_LIMIT_MAX within RATE_LIMIT_WINDOW.
function rateLimiter(req, res, next) {
  const userId = req.body.user_id;
  const now    = Date.now();
  const state  = rateLimitMap.get(userId);

  if (!state || (now - state.windowStart) > RATE_LIMIT_WINDOW) {
    // First event in a new window — open a fresh counter
    rateLimitMap.set(userId, { count: 1, windowStart: now });
    return next();
  }

  if (state.count >= RATE_LIMIT_MAX) {
    return res.status(429).json({ success: false, error: 'rate_limited' });
  }

  state.count++;
  return next();
}

// ── Phase 4: Lead Priority Score Engine ──────────────────────────────────────
// priority_score = total_score + recency_bonus + intent_bonus
//
// recency_bonus: rewards leads who were active recently — signals live intent.
// intent_bonus:  rewards the highest-value intent action the lead has ever taken.
//                Derived from the events table so map_click is captured (no DB flag).
//
// These are pure helpers — they do NOT touch scoring.js or any existing logic.

const RECENCY_TIERS = [
  { maxHours: 1,  bonus: 30 },
  { maxHours: 6,  bonus: 20 },
  { maxHours: 24, bonus: 10 },
];

// Event-type → intent bonus mapping (spec-defined, read-only)
const INTENT_BONUS_MAP = {
  visit_confirmed:  100,
  map_click:         40,
  branch_selected:   30,
  location_request:  20,
};

/**
 * Compute recency bonus from a SQLite datetime string (UTC, space-separated).
 * @param {string|null} lastActivityISO  e.g. "2024-01-15 14:23:00"
 * @returns {number}
 */
function computeRecencyBonus(lastActivityISO) {
  if (!lastActivityISO) return 0;
  // SQLite returns "YYYY-MM-DD HH:MM:SS" (UTC). Replace space with T and add Z
  // so that new Date() always parses it as UTC — not local time.
  const diffMs    = Date.now() - new Date(lastActivityISO.replace(' ', 'T') + 'Z').getTime();
  const diffHours = diffMs / (1000 * 60 * 60);
  for (const { maxHours, bonus } of RECENCY_TIERS) {
    if (diffHours <= maxHours) return bonus;
  }
  return 0;
}

/**
 * Fetch the highest intent bonus for a set of user IDs in a single DB query.
 * Returns Map<userId, intentBonus>.
 * @param {object}   db       better-sqlite3 instance
 * @param {string[]} userIds
 * @returns {Map<string, number>}
 */
function fetchIntentBonuses(db, userIds) {
  const result = new Map();
  if (userIds.length === 0) return result;

  // One query for all users — avoids N+1.
  // MAX(CASE ...) picks the highest-value intent event ever fired by each user.
  // This means a user keeps their map_click bonus (+40) even if their latest
  // event was a lower-intent action, which is the correct business behavior.
  const placeholders = userIds.map(() => '?').join(', ');
  const rows = db.prepare(`
    SELECT
      user_id,
      MAX(CASE event_type
        WHEN 'visit_confirmed'  THEN 100
        WHEN 'map_click'        THEN  40
        WHEN 'branch_selected'  THEN  30
        WHEN 'location_request' THEN  20
        ELSE 0
      END) AS intent_bonus
    FROM events
    WHERE user_id IN (${placeholders})
      AND event_type IN ('visit_confirmed', 'map_click', 'branch_selected', 'location_request')
    GROUP BY user_id
  `).all(...userIds);

  rows.forEach(r => result.set(r.user_id, r.intent_bonus || 0));
  return result;
}


// ════════════════════════════════════════════════════════════════════════════
// Auth Routes — /api/auth/*
// POST /api/auth/login   — returns JWT token (7 days)
// POST /api/auth/logout  — client deletes token; server returns ok
// GET  /api/auth/me      — returns decoded user from token
// ════════════════════════════════════════════════════════════════════════════

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'email and password required' });
  }
  const db   = getDb();
  const user = db.prepare(`SELECT * FROM users WHERE email = ?`).get(email);

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
  }

  const payload = {
    id: user.id, name: user.name, email: user.email,
    role: user.role, branch: user.branch || null,
  };
  const token   = jwt.sign(payload, getJwtSecret(), { expiresIn: '7d' });
  return res.json({ token, user: payload });
});

app.post('/api/auth/logout', (req, res) => {
  return res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  return res.json({ user: req.user });
});

// ════════════════════════════════════════════════════════════════════════════
// POST /api/events — Main Webhook Receiver
// Called by ManyChat on every button click
// ════════════════════════════════════════════════════════════════════════════
app.post('/api/events', validateSecret, validatePayload, rateLimiter, (req, res) => {
  const db = getDb();

  // ── 1. Extract payload ────────────────────────────────────────────────
  // Validation (required fields, types) is handled upstream by validatePayload.
  const {
    user_id,
    first_name,
    event_type,
    event_value: _rawEventValue,
    session_count,
    current_score,
    // O2O attribution fields (optional — sent by ManyChat from ad UTM params)
    campaign_source,
    ad_id,
    visit_code,
    phone,
    // ManyChat product fields — fallback when event_value not provided
    product,
    category,
  } = req.body;

  // Canonical phone (used as the reception lookup key — replaces visit code)
  const normPhone = normalizePhone(phone);

  // Normalise: ManyChat flows send "product" & "category" instead of event_value.
  // Use event_value when present; fall back to product name for product_details events.
  const event_value = _rawEventValue
    || (event_type === 'product_details' ? (product || null) : null)
    || null;

  // Store category alongside the product in lead_profiles (coalesced on first set)
  // We persist it via a dedicated column added below in the UPDATE.
  const productCategory = category || null;

  // ── 2. Phase 1 — In-memory idempotency (fast path) ───────────────────
  // Hash = user_id + event_type + event_value + 10-second time bucket.
  // Catches duplicate retries within the same server session instantly,
  // before any DB reads. Phase 2 below handles cross-restart durability.
  const timeBucket = Math.floor(Date.now() / DEDUP_WINDOW); // changes every 10 s
  const dedupRaw   = `${user_id}:${event_type}:${event_value ?? ''}:${timeBucket}`;
  const dedupHash  = crypto.createHash('sha256').update(dedupRaw).digest('hex');

  if (seenEvents.has(dedupHash)) {
    console.log(`[DEDUP:MEM] Skipped — user:${user_id} type:${event_type}`);
    return res.status(200).json({ success: true, skipped: true, reason: 'duplicate_event' });
  }
  seenEvents.set(dedupHash, Date.now() + DEDUP_WINDOW);

  // ── 3. Phase 2 — Resolve persistent event_id ─────────────────────────
  // Priority:
  //   a) Caller-supplied event_id (e.g. ManyChat passes its own message ID)
  //      → stable across retries at any time interval, even hours later
  //   b) Auto-generated from time-bucket hash (same formula as Phase 1)
  //      → covers short-window retries when caller does not supply an ID
  //
  // The event_id is stored permanently in the events table (TEXT UNIQUE).
  // Any future request carrying the same event_id — regardless of restart —
  // is detected here and rejected before any score or profile mutation.
  const resolvedEventId = (typeof req.body.event_id === 'string' && req.body.event_id.trim() !== '')
    ? req.body.event_id.trim()
    : dedupHash; // reuse the hash already computed above

  // ── 4. Phase 2 — DB-level duplicate check ────────────────────────────
  // Survives server restarts and Railway redeploys.
  // Checked BEFORE profile read/write — zero side effects on a duplicate.
  const existingEvent = db.prepare(`
    SELECT id FROM events WHERE event_id = ?
  `).get(resolvedEventId);

  if (existingEvent) {
    console.log(`[DEDUP:DB] Skipped — event_id:${resolvedEventId} user:${user_id} type:${event_type}`);
    return res.status(200).json({ success: true, skipped: true, reason: 'duplicate_event_db' });
  }

  // ── 5. Get or create lead profile ────────────────────────────────────
  let profile = db.prepare(`
    SELECT * FROM lead_profiles WHERE user_id = ?
  `).get(user_id);

  if (!profile) {
    db.prepare(`
      INSERT INTO lead_profiles (user_id, first_name, campaign_source, ad_id, visit_code, phone)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(user_id, first_name || 'Unknown', campaign_source || null, ad_id || null, visit_code || null, normPhone || null);

    profile = db.prepare(`
      SELECT * FROM lead_profiles WHERE user_id = ?
    `).get(user_id);
  }

  // ── 5b. Per-value dedup — has this user already been scored for this
  //         exact product / category before?  If yes, the event is still
  //         recorded (for analytics) but earns 0 points.
  let alreadyScored = false;
  if (event_type === 'product_details' && event_value) {
    const seen = db.prepare(`
      SELECT 1 FROM events
      WHERE user_id = ? AND event_type = 'product_details' AND product_id = ?
      LIMIT 1
    `).get(user_id, event_value);
    alreadyScored = !!seen;
  } else if (event_type === 'category_request' && productCategory) {
    const seen = db.prepare(`
      SELECT 1 FROM events
      WHERE user_id = ? AND event_type = 'category_request' AND category = ?
      LIMIT 1
    `).get(user_id, productCategory);
    alreadyScored = !!seen;
  }

  // ── 6. Calculate new score & classification ───────────────────────────
  const { scoreDelta, newTotalScore, newLeadClass } = processScore(
    profile,
    event_type,
    event_value,
    alreadyScored
  );

  // ── 7. Detect context-specific flags ─────────────────────────────────
  const isLocationEvent = ['location_request', 'branch_selected', 'entry_location']
    .includes(event_type);

  const isProductEvent = event_type === 'product_details';

  // Both product views AND category picks carry a category we want to persist
  const isCategoryEvent = event_type === 'category_request';
  const hasCategory     = (isProductEvent || isCategoryEvent) && !!productCategory;

  const isVisitConfirmed = event_type === 'visit_confirmed';

  // ── Phase 3: Parse structured visit_confirmed payload ─────────────────
  // event_value for visit_confirmed supports two formats (backward compatible):
  //   Legacy:  "nasr_city"                              (plain string)
  //   Phase 3: '{"branch":"nasr_city","status":"arrived"}' (JSON string)
  // If JSON parsing fails, visitPayload stays null and we fall through to
  // the existing plain-string branch detection below.
  let visitPayload = null;
  if (isVisitConfirmed && event_value) {
    try {
      const parsed = JSON.parse(event_value);
      // Only treat it as structured if it has a branch or status field
      if (parsed && typeof parsed === 'object' && (parsed.branch || parsed.status)) {
        visitPayload = parsed;
      }
    } catch (_) {
      // Not JSON — legacy plain string format, handled below
    }
  }

  // Detect branch:
  //  - visit_confirmed structured payload → explicit branch field
  //  - branch_selected → event_value IS the branch the customer picked
  //    (use it directly — works for ANY branch id, not a hardcoded list)
  //  - otherwise → try a known-id substring match, else keep existing
  const BRANCHES = ['nasr_city', 'maadi', 'helwan', 'faisal', 'ain_shams'];
  const detectedBranch = visitPayload?.branch
    ? visitPayload.branch
    : (event_type === 'branch_selected' && event_value)
      ? event_value.trim()
      : event_value
        ? BRANCHES.find(b => event_value.includes(b)) || profile.preferred_branch
        : profile.preferred_branch;

  // Detect product from event_value (if it's a product event)
  const lastProduct = isProductEvent
    ? (event_value || profile.last_product)
    : profile.last_product;

  // ── 8. Update lead profile ────────────────────────────────────────────
  // visit_at: set to current timestamp on the first visit_confirmed event.
  // CASE WHEN preserves the existing value once set — prevents overwriting
  // a real visit timestamp if a duplicate somehow reaches this point.
  db.prepare(`
    UPDATE lead_profiles SET
      first_name          = COALESCE(?, first_name),
      total_score         = ?,
      lead_class          = ?,
      preferred_branch    = COALESCE(?, preferred_branch),
      last_product        = COALESCE(?, last_product),
      last_category       = COALESCE(?, last_category),
      product_view_count  = product_view_count + ?,
      session_count       = COALESCE(?, session_count),
      visit_confirmed     = CASE WHEN ? = 1 THEN 1 ELSE visit_confirmed END,
      location_requested  = CASE WHEN ? = 1 THEN 1 ELSE location_requested END,
      visit_at            = CASE WHEN ? = 1 AND visit_at IS NULL THEN datetime('now') ELSE visit_at END,
      campaign_source     = COALESCE(campaign_source, ?),
      ad_id               = COALESCE(ad_id, ?),
      visit_code          = COALESCE(visit_code, ?),
      phone               = COALESCE(?, phone),
      last_activity       = datetime('now')
    WHERE user_id = ?
  `).run(
    first_name || null,
    newTotalScore,
    newLeadClass,
    detectedBranch || null,
    lastProduct || null,
    hasCategory ? productCategory : null,
    isProductEvent ? 1 : 0,
    session_count || null,
    isVisitConfirmed ? 1 : 0,
    isLocationEvent ? 1 : 0,
    isVisitConfirmed ? 1 : 0,  // visit_at — same flag, separate param
    campaign_source || null,
    ad_id || null,
    visit_code || null,
    normPhone || null,
    user_id
  );

  // Keep EVERY phone the customer ever sent — never overwrite history.
  // profile.phone above stays as the latest (quick display); lead_phones is
  // the full set the receptionist can match against.
  if (normPhone) {
    db.prepare(`
      INSERT OR IGNORE INTO lead_phones (user_id, phone) VALUES (?, ?)
    `).run(user_id, normPhone);
  }

  // ── 9. Insert raw event record (with event_id) ────────────────────────
  // event_id is stored here permanently — this is what Phase 2 checks on
  // subsequent requests. The UNIQUE constraint on the column guarantees
  // no two rows can share the same event_id at the DB level.
  let eventRow;
  try {
    eventRow = db.prepare(`
      INSERT INTO events (
        event_id, user_id, first_name, event_type, event_value,
        score_delta, session_count, current_score,
        branch, product_id, category, raw_payload
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      resolvedEventId,
      user_id,
      first_name || null,
      event_type,
      event_value || null,
      scoreDelta,
      session_count || null,
      newTotalScore,
      detectedBranch || null,
      isProductEvent ? event_value : null,
      hasCategory ? productCategory : null,
      JSON.stringify(req.body)
    );
  } catch (e) {
    // Concurrent duplicate slipped past the dedup checks and lost the race on
    // the UNIQUE(event_id) constraint → treat as idempotent success, not 500.
    if (e && /UNIQUE constraint failed/i.test(e.message)) {
      console.log(`[DEDUP:RACE] Skipped — event_id:${resolvedEventId} user:${user_id}`);
      return res.status(200).json({ success: true, skipped: true, reason: 'duplicate_event_race' });
    }
    throw e; // anything else → global error handler returns clean 500
  }

  // ── 10. Log transition alerts ─────────────────────────────────────────
  const alreadyAdvanced = ['hot', 'visited', 'purchased', 'converted'].includes(profile.lead_class);
  if (newLeadClass === 'hot' && !alreadyAdvanced) {
    console.log(`🔴 HOT LEAD: ${first_name || user_id} — Score: ${newTotalScore} — Branch: ${detectedBranch || 'unknown'}`);
  }

  // ── Auto-assign on first qualification (cold → warm/hot) ──────────────
  // Fires once when the lead first becomes warm (or jumps straight to hot)
  // and isn't already owned by a rep. Toggle: settings.auto_assign_enabled.
  const becameQualified =
    ['warm', 'hot'].includes(newLeadClass) &&
    ['cold', '', null, undefined].includes(profile.lead_class);
  if (
    becameQualified &&
    !profile.assigned_rep &&
    getSetting('auto_assign_enabled', 'true') === 'true'
  ) {
    autoAssignLead(db, user_id, first_name);
  }

  // Alert on transition into visited (new) or legacy converted
  if (newLeadClass === 'visited' && profile.lead_class !== 'visited' && profile.lead_class !== 'converted') {
    console.log(`🏪 VISITED: ${first_name || user_id} — Score: ${newTotalScore} — Branch: ${detectedBranch || 'unknown'}`);
  }

  // Phase 3: log visit arrival with structured payload info
  if (isVisitConfirmed) {
    const visitStatus = visitPayload?.status || 'confirmed';
    console.log(`🏪 VISIT: ${first_name || user_id} → ${detectedBranch || 'unknown'} [${visitStatus}]`);
  }

  // ── Intelligence: sync class to ManyChat on transition (best-effort) ─
  // Only fires when the class actually changed. Wrapped in try/catch and
  // not awaited — a tagging failure must not affect the webhook response.
  if (newLeadClass !== profile.lead_class) {
    syncLeadClass({ user_id, lead_class: newLeadClass, total_score: newTotalScore })
      .catch((e) => console.warn('[tagging]', e.message));
  }

  // ── 11. Respond to ManyChat ───────────────────────────────────────────
  return res.status(200).json({
    success: true,
    event_id: eventRow.lastInsertRowid,
    lead_class: newLeadClass,
    new_score: newTotalScore,
    score_delta: scoreDelta,
  });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/dashboard — Dashboard Data API
// Returns all stats needed for the dashboard
// ════════════════════════════════════════════════════════════════════════════
// ── Dashboard Cache ────────────────────────────────────────────────────────
const dashboardCache = {
  data: null,
  timestamp: 0,
  ttl: 15 * 1000 // 15 seconds
};

app.get('/api/dashboard', requireAuth, (req, res) => {
  if (dashboardCache.data && (Date.now() - dashboardCache.timestamp < dashboardCache.ttl)) {
    return res.json(dashboardCache.data);
  }

  const db = getDb();

  // Lead class distribution
  const leadCounts = db.prepare(`
    SELECT lead_class, COUNT(*) as count
    FROM lead_profiles
    GROUP BY lead_class
  `).all();

  // Total leads
  const totalLeads = db.prepare(`SELECT COUNT(*) as count FROM lead_profiles`).get();

  // Hot leads today (includes visited and purchased — they were hot before converting)
  const hotToday = db.prepare(`
    SELECT COUNT(*) as count FROM lead_profiles
    WHERE lead_class IN ('hot', 'visited', 'purchased', 'converted')
    AND date(last_activity) = date('now')
  `).get();

  // Top products — DISTINCT customers interested (a customer viewing the
  // same product repeatedly counts once, matching the dedup scoring rule).
  const topProducts = db.prepare(`
    SELECT product_id, COUNT(DISTINCT user_id) as views
    FROM events
    WHERE event_type = 'product_details' AND product_id IS NOT NULL
    GROUP BY product_id
    ORDER BY views DESC
    LIMIT 10
  `).all();

  // Branch demand — DISTINCT customers who asked for each branch (a customer
  // comparing/re-picking the same branch counts once, not per event).
  // Group by the branch the customer actually picked (event_value).
  const branchDemand = db.prepare(`
    SELECT
      COALESCE(NULLIF(event_value,''), branch) AS branch,
      COUNT(DISTINCT user_id) AS requests
    FROM events
    WHERE event_type IN ('branch_selected', 'location_request')
      AND COALESCE(NULLIF(event_value,''), branch) IS NOT NULL
    GROUP BY COALESCE(NULLIF(event_value,''), branch)
    ORDER BY requests DESC
  `).all();

  // Funnel conversion rates — Phase 3: now includes map_click as a funnel step.
  // Full funnel: product_details → location_request → branch_selected → map_click → visit_confirmed
  const funnelStages = db.prepare(`
    SELECT event_type, COUNT(DISTINCT user_id) as unique_users
    FROM events
    WHERE event_type IN (
      'entry_catalog', 'entry_offer', 'entry_location',
      'product_details', 'location_request',
      'branch_selected', 'map_click', 'contact_request', 'visit_confirmed'
    )
    GROUP BY event_type
    ORDER BY unique_users DESC
  `).all();

  // Phase 4: Priority-ranked hot leads ─────────────────────────────────────
  // Fetches ALL hot/converted leads (no LIMIT yet) so we can compute
  // priority_score in JS and then sort before slicing to 10.
  // Hot/converted set is typically small so the full fetch is safe.
  const rawHotLeads = db.prepare(`
    SELECT user_id, first_name, total_score, lead_class,
           preferred_branch, last_product, last_activity,
           visit_confirmed, location_requested,
           campaign_source, ad_id, visit_code, phone
    FROM lead_profiles
    WHERE lead_class IN ('hot', 'visited', 'purchased', 'converted')
  `).all();

  // Batch-fetch the highest intent bonus per user — single query, no N+1
  const hotUserIds   = rawHotLeads.map(l => l.user_id);
  const intentBonusMap = fetchIntentBonuses(db, hotUserIds);

  // Compute priority_score for each lead, then sort desc and take top 10
  const recentHotLeads = rawHotLeads
    .map(lead => {
      const recencyBonus = computeRecencyBonus(lead.last_activity);
      const intentBonus  = intentBonusMap.get(lead.user_id) || 0;
      return {
        ...lead,
        recency_bonus:  recencyBonus,
        intent_bonus:   intentBonus,
        priority_score: lead.total_score + recencyBonus + intentBonus,
      };
    })
    .sort((a, b) => b.priority_score - a.priority_score)
    .slice(0, 10);

  // Events in last 7 days (daily breakdown)
  const weeklyActivity = db.prepare(`
    SELECT date(created_at) as day, COUNT(*) as events
    FROM events
    WHERE created_at >= datetime('now', '-7 days')
    GROUP BY date(created_at)
    ORDER BY day ASC
  `).all();

  // Visit confirmations — all-time.
  // Includes legacy 'converted' rows + new 'visited' and 'purchased' states.
  const visitConfirmed = db.prepare(`
    SELECT COUNT(*) as count FROM lead_profiles
    WHERE visit_confirmed = 1
       OR lead_class IN ('converted', 'visited', 'purchased')
  `).get();

  // ── Phase 3: Visit tracking metrics ───────────────────────────────────

  // visits_today: leads where visit_at was recorded today (UTC).
  // Uses the visit_at column set on visit_confirmed events — more precise
  // than counting lead_class, because visit_at records the exact moment
  // the user physically arrived (status: "arrived").
  const visitsToday = db.prepare(`
    SELECT COUNT(*) as count FROM lead_profiles
    WHERE date(visit_at) = date('now')
  `).get();

  // visits_this_week: rolling 7-day window using visit_at timestamp.
  const visitsThisWeek = db.prepare(`
    SELECT COUNT(*) as count FROM lead_profiles
    WHERE visit_at >= datetime('now', '-7 days')
  `).get();

  // conversion_to_visit: percentage of all leads who confirmed a visit.
  // Denominator is total_leads (not just hot/warm) — gives the true
  // top-of-funnel → showroom conversion rate.
  // Expressed as a float (e.g. 12.5 for 12.5%).
  const totalVisited = db.prepare(`
    SELECT COUNT(*) as count FROM lead_profiles WHERE visit_confirmed = 1
  `).get();

  const conversionToVisit = totalLeads.count > 0
    ? parseFloat(((totalVisited.count / totalLeads.count) * 100).toFixed(1))
    : 0.0;

  // ── Branch visit breakdown ────────────────────────────────────────────
  // Real reception-confirmed arrivals per branch (lead_visits is the source
  // of truth — reception confirmations don't create events).
  const branchVisits = db.prepare(`
    SELECT branch, COUNT(DISTINCT user_id) as visits
    FROM lead_visits
    WHERE branch IS NOT NULL
    GROUP BY branch
    ORDER BY visits DESC
  `).all();

  // ── Campaign Performance (O2O attribution) ────────────────────────────
  // Groups by campaign_source: how many leads came from each campaign,
  // how many visited the showroom, how many purchased.
  const campaignPerformance = db.prepare(`
    SELECT
      COALESCE(lp.campaign_source, 'غير محدد') AS campaign_source,
      COUNT(DISTINCT lp.user_id)                AS total_leads,
      COUNT(DISTINCT CASE WHEN lp.visit_confirmed = 1
            OR lp.lead_class IN ('visited','purchased','converted')
            THEN lp.user_id END)                AS total_visits,
      COUNT(DISTINCT p.user_id)                 AS total_purchases,
      ROUND(
        CAST(COUNT(DISTINCT p.user_id) AS REAL)
        / NULLIF(COUNT(DISTINCT lp.user_id), 0) * 100
      , 1)                                       AS purchase_rate
    FROM lead_profiles lp
    LEFT JOIN purchases p ON p.user_id = lp.user_id
    GROUP BY COALESCE(lp.campaign_source, 'غير محدد')
    ORDER BY total_leads DESC
  `).all();

  // ── Product Gap (online views vs offline purchases) ────────────────────
  // For every product seen in events, compare view count to purchase count.
  // Red flag = high views + zero purchases.
  const productGap = db.prepare(`
    SELECT
      e.product_id,
      COUNT(DISTINCT e.user_id) AS views,
      COALESCE(p.buys, 0)       AS purchases
    FROM events e
    LEFT JOIN (
      SELECT product_id, COUNT(*) AS buys
      FROM purchases
      WHERE product_id IS NOT NULL
      GROUP BY product_id
    ) p ON p.product_id = e.product_id
    WHERE e.event_type = 'product_details'
      AND e.product_id IS NOT NULL
    GROUP BY e.product_id
    ORDER BY views DESC
    LIMIT 20
  `).all();

  const responseData = {
    summary: {
      total_leads:        totalLeads.count,
      hot_leads_today:    hotToday.count,
      visits_confirmed:   visitConfirmed.count,
      visits_today:       visitsToday.count,
      visits_this_week:   visitsThisWeek.count,
      conversion_to_visit: conversionToVisit,
      lead_distribution:  leadCounts,
    },
    top_products:          topProducts,
    branch_demand:         branchDemand,
    branch_visits:         branchVisits,
    funnel_stages:         funnelStages,
    recent_hot_leads:      recentHotLeads,
    weekly_activity:       weeklyActivity,
    campaign_performance:  campaignPerformance,
    product_gap:           productGap,
  };

  dashboardCache.data = responseData;
  dashboardCache.timestamp = Date.now();

  return res.json(responseData);
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/leads — List leads with filters
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/leads', requireAuth, (req, res) => {
  const db = getDb();
  const {
    class: leadClass,
    branch,
    limit  = 50,
    page   = 1,
    search = '',
  } = req.query;

  const pageSize   = Math.min(Math.max(parseInt(limit) || 50, 1), 200);
  const pageNumber = Math.max(parseInt(page) || 1, 1);
  const offset     = (pageNumber - 1) * pageSize;

  let where  = `WHERE 1=1`;
  const params = [];

  // RBAC: sales reps only see leads assigned to them
  if (req.user.role !== 'admin') {
    where += ` AND assigned_rep = ?`;
    params.push(req.user.name);
  }

  if (leadClass) {
    where += ` AND lead_class = ?`;
    params.push(leadClass);
  }
  if (branch) {
    // Match the branch the customer actually requested (branch_selected
    // event_value/branch) — not only the fragile preferred_branch.
    where += ` AND (preferred_branch = ? OR user_id IN (
      SELECT user_id FROM events
      WHERE event_type = 'branch_selected' AND (event_value = ? OR branch = ?)
    ))`;
    params.push(branch, branch, branch);
  }
  if (search) {
    where += ` AND first_name LIKE ?`;
    params.push(`%${search}%`);
  }

  // Total count for pagination metadata
  const total = db.prepare(`SELECT COUNT(*) as n FROM lead_profiles ${where}`).get(...params).n;

  const leads = db.prepare(`
    SELECT lead_profiles.*,
      (SELECT COALESCE(NULLIF(e.event_value,''), e.branch)
         FROM events e
         WHERE e.user_id = lead_profiles.user_id
           AND e.event_type = 'branch_selected'
           AND COALESCE(NULLIF(e.event_value,''), e.branch) IS NOT NULL
         ORDER BY e.created_at DESC LIMIT 1) AS requested_branch
    FROM lead_profiles
    ${where}
    ORDER BY total_score DESC, last_activity DESC
    LIMIT ? OFFSET ?
  `).all(...params, pageSize, offset);

  return res.json({
    leads,
    count:       leads.length,
    total,
    page:        pageNumber,
    page_size:   pageSize,
    total_pages: Math.ceil(total / pageSize),
  });
});

// ════════════════════════════════════════════════════════════════════════════
// PUT /api/leads/:user_id/assign — Admin assigns a lead to a sales rep
// Body: { rep_name } — pass null or "" to unassign
// ════════════════════════════════════════════════════════════════════════════
app.put('/api/leads/:user_id/assign', requireAuth, requireRole('admin'), (req, res) => {
  const { rep_name } = req.body || {};
  const db = getDb();
  const lead = db.prepare(`SELECT user_id FROM lead_profiles WHERE user_id = ?`).get(req.params.user_id);
  if (!lead) return res.status(404).json({ error: 'lead_not_found' });

  db.prepare(`UPDATE lead_profiles SET assigned_rep = ? WHERE user_id = ?`)
    .run(rep_name || null, req.params.user_id);

  return res.json({ ok: true, user_id: req.params.user_id, assigned_rep: rep_name || null });
});

// ════════════════════════════════════════════════════════════════════════════
// DELETE /api/leads/:user_id — Admin permanently deletes a customer + ALL
// their data across every table. Irreversible.
// ════════════════════════════════════════════════════════════════════════════
app.delete('/api/leads/:user_id', requireAuth, requireRole('admin'), (req, res) => {
  const db = getDb();
  const { user_id } = req.params;
  const lead = db.prepare(`SELECT first_name FROM lead_profiles WHERE user_id = ?`).get(user_id);
  if (!lead) return res.status(404).json({ error: 'lead_not_found' });

  const wipe = db.transaction(() => {
    db.prepare(`DELETE FROM events          WHERE user_id = ?`).run(user_id);
    db.prepare(`DELETE FROM lead_phones     WHERE user_id = ?`).run(user_id);
    db.prepare(`DELETE FROM lead_visits     WHERE user_id = ?`).run(user_id);
    db.prepare(`DELETE FROM tasks           WHERE lead_id = ?`).run(user_id);
    db.prepare(`DELETE FROM purchases       WHERE user_id = ?`).run(user_id);
    db.prepare(`DELETE FROM messages_sent   WHERE user_id = ?`).run(user_id);
    db.prepare(`DELETE FROM follow_up_state WHERE user_id = ?`).run(user_id);
    db.prepare(`DELETE FROM lead_profiles   WHERE user_id = ?`).run(user_id);
  });
  wipe();

  console.log(`🗑️  LEAD DELETED by admin ${req.user?.name || '?'}: ${lead.first_name || user_id} (${user_id})`);
  return res.json({ ok: true, deleted: user_id });
});

// ════════════════════════════════════════════════════════════════════════════
// Tasks — rep follow-up reminders
//   POST   /api/tasks            create { lead_id, due_at, note, source? }
//   GET    /api/tasks?status=    list (rep sees own; admin sees all / ?rep=)
//   PATCH  /api/tasks/:id        { status: 'done' | 'pending' }
//   DELETE /api/tasks/:id        delete (owner or admin)
// ════════════════════════════════════════════════════════════════════════════
app.post('/api/tasks', requireAuth, (req, res) => {
  const { lead_id, due_at, note, source } = req.body || {};
  if (!lead_id || typeof lead_id !== 'string') {
    return res.status(400).json({ error: 'lead_id is required' });
  }
  if (!due_at || !/^\d{4}-\d{2}-\d{2}$/.test(due_at)) {
    return res.status(400).json({ error: 'due_at must be YYYY-MM-DD' });
  }
  const db = getDb();
  const lead = db.prepare(`SELECT first_name FROM lead_profiles WHERE user_id = ?`).get(lead_id);
  if (!lead) return res.status(404).json({ error: 'lead_not_found' });

  const repName = req.user?.name || 'مندوب';
  const info = db.prepare(`
    INSERT INTO tasks (lead_id, lead_name, rep_name, due_at, note, source)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(lead_id, lead.first_name || null, repName, due_at,
         (note || '').slice(0, 500), source === 'reschedule' ? 'reschedule' : 'manual');

  return res.json({ ok: true, id: info.lastInsertRowid });
});

app.get('/api/tasks', requireAuth, (req, res) => {
  const db = getDb();
  const isAdmin = req.user?.role === 'admin';
  const status  = req.query.status || 'pending';
  const where = [];
  const params = [];

  if (!isAdmin) { where.push('rep_name = ?'); params.push(req.user?.name || ''); }
  else if (req.query.rep) { where.push('rep_name = ?'); params.push(req.query.rep); }
  if (req.query.lead_id) { where.push('lead_id = ?'); params.push(req.query.lead_id); }
  if (status !== 'all') { where.push('status = ?'); params.push(status); }

  const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const rows = db.prepare(`
    SELECT * FROM tasks ${clause}
    ORDER BY (status = 'done') ASC, due_at ASC, created_at ASC
  `).all(...params);

  return res.json({ tasks: rows });
});

app.patch('/api/tasks/:id', requireAuth, (req, res) => {
  const db = getDb();
  const task = db.prepare(`SELECT * FROM tasks WHERE id = ?`).get(req.params.id);
  if (!task) return res.status(404).json({ error: 'task_not_found' });
  if (req.user?.role !== 'admin' && task.rep_name !== req.user?.name) {
    return res.status(403).json({ error: 'forbidden' });
  }
  const status = req.body?.status === 'done' ? 'done' : 'pending';
  db.prepare(`
    UPDATE tasks
    SET status = ?, completed_at = CASE WHEN ? = 'done' THEN datetime('now') ELSE NULL END
    WHERE id = ?
  `).run(status, status, req.params.id);
  return res.json({ ok: true });
});

app.delete('/api/tasks/:id', requireAuth, (req, res) => {
  const db = getDb();
  const task = db.prepare(`SELECT * FROM tasks WHERE id = ?`).get(req.params.id);
  if (!task) return res.status(404).json({ error: 'task_not_found' });
  if (req.user?.role !== 'admin' && task.rep_name !== req.user?.name) {
    return res.status(403).json({ error: 'forbidden' });
  }
  db.prepare(`DELETE FROM tasks WHERE id = ?`).run(req.params.id);
  return res.json({ ok: true });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/leads/:user_id — Single lead profile + event history
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/leads/:user_id', requireAuth, (req, res) => {
  const db = getDb();
  const { user_id } = req.params;

  const profile = db.prepare(`SELECT * FROM lead_profiles WHERE user_id = ?`).get(user_id);
  if (!profile) return res.status(404).json({ error: 'Lead not found' });

  let history = db.prepare(`
    SELECT event_type, event_value, category, product_id, branch, score_delta, created_at
    FROM events WHERE user_id = ?
    ORDER BY created_at DESC
    LIMIT 50
  `).all(user_id);

  // All phones the customer gave + every branch they actually visited
  const phones = db.prepare(`
    SELECT phone, created_at FROM lead_phones
    WHERE user_id = ? ORDER BY created_at DESC
  `).all(user_id).map(r => r.phone);

  let visits = db.prepare(`
    SELECT branch, visited_at, sales_rep FROM lead_visits
    WHERE user_id = ? ORDER BY visited_at DESC
  `).all(user_id);

  // Every branch the customer ASKED about (branch_selected) — a customer
  // comparing 2 branches must show both, not just the latest preferred_branch.
  let requestedBranches = db.prepare(`
    SELECT
      COALESCE(NULLIF(event_value,''), branch) AS branch,
      MIN(created_at) AS first_at,
      MAX(created_at) AS last_at
    FROM events
    WHERE user_id = ? AND event_type = 'branch_selected'
      AND COALESCE(NULLIF(event_value,''), branch) IS NOT NULL
    GROUP BY COALESCE(NULLIF(event_value,''), branch)
    ORDER BY last_at DESC
  `).all(user_id);

  // Reception accounts see ONLY their own branch — never other branches the
  // customer also asked about. Admin/rep see everything.
  if (req.user?.role === 'reception' && req.user.branch) {
    const b = req.user.branch;
    profile.preferred_branch = b;
    visits = visits.filter(v => v.branch === b);
    requestedBranches = requestedBranches.filter(r => r.branch === b);
    history = history.filter(h =>
      h.event_type !== 'branch_selected' || h.event_value === b || h.branch === b
    );
  }

  return res.json({ profile, history, phones, visits, requestedBranches });
});

// ════════════════════════════════════════════════════════════════════════════
// POST /api/visits/confirm — Receptionist confirms a lead arrived.
// Primary: { phone }  (customer gave their number in ManyChat)
// Fallback: { visit_code }  (legacy — still works)
// Returns: { ok, user_id, first_name, campaign_source, lead_class }
// ════════════════════════════════════════════════════════════════════════════
app.post('/api/visits/confirm', requireAuth, (req, res) => {
  const { phone, visit_code, branch, user_id } = req.body || {};
  const db = getDb();
  // The receptionist explicitly picks the branch they're at — that is the
  // source of truth for WHICH branch was visited (no guessing from intent).
  // A reception account is LOCKED to its own branch (can't confirm for others).
  const pickedBranch = req.user?.role === 'reception'
    ? (req.user.branch || null)
    : ((typeof branch === 'string' && branch.trim()) ? branch.trim() : null);

  let lead = null;
  if (user_id != null && String(user_id).trim() !== '') {
    lead = db.prepare(`
      SELECT user_id, first_name, campaign_source, lead_class,
             visit_confirmed, preferred_branch
      FROM lead_profiles WHERE user_id = ?
    `).get(String(user_id).trim());
    if (!lead) return res.status(404).json({ error: 'lead_not_found' });
  } else if (phone != null && String(phone).trim() !== '') {
    const np = normalizePhone(phone);
    if (!np) return res.status(400).json({ error: 'invalid_phone' });
    // Match against EVERY phone the customer ever gave (lead_phones), not just
    // the latest one on the profile — so an older number still works.
    lead = db.prepare(`
      SELECT lp.user_id, lp.first_name, lp.campaign_source, lp.lead_class,
             lp.visit_confirmed, lp.preferred_branch
      FROM lead_phones ph
      JOIN lead_profiles lp ON lp.user_id = ph.user_id
      WHERE ph.phone = ?
      ORDER BY lp.last_activity DESC LIMIT 1
    `).get(np);
    // Fallback: legacy rows whose phone is only on the profile
    if (!lead) {
      lead = db.prepare(`
        SELECT user_id, first_name, campaign_source, lead_class,
               visit_confirmed, preferred_branch
        FROM lead_profiles WHERE phone = ?
        ORDER BY last_activity DESC LIMIT 1
      `).get(np);
    }
    if (!lead) return res.status(404).json({ error: 'phone_not_found' });
  } else if (visit_code != null && String(visit_code).trim() !== '') {
    lead = db.prepare(`
      SELECT user_id, first_name, campaign_source, lead_class,
             visit_confirmed, preferred_branch
      FROM lead_profiles WHERE visit_code = ?
    `).get(String(visit_code).trim());
    if (!lead) return res.status(404).json({ error: 'visit_code_not_found' });
  } else {
    return res.status(400).json({ error: 'phone_required' });
  }

  // Global "has visited at least one branch" flag — for scoring/funnel.
  // (Idempotent — won't downgrade a purchased lead.)
  const newClass = lead.lead_class === 'purchased' ? 'purchased' : 'visited';
  db.prepare(`
    UPDATE lead_profiles SET
      lead_class      = ?,
      visit_confirmed = 1,
      visit_at        = CASE WHEN visit_at IS NULL THEN datetime('now') ELSE visit_at END,
      last_activity   = datetime('now')
    WHERE user_id = ?
  `).run(newClass, lead.user_id);

  // Record THIS branch visit separately. The receptionist's explicit choice
  // wins; fall back to the lead's last intent only if none was picked.
  // visiting حلوان later must not erase an earlier فيصل visit (one row each).
  const visitBranch = pickedBranch || lead.preferred_branch || null;
  if (visitBranch) {
    db.prepare(`
      INSERT OR IGNORE INTO lead_visits (user_id, branch) VALUES (?, ?)
    `).run(lead.user_id, visitBranch);
  }

  console.log(`🏪 VISIT CONFIRMED: ${lead.first_name || lead.user_id} → ${visitBranch || 'unknown branch'} (${lead.campaign_source || 'no campaign'})`);

  // Event-Triggered Flow: Visit Confirmed
  const visitFlowSetting = db.prepare(`SELECT value FROM settings WHERE key = 'manychat_visit_flow'`).get();
  if (visitFlowSetting && visitFlowSetting.value && visitFlowSetting.value.trim() !== '') {
    getManyChatClient().sendFlow({ user_id: lead.user_id, flow_id: visitFlowSetting.value.trim() })
      .catch(err => console.error('[Event-Trigger] Visit Flow failed:', err.message));
  } else {
    console.warn('[Event-Trigger] ⚠️ Visit confirmed but manychat_visit_flow is empty — no message sent. Set it in Settings → API.');
  }

  return res.json({
    ok:              true,
    user_id:         lead.user_id,
    first_name:      lead.first_name || 'غير معروف',
    campaign_source: lead.campaign_source || null,
    branch:          visitBranch || null,
    lead_class:      newClass,
  });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/reception/leads — customers who requested THIS branch's address.
// reception role → locked to its own branch. admin → ?branch=<id> required.
// Shows everyone who picked the branch (branch_selected event) even if they
// haven't visited yet; visited_here flags who already came.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/reception/leads', requireAuth, (req, res) => {
  const role = req.user?.role;
  if (role !== 'reception' && role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  const branch = role === 'reception'
    ? (req.user.branch || null)
    : (req.query.branch || null);
  if (!branch) return res.status(400).json({ error: 'branch_required' });

  const db = getDb();
  const rows = db.prepare(`
    SELECT
      lp.user_id,
      lp.first_name,
      lp.total_score,
      lp.lead_class,
      lp.last_activity,
      MIN(e.created_at) AS first_requested,
      MAX(e.created_at) AS last_requested,
      (SELECT GROUP_CONCAT(ph.phone, ' ، ')
         FROM lead_phones ph WHERE ph.user_id = lp.user_id)            AS phones,
      (SELECT v.visited_at FROM lead_visits v
         WHERE v.user_id = lp.user_id AND v.branch = ? LIMIT 1)        AS visited_at,
      (SELECT v.sales_rep FROM lead_visits v
         WHERE v.user_id = lp.user_id AND v.branch = ? LIMIT 1)        AS sales_rep
    FROM events e
    JOIN lead_profiles lp ON lp.user_id = e.user_id
    WHERE e.event_type = 'branch_selected'
      AND (e.event_value = ? OR e.branch = ?)
    GROUP BY lp.user_id
    ORDER BY (visited_at IS NOT NULL) ASC, last_requested DESC
  `).all(branch, branch, branch, branch);

  // total branch_selected events for this branch (helps the admin debug
  // an id mismatch between ManyChat / Settings / the reception account)
  const totalForBranch = db.prepare(`
    SELECT COUNT(*) AS n FROM events
    WHERE event_type = 'branch_selected' AND (event_value = ? OR branch = ?)
  `).get(branch, branch).n;

  return res.json({ branch, count: rows.length, total: totalForBranch, leads: rows });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/sales/reps — list showroom salespeople (role='sales').
//   reception → locked to its own branch. admin → all or ?branch=
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/sales/reps', requireAuth, (req, res) => {
  const role = req.user?.role;
  if (!['reception', 'admin', 'sales'].includes(role)) {
    return res.status(403).json({ error: 'forbidden' });
  }
  const branch = role === 'reception' ? (req.user.branch || null) : (req.query.branch || null);
  const db = getDb();
  const rows = branch
    ? db.prepare(`SELECT name, branch FROM users WHERE role='sales' AND branch=? ORDER BY name`).all(branch)
    : db.prepare(`SELECT name, branch FROM users WHERE role='sales' ORDER BY name`).all();
  return res.json({ reps: rows });
});

// ════════════════════════════════════════════════════════════════════════════
// POST /api/visits/set-sales — reception attaches the salesperson who served.
// Body: { user_id, sales_rep }   (reception → own branch; admin → ?branch)
// ════════════════════════════════════════════════════════════════════════════
app.post('/api/visits/set-sales', requireAuth, (req, res) => {
  const role = req.user?.role;
  if (!['reception', 'admin'].includes(role)) {
    return res.status(403).json({ error: 'forbidden' });
  }
  const { user_id, sales_rep, branch: bodyBranch } = req.body || {};
  if (!user_id || !sales_rep) {
    return res.status(400).json({ error: 'user_id and sales_rep required' });
  }
  const branch = role === 'reception' ? (req.user.branch || null) : (bodyBranch || null);
  if (!branch) return res.status(400).json({ error: 'branch_required' });

  const db = getDb();
  // Attach to the existing visit row for this branch; create it if the
  // salesperson is being set without a prior confirm (robust).
  const existing = db.prepare(
    `SELECT id FROM lead_visits WHERE user_id=? AND branch=?`
  ).get(user_id, branch);
  if (existing) {
    db.prepare(`UPDATE lead_visits SET sales_rep=? WHERE id=?`).run(sales_rep, existing.id);
  } else {
    db.prepare(
      `INSERT INTO lead_visits (user_id, branch, sales_rep) VALUES (?,?,?)`
    ).run(user_id, branch, sales_rep);
  }
  console.log(`👥 SALES LINK: ${user_id} @ ${branch} → ${sales_rep}`);
  return res.json({ ok: true, user_id, branch, sales_rep });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/sales/my — a salesperson's own customers + this-month KPIs.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/sales/my', requireAuth, (req, res) => {
  if (req.user?.role !== 'sales') return res.status(403).json({ error: 'forbidden' });
  const me = req.user.name;
  const db = getDb();

  const customers = db.prepare(`
    SELECT
      lp.user_id, lp.first_name, lp.lead_class, lp.total_score, lp.last_activity,
      v.branch, v.visited_at,
      (SELECT GROUP_CONCAT(ph.phone, ' ، ') FROM lead_phones ph
         WHERE ph.user_id = lp.user_id)                                  AS phones,
      (SELECT COUNT(*)        FROM purchases p
         WHERE p.user_id = lp.user_id AND p.rep = ?)                      AS my_purchases,
      (SELECT COALESCE(SUM(p.price),0) FROM purchases p
         WHERE p.user_id = lp.user_id AND p.rep = ?)                      AS my_sales_total
    FROM lead_visits v
    JOIN lead_profiles lp ON lp.user_id = v.user_id
    WHERE v.sales_rep = ?
    ORDER BY (my_purchases > 0) ASC, v.visited_at DESC
  `).all(me, me, me);

  // This-month performance
  const servedMonth = db.prepare(`
    SELECT COUNT(DISTINCT user_id) AS n FROM lead_visits
    WHERE sales_rep = ? AND strftime('%Y-%m', visited_at) = strftime('%Y-%m','now')
  `).get(me).n;
  const boughtMonth = db.prepare(`
    SELECT COUNT(DISTINCT v.user_id) AS n
    FROM lead_visits v
    JOIN purchases p ON p.user_id = v.user_id AND p.rep = ?
    WHERE v.sales_rep = ?
      AND strftime('%Y-%m', p.created_at) = strftime('%Y-%m','now')
  `).get(me, me).n;
  const salesMonth = db.prepare(`
    SELECT COALESCE(SUM(price),0) AS total FROM purchases
    WHERE rep = ? AND strftime('%Y-%m', created_at) = strftime('%Y-%m','now')
  `).get(me).total;

  const kpis = {
    served_month:  servedMonth,
    bought_month:  boughtMonth,
    sales_month:   salesMonth,
    close_rate:    servedMonth ? Math.round((boughtMonth / servedMonth) * 100) : 0,
  };

  return res.json({ kpis, customers });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/sales/analytics — admin: per-salesperson + per-branch sales.
// Filters: ?sales= &branch= &from= &to=  (dates apply to visited_at)
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/sales/analytics', requireAuth, requireRole('admin'), (req, res) => {
  const db = getDb();
  const { sales, branch, from, to } = req.query;
  const where = [`v.sales_rep IS NOT NULL`];
  const params = [];
  if (sales)  { where.push(`v.sales_rep = ?`);              params.push(sales); }
  if (branch) { where.push(`v.branch = ?`);                 params.push(branch); }
  if (from)   { where.push(`date(v.visited_at) >= ?`);      params.push(from); }
  if (to)     { where.push(`date(v.visited_at) <= ?`);      params.push(to); }
  const clause = where.join(' AND ');

  const bySales = db.prepare(`
    SELECT
      v.sales_rep AS sales_rep,
      v.branch    AS branch,
      COUNT(DISTINCT v.user_id) AS served,
      COUNT(DISTINCT CASE WHEN p.user_id IS NOT NULL THEN v.user_id END) AS bought,
      COALESCE(SUM(DISTINCT_PRICE.amount),0) AS total_sales
    FROM lead_visits v
    LEFT JOIN purchases p
      ON p.user_id = v.user_id AND p.rep = v.sales_rep
    LEFT JOIN (
      SELECT user_id, rep, SUM(price) AS amount FROM purchases GROUP BY user_id, rep
    ) DISTINCT_PRICE ON DISTINCT_PRICE.user_id = v.user_id AND DISTINCT_PRICE.rep = v.sales_rep
    WHERE ${clause}
    GROUP BY v.sales_rep, v.branch
    ORDER BY total_sales DESC
  `).all(...params);

  const enriched = bySales.map(r => ({
    ...r,
    not_bought: r.served - r.bought,
    close_rate: r.served ? Math.round((r.bought / r.served) * 100) : 0,
  }));

  const byBranch = db.prepare(`
    SELECT v.branch AS branch,
      COUNT(DISTINCT v.user_id) AS served,
      COUNT(DISTINCT CASE WHEN p.user_id IS NOT NULL THEN v.user_id END) AS bought
    FROM lead_visits v
    LEFT JOIN purchases p ON p.user_id = v.user_id
    WHERE ${clause}
    GROUP BY v.branch
    ORDER BY bought DESC
  `).all(...params);

  return res.json({ bySales: enriched, byBranch });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/branch/overview — branch manager's read-only view of THEIR branch.
//   branch_manager → locked to its own branch. admin → ?branch=<id>
//   Returns branch KPIs + per-salesperson performance for that branch only.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/branch/overview', requireAuth, (req, res) => {
  const role = req.user?.role;
  if (role !== 'branch_manager' && role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  const branch = role === 'branch_manager'
    ? (req.user.branch || null)
    : (req.query.branch || null);
  if (!branch) return res.status(400).json({ error: 'branch_required' });

  const db = getDb();

  // Customers who requested this branch (branch_selected) — even if not visited
  const requested = db.prepare(`
    SELECT COUNT(DISTINCT user_id) AS n FROM events
    WHERE event_type = 'branch_selected' AND (event_value = ? OR branch = ?)
  `).get(branch, branch).n;

  // Customers who actually visited this branch (one row per user/branch)
  const visited = db.prepare(`
    SELECT COUNT(DISTINCT user_id) AS n FROM lead_visits WHERE branch = ?
  `).get(branch).n;

  // Per-salesperson performance in this branch (same logic as admin analytics)
  const bySales = db.prepare(`
    SELECT
      v.sales_rep AS sales_rep,
      COUNT(DISTINCT v.user_id) AS served,
      COUNT(DISTINCT CASE WHEN p.user_id IS NOT NULL THEN v.user_id END) AS bought,
      COALESCE(SUM(DP.amount),0) AS total_sales
    FROM lead_visits v
    LEFT JOIN purchases p ON p.user_id = v.user_id AND p.rep = v.sales_rep
    LEFT JOIN (
      SELECT user_id, rep, SUM(price) AS amount FROM purchases GROUP BY user_id, rep
    ) DP ON DP.user_id = v.user_id AND DP.rep = v.sales_rep
    WHERE v.branch = ? AND v.sales_rep IS NOT NULL
    GROUP BY v.sales_rep
    ORDER BY total_sales DESC
  `).all(branch).map(r => ({
    ...r,
    not_bought: r.served - r.bought,
    close_rate: r.served ? Math.round((r.bought / r.served) * 100) : 0,
  }));

  const served      = bySales.reduce((s, r) => s + r.served, 0);
  const bought      = bySales.reduce((s, r) => s + r.bought, 0);
  const totalSales  = bySales.reduce((s, r) => s + r.total_sales, 0);

  return res.json({
    branch,
    kpis: {
      requested,
      visited,
      bought,
      total_sales: totalSales,
      close_rate: served ? Math.round((bought / served) * 100) : 0,
    },
    bySales,
  });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/branch/customers — customers who requested this branch + follow-up status
//   branch_manager → locked to own branch. admin → ?branch=<id>
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/branch/customers', requireAuth, (req, res) => {
  const role = req.user?.role;
  if (role !== 'branch_manager' && role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  const branch = role === 'branch_manager'
    ? (req.user.branch || null)
    : (req.query.branch || null);
  if (!branch) return res.status(400).json({ error: 'branch_required' });

  const db = getDb();

  // Driven by events (same universe as the "عملاء طلبوا الفرع" KPI) so the
  // count matches it. lead_profiles is LEFT JOINed — a customer with a
  // branch_selected event but no profile row still shows up.
  const customers = db.prepare(`
    SELECT
      req.user_id,
      lp.first_name,
      COALESCE(lp.total_score, 0)    AS total_score,
      COALESCE(lp.lead_class, 'cold') AS lead_class,
      lp.last_activity,
      COALESCE(lp.visit_confirmed, 0) AS visit_confirmed,
      lp.last_product,
      lp.last_category,
      COALESCE(f.followed_up, 0)     AS followed_up,
      f.followed_up_at,
      f.followed_up_by
    FROM (
      SELECT DISTINCT user_id
      FROM events
      WHERE event_type = 'branch_selected'
        AND (event_value = ? OR branch = ?)
    ) req
    LEFT JOIN lead_profiles lp ON lp.user_id = req.user_id
    LEFT JOIN branch_customer_followups f
      ON f.user_id = req.user_id AND f.branch = ?
    ORDER BY COALESCE(lp.total_score, 0) DESC, lp.last_activity DESC
    LIMIT 200
  `).all(branch, branch, branch);

  return res.json({ branch, customers });
});

// ════════════════════════════════════════════════════════════════════════════
// PATCH /api/branch/customers/:userId/followup — toggle follow-up status
// ════════════════════════════════════════════════════════════════════════════
app.patch('/api/branch/customers/:userId/followup', requireAuth, (req, res) => {
  const role = req.user?.role;
  if (role !== 'branch_manager' && role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  const branch = role === 'branch_manager'
    ? (req.user.branch || null)
    : (req.body?.branch || null);
  if (!branch) return res.status(400).json({ error: 'branch_required' });

  const { userId } = req.params;
  const { followed_up } = req.body || {};
  const newVal = followed_up ? 1 : 0;

  const db = getDb();
  db.prepare(`
    INSERT INTO branch_customer_followups (branch, user_id, followed_up, followed_up_at, followed_up_by)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(branch, user_id) DO UPDATE SET
      followed_up    = excluded.followed_up,
      followed_up_at = excluded.followed_up_at,
      followed_up_by = excluded.followed_up_by
  `).run(branch, userId, newVal, newVal ? new Date().toISOString() : null, req.user?.name || null);

  return res.json({ ok: true, followed_up: newVal });
});

// ════════════════════════════════════════════════════════════════════════════
// POST /api/purchases — Sales rep records an offline purchase for a lead.
// Body: { user_id, product_id?, price?, branch?, notes? }
// Returns: { ok, purchase_id, lead_class }
// ════════════════════════════════════════════════════════════════════════════
app.post('/api/purchases', requireAuth, (req, res) => {
  const { user_id, product_id, price, branch, notes } = req.body || {};
  if (!user_id || typeof user_id !== 'string') {
    return res.status(400).json({ error: 'user_id is required' });
  }
  const db  = getDb();
  const rep = req.user?.name || req.headers['x-rep'] || null;

  const lead = db.prepare(`SELECT user_id FROM lead_profiles WHERE user_id = ?`).get(user_id);
  if (!lead) return res.status(404).json({ error: 'lead_not_found' });

  const result = db.prepare(`
    INSERT INTO purchases (user_id, product_id, price, branch, notes, rep)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(user_id, product_id || null, price || null, branch || null, notes || null, rep);

  // Mark lead as purchased (terminal state — won't be overridden by scoring)
  db.prepare(`
    UPDATE lead_profiles SET
      lead_class    = 'purchased',
      purchased_at  = CASE WHEN purchased_at IS NULL THEN datetime('now') ELSE purchased_at END,
      last_activity = datetime('now')
    WHERE user_id = ?
  `).run(user_id);

  console.log(`💰 PURCHASE: user:${user_id} product:${product_id || '?'} price:${price || '?'} rep:${rep || '?'}`);

  // Event-Triggered Flow: Purchase Made
  const purchaseFlowSetting = db.prepare(`SELECT value FROM settings WHERE key = 'manychat_purchase_flow'`).get();
  if (purchaseFlowSetting && purchaseFlowSetting.value && purchaseFlowSetting.value.trim() !== '') {
    getManyChatClient().sendFlow({ user_id, flow_id: purchaseFlowSetting.value.trim() })
      .catch(err => console.error('[Event-Trigger] Purchase Flow failed:', err.message));
  } else {
    console.warn('[Event-Trigger] ⚠️ Purchase recorded but manychat_purchase_flow is empty — no message sent. Set it in Settings → API.');
  }

  return res.json({ ok: true, purchase_id: result.lastInsertRowid, lead_class: 'purchased' });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/leads/:user_id/purchases — Purchase history for a lead
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/leads/:user_id/purchases', requireAuth, (req, res) => {
  const db = getDb();
  const purchases = db.prepare(`
    SELECT * FROM purchases WHERE user_id = ? ORDER BY created_at DESC
  `).all(req.params.user_id);
  return res.json({ purchases });
});

// ════════════════════════════════════════════════════════════════════════════
// Intelligence Layer — Additive endpoints
// All routes below are NEW. Existing endpoints above are unchanged.
// ════════════════════════════════════════════════════════════════════════════

// GET /api/predictions — Weekly visit forecast (next 7 days).
app.get('/api/predictions', requireAuth, (req, res) => {
  try {
    return res.json(predict());
  } catch (err) {
    console.error('[predictions]', err);
    return res.status(500).json({ error: 'prediction_failed' });
  }
});

// POST /api/trigger-message — Fire a ManyChat flow for a specific lead.
// Body: { user_id, action_type?, force? }
//   action_type: optional override; if omitted, the engine picks one from the
//                lead's current state.
//   force:       admin-only escape hatch for the 2/week cap.
//
// Identity is taken from the JWT (req.user) — NOT from client headers, which
// are spoofable. Only a real admin token can use force=true.
app.post('/api/trigger-message', requireAuth, async (req, res) => {
  try {
    const { user_id, action_type, force } = req.body || {};
    if (!user_id || typeof user_id !== 'string') {
      return res.status(400).json({ error: 'user_id is required' });
    }

    const db = getDb();
    const profile = db.prepare(`SELECT * FROM lead_profiles WHERE user_id = ?`).get(user_id);
    if (!profile) return res.status(404).json({ error: 'lead_not_found' });

    const role = String(req.user?.role || '').toLowerCase();
    const rep  = req.user?.name || null;
    const wantsForce = Boolean(force) && role === 'admin';

    const gate = canSend(user_id, { force: wantsForce });
    if (!gate.ok) {
      return res.status(429).json({ error: gate.reason, state: gate.state });
    }

    // Pick action: caller-supplied wins, otherwise let the engine decide.
    let chosenAction = action_type;
    let chosenFlow   = action_type ? flowIdFor(action_type) : null;
    if (!chosenAction) {
      const decision = decide(profile);
      chosenAction = decision.action_type;
      chosenFlow   = decision.flow_id;
    }
    if (!chosenAction || chosenAction === 'none' || !chosenFlow) {
      return res.status(400).json({ error: 'no_action_available' });
    }

    const client = getManyChatClient();
    await client.sendFlow({ user_id, flow_id: chosenFlow });

    db.prepare(`
      INSERT INTO messages_sent (user_id, sent_by_rep, action_type, flow_id, message_text)
      VALUES (?, ?, ?, ?, ?)
    `).run(user_id, rep, chosenAction, chosenFlow, null);

    const newState = recordSend(user_id);

    return res.json({
      ok: true,
      action_type:     chosenAction,
      flow_id:         chosenFlow,
      sends_this_week: newState.sends_this_week,
      last_sent_at:    newState.last_sent_at,
    });
  } catch (err) {
    console.error('[trigger-message]', err);
    return res.status(500).json({ error: 'trigger_failed' });
  }
});

// GET /api/follow-up-state/:user_id — Weekly counter snapshot for a lead.
// Cheap call the dashboard can use to render the "X/2 sent this week" badge
// without a full lead refresh.
app.get('/api/follow-up-state/:user_id', requireAuth, (req, res) => {
  try {
    const state = getStateRotated(req.params.user_id);
    return res.json({ state });
  } catch (err) {
    console.error('[follow-up-state]', err);
    return res.status(500).json({ error: 'state_failed' });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/analytics — Date-filtered analytics
// Query: from (YYYY-MM-DD), to (YYYY-MM-DD), branch, campaign
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/analytics', requireAuth, requireRole('admin'), (req, res) => {
  const db = getDb();
  const { from, to, branch, campaign } = req.query;
  const fromDate = from || new Date(Date.now() - 30 * 86400000).toISOString().split('T')[0];
  const toDate   = to   || new Date().toISOString().split('T')[0];

  // Build optional filter clauses
  const branchClause   = branch   ? `AND lp.preferred_branch = ?` : '';
  const campaignClause = campaign ? `AND lp.campaign_source = ?`  : '';
  const branchParam    = branch   ? [branch]   : [];
  const campaignParam  = campaign ? [campaign] : [];

  // Daily events by type
  const eventsSeries = db.prepare(`
    SELECT date(e.created_at) AS day, e.event_type, COUNT(*) AS count
    FROM events e
    JOIN lead_profiles lp ON e.user_id = lp.user_id
    WHERE date(e.created_at) BETWEEN ? AND ?
      ${branchClause} ${campaignClause}
    GROUP BY day, e.event_type
    ORDER BY day
  `).all(fromDate, toDate, ...branchParam, ...campaignParam);

  // Funnel snapshot for leads created in range
  const funnel = db.prepare(`
    SELECT
      COUNT(DISTINCT lp.user_id)                                                     AS total_leads,
      SUM(CASE WHEN lp.lead_class = 'hot'                                  THEN 1 ELSE 0 END) AS hot,
      SUM(CASE WHEN lp.lead_class IN ('visited','purchased','converted')    THEN 1 ELSE 0 END) AS visited,
      SUM(CASE WHEN lp.lead_class = 'purchased'                            THEN 1 ELSE 0 END) AS purchased
    FROM lead_profiles lp
    WHERE date(lp.created_at) BETWEEN ? AND ?
      ${branchClause} ${campaignClause}
  `).get(fromDate, toDate, ...branchParam, ...campaignParam);

  // Top products in range — DISTINCT customers (not raw repeated views)
  const topProducts = db.prepare(`
    SELECT e.event_value AS product, COUNT(DISTINCT e.user_id) AS views
    FROM events e
    JOIN lead_profiles lp ON e.user_id = lp.user_id
    WHERE e.event_type = 'product_details'
      AND date(e.created_at) BETWEEN ? AND ?
      ${branchClause} ${campaignClause}
    GROUP BY e.event_value
    ORDER BY views DESC
    LIMIT 10
  `).all(fromDate, toDate, ...branchParam, ...campaignParam);

  // ── Category demand breakdown ─────────────────────────────────────────
  // Each category's total interest: product views + category picks + how
  // many distinct customers and distinct models were involved.
  const categories = db.prepare(`
    SELECT
      e.category                                                       AS category,
      COUNT(DISTINCT CASE WHEN e.event_type = 'product_details'
                          THEN e.user_id END)                          AS product_views,
      COUNT(DISTINCT CASE WHEN e.event_type = 'category_request'
                          THEN e.user_id END)                          AS category_requests,
      COUNT(DISTINCT e.user_id)                                        AS unique_users,
      COUNT(DISTINCT CASE WHEN e.event_type = 'product_details'
                          THEN e.event_value END)                      AS models_viewed
    FROM events e
    JOIN lead_profiles lp ON e.user_id = lp.user_id
    WHERE e.category IS NOT NULL AND e.category != ''
      AND e.event_type IN ('product_details','category_request')
      AND date(e.created_at) BETWEEN ? AND ?
      ${branchClause} ${campaignClause}
    GROUP BY e.category
    ORDER BY product_views DESC, category_requests DESC
  `).all(fromDate, toDate, ...branchParam, ...campaignParam);

  // ── Top products PER category ─────────────────────────────────────────
  // Full per-model ranking inside each category (no LIMIT — the UI can
  // show the top 50 of غرف النوم, top 50 of السفرة … independently).
  const productsByCategoryRows = db.prepare(`
    SELECT
      e.category    AS category,
      e.event_value AS product,
      COUNT(DISTINCT e.user_id) AS views,
      COUNT(DISTINCT e.user_id) AS unique_users
    FROM events e
    JOIN lead_profiles lp ON e.user_id = lp.user_id
    WHERE e.event_type = 'product_details'
      AND e.category IS NOT NULL AND e.category != ''
      AND e.event_value IS NOT NULL
      AND date(e.created_at) BETWEEN ? AND ?
      ${branchClause} ${campaignClause}
    GROUP BY e.category, e.event_value
    ORDER BY e.category, views DESC
  `).all(fromDate, toDate, ...branchParam, ...campaignParam);

  // Nest products under their category for the frontend
  const productsByCategory = {};
  for (const row of productsByCategoryRows) {
    if (!productsByCategory[row.category]) productsByCategory[row.category] = [];
    productsByCategory[row.category].push({
      product: row.product,
      views: row.views,
      unique_users: row.unique_users,
    });
  }

  // Campaigns in range
  const branchOnlyClause   = branch   ? `AND lp.preferred_branch = ?` : '';
  const campaignOnlyClause = campaign ? `AND lp.campaign_source = ?`  : '';
  const campaigns = db.prepare(`
    SELECT
      lp.campaign_source,
      COUNT(DISTINCT lp.user_id)                                                                AS leads,
      SUM(CASE WHEN lp.lead_class IN ('visited','purchased','converted') THEN 1 ELSE 0 END)    AS visits,
      SUM(CASE WHEN lp.lead_class = 'purchased'                         THEN 1 ELSE 0 END)     AS purchases
    FROM lead_profiles lp
    WHERE lp.campaign_source IS NOT NULL
      AND date(lp.created_at) BETWEEN ? AND ?
      ${branchOnlyClause}
    GROUP BY lp.campaign_source
    ORDER BY leads DESC
  `).all(fromDate, toDate, ...branchParam);

  // ── Ad funnel — per campaign+ad, how far did customers get? ───────────
  // The key question: each ad reached how many customers up to
  // location_request (the strongest pre-visit buying signal).
  const adFunnel = db.prepare(`
    SELECT
      COALESCE(lp.campaign_source, 'بدون حملة')                              AS campaign_source,
      COALESCE(lp.ad_id, '—')                                               AS ad_id,
      COUNT(DISTINCT lp.user_id)                                            AS leads,
      SUM(CASE WHEN lp.product_view_count > 0 THEN 1 ELSE 0 END)            AS product_viewers,
      SUM(CASE WHEN lp.location_requested = 1 THEN 1 ELSE 0 END)            AS location_requests,
      SUM(CASE WHEN lp.lead_class IN ('visited','purchased','converted')
               THEN 1 ELSE 0 END)                                          AS visited,
      SUM(CASE WHEN lp.lead_class = 'purchased' THEN 1 ELSE 0 END)         AS purchased
    FROM lead_profiles lp
    WHERE lp.campaign_source IS NOT NULL
      AND date(lp.created_at) BETWEEN ? AND ?
      ${branchOnlyClause}
    GROUP BY lp.campaign_source, lp.ad_id
    ORDER BY location_requests DESC, leads DESC
  `).all(fromDate, toDate, ...branchParam);

  // Branch breakdown in range
  const branches = db.prepare(`
    SELECT
      lp.preferred_branch AS branch,
      COUNT(DISTINCT lp.user_id)                                                             AS leads,
      SUM(CASE WHEN lp.lead_class IN ('visited','purchased','converted') THEN 1 ELSE 0 END) AS visits
    FROM lead_profiles lp
    WHERE lp.preferred_branch IS NOT NULL
      AND date(lp.created_at) BETWEEN ? AND ?
      ${campaignOnlyClause}
    GROUP BY lp.preferred_branch
    ORDER BY leads DESC
  `).all(fromDate, toDate, ...campaignParam);

  return res.json({
    eventsSeries,
    funnel:      funnel || { total_leads: 0, hot: 0, visited: 0, purchased: 0 },
    topProducts,
    categories,
    productsByCategory,
    campaigns,
    adFunnel,
    branches,
    meta: { from: fromDate, to: toDate, branch: branch || null, campaign: campaign || null },
  });
});

// ════════════════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════════════════
// GET /api/reps — Returns name list of all sales reps (role != admin).
// Accessible to ALL authenticated users (reps need it for RepSelector + leaderboard).
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/reps', requireAuth, (req, res) => {
  const db   = getDb();
  const reps = db.prepare(
    `SELECT name FROM users WHERE role != 'admin' ORDER BY name`
  ).all().map(r => r.name);
  return res.json({ reps });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/branches  — returns active branches [{id, name}] (any auth user)
// PUT /api/branches  — replaces the full branches list (admin only)
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/branches', requireAuth, (req, res) => {
  const db  = getDb();
  const row = db.prepare(`SELECT value FROM settings WHERE key = 'active_branches'`).get();
  let branches = [];
  try {
    const parsed = JSON.parse(row?.value || '[]');
    // Support both legacy string[] and new {id,name}[] formats
    branches = parsed.map(b =>
      typeof b === 'string' ? { id: b, name: b } : b
    );
  } catch (_) { branches = []; }

  // Also include branches that ACTUALLY appear in branch_selected events —
  // so filters always match real data even if the configured id differs
  // from what ManyChat sent (fysal vs faisal vs Arabic, etc.).
  try {
    const seen = db.prepare(`
      SELECT DISTINCT COALESCE(NULLIF(event_value,''), branch) AS b
      FROM events
      WHERE event_type = 'branch_selected'
        AND COALESCE(NULLIF(event_value,''), branch) IS NOT NULL
    `).all().map(r => r.b);
    const known = new Set(branches.map(x => x.id));
    for (const b of seen) {
      if (!known.has(b)) { branches.push({ id: b, name: b }); known.add(b); }
    }
  } catch (_) { /* events table edge — ignore */ }

  return res.json({ branches });
});

app.put('/api/branches', requireAuth, requireRole('admin'), (req, res) => {
  const { branches } = req.body || {};
  if (!Array.isArray(branches)) {
    return res.status(400).json({ error: 'branches must be an array' });
  }
  // Validate each entry has id & name
  for (const b of branches) {
    if (!b.id || !b.name) {
      return res.status(400).json({ error: 'each branch must have id and name' });
    }
  }
  const db = getDb();
  db.prepare(`
    INSERT INTO settings (key, value, updated_at) VALUES ('active_branches', ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
  `).run(JSON.stringify(branches));
  return res.json({ ok: true, branches });
});

// Settings endpoints — GET /api/settings, PUT /api/settings/:key
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/settings', requireAuth, requireRole('admin'), (req, res) => {
  const db   = getDb();
  const rows = db.prepare(`SELECT key, value FROM settings`).all();
  return res.json(Object.fromEntries(rows.map(r => [r.key, r.value])));
});

// ── Integration status — drives the dashboard ManyChat banner ────────────────
// Admin-only (exposes the webhook secret so it can be pasted into ManyChat).
app.get('/api/integration-status', requireAuth, requireRole('admin'), (req, res) => {
  const apiKey = (getSetting('manychat_api_key') || '').trim();
  const flowKeys = [
    'manychat_flow_immediate', 'manychat_flow_branch_info',
    'manychat_flow_offer',     'manychat_flow_reengage',
    'manychat_visit_flow',     'manychat_purchase_flow',
    'manychat_reminder_flow',
  ];
  const missing_flows = flowKeys.filter(k => !(getSetting(k) || '').trim());

  return res.json({
    manychat: apiKey ? 'live' : 'mock',
    missing_flows,
    webhook: {
      secret:   process.env.WEBHOOK_SECRET || getSetting('webhook_secret') || '',
      enforced: getSetting('webhook_enforce', 'false') === 'true',
      from_env: !!process.env.WEBHOOK_SECRET,
    },
  });
});

app.put('/api/settings/:key', requireAuth, requireRole('admin'), (req, res) => {
  const { key }   = req.params;
  const { value } = req.body || {};
  if (value === undefined || value === null) {
    return res.status(400).json({ error: 'value is required' });
  }
  const db = getDb();
  db.prepare(`
    INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
  `).run(key, String(value));
  return res.json({ ok: true });
});

// ════════════════════════════════════════════════════════════════════════════
// User management — GET/POST /api/users, PUT /api/users/:id  (admin only)
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/users', requireAuth, requireRole('admin'), (req, res) => {
  const db    = getDb();
  const users = db.prepare(
    `SELECT id, name, email, role, branch, created_at FROM users ORDER BY created_at`
  ).all();
  return res.json(users);
});

app.post('/api/users', requireAuth, requireRole('admin'), (req, res) => {
  const { name, email, password, role = 'rep', branch } = req.body || {};
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'name, email, and password are required' });
  }
  // Branch only meaningful for reception accounts
  const branchVal = ['reception', 'sales', 'branch_manager'].includes(role) ? (branch || null) : null;
  const db   = getDb();
  const hash = bcrypt.hashSync(password, 10);
  try {
    const result = db.prepare(
      `INSERT INTO users (name, email, password_hash, role, branch) VALUES (?, ?, ?, ?, ?)`
    ).run(name, email, hash, role, branchVal);
    return res.json({ id: result.lastInsertRowid, name, email, role, branch: branchVal });
  } catch (e) {
    if (e.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'البريد الإلكتروني مستخدم مسبقاً' });
    }
    throw e;
  }
});

app.put('/api/users/:id', requireAuth, requireRole('admin'), (req, res) => {
  const { name, email, role, password, branch } = req.body || {};
  const db      = getDb();
  const updates = [];
  const params  = [];

  if (name)     { updates.push('name = ?');          params.push(name); }
  if (email)    { updates.push('email = ?');         params.push(email); }
  if (role)     { updates.push('role = ?');          params.push(role); }
  if (password) { updates.push('password_hash = ?'); params.push(bcrypt.hashSync(password, 10)); }
  // Set branch for reception accounts; clear it for any other role
  if (role)     { updates.push('branch = ?');        params.push(['reception','sales','branch_manager'].includes(role) ? (branch || null) : null); }
  else if (branch !== undefined) { updates.push('branch = ?'); params.push(branch || null); }

  if (!updates.length) {
    return res.status(400).json({ error: 'Nothing to update' });
  }
  params.push(req.params.id);
  db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...params);
  return res.json({ ok: true });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /health — Health check
// ════════════════════════════════════════════════════════════════════════════
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ── Background Jobs ───────────────────────────────────────────────────────
function runAbandonedIntentJob() {
  try {
    const db = getDb();
    const reminderFlowSetting = db.prepare(`SELECT value FROM settings WHERE key = 'manychat_reminder_flow'`).get();
    
    if (!reminderFlowSetting || !reminderFlowSetting.value || reminderFlowSetting.value.trim() === '') {
      console.warn('[Scheduler] ⚠️ Abandoned-intent job skipped — manychat_reminder_flow is empty. Set it in Settings → API.');
      return; // No flow configured
    }

    // Find leads who requested location > 3 days ago, haven't visited, and haven't been reminded
    const targets = db.prepare(`
      SELECT user_id 
      FROM lead_profiles 
      WHERE location_requested = 1 
        AND visit_confirmed = 0 
        AND location_reminder_sent IS NULL 
        AND last_activity < datetime('now', '-3 days')
    `).all();

    for (const target of targets) {
      getManyChatClient().sendFlow({ user_id: target.user_id, flow_id: reminderFlowSetting.value.trim() })
        .then(() => {
          db.prepare(`UPDATE lead_profiles SET location_reminder_sent = datetime('now') WHERE user_id = ?`)
            .run(target.user_id);
          console.log(`[Cron] Sent abandoned intent reminder to ${target.user_id}`);
        })
        .catch(err => console.error(`[Cron] Failed to send reminder to ${target.user_id}:`, err.message));
    }
  } catch (err) {
    console.error('[Cron] Error running abandoned intent job:', err);
  }
}

// Run once on startup after 5 seconds, then every 1 hour
setTimeout(() => {
  runAbandonedIntentJob();
  setInterval(runAbandonedIntentJob, 60 * 60 * 1000);
}, 5000);

// ── Global Error Handler ──────────────────────────────────────────────────
// Any error thrown/forwarded in a route lands here → clean JSON, no crash.
// MUST be registered after all routes.
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err && err.message === 'Not allowed by CORS') {
    return res.status(403).json({ success: false, error: 'cors_forbidden' });
  }
  console.error('[UNHANDLED]', req.method, req.path, '-', err && err.stack ? err.stack : err);
  return res.status(500).json({ success: false, error: 'internal_error' });
});

// Last-resort safety nets — log instead of crashing the process.
process.on('unhandledRejection', (reason) => {
  console.error('[unhandledRejection]', reason);
});
process.on('uncaughtException', (err) => {
  console.error('[uncaughtException]', err && err.stack ? err.stack : err);
});

// ── Start Server ──────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log('');
  console.log('🛋️  Grand Furniture Backend — Running');
  console.log(`🌐  URL:     http://localhost:${PORT}`);
  console.log(`📡  Webhook: http://localhost:${PORT}/api/events`);
  console.log(`📊  Dashboard API: http://localhost:${PORT}/api/dashboard`);
  console.log('');
  // Initialize DB on startup
  getDb();
});

module.exports = app;
