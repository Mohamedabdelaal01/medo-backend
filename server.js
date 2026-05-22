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
const { requireAuth, requireRole, authorizeRoles, getJwtSecret } = require('./middleware/auth');

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

// ── Branch normalization ──────────────────────────────────────────────────────
// ManyChat sends the same branch under inconsistent ids across different
// External Request blocks (Arabic free text, English slug, alt spellings like
// "fysal" vs "faisal"). Without this, one physical branch lands in the DB under
// several keys and the dashboard counts it as multiple branches.
// Maps any known variant → a single canonical slug. Unknown values pass through
// unchanged so new branches still work without a code change.
const BRANCH_ALIASES = {
  nasr_city: ['nasr_city', 'nasrcity', 'nasr city', 'نصر سيتي', 'نصرسيتي', 'مدينة نصر'],
  maadi:     ['maadi', 'el maadi', 'المعادي', 'معادي'],
  helwan:    ['helwan', 'حلوان'],
  faisal:    ['faisal', 'fysal', 'fysl', 'fisal', 'faysal', 'فيصل'],
  ain_shams: ['ain_shams', 'ain shams', 'ainshams', 'ein shams', 'shams', 'عين شمس', 'عينشمس', 'شمس'],
};
const _branchAliasLookup = (() => {
  const m = new Map();
  for (const [canonical, aliases] of Object.entries(BRANCH_ALIASES)) {
    for (const a of aliases) m.set(a.toLowerCase().replace(/\s+/g, ' ').trim(), canonical);
  }
  return m;
})();
function normalizeBranch(raw) {
  if (raw == null) return null;
  const key = String(raw).toLowerCase().replace(/\s+/g, ' ').trim();
  if (!key) return null;
  return _branchAliasLookup.get(key) || String(raw).trim();
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
      WHERE u.role IN ('sales', 'rep')
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
  const secret  = process.env.WEBHOOK_SECRET || getSetting('webhook_secret');
  const enforce = getSetting('webhook_enforce', 'false') === 'true';

  if (!enforce || !secret) return next();

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

  if (user.active === 0) {
    return res.status(403).json({ error: 'الحساب موقوف — كلّم مدير الفرع أو مدير النظام' });
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
    // ── Enrichment fields (optional — captured if ManyChat sends them) ──
    last_name,
    gender,
    locale,
    timezone,
    last_input_text,
    subscribed_at,
    growth_tool_id,
    source: manychat_source,
  } = req.body;

  // Detect unresolved ManyChat user_field placeholders (e.g. "{{cuf_14597615}}")
  // — these mean the External Request reference is wrong on the ManyChat side
  // and we should treat the value as missing rather than store garbage.
  const isBrokenPlaceholder = (v) => typeof v === 'string' && /^\{\{[^}]+\}\}$/.test(v.trim());
  const cleanCampaignSource = isBrokenPlaceholder(campaign_source) ? null : campaign_source;
  const cleanAdId           = isBrokenPlaceholder(ad_id)           ? null : ad_id;
  const cleanVisitCode      = isBrokenPlaceholder(visit_code)      ? null : visit_code;
  if (isBrokenPlaceholder(campaign_source) || isBrokenPlaceholder(ad_id)) {
    console.warn(`[events] broken placeholder from ManyChat — user_id=${user_id}, event=${event_type}, campaign_source=${campaign_source}, ad_id=${ad_id}`);
  }

  // Canonical phone (used as the reception lookup key — replaces visit code)
  const normPhone = normalizePhone(phone);

  // Build an extra_fields JSON of anything that isn't already a first-class
  // column. Lets us capture future ManyChat additions without another
  // schema migration.
  const KNOWN_FIELDS = new Set([
    'user_id','first_name','event_type','event_value','session_count','current_score',
    'campaign_source','ad_id','visit_code','phone','product','category',
    'last_name','gender','locale','timezone','last_input_text','subscribed_at',
    'growth_tool_id','source','branch','event_id',
  ]);
  const extraFields = {};
  for (const k of Object.keys(req.body || {})) {
    if (!KNOWN_FIELDS.has(k)) extraFields[k] = req.body[k];
  }
  const extraFieldsJson = Object.keys(extraFields).length ? JSON.stringify(extraFields) : null;

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
    `).run(user_id, first_name || 'Unknown', cleanCampaignSource || null, cleanAdId || null, cleanVisitCode || null, normPhone || null);

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
  // Only treat event_value as a branch for location/branch events — for other
  // events (e.g. product_details) event_value carries a product name, not a
  // branch, so we keep the existing preferred_branch instead.
  const detectedBranch = visitPayload?.branch
    ? normalizeBranch(visitPayload.branch)
    : (isLocationEvent && event_value)
      ? normalizeBranch(event_value)
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
      -- ManyChat enrichment fields (only fill if not already set)
      last_name           = COALESCE(?, last_name),
      gender              = COALESCE(?, gender),
      locale              = COALESCE(?, locale),
      timezone            = COALESCE(?, timezone),
      last_input_text     = COALESCE(?, last_input_text),  -- newest typed text wins
      subscribed_at       = COALESCE(subscribed_at, ?),
      growth_tool_id      = COALESCE(growth_tool_id, ?),
      manychat_source     = COALESCE(?, manychat_source),
      extra_fields        = COALESCE(?, extra_fields),
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
    cleanCampaignSource || null,
    cleanAdId || null,
    cleanVisitCode || null,
    normPhone || null,
    // ManyChat enrichment fields
    last_name || null,
    gender || null,
    locale || null,
    timezone || null,
    last_input_text || null,
    subscribed_at || null,
    growth_tool_id || null,
    manychat_source || null,
    extraFieldsJson,
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
      COALESCE(NULLIF(branch,''), event_value) AS branch,
      COUNT(DISTINCT user_id) AS requests
    FROM events
    WHERE event_type IN ('branch_selected', 'location_request')
      AND COALESCE(NULLIF(branch,''), event_value) IS NOT NULL
    GROUP BY COALESCE(NULLIF(branch,''), event_value)
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
           preferred_branch, last_product, last_category, last_activity,
           visit_confirmed, location_requested,
           session_count, product_view_count, last_input_text,
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

  // Distinct customers who have shared at least one phone number — used by
  // admin Customers analytics to compute phone-collection coverage.
  const withPhonesCount = db.prepare(
    `SELECT COUNT(DISTINCT user_id) AS count FROM lead_phones`
  ).get();

  const responseData = {
    summary: {
      total_leads:        totalLeads.count,
      hot_leads_today:    hotToday.count,
      visits_confirmed:   visitConfirmed.count,
      visits_today:       visitsToday.count,
      visits_this_week:   visitsThisWeek.count,
      conversion_to_visit: conversionToVisit,
      lead_distribution:  leadCounts,
      with_phones_count:  withPhonesCount.count,
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
    has_phone,        // 'yes' → left a phone | 'no' → never left one
    registration,     // 'manual' → reception walk-in | 'online' → via ManyChat
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

  if (leadClass === 'lost') {
    // 'lost' isn't a lead_class — it's the post-visit revisit status.
    where += ` AND revisit_status = 'lost'`;
  } else if (leadClass) {
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
    // Search by customer name OR contract number. Contract-number matches are
    // RBAC-scoped: a sales rep only matches their OWN sales, a branch manager
    // only their branch, an admin sees all.
    const like = `%${search}%`;
    let contractRbac = '';
    const contractRbacParams = [];
    if (req.user.role === 'branch_manager') {
      contractRbac = ` AND branch = ?`;
      contractRbacParams.push(req.user.branch || '');
    } else if (req.user.role !== 'admin') {
      contractRbac = ` AND rep = ?`;
      contractRbacParams.push(req.user.name);
    }
    where += ` AND (first_name LIKE ? OR user_id IN (
      SELECT user_id FROM purchases WHERE contract_number LIKE ?${contractRbac}
    ))`;
    params.push(like, like, ...contractRbacParams);
  }
  // Filter by whether the customer ever left a phone number — a phone on the
  // profile OR any row in lead_phones counts as "left a phone".
  if (has_phone === 'yes') {
    where += ` AND ((phone IS NOT NULL AND phone != '')
      OR user_id IN (SELECT user_id FROM lead_phones))`;
  } else if (has_phone === 'no') {
    where += ` AND (phone IS NULL OR phone = '')
      AND user_id NOT IN (SELECT user_id FROM lead_phones)`;
  }
  // Filter by how the customer was registered — reception walk-in vs ManyChat.
  if (registration === 'manual') {
    where += ` AND manychat_source = 'walkin'`;
  } else if (registration === 'online') {
    where += ` AND (manychat_source IS NULL OR manychat_source != 'walkin')`;
  }

  // Total count for pagination metadata
  const total = db.prepare(`SELECT COUNT(*) as n FROM lead_profiles ${where}`).get(...params).n;

  const leads = db.prepare(`
    SELECT lead_profiles.*,
      (SELECT COALESCE(NULLIF(e.branch,''), e.event_value)
         FROM events e
         WHERE e.user_id = lead_profiles.user_id
           AND e.event_type = 'branch_selected'
           AND COALESCE(NULLIF(e.branch,''), e.event_value) IS NOT NULL
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
      COALESCE(NULLIF(branch,''), event_value) AS branch,
      MIN(created_at) AS first_at,
      MAX(created_at) AS last_at
    FROM events
    WHERE user_id = ? AND event_type = 'branch_selected'
      AND COALESCE(NULLIF(branch,''), event_value) IS NOT NULL
    GROUP BY COALESCE(NULLIF(branch,''), event_value)
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

  // Follow-up activity (assignment + completed-call history). Visible to
  // admin/rep (all branches), branch_manager (own branch only), reception
  // (own branch only). The sales role sees their own branch too.
  const scopeBranch =
    (req.user?.role === 'branch_manager' || req.user?.role === 'reception' || req.user?.role === 'sales')
      ? (req.user.branch || null)
      : null;

  let followups = db.prepare(
    `SELECT branch, assigned_sales, assigned_by, assigned_at,
            followed_up, followed_up_by, followed_up_at, call_summary
       FROM branch_customer_followups WHERE user_id = ?`
  ).all(user_id);
  let followupLog = db.prepare(
    `SELECT branch, sales, call_summary, followed_up_at
       FROM followup_log WHERE user_id = ? ORDER BY followed_up_at DESC`
  ).all(user_id);
  if (scopeBranch) {
    followups   = followups.filter(f => f.branch === scopeBranch);
    followupLog = followupLog.filter(l => l.branch === scopeBranch);
  }

  return res.json({ profile, history, phones, visits, requestedBranches, followups, followupLog });
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

  // Resurrect a "lost" lead — they were closed in the re-visit funnel but
  // walked back into the showroom, so put them back in the follow-up queue.
  const revisitRow = db.prepare(
    `SELECT revisit_status FROM lead_profiles WHERE user_id = ?`
  ).get(lead.user_id);
  const wasLostAndReturned = revisitRow?.revisit_status === 'lost';
  if (wasLostAndReturned) {
    db.prepare(`
      UPDATE lead_profiles SET
        revisit_status     = NULL,
        revisit_note       = 'العميل عاد وزار المعرض مرة أخرى بعد إغلاقه',
        revisit_updated_at = datetime('now')
      WHERE user_id = ?
    `).run(lead.user_id);
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

  // Who followed this lead up online before the visit — so reception can see
  // the pre-visit rep but still pick the actual showroom rep manually.
  const preVisitRow = visitBranch
    ? db.prepare(
        `SELECT assigned_sales FROM branch_customer_followups WHERE user_id = ? AND branch = ?`
      ).get(lead.user_id, visitBranch)
    : null;

  // The showroom rep who served this customer on their most recent prior visit.
  const lastShowroomRow = db.prepare(`
    SELECT sales_rep FROM lead_visits
    WHERE user_id = ? AND sales_rep IS NOT NULL
    ORDER BY visited_at DESC LIMIT 1
  `).get(lead.user_id);

  return res.json({
    ok:                   true,
    user_id:              lead.user_id,
    first_name:           lead.first_name || 'غير معروف',
    campaign_source:      lead.campaign_source || null,
    branch:               visitBranch || null,
    lead_class:           newClass,
    pre_visit_rep:        preVisitRow?.assigned_sales || null,
    last_showroom_rep:    lastShowroomRow?.sales_rep || null,
    was_lost_and_returned: wasLostAndReturned,
  });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/reception/leads — customers who requested THIS branch's address.
// reception role → locked to its own branch. admin → ?branch=<id> required.
// Shows everyone who picked the branch (branch_selected event) even if they
// haven't visited yet; visited_here flags who already came.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/reception/leads', requireAuth, authorizeRoles('reception', 'admin'), (req, res) => {
  const role = req.user?.role;
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
         WHERE v.user_id = lp.user_id AND v.branch = ? LIMIT 1)        AS sales_rep,
      f.assigned_sales AS pre_visit_rep,
      f.followed_up,
      (SELECT v2.sales_rep FROM lead_visits v2
         WHERE v2.user_id = lp.user_id AND v2.sales_rep IS NOT NULL
         ORDER BY v2.visited_at DESC LIMIT 1)                          AS last_showroom_rep
    FROM events e
    JOIN lead_profiles lp ON lp.user_id = e.user_id
    LEFT JOIN branch_customer_followups f
      ON f.user_id = lp.user_id AND f.branch = ?
    WHERE e.event_type = 'branch_selected'
      AND (e.event_value = ? OR e.branch = ?)
    GROUP BY lp.user_id
    ORDER BY (visited_at IS NOT NULL) ASC, last_requested DESC
  `).all(branch, branch, branch, branch, branch);

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
app.get('/api/sales/reps', requireAuth, authorizeRoles('reception', 'admin', 'sales'), (req, res) => {
  const role = req.user?.role;
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
app.post('/api/visits/set-sales', requireAuth, authorizeRoles('reception', 'admin'), (req, res) => {
  const role = req.user?.role;
  const { user_id, sales_rep, branch: bodyBranch } = req.body || {};
  if (!user_id || !sales_rep) {
    return res.status(400).json({ error: 'user_id and sales_rep required' });
  }
  const branch = role === 'reception' ? (req.user.branch || null) : (bodyBranch || null);
  if (!branch) return res.status(400).json({ error: 'branch_required' });

  const db = getDb();

  // Step A — who followed this lead up online BEFORE the visit.
  const fuRow = db.prepare(
    `SELECT assigned_sales FROM branch_customer_followups WHERE user_id = ? AND branch = ?`
  ).get(user_id, branch);
  const preVisitRep = fuRow?.assigned_sales || null;

  // Step B — store BOTH the showroom rep and the pre-visit rep on the visit.
  // Create the row if the salesperson is set without a prior confirm (robust).
  // Full old row captured for the audit/undo ledger.
  const existing = db.prepare(
    `SELECT * FROM lead_visits WHERE user_id=? AND branch=?`
  ).get(user_id, branch);
  if (existing) {
    db.prepare(`UPDATE lead_visits SET sales_rep=?, pre_visit_rep=? WHERE id=?`)
      .run(sales_rep, preVisitRep, existing.id);
  } else {
    db.prepare(
      `INSERT INTO lead_visits (user_id, branch, sales_rep, pre_visit_rep) VALUES (?,?,?,?)`
    ).run(user_id, branch, sales_rep, preVisitRep);
  }

  // Step C — handoff: the pre-visit rep is NOT the showroom rep. Log the
  // handoff and move the follow-up record over to the showroom rep.
  if (preVisitRep && preVisitRep !== sales_rep) {
    const logSummary = `العميل زار الفرع. تابعه قبل الزيارة [${preVisitRep}]، ولكن استقبله في الصالة [${sales_rep}].`;
    logFollowup(db, branch, user_id, sales_rep, logSummary);
    db.prepare(`
      UPDATE branch_customer_followups SET
        assigned_sales = ?,
        assigned_by    = ?,
        followed_up    = 0,
        followed_up_at = NULL,
        call_summary   = ?
      WHERE branch = ? AND user_id = ?
    `).run(sales_rep, req.user?.name || null, logSummary, branch, user_id);
  }

  auditLog(db, req.user?.name, 'set_sales', user_id, {
    table: 'lead_visits',
    where: { user_id, branch },
    row:   existing || null,
  });

  console.log(`👥 SALES LINK: ${user_id} @ ${branch} → ${sales_rep}` +
    (preVisitRep && preVisitRep !== sales_rep ? ` (pre-visit: ${preVisitRep})` : ''));
  return res.json({ ok: true, user_id, branch, sales_rep, pre_visit_rep: preVisitRep });
});

// ════════════════════════════════════════════════════════════════════════════
// POST /api/reception/walkin — register a walk-in customer who never came
// through ManyChat (found us on the street / by referral, etc.). Reception
// captures name + phone + interest + source, and the customer is created as a
// normal confirmed-visit lead so the rest of the system (sales linking,
// purchase logging, follow-up) treats them exactly like an online lead.
//   reception → locked to own branch. admin → body.branch
// ════════════════════════════════════════════════════════════════════════════
app.post('/api/reception/walkin', requireAuth, authorizeRoles('reception', 'admin'), (req, res) => {
  const role = req.user?.role;
  const { first_name, phone, interest, source, branch: bodyBranch } = req.body || {};

  const branch = role === 'reception' ? (req.user.branch || null) : (bodyBranch || null);
  if (!branch) return res.status(400).json({ error: 'branch_required' });

  const name = (first_name && String(first_name).trim()) || '';
  if (!name) return res.status(400).json({ error: 'first_name_required' });

  const np = normalizePhone(phone);
  if (!np) return res.status(400).json({ error: 'invalid_phone' });

  const interestVal = (interest && String(interest).trim()) || null;
  const sourceVal   = (source   && String(source).trim())   || 'زيارة مباشرة';

  const db = getDb();

  // Re-use an existing lead if this phone is already known — avoid duplicates.
  let lead = db.prepare(`
    SELECT lp.user_id FROM lead_phones ph
    JOIN lead_profiles lp ON lp.user_id = ph.user_id
    WHERE ph.phone = ? ORDER BY lp.last_activity DESC LIMIT 1
  `).get(np)
    || db.prepare(`SELECT user_id FROM lead_profiles WHERE phone = ? LIMIT 1`).get(np);

  const existed = !!lead;
  const userId  = existed ? lead.user_id : `walkin_${crypto.randomUUID()}`;

  const tx = db.transaction(() => {
    if (existed) {
      // Known customer walking in again — refresh + mark this visit.
      db.prepare(`
        UPDATE lead_profiles SET
          first_name      = COALESCE(NULLIF(?,''), first_name),
          last_category   = COALESCE(?, last_category),
          campaign_source = COALESCE(campaign_source, ?),
          lead_class      = CASE WHEN lead_class = 'purchased' THEN 'purchased' ELSE 'visited' END,
          visit_confirmed = 1,
          visit_at        = CASE WHEN visit_at IS NULL THEN datetime('now') ELSE visit_at END,
          last_activity   = datetime('now')
        WHERE user_id = ?
      `).run(name, interestVal, sourceVal, userId);
    } else {
      db.prepare(`
        INSERT INTO lead_profiles
          (user_id, first_name, phone, preferred_branch, last_category,
           campaign_source, lead_class, total_score, visit_confirmed, visit_at,
           manychat_source, last_activity, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 'visited', 30, 1, datetime('now'),
                'walkin', datetime('now'), datetime('now'))
      `).run(userId, name, np, branch, interestVal, sourceVal);
    }

    db.prepare(`INSERT OR IGNORE INTO lead_phones (user_id, phone) VALUES (?, ?)`).run(userId, np);

    // A branch_selected event makes the walk-in show up everywhere online
    // leads do (reception list, branch-manager customers, funnels).
    db.prepare(`
      INSERT INTO events
        (event_id, user_id, first_name, event_type, event_value,
         score_delta, current_score, branch, category)
      VALUES (?, ?, ?, 'branch_selected', ?, 30, 30, ?, ?)
    `).run(crypto.randomUUID(), userId, name, branch, branch, interestVal);

    // Record the actual showroom visit.
    db.prepare(`INSERT OR IGNORE INTO lead_visits (user_id, branch) VALUES (?, ?)`)
      .run(userId, branch);
  });
  tx();

  console.log(`🚶 WALK-IN ${existed ? 'RE-VISIT' : 'CREATED'}: ${name} → ${branch} (${sourceVal})`);

  return res.json({
    ok:              true,
    user_id:         userId,
    first_name:      name,
    campaign_source: sourceVal,
    branch,
    lead_class:      'visited',
    walk_in:         true,
    existed,
  });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/sales/my — a salesperson's own customers + this-month KPIs.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/sales/my', requireAuth, authorizeRoles('sales'), (req, res) => {
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
    followed_up: 0, fu_visited: 0, fu_not_visited: 0,
  }));

  // Follow-up stats per (assigned_sales, branch). Reuses the sales/branch
  // filters (date filters apply to visits, not the follow-up timeline).
  const fuWhere  = [`f.assigned_sales IS NOT NULL`, `f.followed_up = 1`];
  const fuParams = [];
  if (sales)  { fuWhere.push(`f.assigned_sales = ?`); fuParams.push(sales); }
  if (branch) { fuWhere.push(`f.branch = ?`);         fuParams.push(branch); }
  const fuStats = db.prepare(`
    SELECT f.assigned_sales AS sales_rep, f.branch AS branch,
      COUNT(*) AS followed_up,
      SUM(CASE WHEN lv.user_id IS NOT NULL THEN 1 ELSE 0 END) AS fu_visited
    FROM branch_customer_followups f
    LEFT JOIN lead_visits lv
      ON lv.user_id = f.user_id AND lv.branch = f.branch
    WHERE ${fuWhere.join(' AND ')}
    GROUP BY f.assigned_sales, f.branch
  `).all(...fuParams);

  const keyOf = (rep, br) => `${rep}|${br}`;
  const idx = new Map(enriched.map(r => [keyOf(r.sales_rep, r.branch), r]));
  for (const s of fuStats) {
    const k = keyOf(s.sales_rep, s.branch);
    const row = idx.get(k) || {
      sales_rep: s.sales_rep, branch: s.branch, served: 0, bought: 0,
      not_bought: 0, close_rate: 0, total_sales: 0,
      followed_up: 0, fu_visited: 0, fu_not_visited: 0,
    };
    row.followed_up    = s.followed_up;
    row.fu_visited     = s.fu_visited;
    row.fu_not_visited = s.followed_up - s.fu_visited;
    if (!idx.has(k)) { idx.set(k, row); enriched.push(row); }
  }

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
// Admin Achievements — composite-score leaderboards for sales reps & branches.
//
// Score formula (weights configurable in settings, default 30/30/40):
//   followup_rate = followups_done / phones_received
//   visit_rate    = visits_done    / followups_done
//   close_rate    = purchases_done / visits_done
//   score = followup_rate*W1 + visit_rate*W2 + close_rate*W3   (0..100)
//
// "phones_received" = customers assigned to this sales/branch AND lead has
// at least one phone in lead_phones (i.e. the customer actually left a number).
// ════════════════════════════════════════════════════════════════════════════
function getAchievementWeights() {
  const db  = getDb();
  const row = db.prepare(`SELECT key, value FROM settings WHERE key IN (
    'achievement_followup_weight','achievement_visit_weight','achievement_close_weight'
  )`).all();
  const m = Object.fromEntries(row.map(r => [r.key, parseFloat(r.value) || 0]));
  const w = {
    followup: m.achievement_followup_weight || 30,
    visit:    m.achievement_visit_weight    || 30,
    close:    m.achievement_close_weight    || 40,
  };
  return w;
}

function computeScore(metrics, weights) {
  const fr = metrics.phones_received  ? metrics.followups_done / metrics.phones_received : 0;
  const vr = metrics.followups_done   ? metrics.visits_done    / metrics.followups_done  : 0;
  const cr = metrics.visits_done      ? metrics.purchases_done / metrics.visits_done     : 0;
  return {
    followup_rate: Math.round(fr * 100),
    visit_rate:    Math.round(vr * 100),
    close_rate:    Math.round(cr * 100),
    score:         Math.round(fr * weights.followup + vr * weights.visit + cr * weights.close),
  };
}

app.get('/api/admin/achievements/sales', requireAuth, requireRole('admin'), (req, res) => {
  const db = getDb();
  const { branch, rep, startDate, endDate } = req.query;
  let scopeClause = '';
  const scopeParams = [];
  if (branch) { scopeClause += ` AND f.branch = ?`;          scopeParams.push(branch); }
  if (rep)    { scopeClause += ` AND f.assigned_sales = ?`;  scopeParams.push(rep); }
  // Date range bounds the cohort by when the customer was assigned to the rep.
  const dr = dateRangeClause('f.assigned_at', startDate, endDate);
  scopeClause += dr.clause;
  scopeParams.push(...dr.params);
  const branchClause = scopeClause;
  const branchParam  = scopeParams;

  // For each (sales_rep, branch): count phones_received, followups_done,
  // visits_done (by that rep at that branch), purchases_done (by that rep).
  const rows = db.prepare(`
    SELECT
      f.assigned_sales AS sales_rep,
      f.branch         AS branch,
      COUNT(DISTINCT CASE WHEN ph.user_id IS NOT NULL THEN f.user_id END)   AS phones_received,
      SUM(CASE WHEN f.followed_up = 1 THEN 1 ELSE 0 END)                    AS followups_done,
      (SELECT COUNT(DISTINCT v.user_id) FROM lead_visits v
        WHERE (v.sales_rep = f.assigned_sales OR v.pre_visit_rep = f.assigned_sales)
          AND v.branch = f.branch)                                         AS visits_done,
      (SELECT COUNT(DISTINCT p.user_id) FROM purchases p
        WHERE p.rep = f.assigned_sales AND p.branch = f.branch)             AS purchases_done
    FROM branch_customer_followups f
    LEFT JOIN lead_phones ph ON ph.user_id = f.user_id
    WHERE f.assigned_sales IS NOT NULL ${branchClause}
    GROUP BY f.assigned_sales, f.branch
  `).all(...branchParam);

  const weights = getAchievementWeights();
  const enriched = rows.map(r => ({ ...r, ...computeScore(r, weights) }))
    .sort((a, b) => b.score - a.score)
    .map((r, i) => ({ ...r, rank: i + 1 }));

  // Attach badges
  const badges = db.prepare(`
    SELECT entity_id, badge_code, badge_label, earned_at, score
    FROM achievement_badges WHERE entity_type = 'sales'
    ORDER BY earned_at DESC
  `).all();
  const badgesByRep = badges.reduce((acc, b) => {
    (acc[b.entity_id] ||= []).push(b);
    return acc;
  }, {});
  for (const r of enriched) r.badges = badgesByRep[r.sales_rep] || [];

  return res.json({ weights, rows: enriched });
});

app.get('/api/admin/achievements/branches', requireAuth, requireRole('admin'), (req, res) => {
  const db = getDb();
  const rows = db.prepare(`
    SELECT
      f.branch AS branch,
      COUNT(DISTINCT CASE WHEN ph.user_id IS NOT NULL THEN f.user_id END)  AS phones_received,
      SUM(CASE WHEN f.followed_up = 1 THEN 1 ELSE 0 END)                   AS followups_done,
      (SELECT COUNT(DISTINCT v.user_id) FROM lead_visits v
        WHERE v.branch = f.branch)                                         AS visits_done,
      (SELECT COUNT(DISTINCT p.user_id) FROM purchases p
        WHERE p.branch = f.branch)                                         AS purchases_done
    FROM branch_customer_followups f
    LEFT JOIN lead_phones ph ON ph.user_id = f.user_id
    WHERE f.branch IS NOT NULL
    GROUP BY f.branch
  `).all();

  const weights = getAchievementWeights();
  const enriched = rows.map(r => ({ ...r, ...computeScore(r, weights) }))
    .sort((a, b) => b.score - a.score)
    .map((r, i) => ({ ...r, rank: i + 1 }));

  const badges = db.prepare(`
    SELECT entity_id, badge_code, badge_label, earned_at, score
    FROM achievement_badges WHERE entity_type = 'branch'
    ORDER BY earned_at DESC
  `).all();
  const badgesByBranch = badges.reduce((acc, b) => {
    (acc[b.entity_id] ||= []).push(b);
    return acc;
  }, {});
  for (const r of enriched) r.badges = badgesByBranch[r.branch] || [];

  return res.json({ weights, rows: enriched });
});

app.post('/api/admin/achievements/award', requireAuth, requireRole('admin'), (req, res) => {
  const { entity_type, entity_id, badge_code, badge_label, score } = req.body || {};
  if (!['sales','branch'].includes(entity_type)) return res.status(400).json({ error: 'bad_entity_type' });
  if (!entity_id || !badge_code || !badge_label) return res.status(400).json({ error: 'missing_fields' });

  const db = getDb();
  try {
    db.prepare(`
      INSERT INTO achievement_badges (entity_type, entity_id, badge_code, badge_label, score)
      VALUES (?, ?, ?, ?, ?)
    `).run(entity_type, entity_id, badge_code, badge_label, score ?? null);
    return res.json({ ok: true });
  } catch (e) {
    // UNIQUE violation = badge already awarded → idempotent
    if (String(e.message).includes('UNIQUE')) return res.json({ ok: true, alreadyEarned: true });
    return res.status(500).json({ error: 'award_failed' });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/admin/reps-analytics — per-call-rep performance (role='rep').
// Returns per-rep counters: leads assigned, hot/visited/purchased among them,
// messages triggered, tasks pending/done. No personal tools — pure analytics.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/admin/reps-analytics', requireAuth, requireRole('admin'), (_req, res) => {
  const db = getDb();

  // All users with role='rep' (call reps / موديريتورز)
  const reps = db.prepare(`
    SELECT name, email, branch, active, created_at
    FROM users
    WHERE role = 'rep'
    ORDER BY name
  `).all();

  // Lead aggregates grouped by assigned_rep
  const leadStats = db.prepare(`
    SELECT
      assigned_rep AS rep,
      COUNT(*) AS leads_assigned,
      SUM(CASE WHEN lead_class = 'hot'       THEN 1 ELSE 0 END) AS hot_leads,
      SUM(CASE WHEN lead_class IN ('visited','purchased','converted') THEN 1 ELSE 0 END) AS visited,
      SUM(CASE WHEN lead_class = 'purchased' THEN 1 ELSE 0 END) AS purchased
    FROM lead_profiles
    WHERE assigned_rep IS NOT NULL AND assigned_rep != ''
    GROUP BY assigned_rep
  `).all();
  const leadsByRep = Object.fromEntries(leadStats.map(r => [r.rep, r]));

  // Messages sent per rep
  const msgStats = db.prepare(`
    SELECT sent_by_rep AS rep, COUNT(*) AS messages_sent
    FROM messages_sent
    WHERE sent_by_rep IS NOT NULL
    GROUP BY sent_by_rep
  `).all();
  const msgsByRep = Object.fromEntries(msgStats.map(r => [r.rep, r.messages_sent]));

  // Tasks per rep
  const taskStats = db.prepare(`
    SELECT rep_name AS rep,
      SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS tasks_pending,
      SUM(CASE WHEN status = 'done'    THEN 1 ELSE 0 END) AS tasks_done
    FROM tasks
    WHERE rep_name IS NOT NULL
    GROUP BY rep_name
  `).all();
  const tasksByRep = Object.fromEntries(taskStats.map(r => [r.rep, r]));

  const rows = reps.map(u => {
    const ls = leadsByRep[u.name]   || {};
    const ts = tasksByRep[u.name]   || {};
    const leads     = ls.leads_assigned || 0;
    const visited   = ls.visited        || 0;
    const purchased = ls.purchased      || 0;
    return {
      name:           u.name,
      email:          u.email,
      branch:         u.branch,
      active:         u.active,
      leads_assigned: leads,
      hot_leads:      ls.hot_leads || 0,
      visited,
      purchased,
      messages_sent:  msgsByRep[u.name] || 0,
      tasks_pending:  ts.tasks_pending  || 0,
      tasks_done:     ts.tasks_done     || 0,
      conversion_rate: leads   ? Math.round((visited   / leads)   * 100) : 0,
      close_rate:      visited ? Math.round((purchased / visited) * 100) : 0,
    };
  }).sort((a, b) => (b.purchased - a.purchased) || (b.visited - a.visited));

  return res.json({ rows });
});

app.get('/api/settings/achievement-weights', requireAuth, requireRole('admin'), (_req, res) => {
  return res.json(getAchievementWeights());
});

// Admin alert: surface ManyChat External Requests that still send the
// literal placeholder "{{cuf_…}}" because the user_field reference was
// configured wrong. Lets the admin spot broken attribution at a glance.
app.get('/api/admin/manychat-health', requireAuth, requireRole('admin'), (_req, res) => {
  const db = getDb();
  // Count leads stored with literal placeholders (legacy rows from before
  // we started rejecting them on ingest).
  const broken = db.prepare(`
    SELECT
      SUM(CASE WHEN campaign_source LIKE '{{%}}' THEN 1 ELSE 0 END) AS broken_campaign_source,
      SUM(CASE WHEN ad_id           LIKE '{{%}}' THEN 1 ELSE 0 END) AS broken_ad_id,
      SUM(CASE WHEN visit_code      LIKE '{{%}}' THEN 1 ELSE 0 END) AS broken_visit_code,
      COUNT(*) AS total_leads
    FROM lead_profiles
  `).get();

  // Count enrichment-field coverage to see which fields ManyChat is
  // actually sending us right now.
  const coverage = db.prepare(`
    SELECT
      COUNT(CASE WHEN gender          IS NOT NULL AND gender != ''           THEN 1 END) AS with_gender,
      COUNT(CASE WHEN locale          IS NOT NULL AND locale != ''           THEN 1 END) AS with_locale,
      COUNT(CASE WHEN last_input_text IS NOT NULL AND last_input_text != ''  THEN 1 END) AS with_last_input_text,
      COUNT(CASE WHEN last_name       IS NOT NULL AND last_name != ''        THEN 1 END) AS with_last_name,
      COUNT(CASE WHEN growth_tool_id  IS NOT NULL AND growth_tool_id != ''   THEN 1 END) AS with_growth_tool_id,
      COUNT(CASE WHEN extra_fields    IS NOT NULL AND extra_fields != ''     THEN 1 END) AS with_extra_fields,
      COUNT(*) AS total
    FROM lead_profiles
  `).get();

  return res.json({ broken_placeholders: broken, enrichment_coverage: coverage });
});

// Debug endpoint — show the raw_payload fields ManyChat actually sends, so
// we know what extra data we could be capturing but currently ignore.
app.get('/api/admin/manychat-payload-sample', requireAuth, requireRole('admin'), (_req, res) => {
  const db = getDb();
  const rows = db.prepare(`
    SELECT event_type, raw_payload, created_at
    FROM events
    WHERE raw_payload IS NOT NULL AND raw_payload != ''
      AND created_at >= datetime('now', '-7 days')
    ORDER BY created_at DESC
    LIMIT 20
  `).all();

  // Aggregate ALL keys we've ever seen in raw_payload across the sample,
  // so the admin can see at a glance which fields ManyChat sends.
  const fieldFrequency = {};
  const samples = [];
  for (const r of rows) {
    try {
      const parsed = JSON.parse(r.raw_payload);
      for (const k of Object.keys(parsed)) {
        fieldFrequency[k] = (fieldFrequency[k] || 0) + 1;
      }
      samples.push({ event_type: r.event_type, payload: parsed });
    } catch (_) {
      // ignore malformed rows
    }
  }
  return res.json({
    fields_observed:   fieldFrequency,
    sample_payloads:   samples.slice(0, 5),
    extracted_today:   {
      // What our handler currently destructures from the body:
      handled_fields: ['user_id','event_type','event_value','campaign_source','ad_id','visit_code','phone','product','category','branch','event_id'],
    },
  });
});

// Debug endpoint — verify the forecast split logic against raw data
app.get('/api/admin/forecast-debug', requireAuth, requireRole('admin'), (_req, res) => {
  const db = getDb();

  // Breakdown of ALL event types from last 7 days, with phone-coverage stats
  const eventBreakdown = db.prepare(`
    SELECT
      event_type,
      COUNT(*)                                                                AS events,
      COUNT(DISTINCT user_id)                                                 AS unique_users,
      COUNT(DISTINCT CASE WHEN EXISTS (
        SELECT 1 FROM lead_phones p WHERE p.user_id = events.user_id
      ) THEN user_id END)                                                     AS users_with_phone
    FROM events
    WHERE created_at >= datetime('now', '-7 days')
    GROUP BY event_type
    ORDER BY unique_users DESC
  `).all();

  // For users who did branch_selected last 7 days, sample with timing
  const rows = db.prepare(`
    SELECT
      e.user_id,
      e.created_at AS branch_event_at,
      (SELECT MIN(p.created_at) FROM lead_phones p WHERE p.user_id = e.user_id) AS first_phone_at,
      (SELECT COUNT(*)            FROM lead_phones p WHERE p.user_id = e.user_id) AS phone_count
    FROM events e
    WHERE e.event_type = 'branch_selected'
      AND e.created_at >= datetime('now', '-7 days')
    ORDER BY e.created_at DESC
    LIMIT 10
  `).all();

  // Users who did location_request but NEVER gave phone — the "got address
  // without phone" cohort
  const locationNoPhone = db.prepare(`
    SELECT COUNT(DISTINCT user_id) AS n
    FROM events e
    WHERE e.event_type = 'location_request'
      AND e.created_at >= datetime('now', '-7 days')
      AND NOT EXISTS (SELECT 1 FROM lead_phones p WHERE p.user_id = e.user_id)
  `).get();

  const branchNoPhone = db.prepare(`
    SELECT COUNT(DISTINCT user_id) AS n
    FROM events e
    WHERE e.event_type = 'branch_selected'
      AND e.created_at >= datetime('now', '-7 days')
      AND NOT EXISTS (SELECT 1 FROM lead_phones p WHERE p.user_id = e.user_id)
  `).get();

  return res.json({
    event_breakdown_last7: eventBreakdown,
    branch_selected_no_phone_users: branchNoPhone.n,
    location_request_no_phone_users: locationNoPhone.n,
    sample: rows,
  });
});

app.get('/api/settings/forecast-weights', requireAuth, requireRole('admin'), (_req, res) => {
  const db = getDb();
  const rows = db.prepare(`SELECT key, value FROM settings WHERE key IN
    ('forecast_with_phone_weight','forecast_without_phone_weight')`).all();
  const m = Object.fromEntries(rows.map(r => [r.key, parseFloat(r.value)]));
  return res.json({
    with_phone:    Number.isFinite(m.forecast_with_phone_weight)    ? m.forecast_with_phone_weight    : 80,
    without_phone: Number.isFinite(m.forecast_without_phone_weight) ? m.forecast_without_phone_weight : 35,
  });
});

app.put('/api/settings/forecast-weights', requireAuth, requireRole('admin'), (req, res) => {
  const { with_phone, without_phone } = req.body || {};
  const w = parseFloat(with_phone), wo = parseFloat(without_phone);
  if (!Number.isFinite(w)  || w  < 0 || w  > 100) return res.status(400).json({ error: 'invalid_with_phone_weight' });
  if (!Number.isFinite(wo) || wo < 0 || wo > 100) return res.status(400).json({ error: 'invalid_without_phone_weight' });
  const db = getDb();
  const upsert = db.prepare(`
    INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')
  `);
  upsert.run('forecast_with_phone_weight',    String(w));
  upsert.run('forecast_without_phone_weight', String(wo));
  return res.json({ ok: true, weights: { with_phone: w, without_phone: wo } });
});

app.put('/api/settings/achievement-weights', requireAuth, requireRole('admin'), (req, res) => {
  const { followup, visit, close } = req.body || {};
  const f = parseFloat(followup), v = parseFloat(visit), c = parseFloat(close);
  if ([f, v, c].some(n => !Number.isFinite(n) || n < 0 || n > 100)) {
    return res.status(400).json({ error: 'invalid_weights' });
  }
  if (Math.round(f + v + c) !== 100) {
    return res.status(400).json({ error: 'weights_must_sum_to_100' });
  }
  const db = getDb();
  const upsert = db.prepare(`
    INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')
  `);
  upsert.run('achievement_followup_weight', String(f));
  upsert.run('achievement_visit_weight',    String(v));
  upsert.run('achievement_close_weight',    String(c));
  return res.json({ ok: true, weights: getAchievementWeights() });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/branch/overview — branch manager's read-only view of THEIR branch.
//   branch_manager → locked to its own branch. admin → ?branch=<id>
//   Returns branch KPIs + per-salesperson performance for that branch only.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/branch/overview', requireAuth, authorizeRoles('branch_manager', 'admin'), (req, res) => {
  const role = req.user?.role;
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
    followed_up: 0, fu_visited: 0, fu_not_visited: 0,
  }));

  // Follow-up stats per assigned sales rep (a rep may have follow-ups but no
  // visits yet, so merge — adding rows for reps missing from the visit query).
  const fuStats = db.prepare(`
    SELECT
      f.assigned_sales AS sales_rep,
      COUNT(*)                                                    AS followed_up,
      SUM(CASE WHEN lv.user_id IS NOT NULL THEN 1 ELSE 0 END)      AS fu_visited
    FROM branch_customer_followups f
    LEFT JOIN (
      SELECT DISTINCT user_id FROM lead_visits WHERE branch = ?
    ) lv ON lv.user_id = f.user_id
    WHERE f.branch = ? AND f.assigned_sales IS NOT NULL AND f.followed_up = 1
    GROUP BY f.assigned_sales
  `).all(branch, branch);

  const byName = new Map(bySales.map(r => [r.sales_rep, r]));
  for (const s of fuStats) {
    const row = byName.get(s.sales_rep) || {
      sales_rep: s.sales_rep, served: 0, bought: 0, not_bought: 0,
      close_rate: 0, total_sales: 0, followed_up: 0, fu_visited: 0, fu_not_visited: 0,
    };
    row.followed_up    = s.followed_up;
    row.fu_visited     = s.fu_visited;
    row.fu_not_visited = s.followed_up - s.fu_visited;
    if (!byName.has(s.sales_rep)) { byName.set(s.sales_rep, row); bySales.push(row); }
  }

  // Attach each rep's CURRENT-MONTH target + achievement (revenue this month).
  for (const r of bySales) {
    r.target     = getTarget(db, 'sales_rep', r.sales_rep);
    r.target_pct = pctAchieved(monthRevenue(db, { rep: r.sales_rep }), r.target);
  }

  const served      = bySales.reduce((s, r) => s + r.served, 0);
  const bought      = bySales.reduce((s, r) => s + r.bought, 0);
  const totalSales  = bySales.reduce((s, r) => s + r.total_sales, 0);

  // Branch target progress — current month's target vs this month's revenue.
  const branchTarget = getTarget(db, 'branch', branch);
  const branchMonthRevenue = monthRevenue(db, { branch });

  return res.json({
    branch,
    target_month: currentMonth(),
    kpis: {
      requested,
      visited,
      bought,
      total_sales: totalSales,
      close_rate: served ? Math.round((bought / served) * 100) : 0,
      target:        branchTarget,
      month_revenue: branchMonthRevenue,
      target_pct:    pctAchieved(branchMonthRevenue, branchTarget),
    },
    bySales,
  });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/branch/customers — customers who requested this branch + follow-up status
//   branch_manager → locked to own branch. admin → ?branch=<id>
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/branch/customers', requireAuth, authorizeRoles('branch_manager', 'admin'), (req, res) => {
  const role = req.user?.role;
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
      lp.phone,
      COALESCE(lp.total_score, 0)    AS total_score,
      COALESCE(lp.lead_class, 'cold') AS lead_class,
      lp.last_activity,
      COALESCE(lp.visit_confirmed, 0) AS visit_confirmed,
      lp.last_product,
      lp.last_category,
      COALESCE(lp.session_count, 0)      AS session_count,
      COALESCE(lp.product_view_count, 0) AS product_view_count,
      lp.campaign_source,
      lp.ad_id,
      lp.last_input_text,
      lp.manychat_source,
      COALESCE(f.followed_up, 0)     AS followed_up,
      f.followed_up_at,
      f.followed_up_by,
      f.assigned_sales,
      f.assigned_by,
      f.call_summary,
      CASE WHEN lv.user_id IS NOT NULL THEN 1 ELSE 0 END AS visited
    FROM (
      SELECT DISTINCT user_id
      FROM events
      WHERE event_type = 'branch_selected'
        AND (event_value = ? OR branch = ?)
    ) req
    LEFT JOIN lead_profiles lp ON lp.user_id = req.user_id
    LEFT JOIN branch_customer_followups f
      ON f.user_id = req.user_id AND f.branch = ?
    LEFT JOIN (
      SELECT DISTINCT user_id FROM lead_visits WHERE branch = ?
    ) lv ON lv.user_id = req.user_id
    ORDER BY COALESCE(lp.total_score, 0) DESC, lp.last_activity DESC
    LIMIT 200
  `).all(branch, branch, branch, branch);

  return res.json({ branch, customers });
});

// Records a completed follow-up in the append-only log (history survives
// reassignment). Only called when a follow-up is actually marked done.
function logFollowup(db, branch, userId, sales, summary) {
  db.prepare(`
    INSERT INTO followup_log (branch, user_id, sales, call_summary, followed_up_at)
    VALUES (?, ?, ?, ?, datetime('now'))
  `).run(branch, userId, sales || null, (summary && String(summary).trim()) || null);
}

// Records an admin/manager action in the undo ledger. `oldState` describes how
// to restore the affected row: { table, where: {...}, row: {...}|null }.
function auditLog(db, operator, actionType, targetId, oldState) {
  try {
    db.prepare(`
      INSERT INTO system_audit_log (operator_name, action_type, target_id, old_state)
      VALUES (?, ?, ?, ?)
    `).run(operator || null, actionType, String(targetId), JSON.stringify(oldState));
  } catch (e) {
    console.error('[audit] failed to log:', e.message);
  }
}

// Creates a backend notification for a role bucket (e.g. 'admin').
function createNotification(db, audience, type, message) {
  try {
    db.prepare(
      `INSERT INTO notifications (audience, type, message) VALUES (?, ?, ?)`
    ).run(audience, type, message);
  } catch (e) {
    console.error('[notif] failed to create:', e.message);
  }
}

// ── Sales-target helpers ────────────────────────────────────────────────────
// Current calendar month as 'YYYY-MM'.
function currentMonth() {
  return new Date().toISOString().slice(0, 7);
}

// Monthly target for a scope. `month` defaults to the current calendar month.
function getTarget(db, scopeType, scopeName, month) {
  if (!scopeName) return 0;
  const row = db.prepare(`
    SELECT target_amount FROM sales_targets
    WHERE scope_type = ? AND scope_name = ? AND target_month = ?
  `).get(scopeType, scopeName, month || currentMonth());
  return row ? (Number(row.target_amount) || 0) : 0;
}

// Revenue (SUM of purchase price) generated WITHIN a calendar month, optionally
// scoped to a branch or a sales rep. `month` defaults to the current month.
function monthRevenue(db, { branch, rep, month } = {}) {
  let where = `strftime('%Y-%m', created_at) = ?`;
  const params = [month || currentMonth()];
  if (branch) { where += ` AND branch = ?`; params.push(branch); }
  if (rep)    { where += ` AND rep = ?`;    params.push(rep); }
  return db.prepare(
    `SELECT COALESCE(SUM(price), 0) AS r FROM purchases WHERE ${where}`
  ).get(...params).r || 0;
}

function pctAchieved(actual, target) {
  return target > 0 ? Math.round(((actual || 0) / target) * 100) : 0;
}

// Builds a SQL date-range clause for a column. Returns { clause, params }.
function dateRangeClause(column, startDate, endDate) {
  const parts = [];
  const params = [];
  if (startDate) { parts.push(`date(${column}) >= ?`); params.push(startDate); }
  if (endDate)   { parts.push(`date(${column}) <= ?`); params.push(endDate); }
  return { clause: parts.length ? ' AND ' + parts.join(' AND ') : '', params };
}

// ════════════════════════════════════════════════════════════════════════════
// PATCH /api/branch/customers/:userId/assign — manager hands a customer to a
// sales rep. Reassigning to a DIFFERENT sales rep resets the follow-up so the
// new rep starts fresh; prior call summaries stay in followup_log.
// Body: { sales }   (branch_manager → own branch; admin → body.branch)
// ════════════════════════════════════════════════════════════════════════════
app.patch('/api/branch/customers/:userId/assign', requireAuth, authorizeRoles('branch_manager', 'admin'), (req, res) => {
  const role = req.user?.role;
  const branch = role === 'branch_manager'
    ? (req.user.branch || null)
    : (req.body?.branch || null);
  if (!branch) return res.status(400).json({ error: 'branch_required' });

  const { userId } = req.params;
  const sales = (req.body?.sales && String(req.body.sales).trim()) || null;
  if (!sales) return res.status(400).json({ error: 'sales_required' });

  const db  = getDb();
  // Full old row — kept for the audit/undo ledger.
  const cur = db.prepare(
    `SELECT * FROM branch_customer_followups WHERE branch = ? AND user_id = ?`
  ).get(branch, userId);

  // Changing the owner → start a brand-new follow-up cycle.
  const resetCycle = cur && cur.assigned_sales && cur.assigned_sales !== sales;

  db.prepare(`
    INSERT INTO branch_customer_followups
      (branch, user_id, assigned_sales, assigned_at, assigned_by, followed_up, followed_up_at, followed_up_by, call_summary)
    VALUES (?, ?, ?, datetime('now'), ?, 0, NULL, NULL, NULL)
    ON CONFLICT(branch, user_id) DO UPDATE SET
      assigned_sales = excluded.assigned_sales,
      assigned_at    = excluded.assigned_at,
      assigned_by    = excluded.assigned_by
      ${resetCycle ? `,
      followed_up    = 0,
      followed_up_at = NULL,
      followed_up_by = NULL,
      call_summary   = NULL` : ''}
  `).run(branch, userId, sales, req.user?.name || null);

  auditLog(db, req.user?.name, 'assign_customer', userId, {
    table: 'branch_customer_followups',
    where: { branch, user_id: userId },
    row:   cur || null,
  });

  return res.json({ ok: true, assigned_sales: sales, reset: !!resetCycle });
});

// ════════════════════════════════════════════════════════════════════════════
// PATCH /api/branch/customers/:userId/followup — manager marks follow-up done
// himself (he can also do the call). Accepts an optional call_summary.
// ════════════════════════════════════════════════════════════════════════════
app.patch('/api/branch/customers/:userId/followup', requireAuth, authorizeRoles('branch_manager', 'admin'), (req, res) => {
  const role = req.user?.role;
  const branch = role === 'branch_manager'
    ? (req.user.branch || null)
    : (req.body?.branch || null);
  if (!branch) return res.status(400).json({ error: 'branch_required' });

  const { userId } = req.params;
  const { followed_up, followed_up_by, call_summary } = req.body || {};
  const newVal = followed_up ? 1 : 0;
  const byName = newVal
    ? (followed_up_by && String(followed_up_by).trim()) || req.user?.name || null
    : null;
  const summary = newVal ? (call_summary && String(call_summary).trim()) || null : null;

  const db = getDb();
  db.prepare(`
    INSERT INTO branch_customer_followups
      (branch, user_id, followed_up, followed_up_at, followed_up_by, call_summary)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(branch, user_id) DO UPDATE SET
      followed_up    = excluded.followed_up,
      followed_up_at = excluded.followed_up_at,
      followed_up_by = excluded.followed_up_by,
      call_summary   = excluded.call_summary
  `).run(branch, userId, newVal, newVal ? new Date().toISOString() : null, byName, summary);

  if (newVal) logFollowup(db, branch, userId, byName, summary);

  return res.json({ ok: true, followed_up: newVal, followed_up_by: byName });
});

// ════════════════════════════════════════════════════════════════════════════
// Sales follow-ups — the sales rep sees customers the branch manager assigned
// to them, splits pending vs done, and writes a call summary on completion.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/sales/followups', requireAuth, authorizeRoles('sales'), (req, res) => {
  const me     = req.user.name;
  const branch = req.user.branch || null;
  if (!branch) return res.status(400).json({ error: 'branch_required' });

  const db = getDb();
  const customers = db.prepare(`
    SELECT
      f.user_id,
      lp.first_name,
      COALESCE(lp.total_score, 0)     AS total_score,
      COALESCE(lp.lead_class, 'cold') AS lead_class,
      lp.last_activity,
      lp.last_category,
      f.followed_up,
      f.followed_up_at,
      f.call_summary,
      f.assigned_at,
      (SELECT GROUP_CONCAT(ph.phone, ' ، ') FROM lead_phones ph
         WHERE ph.user_id = f.user_id)                              AS phones,
      CASE WHEN lv.user_id IS NOT NULL THEN 1 ELSE 0 END            AS visited
    FROM branch_customer_followups f
    LEFT JOIN lead_profiles lp ON lp.user_id = f.user_id
    LEFT JOIN (
      SELECT DISTINCT user_id FROM lead_visits WHERE branch = ?
    ) lv ON lv.user_id = f.user_id
    WHERE f.branch = ? AND f.assigned_sales = ?
    ORDER BY f.followed_up ASC, f.assigned_at DESC
  `).all(branch, branch, me);

  return res.json({ branch, customers });
});

app.patch('/api/sales/followups/:userId', requireAuth, authorizeRoles('sales'), (req, res) => {
  const me     = req.user.name;
  const branch = req.user.branch || null;
  if (!branch) return res.status(400).json({ error: 'branch_required' });

  const { userId } = req.params;
  const { followed_up, call_summary } = req.body || {};
  const newVal = followed_up ? 1 : 0;

  const db  = getDb();
  const own = db.prepare(`
    SELECT id FROM branch_customer_followups
    WHERE branch = ? AND user_id = ? AND assigned_sales = ?
  `).get(branch, userId, me);
  if (!own) return res.status(404).json({ error: 'العميل ده مش مسنود ليك' });

  const summary = newVal ? (call_summary && String(call_summary).trim()) || null : null;
  db.prepare(`
    UPDATE branch_customer_followups SET
      followed_up    = ?,
      followed_up_at = ?,
      followed_up_by = ?,
      call_summary   = ?
    WHERE branch = ? AND user_id = ?
  `).run(newVal, newVal ? new Date().toISOString() : null, newVal ? me : null, summary, branch, userId);

  if (newVal) logFollowup(db, branch, userId, me, summary);

  return res.json({ ok: true, followed_up: newVal });
});

// ════════════════════════════════════════════════════════════════════════════
// Branch sales accounts — branch_manager manages the sales users of THEIR
// branch only. admin may target any branch via ?branch / body.branch.
// These rows live in the same `users` table, so they also show up in the
// admin's user-management screen automatically.
// ════════════════════════════════════════════════════════════════════════════
function resolveBranchScope(req) {
  const role = req.user?.role;
  if (role !== 'branch_manager' && role !== 'admin') return { error: 'forbidden' };
  const branch = role === 'branch_manager'
    ? (req.user.branch || null)
    : (req.query.branch || req.body?.branch || null);
  if (!branch) return { error: 'branch_required' };
  return { branch };
}

app.get('/api/branch/sales', requireAuth, (req, res) => {
  const scope = resolveBranchScope(req);
  if (scope.error) return res.status(scope.error === 'forbidden' ? 403 : 400).json({ error: scope.error });
  const db = getDb();
  const sales = db.prepare(
    `SELECT id, name, email, branch, active, created_at
       FROM users WHERE role = 'sales' AND branch = ? ORDER BY name`
  ).all(scope.branch);
  return res.json({ branch: scope.branch, sales });
});

app.post('/api/branch/sales', requireAuth, (req, res) => {
  const scope = resolveBranchScope(req);
  if (scope.error) return res.status(scope.error === 'forbidden' ? 403 : 400).json({ error: scope.error });
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'الاسم والإيميل والباسورد مطلوبين' });
  }
  const db = getDb();
  try {
    const result = db.prepare(
      `INSERT INTO users (name, email, password_hash, role, branch, active)
       VALUES (?, ?, ?, 'sales', ?, 1)`
    ).run(name, email, bcrypt.hashSync(password, 10), scope.branch);
    return res.json({ id: result.lastInsertRowid, name, email, branch: scope.branch, active: 1 });
  } catch (e) {
    if (e.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'البريد الإلكتروني مستخدم مسبقاً' });
    }
    throw e;
  }
});

// Guard: the target user must be a 'sales' account in the manager's branch.
function loadOwnedSales(db, id, branch) {
  return db.prepare(
    `SELECT id FROM users WHERE id = ? AND role = 'sales' AND branch = ?`
  ).get(id, branch);
}

app.put('/api/branch/sales/:id', requireAuth, (req, res) => {
  const scope = resolveBranchScope(req);
  if (scope.error) return res.status(scope.error === 'forbidden' ? 403 : 400).json({ error: scope.error });
  const db = getDb();
  if (!loadOwnedSales(db, req.params.id, scope.branch)) {
    return res.status(404).json({ error: 'الحساب مش موجود في فرعك' });
  }
  const { name, email, password, active } = req.body || {};
  const updates = [];
  const params  = [];
  if (name)               { updates.push('name = ?');          params.push(name); }
  if (email)              { updates.push('email = ?');         params.push(email); }
  if (password)           { updates.push('password_hash = ?'); params.push(bcrypt.hashSync(password, 10)); }
  if (active !== undefined) { updates.push('active = ?');       params.push(active ? 1 : 0); }
  if (!updates.length) return res.status(400).json({ error: 'مفيش حاجة تتعدّل' });
  params.push(req.params.id);
  try {
    db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...params);
  } catch (e) {
    if (e.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'البريد الإلكتروني مستخدم مسبقاً' });
    }
    throw e;
  }
  return res.json({ ok: true });
});

app.delete('/api/branch/sales/:id', requireAuth, (req, res) => {
  const scope = resolveBranchScope(req);
  if (scope.error) return res.status(scope.error === 'forbidden' ? 403 : 400).json({ error: scope.error });
  const db = getDb();
  if (!loadOwnedSales(db, req.params.id, scope.branch)) {
    return res.status(404).json({ error: 'الحساب مش موجود في فرعك' });
  }
  db.prepare(`DELETE FROM users WHERE id = ?`).run(req.params.id);
  return res.json({ ok: true });
});

// ════════════════════════════════════════════════════════════════════════════
// POST /api/purchases — Sales rep records an offline purchase for a lead.
// Body: { user_id, product_id?, price?, branch?, notes? }
// Returns: { ok, purchase_id, lead_class }
// ════════════════════════════════════════════════════════════════════════════
app.post('/api/purchases', requireAuth, (req, res) => {
  const { user_id, product_id, price, branch, notes, contract_number } = req.body || {};
  if (!user_id || typeof user_id !== 'string') {
    return res.status(400).json({ error: 'user_id is required' });
  }
  const db  = getDb();
  const rep = req.user?.name || req.headers['x-rep'] || null;

  const lead = db.prepare(`SELECT user_id FROM lead_profiles WHERE user_id = ?`).get(user_id);
  if (!lead) return res.status(404).json({ error: 'lead_not_found' });

  const result = db.prepare(`
    INSERT INTO purchases (user_id, product_id, price, branch, notes, rep, contract_number)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(user_id, product_id || null, price || null, branch || null, notes || null, rep,
         (contract_number && String(contract_number).trim()) || null);

  // Mark lead as purchased (terminal state — won't be overridden by scoring)
  db.prepare(`
    UPDATE lead_profiles SET
      lead_class    = 'purchased',
      purchased_at  = CASE WHEN purchased_at IS NULL THEN datetime('now') ELSE purchased_at END,
      last_activity = datetime('now')
    WHERE user_id = ?
  `).run(user_id);

  console.log(`💰 PURCHASE: user:${user_id} product:${product_id || '?'} price:${price || '?'} rep:${rep || '?'}`);

  // Every purchase → macro alert for the admin war-room.
  createNotification(db, 'admin', 'new_purchase',
    `🎉 تم إغلاق تعاقد جديد (عقد: ${contract_number || '—'}) بقيمة ` +
    `${new Intl.NumberFormat('en-US').format(Number(price) || 0)} ج.م بواسطة ` +
    `${rep || '؟'} في فرع ${branch || '—'}`);

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
// Re-visit follow-up — customers who visited the showroom but did NOT buy.
// Three buckets:
//   pending → still being followed up (visited, no purchase, not closed)
//   bought  → visited AND later purchased (success)
//   lost    → sales closed them ("won't buy" — e.g. bought elsewhere)
// Scope: admin → all | branch_manager → own branch | sales → own customers.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/revisit/customers', requireAuth, authorizeRoles('admin', 'branch_manager', 'sales', 'rep'), (req, res) => {
  const status = ['pending', 'bought', 'lost'].includes(req.query.status)
    ? req.query.status : 'pending';
  const db   = getDb();
  const role = req.user?.role;

  let statusWhere;
  if (status === 'bought') {
    statusWhere = `(lp.lead_class = 'purchased' OR lp.purchased_at IS NOT NULL)`;
  } else if (status === 'lost') {
    statusWhere = `lp.lead_class != 'purchased' AND lp.purchased_at IS NULL
                   AND lp.revisit_status = 'lost'`;
  } else {
    statusWhere = `lp.lead_class != 'purchased' AND lp.purchased_at IS NULL
                   AND (lp.revisit_status IS NULL OR lp.revisit_status = 'pending')`;
  }

  let rbacWhere = '1=1';
  const params = [];
  if (role === 'branch_manager') {
    const b = req.user.branch || null;
    if (!b) return res.status(400).json({ error: 'branch_required' });
    rbacWhere = `(lp.preferred_branch = ?
      OR lp.user_id IN (SELECT user_id FROM lead_visits WHERE branch = ?))`;
    params.push(b, b);
  } else if (role === 'sales' || role === 'rep') {
    const me = req.user.name;
    rbacWhere = `(lp.assigned_rep = ?
      OR lp.user_id IN (SELECT user_id FROM lead_visits WHERE sales_rep = ?))`;
    params.push(me, me);
  }

  const customers = db.prepare(`
    SELECT
      lp.user_id, lp.first_name, lp.phone, lp.total_score, lp.lead_class,
      lp.last_product, lp.last_category, lp.last_activity, lp.visit_at,
      lp.campaign_source, lp.manychat_source, lp.preferred_branch,
      lp.revisit_status, lp.revisit_note, lp.revisit_updated_by, lp.revisit_updated_at,
      lp.purchased_at,
      (SELECT v.branch    FROM lead_visits v WHERE v.user_id = lp.user_id
         ORDER BY v.visited_at DESC LIMIT 1) AS branch,
      (SELECT v.sales_rep FROM lead_visits v WHERE v.user_id = lp.user_id
         ORDER BY v.visited_at DESC LIMIT 1) AS sales_rep,
      (SELECT COALESCE(SUM(p.price), 0) FROM purchases p
         WHERE p.user_id = lp.user_id)       AS purchase_total,
      (SELECT COUNT(*) FROM revisit_followups rf
         WHERE rf.user_id = lp.user_id)      AS followup_count,
      (SELECT rf.created_at FROM revisit_followups rf
         WHERE rf.user_id = lp.user_id
         ORDER BY rf.created_at DESC LIMIT 1) AS last_followup_at,
      (SELECT rf.followed_up_by FROM revisit_followups rf
         WHERE rf.user_id = lp.user_id
         ORDER BY rf.created_at DESC LIMIT 1) AS last_followup_by,
      (SELECT rf.note FROM revisit_followups rf
         WHERE rf.user_id = lp.user_id
         ORDER BY rf.created_at DESC LIMIT 1) AS last_followup_note
    FROM lead_profiles lp
    WHERE lp.visit_confirmed = 1
      AND ${statusWhere}
      AND ${rbacWhere}
    ORDER BY COALESCE(lp.revisit_updated_at, lp.purchased_at, lp.last_activity) DESC
    LIMIT 300
  `).all(...params);

  return res.json({ status, count: customers.length, customers });
});

// POST /api/revisit/:userId/close — sales/manager closes a customer who won't
// buy (e.g. bought elsewhere). Body: { note }.
app.post('/api/revisit/:userId/close', requireAuth, authorizeRoles('admin', 'branch_manager', 'sales', 'rep'), (req, res) => {
  const { userId } = req.params;
  const note = (req.body?.note && String(req.body.note).trim()) || null;
  const db = getDb();
  const lead = db.prepare(`SELECT user_id FROM lead_profiles WHERE user_id = ?`).get(userId);
  if (!lead) return res.status(404).json({ error: 'lead_not_found' });

  db.prepare(`
    UPDATE lead_profiles SET
      revisit_status     = 'lost',
      revisit_note       = ?,
      revisit_updated_by = ?,
      revisit_updated_at = datetime('now')
    WHERE user_id = ?
  `).run(note, req.user?.name || null, userId);

  console.log(`🚫 REVISIT CLOSED: ${userId} by ${req.user?.name || '?'} — ${note || 'no note'}`);
  return res.json({ ok: true, revisit_status: 'lost' });
});

// POST /api/revisit/:userId/reopen — move a closed customer back to follow-up.
app.post('/api/revisit/:userId/reopen', requireAuth, authorizeRoles('admin', 'branch_manager', 'sales', 'rep'), (req, res) => {
  const { userId } = req.params;
  const db = getDb();
  const lead = db.prepare(`SELECT user_id FROM lead_profiles WHERE user_id = ?`).get(userId);
  if (!lead) return res.status(404).json({ error: 'lead_not_found' });

  db.prepare(`
    UPDATE lead_profiles SET
      revisit_status     = NULL,
      revisit_note       = NULL,
      revisit_updated_by = ?,
      revisit_updated_at = datetime('now')
    WHERE user_id = ?
  `).run(req.user?.name || null, userId);

  return res.json({ ok: true, revisit_status: 'pending' });
});

// POST /api/revisit/:userId/followup — log a re-visit follow-up attempt.
// Appends to revisit_followups so we can see how many times (and when) the
// customer was followed up — the customer STAYS in the pending list.
// Body: { note }.
app.post('/api/revisit/:userId/followup', requireAuth, authorizeRoles('admin', 'branch_manager', 'sales', 'rep'), (req, res) => {
  const { userId } = req.params;
  const note = (req.body?.note && String(req.body.note).trim()) || null;
  const db = getDb();
  const lead = db.prepare(`SELECT user_id FROM lead_profiles WHERE user_id = ?`).get(userId);
  if (!lead) return res.status(404).json({ error: 'lead_not_found' });

  db.prepare(`
    INSERT INTO revisit_followups (user_id, followed_up_by, note)
    VALUES (?, ?, ?)
  `).run(userId, req.user?.name || null, note);

  // Surface the latest activity on the profile too.
  db.prepare(`UPDATE lead_profiles SET last_activity = datetime('now') WHERE user_id = ?`)
    .run(userId);

  const count = db.prepare(
    `SELECT COUNT(*) AS n FROM revisit_followups WHERE user_id = ?`
  ).get(userId).n;

  console.log(`📞 REVISIT FOLLOWUP #${count}: ${userId} by ${req.user?.name || '?'}`);
  return res.json({ ok: true, followup_count: count });
});

// GET /api/revisit/:userId/followups — full re-visit follow-up history.
app.get('/api/revisit/:userId/followups', requireAuth, authorizeRoles('admin', 'branch_manager', 'sales', 'rep'), (req, res) => {
  const db = getDb();
  const followups = db.prepare(`
    SELECT id, followed_up_by, note, created_at
    FROM revisit_followups
    WHERE user_id = ?
    ORDER BY created_at DESC
  `).all(req.params.userId);
  return res.json({ followups });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/revisit/analytics — funnel analytics for visited-but-no-purchase
// customers + re-follow-up activity. Scoped by role (admin / manager / sales).
// Returns: { summary, byBranch[], bySales[] }
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/revisit/analytics', requireAuth, authorizeRoles('admin', 'branch_manager', 'sales', 'rep'), (req, res) => {
  const db   = getDb();
  const role = req.user?.role;

  let rbacWhere = '1=1';
  const params = [];
  if (role === 'branch_manager') {
    const b = req.user.branch || null;
    if (!b) return res.status(400).json({ error: 'branch_required' });
    rbacWhere = `(lp.preferred_branch = ?
      OR lp.user_id IN (SELECT user_id FROM lead_visits WHERE branch = ?))`;
    params.push(b, b);
  } else if (role === 'sales' || role === 'rep') {
    const me = req.user.name;
    rbacWhere = `(lp.assigned_rep = ?
      OR lp.user_id IN (SELECT user_id FROM lead_visits WHERE sales_rep = ?))`;
    params.push(me, me);
  }

  // One row per customer who visited the showroom.
  const rows = db.prepare(`
    SELECT
      lp.user_id, lp.lead_class, lp.purchased_at, lp.revisit_status,
      (SELECT v.branch    FROM lead_visits v WHERE v.user_id = lp.user_id
         ORDER BY v.visited_at DESC LIMIT 1) AS branch,
      (SELECT v.sales_rep FROM lead_visits v WHERE v.user_id = lp.user_id
         ORDER BY v.visited_at DESC LIMIT 1) AS sales_rep,
      (SELECT COUNT(*) FROM revisit_followups rf WHERE rf.user_id = lp.user_id) AS followup_count
    FROM lead_profiles lp
    WHERE lp.visit_confirmed = 1 AND ${rbacWhere}
  `).all(...params);

  const blank = () => ({ pending: 0, bought: 0, lost: 0, followups: 0 });
  const summary = { visited_total: rows.length, pending: 0, bought: 0, lost: 0,
                    followups_total: 0, customers_followed: 0 };
  const branchMap = new Map();
  const salesMap  = new Map();

  for (const r of rows) {
    const bucket = (r.lead_class === 'purchased' || r.purchased_at) ? 'bought'
      : (r.revisit_status === 'lost') ? 'lost' : 'pending';
    summary[bucket]++;
    summary.followups_total += r.followup_count || 0;
    if (r.followup_count > 0) summary.customers_followed++;

    const bKey = r.branch || '—';
    if (!branchMap.has(bKey)) branchMap.set(bKey, { branch: bKey, ...blank() });
    branchMap.get(bKey)[bucket]++;
    branchMap.get(bKey).followups += r.followup_count || 0;

    if (r.sales_rep) {
      const sKey = `${r.sales_rep}|${r.branch || ''}`;
      if (!salesMap.has(sKey)) salesMap.set(sKey, { sales_rep: r.sales_rep, branch: r.branch || '—', ...blank() });
      salesMap.get(sKey)[bucket]++;
      salesMap.get(sKey).followups += r.followup_count || 0;
    }
  }

  const noBuy = summary.pending + summary.lost;
  summary.no_purchase_total = noBuy;
  summary.conversion_rate   = summary.visited_total
    ? Math.round((summary.bought / summary.visited_total) * 100) : 0;
  summary.avg_followups = summary.customers_followed
    ? Math.round((summary.followups_total / summary.customers_followed) * 10) / 10 : 0;

  const withRate = (o) => {
    const total = o.pending + o.bought + o.lost;
    return { ...o, conversion: total ? Math.round((o.bought / total) * 100) : 0 };
  };

  return res.json({
    summary,
    byBranch: [...branchMap.values()].map(withRate).sort((a, b) => b.bought - a.bought),
    bySales:  [...salesMap.values()].map(withRate).sort((a, b) => b.bought - a.bought),
  });
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
// Contracts module — purchases viewed as contracts.
//   GET    /api/contracts      — RBAC: sales→own, branch_manager→branch, admin→all
//   PUT    /api/contracts/:id  — admin / branch_manager (manager → own branch)
//   DELETE /api/contracts/:id  — admin / branch_manager (manager → own branch)
//                                + smart reversion when a customer's last
//                                  purchase is removed.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/contracts', requireAuth, authorizeRoles('admin', 'branch_manager', 'sales', 'rep'), (req, res) => {
  const db   = getDb();
  const role = req.user?.role;
  let where = '1=1';
  const params = [];
  if (role === 'branch_manager') {
    const b = req.user.branch || null;
    if (!b) return res.status(400).json({ error: 'branch_required' });
    where = 'p.branch = ?';
    params.push(b);
  } else if (role === 'sales' || role === 'rep') {
    where = 'p.rep = ?';
    params.push(req.user.name);
  }

  // Optional filters — date range, branch & rep (admin/manager scoping above
  // already constrains non-admins, so these only narrow further).
  const { startDate, endDate, branch: fBranch, rep: fRep } = req.query;
  const dr = dateRangeClause('p.created_at', startDate, endDate);
  where += dr.clause;
  params.push(...dr.params);
  if (fBranch && role === 'admin') { where += ' AND p.branch = ?'; params.push(fBranch); }
  if (fRep && (role === 'admin' || role === 'branch_manager')) {
    where += ' AND p.rep = ?';
    params.push(fRep);
  }

  const contracts = db.prepare(`
    SELECT p.id, p.user_id, p.price, p.contract_number, p.branch, p.rep,
           p.product_id, p.notes, p.created_at,
           lp.first_name, lp.phone
    FROM purchases p
    LEFT JOIN lead_profiles lp ON lp.user_id = p.user_id
    WHERE ${where}
    ORDER BY p.created_at DESC
    LIMIT 500
  `).all(...params);

  return res.json({ contracts });
});

app.put('/api/contracts/:id', requireAuth, authorizeRoles('admin', 'branch_manager'), (req, res) => {
  const db  = getDb();
  const row = db.prepare(`SELECT id, branch, contract_number FROM purchases WHERE id = ?`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'contract_not_found' });
  if (req.user?.role === 'branch_manager' && row.branch !== req.user.branch) {
    return res.status(403).json({ error: 'forbidden' });
  }

  const { price, contract_number } = req.body || {};
  const newNumber = (contract_number && String(contract_number).trim()) || null;
  db.prepare(`UPDATE purchases SET price = ?, contract_number = ? WHERE id = ?`).run(
    price != null && price !== '' ? Number(price) : null,
    newNumber,
    row.id
  );

  // Macro alert for the admin war-room.
  createNotification(db, 'admin', 'contract_modified',
    `تم تعديل تعاقد رقم [${newNumber || row.contract_number || row.id}] بواسطة [${req.user?.name || '؟'}]`);

  return res.json({ ok: true });
});

app.delete('/api/contracts/:id', requireAuth, authorizeRoles('admin', 'branch_manager'), (req, res) => {
  const db  = getDb();
  const row = db.prepare(`SELECT id, user_id, branch, contract_number FROM purchases WHERE id = ?`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'contract_not_found' });
  if (req.user?.role === 'branch_manager' && row.branch !== req.user.branch) {
    return res.status(403).json({ error: 'forbidden' });
  }

  let reverted = false;
  const tx = db.transaction(() => {
    db.prepare(`DELETE FROM purchases WHERE id = ?`).run(row.id);
    // Smart reversion — if this was the customer's last purchase, send them
    // back into the post-visit follow-up queue.
    const remaining = db.prepare(
      `SELECT COUNT(*) AS n FROM purchases WHERE user_id = ?`
    ).get(row.user_id).n;
    if (remaining === 0) {
      db.prepare(`
        UPDATE lead_profiles SET lead_class = 'visited', purchased_at = NULL
        WHERE user_id = ?
      `).run(row.user_id);
      reverted = true;
    }
  });
  tx();

  // Macro alert for the admin war-room.
  createNotification(db, 'admin', 'contract_deleted',
    `تم حذف تعاقد رقم [${row.contract_number || row.id}] بواسطة [${req.user?.name || '؟'}]`);

  return res.json({ ok: true, reverted });
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
app.post('/api/trigger-message', requireAuth, authorizeRoles('admin', 'branch_manager', 'sales'), async (req, res) => {
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
      SELECT DISTINCT COALESCE(NULLIF(branch,''), event_value) AS b
      FROM events
      WHERE event_type = 'branch_selected'
        AND COALESCE(NULLIF(branch,''), event_value) IS NOT NULL
    `).all().map(r => r.b);
    const known = new Set(branches.map(x => x.id));
    for (const b of seen) {
      // Normalize so 'shams'/'عين شمس'/'ain_shams' don't appear as 3 branches.
      const nb = normalizeBranch(b);
      if (nb && !known.has(nb)) { branches.push({ id: nb, name: nb }); known.add(nb); }
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

// ════════════════════════════════════════════════════════════════════════════
// GET /api/interests  — interest categories the reception desk offers when
//                       registering a walk-in customer (any auth user).
// PUT /api/interests  — replace the full list (admin only).
// Stored in settings under 'interest_categories' as a JSON string[].
// ════════════════════════════════════════════════════════════════════════════
const DEFAULT_INTERESTS = [
  'غرف النوم', 'السفرة', 'الانتريهات', 'غرف الأطفال',
  'الركنات', 'المطابخ', 'المكاتب', 'أخرى',
];

app.get('/api/interests', requireAuth, (req, res) => {
  const db  = getDb();
  const row = db.prepare(`SELECT value FROM settings WHERE key = 'interest_categories'`).get();
  let interests = null;
  try {
    const parsed = JSON.parse(row?.value || 'null');
    if (Array.isArray(parsed)) {
      interests = parsed.map(x => String(x).trim()).filter(Boolean);
    }
  } catch (_) { interests = null; }
  // Fall back to defaults until the admin saves a custom list.
  return res.json({ interests: interests && interests.length ? interests : DEFAULT_INTERESTS });
});

app.put('/api/interests', requireAuth, requireRole('admin'), (req, res) => {
  const { interests } = req.body || {};
  if (!Array.isArray(interests)) {
    return res.status(400).json({ error: 'interests must be an array' });
  }
  // Normalise: trim, drop blanks, drop duplicates.
  const clean = [];
  for (const it of interests) {
    const v = String(it ?? '').trim();
    if (v && !clean.includes(v)) clean.push(v);
  }
  const db = getDb();
  db.prepare(`
    INSERT INTO settings (key, value, updated_at) VALUES ('interest_categories', ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
  `).run(JSON.stringify(clean));
  return res.json({ ok: true, interests: clean });
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
    `SELECT id, name, email, role, branch, active, created_at FROM users ORDER BY created_at`
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

// DELETE /api/users/:id — admin removes a user account permanently.
// Safety: admin cannot delete their OWN account (prevents self-lockout).
// Returns 404 if the user doesn't exist, 400 if attempting self-deletion.
app.delete('/api/users/:id', requireAuth, requireRole('admin'), (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  if (!Number.isFinite(targetId)) return res.status(400).json({ error: 'bad_id' });
  if (targetId === req.user.id)   return res.status(400).json({ error: 'cannot_delete_self' });

  const db = getDb();
  const row = db.prepare(`SELECT id, role FROM users WHERE id = ?`).get(targetId);
  if (!row) return res.status(404).json({ error: 'user_not_found' });

  // Safety: never delete the last admin account.
  if (row.role === 'admin') {
    const others = db.prepare(
      `SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND id != ?`
    ).get(targetId);
    if ((others?.n || 0) === 0) {
      return res.status(400).json({ error: 'cannot_delete_last_admin' });
    }
  }

  db.prepare(`DELETE FROM users WHERE id = ?`).run(targetId);
  return res.json({ ok: true });
});

// ════════════════════════════════════════════════════════════════════════════
// DELETE /api/admin/users/sales-rep/:name — remove a sales rep AND scrub every
// reference to them across the system, in a single transaction. Used to keep
// the data clean after a salesperson leaves.
// ════════════════════════════════════════════════════════════════════════════
app.delete('/api/admin/users/sales-rep/:name', requireAuth, requireRole('admin'), (req, res) => {
  const name = String(req.params.name || '').trim();
  if (!name) return res.status(400).json({ error: 'name_required' });

  const db   = getDb();
  const user = db.prepare(`SELECT id FROM users WHERE role = 'sales' AND name = ?`).get(name);
  if (!user) return res.status(404).json({ error: 'sales_rep_not_found' });

  const scrub = db.transaction(() => {
    db.prepare(`DELETE FROM users WHERE role = 'sales' AND name = ?`).run(name);
    db.prepare(`UPDATE lead_profiles SET assigned_rep = NULL WHERE assigned_rep = ?`).run(name);
    db.prepare(`UPDATE lead_visits SET sales_rep = NULL WHERE sales_rep = ?`).run(name);
    db.prepare(
      `UPDATE branch_customer_followups SET assigned_sales = NULL, followed_up = 0 WHERE assigned_sales = ?`
    ).run(name);
    db.prepare(`UPDATE purchases SET rep = NULL WHERE rep = ?`).run(name);
    db.prepare(`DELETE FROM followup_log WHERE sales = ?`).run(name);
    db.prepare(`DELETE FROM revisit_followups WHERE followed_up_by = ?`).run(name);
  });
  scrub();

  console.log(`🗑️  SALES REP DELETED + SCRUBBED: ${name}`);
  return res.json({ ok: true, name });
});

// ════════════════════════════════════════════════════════════════════════════
// Admin undo ledger — list recent assignment actions and revert human errors.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/admin/audit-logs', requireAuth, requireRole('admin'), (req, res) => {
  const db = getDb();
  const logs = db.prepare(`
    SELECT id, operator_name, action_type, target_id, old_state, created_at
    FROM system_audit_log
    ORDER BY created_at DESC, id DESC
    LIMIT 200
  `).all();
  return res.json({ logs });
});

app.post('/api/admin/audit-logs/:id/revert', requireAuth, requireRole('admin'), (req, res) => {
  const db  = getDb();
  const log = db.prepare(`SELECT * FROM system_audit_log WHERE id = ?`).get(req.params.id);
  if (!log) return res.status(404).json({ error: 'log_not_found' });

  let state;
  try { state = JSON.parse(log.old_state || 'null'); } catch (_) { state = null; }
  if (!state || !state.table) return res.status(400).json({ error: 'bad_old_state' });

  // Whitelist the tables the ledger is allowed to touch.
  const ALLOWED = ['branch_customer_followups', 'lead_visits'];
  if (!ALLOWED.includes(state.table)) {
    return res.status(400).json({ error: 'table_not_revertable' });
  }

  const whereKeys = Object.keys(state.where || {});
  const whereSql  = whereKeys.map(k => `${k} = ?`).join(' AND ');
  const whereVals = whereKeys.map(k => state.where[k]);

  if (!state.row) {
    // The row did not exist before the action → undo = delete it.
    db.prepare(`DELETE FROM ${state.table} WHERE ${whereSql}`).run(...whereVals);
  } else {
    // Restore the row exactly as it was (row includes the primary key).
    const cols = Object.keys(state.row);
    db.prepare(
      `INSERT OR REPLACE INTO ${state.table} (${cols.join(', ')}) VALUES (${cols.map(() => '?').join(', ')})`
    ).run(...cols.map(c => state.row[c]));
  }

  console.log(`↩️  AUDIT REVERT: log#${log.id} (${log.action_type}) by ${req.user?.name}`);
  return res.json({ ok: true, reverted: log.action_type, target_id: log.target_id });
});

// ════════════════════════════════════════════════════════════════════════════
// Live / Demo sandbox switch. GET is open to any authenticated user (the demo
// banner must show to everyone); toggling is admin-only.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/admin/system-mode', requireAuth, (req, res) => {
  return res.json({ mode: global.systemMode || 'live' });
});

app.post('/api/admin/toggle-system-mode', requireAuth, requireRole('admin'), (req, res) => {
  global.systemMode = global.systemMode === 'demo' ? 'live' : 'demo';
  getDb(); // force-init the target DB (creates + seeds the demo DB on first switch)
  console.log(`🔀 SYSTEM MODE → ${global.systemMode}`);
  return res.json({ ok: true, mode: global.systemMode });
});

// ════════════════════════════════════════════════════════════════════════════
// Notifications — admin-only macro alerts (contracts changed, big deals).
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/notifications', requireAuth, requireRole('admin'), (req, res) => {
  const db = getDb();
  const notifications = db.prepare(`
    SELECT id, type, message, read, created_at
    FROM notifications
    WHERE audience = 'admin'
    ORDER BY created_at DESC, id DESC
    LIMIT 50
  `).all();
  const unread = notifications.filter(n => !n.read).length;
  return res.json({ notifications, unread });
});

app.post('/api/notifications/read-all', requireAuth, requireRole('admin'), (req, res) => {
  getDb().prepare(`UPDATE notifications SET read = 1 WHERE audience = 'admin' AND read = 0`).run();
  return res.json({ ok: true });
});

// ════════════════════════════════════════════════════════════════════════════
// Sales targets — admin sets revenue goals per branch / per sales rep.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/admin/targets', requireAuth, authorizeRoles('admin', 'branch_manager'), (req, res) => {
  // Defaults to the current calendar month when ?month is not given.
  const month = (req.query.month && String(req.query.month).trim()) || currentMonth();
  const rows = getDb().prepare(`
    SELECT scope_type, scope_name, target_month, target_amount
    FROM sales_targets WHERE target_month = ?
  `).all(month);
  return res.json({ month, targets: rows });
});

app.post('/api/admin/targets', requireAuth, requireRole('admin'), (req, res) => {
  const { scope_type, scope_name, target_amount, target_month } = req.body || {};
  if (!['branch', 'sales_rep'].includes(scope_type)) {
    return res.status(400).json({ error: 'bad_scope_type' });
  }
  const name = (scope_name && String(scope_name).trim()) || '';
  if (!name) return res.status(400).json({ error: 'scope_name_required' });
  const amount = Number(target_amount);
  if (!Number.isFinite(amount) || amount < 0) {
    return res.status(400).json({ error: 'bad_target_amount' });
  }
  // Default to the current calendar month; validate the 'YYYY-MM' shape.
  let month = (target_month && String(target_month).trim()) || currentMonth();
  if (!/^\d{4}-\d{2}$/.test(month)) month = currentMonth();

  getDb().prepare(`
    INSERT INTO sales_targets (scope_type, scope_name, target_month, target_amount)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(scope_type, scope_name, target_month)
      DO UPDATE SET target_amount = excluded.target_amount
  `).run(scope_type, name, month, amount);
  return res.json({ ok: true, scope_type, scope_name: name, target_month: month, target_amount: amount });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/admin/kpis — filtered executive KPIs (revenue / visits / closing
// rate) + target achievement. Filters: startDate, endDate, branch, rep.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/admin/kpis', requireAuth, requireRole('admin'), (req, res) => {
  const db = getDb();
  const { startDate, endDate, branch, rep } = req.query;

  // Revenue + buyer count from purchases.
  const purDate = dateRangeClause('created_at', startDate, endDate);
  let purWhere = '1=1' + purDate.clause;
  const purParams = [...purDate.params];
  if (branch) { purWhere += ' AND branch = ?'; purParams.push(branch); }
  if (rep)    { purWhere += ' AND rep = ?';    purParams.push(rep); }
  const purRow = db.prepare(`
    SELECT COALESCE(SUM(price), 0) AS revenue, COUNT(DISTINCT user_id) AS buyers
    FROM purchases WHERE ${purWhere}
  `).get(...purParams);

  // Visit count from lead_visits.
  const visDate = dateRangeClause('visited_at', startDate, endDate);
  let visWhere = '1=1' + visDate.clause;
  const visParams = [...visDate.params];
  if (branch) { visWhere += ' AND branch = ?';    visParams.push(branch); }
  if (rep)    { visWhere += ' AND sales_rep = ?'; visParams.push(rep); }
  const visits = db.prepare(
    `SELECT COUNT(DISTINCT user_id) AS n FROM lead_visits WHERE ${visWhere}`
  ).get(...visParams).n;

  // Target progress — strictly the CURRENT calendar month: this month's
  // target vs revenue generated this month (independent of the filter range).
  const curMonth = currentMonth();
  let target = 0;
  if (rep)         target = getTarget(db, 'sales_rep', rep);
  else if (branch) target = getTarget(db, 'branch', branch);
  else {
    target = db.prepare(`
      SELECT COALESCE(SUM(target_amount), 0) AS t
      FROM sales_targets WHERE scope_type = 'branch' AND target_month = ?
    `).get(curMonth).t || 0;
  }
  const monthRev = monthRevenue(db, { branch, rep, month: curMonth });

  const revenue = purRow.revenue || 0;

  // ── Filtered chart datasets (so the dashboard charts honour the filters) ──
  const evDate = dateRangeClause('created_at', startDate, endDate);

  // Branch demand — customers who asked for each branch.
  let bdWhere = `event_type IN ('branch_selected', 'location_request')
    AND COALESCE(NULLIF(branch,''), event_value) IS NOT NULL` + evDate.clause;
  const bdParams = [...evDate.params];
  if (branch) { bdWhere += ` AND COALESCE(NULLIF(branch,''), event_value) = ?`; bdParams.push(branch); }
  const branch_demand = db.prepare(`
    SELECT COALESCE(NULLIF(branch,''), event_value) AS branch, COUNT(DISTINCT user_id) AS requests
    FROM events WHERE ${bdWhere}
    GROUP BY COALESCE(NULLIF(branch,''), event_value)
    ORDER BY requests DESC
  `).all(...bdParams);

  // Branch visits — reception-confirmed arrivals per branch.
  let bvWhere = 'branch IS NOT NULL' + visDate.clause;
  const bvParams = [...visDate.params];
  if (branch) { bvWhere += ' AND branch = ?'; bvParams.push(branch); }
  const branch_visits = db.prepare(`
    SELECT branch, COUNT(DISTINCT user_id) AS visits
    FROM lead_visits WHERE ${bvWhere}
    GROUP BY branch ORDER BY visits DESC
  `).all(...bvParams);

  // Funnel stages (date-filtered; branch filter skipped — early stages carry
  // no branch and would zero-out the funnel).
  const funnel_stages = db.prepare(`
    SELECT event_type, COUNT(DISTINCT user_id) AS unique_users
    FROM events
    WHERE event_type IN (
      'entry_catalog', 'entry_offer', 'entry_location',
      'product_details', 'location_request',
      'branch_selected', 'map_click', 'contact_request', 'visit_confirmed'
    )${evDate.clause}
    GROUP BY event_type ORDER BY unique_users DESC
  `).all(...evDate.params);

  // Lead distribution by class.
  const ldDate = dateRangeClause('created_at', startDate, endDate);
  let ldWhere = '1=1' + ldDate.clause;
  const ldParams = [...ldDate.params];
  if (branch) { ldWhere += ' AND preferred_branch = ?'; ldParams.push(branch); }
  const lead_distribution = db.prepare(`
    SELECT lead_class, COUNT(*) AS count FROM lead_profiles WHERE ${ldWhere}
    GROUP BY lead_class
  `).all(...ldParams);

  return res.json({
    total_revenue:    revenue,
    total_visits:     visits,
    closing_rate:     visits ? Math.round((purRow.buyers / visits) * 100) : 0,
    target,
    target_month:     curMonth,
    month_revenue:    monthRev,
    percent_achieved: pctAchieved(monthRev, target),
    funnel_stages,
    lead_distribution,
    branch_demand,
    branch_visits,
  });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/sales/my-target — a sales rep sees their OWN target + achievement.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/sales/my-target', requireAuth, authorizeRoles('sales', 'rep'), (req, res) => {
  const db = getDb();
  const me = req.user.name;
  // Current calendar month: this month's target vs this month's revenue.
  const target  = getTarget(db, 'sales_rep', me);
  const revenue = monthRevenue(db, { rep: me });
  return res.json({
    target,
    revenue,
    percent:      pctAchieved(revenue, target),
    target_month: currentMonth(),
  });
});

// Also expose the dashboard summary's age buckets so the customers analytics
// page can show *real* aging across all leads (not just the recent_hot_leads
// preview). Returns counts for today / week / month / older.
app.get('/api/admin/leads-aging', requireAuth, requireRole('admin'), (_req, res) => {
  const db = getDb();
  const row = db.prepare(`
    SELECT
      SUM(CASE WHEN julianday('now') - julianday(created_at) <= 1  THEN 1 ELSE 0 END) AS today,
      SUM(CASE WHEN julianday('now') - julianday(created_at) >  1
            AND julianday('now') - julianday(created_at) <= 7  THEN 1 ELSE 0 END) AS week,
      SUM(CASE WHEN julianday('now') - julianday(created_at) >  7
            AND julianday('now') - julianday(created_at) <= 30 THEN 1 ELSE 0 END) AS month,
      SUM(CASE WHEN julianday('now') - julianday(created_at) > 30 THEN 1 ELSE 0 END) AS older,
      COUNT(*) AS total
    FROM lead_profiles
    WHERE created_at IS NOT NULL
  `).get();
  return res.json({
    today: row?.today || 0,
    week:  row?.week  || 0,
    month: row?.month || 0,
    older: row?.older || 0,
    total: row?.total || 0,
  });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /health — Health check
// ════════════════════════════════════════════════════════════════════════════
// Version marker — bumped on every meaningful release so the admin
// (and our deploy checks) can confirm production is running the latest code.
const BUILD_VERSION = '2026-05-20-manychat-enrichment-v1';
app.get('/health', (req, res) => {
  res.json({
    status:    'ok',
    timestamp: new Date().toISOString(),
    version:   BUILD_VERSION,
  });
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

// ── One-time data migration: normalize historical branch ids ──────────────
// Old rows stored the branch under whatever ManyChat sent (Arabic free text,
// alt spellings) so one branch was counted as several. Collapse them all to
// the canonical slug. Idempotent — safe to run on every startup.
(function normalizeHistoricalBranches() {
  try {
    const db = getDb();

    const eventRows = db.prepare(`
      SELECT id, event_value, branch FROM events
      WHERE event_type IN ('branch_selected', 'location_request', 'entry_location')
    `).all();
    const updEvent = db.prepare(`UPDATE events SET branch = ? WHERE id = ?`);
    let eventsFixed = 0;
    db.transaction(() => {
      for (const r of eventRows) {
        const source    = (r.branch && r.branch.trim()) || r.event_value;
        const canonical = normalizeBranch(source);
        if (canonical && canonical !== r.branch) { updEvent.run(canonical, r.id); eventsFixed++; }
      }
    })();

    const visitRows = db.prepare(`SELECT id, branch FROM lead_visits WHERE branch IS NOT NULL`).all();
    // OR REPLACE: if normalizing collapses two visit rows for the same user
    // onto the same (user_id, branch) pair, drop the stale duplicate.
    const updVisit  = db.prepare(`UPDATE OR REPLACE lead_visits SET branch = ? WHERE id = ?`);
    let visitsFixed = 0;
    db.transaction(() => {
      for (const r of visitRows) {
        const canonical = normalizeBranch(r.branch);
        if (canonical && canonical !== r.branch) { updVisit.run(canonical, r.id); visitsFixed++; }
      }
    })();

    const profileRows = db.prepare(
      `SELECT user_id, preferred_branch FROM lead_profiles WHERE preferred_branch IS NOT NULL`
    ).all();
    const updProfile = db.prepare(`UPDATE lead_profiles SET preferred_branch = ? WHERE user_id = ?`);
    let profilesFixed = 0;
    db.transaction(() => {
      for (const r of profileRows) {
        const canonical = normalizeBranch(r.preferred_branch);
        if (canonical && canonical !== r.preferred_branch) { updProfile.run(canonical, r.user_id); profilesFixed++; }
      }
    })();

    // Normalize the configured branch list itself — if its ids aren't the
    // canonical slugs, the branch filter shows a branch twice (once as the
    // configured name, once as the raw event id).
    let configFixed = 0;
    const cfgRow = db.prepare(`SELECT value FROM settings WHERE key = 'active_branches'`).get();
    if (cfgRow && cfgRow.value) {
      try {
        const parsed = JSON.parse(cfgRow.value);
        if (Array.isArray(parsed)) {
          const seenIds = new Set();
          const fixed = [];
          for (const b of parsed) {
            const entry = typeof b === 'string' ? { id: b, name: b } : { ...b };
            const canonical = normalizeBranch(entry.id);
            if (canonical !== entry.id) configFixed++;
            entry.id = canonical;
            if (!seenIds.has(entry.id)) { seenIds.add(entry.id); fixed.push(entry); }
          }
          if (configFixed) {
            db.prepare(`
              INSERT INTO settings (key, value, updated_at)
              VALUES ('active_branches', ?, datetime('now'))
              ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            `).run(JSON.stringify(fixed));
          }
        }
      } catch (_) { /* malformed setting — leave it */ }
    }

    if (eventsFixed || visitsFixed || profilesFixed || configFixed) {
      console.log(`✅ Migration: normalized branch ids — events:${eventsFixed} visits:${visitsFixed} profiles:${profilesFixed} config:${configFixed}`);
    }
  } catch (e) {
    console.error('[migration] branch normalize failed:', e.message);
  }
})();

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
