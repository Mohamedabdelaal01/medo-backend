// server.js — Grand Furniture Backend
// Receives ManyChat webhooks, scores leads, feeds dashboard API
// Node.js + Express + SQLite — beginner-friendly & production-ready

require('dotenv').config();
const express  = require('express');
const cors     = require('cors');
const crypto   = require('crypto'); // built-in — no install needed
const fs       = require('fs');
const bcrypt   = require('bcryptjs');
const { getDb, getLiveDb,
        DB_PATH, isDemoContext, getDbContextName, getReadonlyDb, removeDemoDbAtBoot } = require('./db');
// Version marker — bumped on every meaningful release so the admin (and our
// deploy checks, GET /health) can confirm production runs the latest code.
// Declared here (not next to /health) because the boot backup below names its
// pre-migration copy after it.
const BUILD_VERSION = '2026-11-25-contracts-filters-r2';
// Phase 0: a copy of the live DB BEFORE this boot's migrations (first boot of
// each version) + the day's copy — /data/backups, see services/backup.js.
const backup = require('./services/backup');
backup.bootBackup({ dbPath: DB_PATH, version: BUILD_VERSION });
// Phase 0: no outgoing call from a demo_ session (fetch backstop installed on require).
const outbound = require('./services/outbound');
const sqlGuard = require('./services/sqlGuard');
const secrets  = require('./services/secrets');
const { processScore, getScoringConfig, computeDecayedScore, classifyLead, DEFAULT_SCORE_MAP, ONCE_PER_USER_EVENTS } = require('./scoring');
const { canSend, recordSend, getStateRotated, getWeeklyLimit } = require('./services/scheduler');
const { decide, flowIdFor }= require('./services/nextAction');
const { syncLeadClass }    = require('./services/tagging');
const { sendMetaEvent, leadEventId } = require('./services/metaCapi');
const { callAi, getAiConfig, extractJson, isAllowedAiBaseUrl } = require('./services/ai');
const { getManyChatClient }= require('./manychat/client');
const counters             = require('./services/healthCounters');
const { guardedSendFlow, SKIP_MESSAGES_AR } = require('./services/windowGuard');
const { createPhoneMasker } = require('./services/phoneMask');
const visitIntent           = require('./services/visitIntent');
const grandCatalog          = require('./services/grandCatalog');
const { requireAuth, requireRole, authorizeRoles, signSessionToken,
        rotateJwtSecretOnce, jwtRotated, ROTATED_FLAG } = require('./middleware/auth');

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
  // Arabic-Indic (٠-٩) and extended (۰-۹) digits → ASCII first: customers in
  // Egypt often type their number that way, and \D would drop every digit.
  let d = String(raw)
    .replace(/[\u0660-\u0669]/g, (c) => String(c.charCodeAt(0) - 0x0660))
    .replace(/[\u06F0-\u06F9]/g, (c) => String(c.charCodeAt(0) - 0x06F0))
    .replace(/\D/g, '');                             // digits only
  if (!d) return null;
  d = d.replace(/^00/, '');                          // drop intl "00" prefix
  if (d.startsWith('20') && d.length >= 11) d = d.slice(2); // drop EG country code
  if (d.length === 10 && d[0] !== '0') d = '0' + d;  // 1012345678 → 01012345678
  return d;
}

// ── ManyChat placeholder guard ────────────────────────────────────────────────
// An unresolved ManyChat field reference arrives as a literal "{{...}}" template
// token (e.g. "{{gender}}", "{{cuf_14597615}}") — it means the External Request
// block points at a field that didn't resolve. It's never a real value, so we
// store NULL instead of polluting the column. Matches a "{{ }}" token ANYWHERE
// in the string (not just a whole-string match), so partially-broken values
// like "John {{last_name}}" are caught too.
function isBrokenPlaceholder(v) {
  return typeof v === 'string' && /\{\{.*?\}\}/.test(v);
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

// ── Intake branch check (C1.1) ────────────────────────────────────────────────
// What the bot may write as a branch on intake (preferred_branch, events.branch,
// location_requested): one of the 6 fixed codes the bot's chips send (runbook
// Appendix 3), a known alias of one, or an id in the live active_branches list.
// Anything else — 'all_branches', a typo, free text — is null: never stored as
// a branch. normalizeBranch above is untouched (visits and the branch config
// still use it, so alexandria / new_cairo / october survive there).
const INTAKE_BRANCH_CODES = ['nasr_city', 'maadi', 'helwan', 'faisal', 'ain_shams', 'alexandria'];
const INTAKE_EXTRA_ALIASES = {
  alexandria: ['alexandria', 'alex', 'الإسكندرية', 'الاسكندرية', 'إسكندرية', 'اسكندرية', 'الاسكندريه', 'اسكندريه'],
};
const _intakeExtraLookup = (() => {
  const m = new Map();
  for (const [canonical, aliases] of Object.entries(INTAKE_EXTRA_ALIASES)) {
    for (const a of aliases) m.set(a.toLowerCase().replace(/\s+/g, ' ').trim(), canonical);
  }
  return m;
})();
// The live branch list: [{ id, nameKey }] (nameKey = the configured Arabic
// name, lower-cased, spaces collapsed — the old bot sent names).
function activeBranchIds(db) {
  try {
    const row = db.prepare(`SELECT value FROM settings WHERE key = 'active_branches'`).get();
    const parsed = row && row.value ? JSON.parse(row.value) : [];
    if (!Array.isArray(parsed)) return [];
    return parsed
      .map(b => (typeof b === 'string' ? { id: b, name: null } : { id: b && b.id, name: b && b.name }))
      .filter(b => typeof b.id === 'string' && b.id.trim() && b.id.trim().toLowerCase() !== 'all_branches')
      .map(b => ({ id: b.id.trim(),
        nameKey: typeof b.name === 'string' ? b.name.toLowerCase().replace(/\s+/g, ' ').trim() : null }));
  } catch (_) { return []; }
}
// opts.ids — activeBranchIds(), when the caller already read it (boot passes).
function intakeBranch(raw, opts = {}) {
  if (raw == null) return null;
  const key = String(raw).toLowerCase().replace(/\s+/g, ' ').trim();
  if (!key || key === 'all_branches') return null;
  if (INTAKE_BRANCH_CODES.includes(key)) return key;
  const alias = _branchAliasLookup.get(key) || _intakeExtraLookup.get(key);
  if (alias) return alias;
  const live = opts.ids || activeBranchIds(opts.db || getDb());
  const trimmed = String(raw).trim();
  const hit = live.find(b => b.id === trimmed) || live.find(b => b.nameKey && b.nameKey === key);
  return hit ? hit.id : null;
}

// visit_planned's day, normalised (C1.8): «النهارده» → today, «بكره» → tomorrow,
// «الأسبوع ده» → this_week, «لسه مش متأكد» → unsure, anything else → other.
function normalizePlannedDay(raw) {
  if (raw == null) return null;
  const s = String(raw).toLowerCase()
    .replace(/[\u064B-\u0652\u0640]/g, '')          // harakat + tatweel
    .replace(/[أإآ]/g, 'ا').replace(/ة/g, 'ه').replace(/ى/g, 'ي')
    .replace(/\s+/g, ' ').trim();
  if (!s) return null;
  if (s === 'unsure' || s.includes('مش متاكد') || s.includes('مش عارف')) return 'unsure';
  if (s === 'today' || s.includes('النهارده') || s.includes('انهارده') || s.includes('النهاردا')) return 'today';
  if (s === 'tomorrow' || s.includes('بكره') || s.includes('بكرا')) return 'tomorrow';
  if (s === 'this_week') return 'this_week';
  if (s.includes('اسبوع')) {
    // «الأسبوع الجاي» / «الأسبوع القادم» is NOT this week (review r2).
    if (/(جاي|جاى|القادم|الجديد)/.test(s)) return 'other';
    if (/(^|\s)(ده|دا|دي|هذا|هدا)(\s|$)/.test(s)) return 'this_week';
  }
  return 'other';
}

// ── Cairo calendar day ────────────────────────────────────────────────────────
// Reception's «زيارة اليوم» is a CAIRO day, not a UTC day (a customer confirmed
// at 01:00 Cairo is "today" there but "yesterday" in UTC). Everything stored
// stays UTC (datetime('now') → 'YYYY-MM-DD HH:MM:SS'); these helpers only turn
// "today in Cairo" into UTC bounds. Intl knows Egypt's summer time — never
// hard-code +2/+3 and never use SQLite 'localtime' (the server runs in UTC).
// Every month counter is a Cairo month since 2026-11-25 (currentMonth below).
const CAIRO_TZ = 'Africa/Cairo';
const _cairoFmt = new Intl.DateTimeFormat('en-CA', { timeZone: CAIRO_TZ, year: 'numeric', month: '2-digit',
  day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' });
function cairoParts(d) { const o = {}; for (const p of _cairoFmt.formatToParts(d)) o[p.type] = p.value; return o; }
// 'YYYY-MM-DD' of `d` in Cairo.
function cairoDay(d = new Date()) { const p = cairoParts(d); return `${p.year}-${p.month}-${p.day}`; }
function cairoOffsetMs(d) {
  const p = cairoParts(d);
  return Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour, +p.minute, +p.second) - Math.floor(d.getTime() / 1000) * 1000;
}
// Date of 00:00 Cairo (or the summer-time jump instant) on `day` ('YYYY-MM-DD').
function cairoDayStart(day) {
  const [y, m, dd] = day.split('-').map(Number); const g = Date.UTC(y, m - 1, dd);
  let t = g - cairoOffsetMs(new Date(g)); t = g - cairoOffsetMs(new Date(t)); return new Date(t);
}
function toSqlUtc(d) { return d.toISOString().slice(0, 19).replace('T', ' '); }
// [start, end) of a Cairo day as UTC SQL strings — compare with datetime(col).
function cairoDayBoundsSql(day) {
  const [y, m, dd] = day.split('-').map(Number);
  const next = new Date(Date.UTC(y, m - 1, dd + 1)).toISOString().slice(0, 10);
  return [toSqlUtc(cairoDayStart(day)), toSqlUtc(cairoDayStart(next))];
}
// A stored UTC 'YYYY-MM-DD HH:MM:SS' (no zone) → Date.
function sqlUtcToDate(s) {
  if (!s) return null; const v = String(s);
  return new Date(/Z$|[+-]\d\d:\d\d$/.test(v) ? v : v.replace(' ', 'T') + 'Z');
}
// 'HH:MM' (24h) of `d` in Cairo.
function cairoHHMM(d) { const p = cairoParts(d); return `${p.hour}:${p.minute}`; }
// «أرقام حقيقية» (2026-11-22): what every analytics step counts — Cairo days,
// people not events, walk-ins never a chat step (services/honestNumbers.js).
const honest = require('./services/honestNumbers')({ cairoDay, cairoDayBoundsSql, sqlUtcToDate, normalizeBranch });
// The moment a sale was TYPED (2026-11-25): a contract's date (created_at) can
// be corrected by its branch manager / the admin; recorded_at keeps the typing
// moment then (NULL = never re-dated → created_at). Analytics and the reception
// desk's «اشترى النهارده» (today's list, «مشي من غير شراء», review r2) read
// created_at — the contract's day; Meta's re-send window and the duplicate /
// old-tab guards read this.
const RECORDED_AT = (a = '') => `COALESCE(${a ? a + '.' : ''}recorded_at, ${a ? a + '.' : ''}created_at)`;

// ── Auto-assignment ───────────────────────────────────────────────────────────
// Assigns an unassigned lead to the SALES user of the lead's OWN branch
// (lead_profiles.preferred_branch) with the FEWEST active leads (active = not
// purchased/converted). A lead with no branch is not auto-assigned — the
// branch manager assigns it. Returns the name or null.
// Phase 0 (2026-11-22): it used to pick the least-loaded 'sales' OR 'rep'
// user company-wide, so a salesperson's list filled with other branches'
// customers. Rollback without a redeploy: settings auto_assign_scope =
// 'company' (the old pick). settings auto_assign_enabled still turns it off.
// Safe & best-effort: never throws into the webhook path.
function autoAssignLead(db, userId, leadName, branchHint = null) {
  try {
    const scope = getSetting('auto_assign_scope', 'branch');
    let pick;
    if (scope === 'company') {
      pick = db.prepare(`
        SELECT u.name AS rep,
          (SELECT COUNT(*) FROM lead_profiles lp
             WHERE lp.assigned_rep = u.name
               AND lp.lead_class NOT IN ('purchased','converted')) AS load
        FROM users u
        WHERE u.role = 'sales' AND u.active = 1   -- phase 1: never a call rep
        ORDER BY load ASC, u.name ASC
        LIMIT 1
      `).get();
    } else {
      const row = db.prepare(`SELECT preferred_branch FROM lead_profiles WHERE user_id = ?`).get(userId);
      const branch = String((row && row.preferred_branch) || branchHint || '').trim();
      if (!branch || branch.toLowerCase() === 'all_branches') return null;   // no branch → the manager assigns
      pick = db.prepare(`
        SELECT u.name AS rep,
          (SELECT COUNT(*) FROM lead_profiles lp
             WHERE lp.assigned_rep = u.name
               AND lp.lead_class NOT IN ('purchased','converted')) AS load
        FROM users u
        WHERE u.role = 'sales' AND u.active = 1
          AND LOWER(TRIM(COALESCE(u.branch, ''))) = LOWER(?)
        ORDER BY load ASC, u.name ASC
        LIMIT 1
      `).get(branch);
    }

    if (!pick || !pick.rep) return null; // nobody to assign to in that branch

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
// Key for the phone part of the dedup hash: random per boot, never stored or
// logged (a retry across a restart inside 10 s is the only thing it can miss).
const DEDUP_PHONE_KEY = crypto.randomBytes(32);

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
  'https://portal.grandfurnitureeg.com',  // Production subdomain (GoDaddy → Vercel)
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

// ── «تقريبي» is the admin's only (owner, 2026-11-22) ─────────────────────────
// A sale's estimate (today's LIST prices of what was recorded) is shown to the
// admin ONLY. The routes that build it ask for role === 'admin' themselves; this
// is the backstop for every route, present and future: for anyone but an admin
// (or with no session) any key below is removed from a JSON answer, at any
// depth, before it leaves. Keys only the estimate uses — never a key staff need
// (price = the paid amount staff typed stays).
const ADMIN_ONLY_KEYS = new Set([
  'estimate', 'estimates', 'list_total_estimate', 'estimate_complete', 'estimate_total', 'estimate_count',
  'estimate_incomplete', 'estimate_source', 'estimate_lines', 'value_total', 'sales_value',
]);
function stripAdminOnly(v, depth = 0) {
  if (v == null || typeof v !== 'object' || depth > 12) return v;
  if (Array.isArray(v)) {
    let out = null;
    for (let i = 0; i < v.length; i++) {
      const s = stripAdminOnly(v[i], depth + 1);
      if (s !== v[i]) { out = out || v.slice(); out[i] = s; }
    }
    return out || v;
  }
  if (Object.getPrototypeOf(v) !== Object.prototype && Object.getPrototypeOf(v) !== null) return v;
  let out = null;
  for (const k of Object.keys(v)) {
    if (ADMIN_ONLY_KEYS.has(k)) { out = out || { ...v }; delete out[k]; continue; }
    const s = stripAdminOnly(v[k], depth + 1);
    if (s !== v[k]) { out = out || { ...v }; out[k] = s; }
  }
  return out || v;
}
app.use((req, res, next) => {
  const json = res.json.bind(res);
  res.json = (body) => json(req.user && req.user.role === 'admin' ? body : stripAdminOnly(body));
  next();
});

// Request logger — skip health checks (Railway pings them constantly) and
// stay quiet in production to avoid log bloat. Set LOG_REQUESTS=1 to force on.
const LOG_REQUESTS = process.env.LOG_REQUESTS === '1' || process.env.NODE_ENV !== 'production';
app.use((req, res, next) => {
  if (LOG_REQUESTS && req.path !== '/health') {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  }
  next();
});

// ── Usage counters (phase 0) ─────────────────────────────────────────────────
// Since boot, counts only (roles, never names or ids), on /health «usage»: the
// features the overhaul plan wants measured before removing them. Counted when
// the response finishes, so req.user (set by requireAuth) tells the role and
// whether it was a demo_ session. The rep dashboard and the AI SQL / MCP tools
// count themselves (role-scoped inside their routes).
const USAGE_ROUTES = [
  ['ai_brief',            (m, p) => /^\/api\/sales\/customers\/[^/]+\/ai-brief$/.test(p)],
  ['mcp',                 (m, p) => p.startsWith('/api/mcp/')],
  ['analytics_campaigns', (m, p) => p === '/api/analytics'],
  ['analytics_advanced',  (m, p) => p === '/api/analytics/advanced'],
  ['ad_funnel',           (m, p) => p === '/api/admin/ad-funnel'],
  ['catalog_read',        (m, p) => m === 'GET' && (p === '/api/products' || p.startsWith('/api/products/'))],
  ['catalog_write',       (m, p) => m !== 'GET' && (p === '/api/products' || p.startsWith('/api/products/'))],
];
app.use((req, res, next) => {
  const hit = USAGE_ROUTES.find(([, test]) => test(req.method, req.path));
  if (hit) {
    res.on('finish', () => {
      // Counted when the route answered (a refused login / role / unknown id is not use).
      if ([401, 403, 404].includes(res.statusCode)) return;
      const role = hit[0] === 'mcp' ? 'mcp' : req.user?.role;
      counters.countUsage(hit[0], role, req.user?.ctx === 'demo');   // the signed claim (phase 0 r2), not the name
    });
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
  // Accept `psid` as an alias for `user_id`. Several ManyChat External Request
  // nodes send only `psid` (both are mapped to the same [Contact Id] merge tag
  // in the flows that send both, so they are literally the same value). Without
  // this, those nodes got a 400 and ManyChat aborted the rest of the flow —
  // which silently stopped the "leave your phone number" step from ever being
  // sent, and with it the phone captures that feed the Meta CAPI Lead event.
  if (req.body && !req.body.user_id && typeof req.body.psid === 'string' && req.body.psid.trim() !== '') {
    req.body.user_id = req.body.psid.trim();
  }

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
  // A request that carries a usable phone is never refused: the bot sends the
  // phone once and ManyChat doesn't retry, so a 429 here would lose it. Same
  // rule as the handler (a "{{…}}" placeholder is no phone). Repeats: the 10 s
  // dedup for all, R1 for branch_selected; other types have no cap here.
  const p = req.body.phone;
  if (!isBrokenPlaceholder(p) && /^01\d{9}$/.test(normalizePhone(p) || '')) return next();
  const userId = req.body.user_id;
  const now    = Date.now();
  const state  = rateLimitMap.get(userId);

  if (!state || (now - state.windowStart) > RATE_LIMIT_WINDOW) {
    // First event in a new window — open a fresh counter
    rateLimitMap.set(userId, { count: 1, windowStart: now });
    return next();
  }

  if (state.count >= RATE_LIMIT_MAX) {
    counters.countRateLimited(req.body.event_type);
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
  // Phase 0 r4: the demo sandbox («وضع التدريب») is removed (owner,
  // 2026-11-22). A demo_ login used to open the sandbox DB; now it is 401 with
  // a plain message, and nothing ever opens that DB again (db.js).
  if (typeof email === 'string' && email.trim().toLowerCase().startsWith('demo_')) {
    return res.status(401).json({ error: 'وضع التدريب اتشال — الحسابات التجريبية مبقتش شغالة. ادخل بحسابك العادي', code: 'demo_removed' });
  }
  const db   = getLiveDb();
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
  // The signed claims: ctx 'live' (the only DB now) and tv = the row's
  // token_version — requireAuth compares it on every request (phase 0 r4).
  const token   = signSessionToken({ ...payload, tv: Number(user.token_version) || 0 }, 'live');
  return res.json({ token, user: payload });
});

app.post('/api/auth/logout', (req, res) => {
  return res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  return res.json({ user: req.user });
});

// ── Intake answer keys (C1 / §2.3 R4) ─────────────────────────────────────
// Every 200 from /api/events carries lead_class, new_score and has_phone
// ('yes' / 'no') — skips and test answers included — so a ManyChat response
// mapping never empties a real field. Read-only.
function userHasPhone(db, userId) {
  const r = db.prepare(`
    SELECT EXISTS (SELECT 1 FROM lead_phones WHERE user_id = ?)
        OR EXISTS (SELECT 1 FROM lead_profiles WHERE user_id = ? AND phone IS NOT NULL AND phone <> '') AS has
  `).get(userId, userId);
  return !!(r && r.has);
}
function answerKeys(db, userId) {
  const p = db.prepare(`SELECT lead_class, total_score FROM lead_profiles WHERE user_id = ?`).get(userId);
  return {
    lead_class: (p && p.lead_class) || 'cold',
    new_score:  (p && p.total_score) || 0,
    has_phone:  userHasPhone(db, userId) ? 'yes' : 'no',
  };
}

// A phone a chat lead sent: kept forever in lead_phones (never overwritten).
// The Meta CAPI "Lead" fires the first time THIS user leaves THIS phone — unless
// the phone already sits on another profile (the same person on Instagram and
// Messenger, or a reception walk-in): then it is stored and no Lead fires
// (C1.6, «one Lead per person»). Logged as a count, never the phone.
function storeChatPhone(db, { userId, phone, capi }) {
  if (!phone) return { stored: false, lead: false };
  const ins = db.prepare(`INSERT OR IGNORE INTO lead_phones (user_id, phone, source) VALUES (?, ?, 'chat')`).run(userId, phone);
  if (ins.changes === 0) return { stored: false, lead: false };
  const elsewhere = db.prepare(`SELECT 1 FROM lead_phones WHERE phone = ? AND user_id <> ? LIMIT 1`).get(phone, userId)
    || db.prepare(`SELECT 1 FROM lead_profiles WHERE phone = ? AND user_id <> ? LIMIT 1`).get(phone, userId);
  if (elsewhere) {
    counters.countLeadSkipped();
    console.log('[lead-rule] Lead not sent: this phone is already on another profile (phone: present)');
    return { stored: true, lead: false };
  }
  // Advanced Matching: the Messenger PSID as external_id (explicit psid, else
  // user_id) so leads from direct m.me links (no fbclid) still match.
  sendMetaEvent('Lead',
    { phone, firstName: capi.firstName, lastName: capi.lastName, branch: capi.branch, gender: capi.gender,
      externalId: capi.psid || userId },
    leadEventId(userId, phone));
  return { stored: true, lead: true };
}

// The body's "test" key (§2.3 R5): test mode only for these values (trimmed,
// case-insensitive) or boolean true. A number counts by its digits (1 → "1").
const TEST_FLAG_VALUES = new Set(['ask', 'known', 'true', '1', 'yes', 'test']);
function isTestFlag(v) {
  if (v === true) return true;
  if (typeof v !== 'string' && typeof v !== 'number') return false;
  return TEST_FLAG_VALUES.has(String(v).trim().toLowerCase());
}

// Cairo date for visit_planned's today / tomorrow (DST-safe: date arithmetic
// on the Cairo calendar day, not on +24 h).
function plannedDayDate(norm, now = new Date()) {
  if (norm !== 'today' && norm !== 'tomorrow') return null;
  const today = cairoDay(now);
  if (norm === 'today') return today;
  const [y, m, d] = today.split('-').map(Number);
  return new Date(Date.UTC(y, m - 1, d + 1)).toISOString().slice(0, 10);
}

// ════════════════════════════════════════════════════════════════════════════
// POST /api/events — Main Webhook Receiver
// Called by ManyChat on every button click
// ════════════════════════════════════════════════════════════════════════════
app.post('/api/events', validateSecret, validatePayload, rateLimiter, (req, res) => {
  const db = getDb();

  // ── 0. Sanitize unresolved ManyChat placeholders ──────────────────────
  // Single entry point: null any "{{...}}" token BEFORE the payload is read,
  // so garbage never reaches a DB column, extra_fields, the event_id dedup key,
  // or the Meta CAPI payload. user_id and event_type are structural (already
  // guaranteed non-empty by validatePayload) and left untouched.
  const PLACEHOLDER_SKIP = new Set(['user_id', 'event_type']);
  const brokenFields = [];
  for (const k of Object.keys(req.body || {})) {
    if (!PLACEHOLDER_SKIP.has(k) && isBrokenPlaceholder(req.body[k])) {
      brokenFields.push(k);   // the field name only: a value can hold a phone or a name
      req.body[k] = null;
    }
  }
  if (brokenFields.length) {
    console.warn(`[events] nulled broken ManyChat placeholders — user_id=${req.body.user_id}, event=${req.body.event_type}: ${brokenFields.join(', ')}`);
  }

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
    // platform: 'instagram' or 'facebook' — set per-flow in ManyChat
    platform: rawPlatform,
    // psid: Messenger Page-Scoped ID — sent for Meta CAPI Advanced Matching so
    // leads from direct m.me links (no fbclid) still match. Optional.
    psid,
    // Instagram flow fields (optional): full_name is split into first/last when
    // first_name/last_name aren't sent; ig_username is the @handle for sales.
    full_name,
    ig_username,
  } = req.body;

  // Derive first/last name. Prefer explicit first_name/last_name; otherwise split
  // full_name → first word = first, the rest = last (matches metaCapi splitName).
  const nameParts = String(full_name || '').trim().split(/\s+/).filter(Boolean);
  const effFirstName = (first_name && String(first_name).trim())
    || (nameParts.length ? nameParts[0] : null);
  const effLastName  = (last_name && String(last_name).trim())
    || (nameParts.length > 1 ? nameParts.slice(1).join(' ') : null);
  const igHandle = (ig_username && String(ig_username).trim()) || null;

  // Normalize platform: lowercase, only accept known values
  const normalizedPlatform = (() => {
    if (!rawPlatform || typeof rawPlatform !== 'string') return null;
    const v = rawPlatform.trim().toLowerCase();
    return (v === 'instagram' || v === 'facebook') ? v : null;
  })();

  // (campaign_source, ad_id, visit_code and every other field were already
  // stripped of unresolved "{{...}}" placeholders in step 0 above.)

  // Canonical phone (used as the reception lookup key — replaces visit code)
  const normPhone = normalizePhone(phone);

  // Build an extra_fields JSON of anything that isn't already a first-class
  // column. Lets us capture future ManyChat additions without another
  // schema migration.
  const KNOWN_FIELDS = new Set([
    'user_id','first_name','event_type','event_value','session_count','current_score',
    'campaign_source','ad_id','visit_code','phone','product','category',
    'last_name','gender','locale','timezone','last_input_text','subscribed_at',
    'growth_tool_id','source','branch','event_id','platform',
    'full_name','ig_username','psid','test',
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

  // ── 1b. Test mode (§2.3 R5, C1.7) ────────────────────────────────────
  // A body whose `test` is not empty is answered from the profile AS IT IS and
  // nothing is written: no profile, no event, no phone, no Lead, no ManyChat
  // write-back, not even the dedup memory. Only GET /health counts it (by
  // type, phone present or not — never the phone). ManyChat sends
  // "test":"{gate_test}", empty for every real customer.
  // An ALLOWLIST (C1.7 hardening, 2026-11-22): only ask / known / true / 1 /
  // yes / test (trimmed, any case) or boolean true is test mode; "", "false",
  // "0", "no", random text, an unresolved field and anything else is a NORMAL
  // event — a stray value can never silently drop a real customer's event.
  const isTest = isTestFlag(req.body.test);
  if (isTest) {
    counters.countTestEvent(event_type, !!normPhone);
    return res.status(200).json({ success: true, test: true, ...answerKeys(db, user_id) });
  }

  // ── 2. Phase 1 — In-memory idempotency (fast path) ───────────────────
  // Hash = user_id + event_type + event_value + 10-second time bucket.
  // Catches duplicate retries within the same server session instantly,
  // before any DB reads. Phase 2 below handles cross-restart durability.
  const timeBucket = Math.floor(Date.now() / DEDUP_WINDOW); // changes every 10 s
  // The phone is part of the key (a repeat that brings a new phone is not a
  // duplicate) only as a keyed HMAC: the hash becomes events.event_id, which the
  // admin AI can read, and a plain sha256 of a phone is reversible in seconds.
  const phoneTag   = normPhone ? crypto.createHmac('sha256', DEDUP_PHONE_KEY).update(normPhone).digest('hex').slice(0, 16) : '';
  const dedupRaw   = `${user_id}:${event_type}:${event_value ?? ''}:${phoneTag}:${timeBucket}`;
  const dedupHash  = crypto.createHash('sha256').update(dedupRaw).digest('hex');

  if (seenEvents.has(dedupHash)) {
    console.log(`[DEDUP:MEM] Skipped — user:${user_id} type:${event_type}`);
    return res.status(200).json({ success: true, skipped: true, reason: 'duplicate_event', ...answerKeys(db, user_id) });
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
    return res.status(200).json({ success: true, skipped: true, reason: 'duplicate_event_db', ...answerKeys(db, user_id) });
  }

  // ── 4b. Branch the bot sent (C1.1) ───────────────────────────────────
  // event_value, or the `branch` key (visit_planned, a location_request that
  // carries the chip there) — through intakeBranch: never 'all_branches'.
  const bodyBranch = req.body.branch;
  const intakeBr = event_type === 'visit_planned'
    ? intakeBranch(bodyBranch)
    : (intakeBranch(_rawEventValue) || intakeBranch(bodyBranch));

  // ── 4c. R1 — one branch_selected per user and branch per 6 hours ──────
  // A repeat inside 6 h adds no row and no points; a NEW phone it carries is
  // still stored (and the Lead rule applies to it).
  if (event_type === 'branch_selected') {
    const repeat = db.prepare(`
      SELECT 1 FROM events
      WHERE user_id = ? AND event_type = 'branch_selected' AND branch IS ?
        AND datetime(created_at) >= datetime('now', '-6 hours')
      LIMIT 1
    `).get(user_id, intakeBr);
    if (repeat) {
      if (normPhone) {
        storeChatPhone(db, { userId: user_id, phone: normPhone,
          capi: { firstName: effFirstName, lastName: effLastName, branch: intakeBr, gender, psid } });
        db.prepare(`UPDATE lead_profiles SET phone = ? WHERE user_id = ?`).run(normPhone, user_id);
      }
      counters.countBranchRepeat();
      return res.status(200).json({ success: true, skipped: 'branch_repeat', reason: 'branch_repeat', ...answerKeys(db, user_id) });
    }
  }

  // ── 5. Get or create lead profile ────────────────────────────────────
  let profile = db.prepare(`
    SELECT * FROM lead_profiles WHERE user_id = ?
  `).get(user_id);

  if (!profile) {
    db.prepare(`
      INSERT INTO lead_profiles (user_id, first_name, last_name, campaign_source, ad_id, visit_code, phone, platform, ig_username)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(user_id, effFirstName || 'Unknown', effLastName || null, campaign_source || null, ad_id || null, visit_code || null, normPhone || null, normalizedPlatform, igHandle);

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

  // ── 5c. Once per user (C1.4) ─────────────────────────────────────────
  // location_request / map_click / entry_location / entry_catalog score once
  // per user whatever the value; branch_selected once per user and only with a
  // phone (in this request or already held); visit_planned never scores.
  const mapClickScored = !!db.prepare(`
    SELECT 1 FROM events
    WHERE user_id = ? AND score_delta > 0
      AND (event_type = 'map_click' OR event_value LIKE '%map_click%')
    LIMIT 1
  `).get(user_id);
  if (ONCE_PER_USER_EVENTS.includes(event_type)) {
    alreadyScored = event_type === 'map_click'
      ? mapClickScored
      : !!db.prepare(`
          SELECT 1 FROM events WHERE user_id = ? AND event_type = ? AND score_delta > 0 LIMIT 1
        `).get(user_id, event_type);
  }
  const phoneKnownBefore = userHasPhone(db, user_id);
  const forceZero = event_type === 'visit_planned'
    || (event_type === 'branch_selected' && !normPhone && !phoneKnownBefore);

  // ── 6. Calculate new score & classification ───────────────────────────
  const { scoreDelta, newTotalScore, newLeadClass } = processScore(
    profile,
    event_type,
    event_value,
    alreadyScored,
    getScoringConfig(db),
    { forceZero, noMapClickBonus: mapClickScored }
  );

  // ── 7. Detect context-specific flags ─────────────────────────────────
  const isLocationEvent = ['location_request', 'branch_selected', 'entry_location']
    .includes(event_type);
  // location_requested (📍, the reminder's target) — only a real branch ask:
  // branch_selected, or a location_request that names an intake branch.
  // entry_location (opened the branches menu) no longer sets it (C1.2).
  const setsLocationRequested = event_type === 'branch_selected'
    || (event_type === 'location_request' && !!intakeBr);
  const isVisitPlanned = event_type === 'visit_planned';
  const plannedNorm = isVisitPlanned ? (normalizePlannedDay(_rawEventValue) || 'other') : null;
  const plannedDay  = isVisitPlanned ? plannedDayDate(plannedNorm) : null;

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
  // Every branch written here passes intakeBranch (C1.1): 'all_branches' or an
  // unknown value becomes null (COALESCE keeps the profile's real branch).
  const detectedBranch = visitPayload?.branch
    ? intakeBranch(visitPayload.branch)
    : isVisitPlanned
      ? intakeBr
      : (isLocationEvent && (event_value || bodyBranch))
        ? intakeBr
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
      platform            = COALESCE(platform, ?),
      ig_username         = COALESCE(?, ig_username),
      extra_fields        = COALESCE(?, extra_fields),
      last_activity       = datetime('now')
    WHERE user_id = ?
  `).run(
    effFirstName || null,
    newTotalScore,
    newLeadClass,
    detectedBranch || null,
    lastProduct || null,
    hasCategory ? productCategory : null,
    isProductEvent ? 1 : 0,
    session_count || null,
    isVisitConfirmed ? 1 : 0,
    setsLocationRequested ? 1 : 0,
    isVisitConfirmed ? 1 : 0,  // visit_at — same flag, separate param
    campaign_source || null,
    ad_id || null,
    visit_code || null,
    normPhone || null,
    // ManyChat enrichment fields
    effLastName || null,
    gender || null,
    locale || null,
    timezone || null,
    last_input_text || null,
    subscribed_at || null,
    growth_tool_id || null,
    manychat_source || null,
    normalizedPlatform,
    igHandle,
    extraFieldsJson,
    user_id
  );

  // Keep EVERY phone the customer ever sent — never overwrite history.
  // profile.phone above stays as the latest (quick display); lead_phones is
  // the full set the receptionist can match against. Meta CAPI "Lead" fires
  // the first time this user leaves this phone, unless the phone already sits
  // on another profile (C1.6) — see storeChatPhone. Fire-and-forget.
  if (normPhone) {
    storeChatPhone(db, { userId: user_id, phone: normPhone,
      capi: { firstName: effFirstName, lastName: effLastName, branch: detectedBranch, gender, psid } });
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
        branch, product_id, category, raw_payload, planned_day
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      resolvedEventId,
      user_id,
      first_name || null,
      event_type,
      (isVisitPlanned ? plannedNorm : event_value) || null,
      scoreDelta,
      session_count || null,
      newTotalScore,
      detectedBranch || null,
      isProductEvent ? event_value : null,
      hasCategory ? productCategory : null,
      JSON.stringify(req.body),
      plannedDay
    );
  } catch (e) {
    // Concurrent duplicate slipped past the dedup checks and lost the race on
    // the UNIQUE(event_id) constraint → treat as idempotent success, not 500.
    if (e && /UNIQUE constraint failed/i.test(e.message)) {
      console.log(`[DEDUP:RACE] Skipped — event_id:${resolvedEventId} user:${user_id}`);
      return res.status(200).json({ success: true, skipped: true, reason: 'duplicate_event_race', ...answerKeys(db, user_id) });
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
  // Phase 0 r2: …and once when a warm/hot lead with no rep FIRST gets a branch
  // (it qualified before naming one, so the pick above found no branch and
  // left it for the manager). Same branch-scoped pick, with this branch.
  const firstBranch =
    ['warm', 'hot'].includes(newLeadClass) &&
    !profile.preferred_branch &&
    !!detectedBranch;
  if (
    (becameQualified || firstBranch) &&
    !profile.assigned_rep &&
    getSetting('auto_assign_enabled', 'true') === 'true'
  ) {
    autoAssignLead(db, user_id, first_name, detectedBranch);
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
    has_phone: userHasPhone(db, user_id) ? 'yes' : 'no',
  });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/dashboard — Dashboard Data API
// Returns all stats needed for the dashboard
// ════════════════════════════════════════════════════════════════════════════
// ── Dashboard Cache ────────────────────────────────────────────────────────
// Phase 0: one entry per DB context × scope («live|admin», «demo|rep», …), so
// a demo_ session is never served the live numbers or the reverse. Who gets
// what (read from the portal: only AdminDashboardView calls it):
//   admin → everything (company-wide numbers);
//   anyone else → 403 (no portal page of theirs calls it; branch managers
//           have /api/branch/overview).
const DASHBOARD_TTL_MS = 15 * 1000;
const dashboardCache = new Map();           // `${ctx}|${scope}` → { data, timestamp }
// Phase 1 (2026-11-22): the call-rep («مندوب») dashboard is gone — 0 rep
// users live; the role value stays valid in the users table so an old row
// never crashes a login, but /api/dashboard is admin-only and a rep opens
// only a lead that is his (leadIsMine). The 30-minute «served on my
// dashboard» grant went with the page.
function dashboardScope(user) {
  return user?.role === 'admin' ? 'admin' : null;
}

app.get('/api/dashboard', requireAuth, (req, res) => {
  const scope = dashboardScope(req.user);
  if (!scope) return res.status(403).json({ error: 'Forbidden' });
  const ctx = getDbContextName();
  const key = `${ctx}|${scope}`;
  const hit = dashboardCache.get(key);
  if (hit && (Date.now() - hit.timestamp < DASHBOARD_TTL_MS)) return res.json(hit.data);
  const data = computeDashboard(getDb());
  dashboardCache.set(key, { data, timestamp: Date.now() });
  return res.json(data);
});

function computeDashboard(db) {

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

  return responseData;
}

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
    platform,         // 'instagram' | 'facebook' — ManyChat source channel
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
  // Filter by ManyChat source channel — Instagram vs Facebook flow.
  if (platform === 'instagram' || platform === 'facebook') {
    where += ` AND platform = ?`;
    params.push(platform);
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
         ORDER BY e.created_at DESC LIMIT 1) AS requested_branch,
      -- phase 1: the list shows a phone (the profile's, else the first one he gave), never the raw id
      (SELECT ph.phone FROM lead_phones ph WHERE ph.user_id = lead_profiles.user_id ORDER BY ph.id LIMIT 1) AS first_phone
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
  // 2026-11-25: only an ACTIVE salesperson (never a stopped one or a free-typed name).
  if (rep_name && !db.prepare(`SELECT 1 FROM users WHERE TRIM(name) = TRIM(?) AND role IN ('sales','rep') AND active = 1`).get(String(rep_name))) {
    return res.status(400).json({ error: 'السيلز ده متوقف أو مش موجود — اختار من القايمة', code: 'rep_not_active' });
  }

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
    db.prepare(`DELETE FROM visit_checkins  WHERE user_id = ?`).run(user_id);
    db.prepare(`DELETE FROM visit_outcomes  WHERE user_id = ?`).run(user_id);
    db.prepare(`DELETE FROM tasks           WHERE lead_id = ?`).run(user_id);
    // a sale's rows first (lines / estimates have no foreign key), then the sales
    deletePurchaseRows(db, `SELECT id FROM purchases WHERE user_id = ?`, user_id);
    db.prepare(`DELETE FROM purchases       WHERE user_id = ?`).run(user_id);
    db.prepare(`DELETE FROM messages_sent   WHERE user_id = ?`).run(user_id);
    db.prepare(`DELETE FROM follow_up_state WHERE user_id = ?`).run(user_id);
    // These are keyed by user_id too — leaving them behind orphans the lead's
    // assignment (it would resurface as a nameless ghost in a rep's list).
    db.prepare(`DELETE FROM branch_customer_followups WHERE user_id = ?`).run(user_id);
    db.prepare(`DELETE FROM followup_log     WHERE user_id = ?`).run(user_id);
    db.prepare(`DELETE FROM revisit_followups WHERE user_id = ?`).run(user_id);
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
  // Phase 0 r3: a task makes the lead «his» (leadIsMine) — only for a lead he
  // may already open, so a task is never a way in. r4: a rep's dashboard
  // grant is read-only (canActOnLead).
  if (!canActOnLead(db, req.user, lead_id)) return res.status(404).json({ error: 'lead_not_found' });

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
// ── Who may open one customer's profile (phase 0) ───────────────────────────
//   admin     → every customer;
//   reception → as before (the branch trim below still applies);
//   branch_manager (branch B) → the customer is tied to B: preferred branch,
//               a branch pick / location ask / event in B, a visit or arrival in
//               B, a follow-up row or call in B, a purchase in B, or assigned
//               to a staff member of B;
//   sales (name N, branch B) → tied to B as above, or his: assigned_rep = N,
//               the pre-visit follow-up assigned to N, a visit / call / sale /
//               post-visit follow-up / task / sent flow by N;
//   rep (name N) → his (as sales, no branch), or one of the hot leads the rep
//               dashboard served in the last 30 minutes (what that page lists
//               and opens today);
//   anyone else → no.
// Out of scope answers 404 — the same as an unknown id, so ids can't be probed.
// Phase 0 r3: every tie below that a staff member can write (a task, a sent
// flow, a follow-up / assignment row, a purchase, a revisit note) is written
// only by a route that checks canSeeLead (or, for a branch manager's
// follow-up / assignment, leadOwnBranchTie) first — so a tie is never a way
// in. A branch manager's follow-up row is stamped with his own name.
function leadTiedToBranch(db, userId, branch) {
  if (!branch) return false;
  return !!db.prepare(`
    SELECT 1 WHERE
         EXISTS (SELECT 1 FROM lead_profiles WHERE user_id = @u AND preferred_branch = @b)
      OR EXISTS (SELECT 1 FROM events WHERE user_id = @u AND (branch = @b
                   OR (event_type IN ('branch_selected','location_request') AND event_value = @b)))
      OR EXISTS (SELECT 1 FROM lead_visits WHERE user_id = @u AND branch = @b)
      OR EXISTS (SELECT 1 FROM visit_checkins WHERE user_id = @u AND branch = @b)
      OR EXISTS (SELECT 1 FROM branch_customer_followups WHERE user_id = @u AND branch = @b)
      OR EXISTS (SELECT 1 FROM followup_log WHERE user_id = @u AND branch = @b)
      OR EXISTS (SELECT 1 FROM purchases WHERE user_id = @u AND branch = @b)
      OR EXISTS (SELECT 1 FROM lead_profiles lp JOIN users su ON su.name = lp.assigned_rep
                 WHERE lp.user_id = @u AND su.branch = @b)
  `).get({ u: userId, b: branch });
}
// A lead's OWN tie to branch B (phase 0 r3) — what the customer did, or a
// visit / sale recorded there; never a tie a staff member writes himself
// (an assignment, a follow-up row, a task). A branch manager may create a
// follow-up / assignment only for such a lead (PATCH …/followup, …/assign,
// bulk-reassign's new ids), so the ties those rows give stay earned.
function leadOwnBranchTie(db, userId, branch) {
  if (!branch) return false;
  return !!db.prepare(`
    SELECT 1 WHERE
         EXISTS (SELECT 1 FROM lead_profiles WHERE user_id = @u AND preferred_branch = @b)
      OR EXISTS (SELECT 1 FROM events WHERE user_id = @u AND event_type = 'branch_selected'
                   AND (event_value = @b OR branch = @b))
      OR EXISTS (SELECT 1 FROM lead_visits WHERE user_id = @u AND branch = @b)
      OR EXISTS (SELECT 1 FROM purchases WHERE user_id = @u AND branch = @b)
  `).get({ u: userId, b: branch });
}
// A customer the branch lists may have a branch_selected event and no profile
// row yet (GET /api/branch/customers shows those too) — known = either.
function branchCustomerKnown(db, userId) {
  return !!db.prepare(`SELECT 1 WHERE EXISTS (SELECT 1 FROM lead_profiles WHERE user_id = @u)
                                    OR EXISTS (SELECT 1 FROM events WHERE user_id = @u)`).get({ u: userId });
}
function leadIsMine(db, userId, name) {
  if (!name) return false;
  return !!db.prepare(`
    SELECT 1 WHERE
         EXISTS (SELECT 1 FROM lead_profiles WHERE user_id = @u AND assigned_rep = @n)
      OR EXISTS (SELECT 1 FROM branch_customer_followups WHERE user_id = @u AND TRIM(assigned_sales) = TRIM(@n))
      OR EXISTS (SELECT 1 FROM lead_visits WHERE user_id = @u AND (TRIM(sales_rep) = TRIM(@n) OR pre_visit_rep = @n))
      OR EXISTS (SELECT 1 FROM followup_log WHERE user_id = @u AND sales = @n)
      OR EXISTS (SELECT 1 FROM purchases WHERE user_id = @u AND TRIM(rep) = TRIM(@n))
      OR EXISTS (SELECT 1 FROM revisit_followups WHERE user_id = @u AND followed_up_by = @n)
      OR EXISTS (SELECT 1 FROM tasks WHERE lead_id = @u AND rep_name = @n)
      OR EXISTS (SELECT 1 FROM messages_sent WHERE user_id = @u AND sent_by_rep = @n)
  `).get({ u: userId, n: name });
}
function canSeeLead(db, user, userId) {
  const role = user?.role;
  if (role === 'admin' || role === 'reception') return true;
  if (role === 'branch_manager') return leadTiedToBranch(db, userId, user.branch || null);
  if (role === 'sales') return leadIsMine(db, userId, user.name) || leadTiedToBranch(db, userId, user.branch || null);
  if (role === 'rep') return leadIsMine(db, userId, user.name);   // phase 1: no dashboard grant
  return false;
}
// What a WRITE that ties the lead to the writer needs (phase 0 r4): the same
// as canSeeLead, except a rep's 30-minute «served on my dashboard» grant —
// read-only — doesn't count. A rep's task / sale / sent flow / revisit note
// is only for a lead that is already his (leadIsMine), so opening the
// dashboard can never be turned into permanent ownership.
function canActOnLead(db, user, userId) {
  if (user?.role === 'rep') return leadIsMine(db, userId, user.name);
  return canSeeLead(db, user, userId);
}

app.get('/api/leads/:user_id', requireAuth, (req, res) => {
  const db = getDb();
  const { user_id } = req.params;

  const profile = db.prepare(`SELECT * FROM lead_profiles WHERE user_id = ?`).get(user_id);
  if (!profile) return res.status(404).json({ error: 'Lead not found' });
  if (!canSeeLead(db, req.user, user_id)) return res.status(404).json({ error: 'Lead not found' });

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
// Reception capability is available to receptionists & admins, and — by request
// — the branch managers of specific branches (who double as reception). For a
// branch manager it's locked to their own branch; a manager of any OTHER branch
// is rejected here so the capability can't leak.
const RECEPTION_MANAGER_BRANCHES = ['faisal', 'nasr_city'];
function denyNonReceptionManager(req, res) {
  if (req.user?.role === 'branch_manager' && !RECEPTION_MANAGER_BRANCHES.includes(req.user.branch)) {
    res.status(403).json({ error: 'forbidden' });
    return true;
  }
  return false;
}
// True for any role that acts as reception locked to its own branch.
const actsAsReception = (req) =>
  req.user?.role === 'reception' ||
  (req.user?.role === 'branch_manager' && RECEPTION_MANAGER_BRANCHES.includes(req.user.branch));

// Records that the customer ARRIVED at this branch today (Cairo day) — feeds
// reception's «قايمة العملاء زيارة اليوم». One row per (customer, branch, day):
// a second confirm the same day keeps the FIRST arrival time. Written with the
// exact branch value of the lead_visits row (call it right after that insert).
function recordCheckin(db, { userId, branch, source, recordedBy }) {
  if (!userId || !branch) return;
  db.prepare(`INSERT INTO visit_checkins (user_id, branch, visit_day, source, recorded_by)
              VALUES (?, ?, ?, ?, ?) ON CONFLICT(user_id, branch, visit_day) DO NOTHING`)
    .run(userId, branch, cairoDay(), source, recordedBy || null);
}

// Today's (Cairo) check-in of a customer at a branch, or null.
function todayCheckin(db, userId, branch) {
  return db.prepare(
    `SELECT * FROM visit_checkins WHERE user_id = ? AND branch = ? AND visit_day = ?`
  ).get(userId, branch, cairoDay()) || null;
}

// Phase 2 r2: a sale recorded today for a customer who checked in today at
// the branch takes back today's «مشي من غير شراء» answer there (he bought —
// the reason no longer stands). Call it INSIDE the sale's transaction.
function clearLeftOnSale(db, userId, branch) {
  if (!userId || !branch) return 0;
  const ci = todayCheckin(db, userId, branch);
  return ci ? db.prepare(`DELETE FROM visit_outcomes WHERE checkin_id = ?`).run(ci.id).changes : 0;
}

// Phase 0 r4: is the customer on one of THIS branch's reception lists — the
// «طلبوا عنوان الفرع» list (GET /api/reception/leads: a branch_selected for the
// branch + a phone) or «جايين النهارده» (GET /api/reception/expected-visits)?
// A reception manager confirms by id only a customer those lists show him.
// r2 (2026-11-22): also «زيارة اليوم» — a customer already checked in TODAY at
// the branch (GET /api/reception/today lists him), so a repeat confirm by id
// answers 200 already_checked_in, not 404.
function onReceptionLists(db, userId, branch) {
  if (!branch) return false;
  if (todayCheckin(db, userId, branch)) return true;
  const listed = db.prepare(`
    SELECT 1 FROM events e JOIN lead_profiles lp ON lp.user_id = e.user_id
    WHERE e.user_id = ? AND e.event_type = 'branch_selected' AND (e.event_value = ? OR e.branch = ?)
      AND EXISTS (SELECT 1 FROM lead_phones ph WHERE ph.user_id = e.user_id)
    LIMIT 1`).get(userId, branch, branch);
  if (listed) return true;
  try { return visitIntent.expectedVisits(db, branch).rows.some(r => r.user_id === userId); }
  catch (_) { return false; }
}

// lead_visits keeps ONE row per (customer, branch), so its sales_rep may be the
// salesperson of an EARLIER visit. It counts as this visit's only when it was
// set at/after the check-in (sales_rep_set_at >= checked_in_at). Both are UTC
// SQL strings; normalized through Date so a stray 'T'/'Z' never breaks the compare.
function repSetThisVisit(lvSalesRep, salesRepSetAt, checkedInAt) {
  if (!lvSalesRep || !salesRepSetAt || !checkedInAt) return false;
  const set = sqlUtcToDate(salesRepSetAt), inAt = sqlUtcToDate(checkedInAt);
  if (!set || !inAt || isNaN(set) || isNaN(inAt)) return false;
  return toSqlUtc(set) >= toSqlUtc(inAt);
}

// An ACTIVE showroom salesperson (role='sales') of `branch` by name (TRIM match)
// → { id, name } with the DB's exact name, or null. Same set of names
// GET /api/sales/reps offers — staff names are join keys (targets, contracts,
// ownership), so a free-typed or cross-branch name is never stored.
function findBranchSalesRep(db, name, branch) {
  return db.prepare(`SELECT id, name FROM users WHERE TRIM(name) = TRIM(?) AND role = 'sales'
                     AND active = 1 AND branch = ?`).get(String(name || ''), branch) || null;
}

// Links the showroom salesperson to the customer's visit at `branch` — the
// shared body of POST /api/visits/set-sales and of a reception-recorded sale
// (POST /api/reception/sales). Call it INSIDE a db.transaction.
//   → { preVisitRep, unchanged }
function linkVisitSales(db, { userId, branch, salesRep, operator }) {
  // Full old row captured for the audit/undo ledger (it carries
  // sales_rep_set_at too, so an undo puts the old "set at" back with the row).
  const existing = db.prepare(
    `SELECT * FROM lead_visits WHERE user_id=? AND branch=?`
  ).get(userId, branch);

  // A RE-link: the visit already got its salesperson at THIS visit (set at/after
  // today's check-in) and reception corrects it. The follow-up row was then
  // written by that first link, so its assigned_sales is the showroom
  // salesperson, not who followed the customer up before the visit — keep the
  // pre-visit rep the first link recorded instead of reading it from there.
  const checkin = todayCheckin(db, userId, branch);
  const relink  = !!(existing && checkin &&
    repSetThisVisit(existing.sales_rep, existing.sales_rep_set_at, checkin.checked_in_at));
  if (relink && existing.sales_rep === salesRep) {
    return { preVisitRep: existing.pre_visit_rep || null, unchanged: true }; // same person again → nothing to do
  }

  // Step A — who followed this lead up online BEFORE the visit.
  const fuRow = db.prepare(
    `SELECT assigned_sales FROM branch_customer_followups WHERE user_id = ? AND branch = ?`
  ).get(userId, branch);
  const preVisitRep = relink ? (existing.pre_visit_rep || null) : (fuRow?.assigned_sales || null);

  // Step B — store BOTH the showroom rep and the pre-visit rep on the visit.
  // Create the row if the salesperson is set without a prior confirm (robust).
  if (existing) {
    db.prepare(`UPDATE lead_visits SET sales_rep=?, pre_visit_rep=?, sales_rep_set_at=datetime('now') WHERE id=?`)
      .run(salesRep, preVisitRep, existing.id);
  } else {
    db.prepare(
      `INSERT INTO lead_visits (user_id, branch, sales_rep, pre_visit_rep, sales_rep_set_at)
       VALUES (?,?,?,?,datetime('now'))`
    ).run(userId, branch, salesRep, preVisitRep);
  }

  // Step C — handoff: the pre-visit rep is NOT the showroom rep. Log the
  // handoff and move the follow-up record over to the showroom rep.
  if (preVisitRep && preVisitRep !== salesRep) {
    const logSummary = `العميل زار الفرع. تابعه قبل الزيارة [${preVisitRep}]، ولكن استقبله في الصالة [${salesRep}].`;
    logFollowup(db, branch, userId, salesRep, logSummary, 'handoff');   // a note, not a call
    db.prepare(`
      UPDATE branch_customer_followups SET
        assigned_sales = ?,
        assigned_by    = ?,
        followed_up    = 0,
        followed_up_at = NULL,
        call_summary   = ?,
        auto_assigned  = 1
      WHERE branch = ? AND user_id = ?
    `).run(salesRep, operator || null, logSummary, branch, userId);

    // Transfer primary ownership of the lead to the showroom rep so the
    // pre-visit rep STOPS seeing this customer in /revisit (post-visit
    // follow-up). Their pre-visit work is still preserved in followup_log
    // and lead_visits.pre_visit_rep — this only stops new responsibility.
    db.prepare(`UPDATE lead_profiles SET assigned_rep = ? WHERE user_id = ?`)
      .run(salesRep, userId);
  } else {
    // Step C′ — no pre-visit rep (or same rep). The customer is now linked to a
    // showroom rep, so AUTO-assign them in the branch follow-up queue so the
    // manager doesn't have to distribute them manually. auto_assigned=1 lets
    // the UI show a "اسناد تلقائي" tag. Don't overwrite a manual manager
    // assignment (auto_assigned=0 AND assigned_sales set).
    const bcf = db.prepare(
      `SELECT id, assigned_sales, auto_assigned FROM branch_customer_followups
         WHERE branch=? AND user_id=?`
    ).get(branch, userId);
    const manualAlreadySet = bcf && bcf.assigned_sales && bcf.auto_assigned === 0;
    if (!manualAlreadySet) {
      if (bcf) {
        db.prepare(`
          UPDATE branch_customer_followups SET
            assigned_sales = ?,
            assigned_at    = datetime('now'),
            assigned_by    = ?,
            auto_assigned  = 1
          WHERE id = ?
        `).run(salesRep, operator || 'reception', bcf.id);
      } else {
        db.prepare(`
          INSERT INTO branch_customer_followups
            (branch, user_id, assigned_sales, assigned_at, assigned_by, auto_assigned)
          VALUES (?, ?, ?, datetime('now'), ?, 1)
        `).run(branch, userId, salesRep, operator || 'reception');
      }
    }
    // A re-link back to the pre-visit rep: the first link's handoff had moved
    // the customer's owner to the showroom rep it named — move it back too.
    if (relink && existing.pre_visit_rep && existing.pre_visit_rep !== existing.sales_rep) {
      db.prepare(`UPDATE lead_profiles SET assigned_rep = ? WHERE user_id = ? AND assigned_rep = ?`)
        .run(salesRep, userId, existing.sales_rep);
    }
  }

  auditLog(db, operator, 'set_sales', userId, {
    table: 'lead_visits',
    where: { user_id: userId, branch },
    row:   existing || null,
  });

  return { preVisitRep, unchanged: false };
}

// Phase 0 r3: not for 'sales' — a visit row ties the lead to the branch
// (leadTiedToBranch), so a salesperson confirming one would open any customer
// for himself; reception's desk (reception, admin, the reception managers and
// the legacy rep dashboard's reception tab) keeps it.
app.post('/api/visits/confirm', requireAuth, authorizeRoles('reception', 'admin', 'branch_manager'), (req, res) => {
  if (denyNonReceptionManager(req, res)) return;
  const { phone, visit_code, branch, user_id, sales_rep } = req.body || {};
  const db = getDb();
  const role = req.user?.role;
  // Phase 0 r4 — who may look a customer up how:
  //   reception, admin                → phone, user_id (their lists), visit_code;
  //   a reception manager (faisal / nasr_city) → phone; user_id / visit_code
  //       only for a customer on HIS branch's lists (/api/reception/leads,
  //       «جايين النهارده»), never any id he types;
  //   rep (the legacy dashboard's desk) → phone only — the number the customer
  //       standing there gives. No id lookups: an id is not proof he is here.
  const desk       = actsAsReception(req);            // reception + the reception managers: locked to own branch
  const managerDesk = desk && role === 'branch_manager';
  const phoneOnly  = !desk && role !== 'admin';        // rep (any non-reception role)
  const given = (v) => v != null && String(v).trim() !== '';

  // The receptionist explicitly picks the branch they're at — that is the
  // source of truth for WHICH branch was visited (no guessing from intent).
  // A reception account is LOCKED to its own branch (can't confirm for others).
  // Anyone else's typed branch must be a configured one (intakeBranch: the 6
  // codes, their aliases, an active_branches id) — anything else 400, never
  // stored as a visit (phase 0 r4).
  let pickedBranch = null;
  if (desk) pickedBranch = req.user.branch || null;
  else if (branch != null && !(typeof branch === 'string' && branch.trim() === '')) {
    pickedBranch = typeof branch === 'string' ? intakeBranch(branch, { db }) : null;
    if (!pickedBranch) return res.status(400).json({ error: 'invalid_branch', message: 'الفرع ده مش من فروع السيستم — اختار من القايمة' });
  }

  if (phoneOnly && (given(user_id) || given(visit_code))) {
    return res.status(400).json({ error: 'phone_only', message: 'أكّد الزيارة برقم تليفون العميل' });
  }

  let lead = null;
  let foundByPhone = false;
  if (given(user_id)) {
    lead = db.prepare(`
      SELECT user_id, first_name, last_name, gender, campaign_source, lead_class,
             visit_confirmed, preferred_branch
      FROM lead_profiles WHERE user_id = ?
    `).get(String(user_id).trim());
    if (!lead) return res.status(404).json({ error: 'lead_not_found' });
    // Phase 2 r2: the desk's «هو ده؟» card came from a phone lookup and sends
    // the number WITH the picked profile (a number can carry several). The id
    // counts as found by phone only when that profile carries the number
    // (lead_phones, or the legacy profile phone) — the customer standing there
    // gave it, so no list check. A number the profile doesn't carry → 404 like
    // an unknown id (ids can't be probed with any number).
    if (given(phone)) {
      const np = normalizePhone(phone);
      if (!np || np.length < 10) return res.status(400).json({ error: 'invalid_phone' });
      const carries = db.prepare(`
        SELECT 1 FROM lead_phones WHERE user_id = ? AND phone = ?
        UNION ALL SELECT 1 FROM lead_profiles WHERE user_id = ? AND phone = ?
        LIMIT 1`).get(lead.user_id, np, lead.user_id, np);
      if (!carries) return res.status(404).json({ error: 'lead_not_found' });
      foundByPhone = true;
    }
  } else if (given(phone)) {
    const np = normalizePhone(phone);
    if (!np) return res.status(400).json({ error: 'invalid_phone' });
    // Match against EVERY phone the customer ever gave (lead_phones), not just
    // the latest one on the profile — so an older number still works.
    lead = db.prepare(`
      SELECT lp.user_id, lp.first_name, lp.last_name, lp.gender, lp.campaign_source, lp.lead_class,
             lp.visit_confirmed, lp.preferred_branch
      FROM lead_phones ph
      JOIN lead_profiles lp ON lp.user_id = ph.user_id
      WHERE ph.phone = ?
      ORDER BY lp.last_activity DESC LIMIT 1
    `).get(np);
    // Fallback: legacy rows whose phone is only on the profile
    if (!lead) {
      lead = db.prepare(`
        SELECT user_id, first_name, last_name, gender, campaign_source, lead_class,
               visit_confirmed, preferred_branch
        FROM lead_profiles WHERE phone = ?
        ORDER BY last_activity DESC LIMIT 1
      `).get(np);
    }
    if (!lead) return res.status(404).json({ error: 'phone_not_found' });
    foundByPhone = true;
  } else if (given(visit_code)) {
    lead = db.prepare(`
      SELECT user_id, first_name, last_name, gender, campaign_source, lead_class,
             visit_confirmed, preferred_branch
      FROM lead_profiles WHERE visit_code = ?
    `).get(String(visit_code).trim());
    if (!lead) return res.status(404).json({ error: 'visit_code_not_found' });
  } else {
    return res.status(400).json({ error: 'phone_required' });
  }

  // A reception manager's id lookup: only a customer his branch's lists show
  // (404 like an unknown id, so ids can't be probed).
  if (managerDesk && !foundByPhone && !onReceptionLists(db, lead.user_id, pickedBranch)) {
    return res.status(404).json({ error: 'lead_not_found' });
  }
  // May this account see the customer's other branches? Decided BEFORE the
  // confirm writes this branch's visit (a visit row is itself a tie).
  const canSee = canSeeLead(db, req.user, lead.user_id);
  if (!desk && role !== 'admin' && !foundByPhone && !canSee) {
    return res.status(404).json({ error: 'lead_not_found' });
  }

  // Phase 2 («وصل — سجّل الزيارة»): reception may name the salesperson he
  // stands with in the same request. Checked BEFORE anything is written: a
  // name that isn't an active salesperson of the visit's branch refuses the
  // whole confirm (no visit, no Meta event, no ManyChat message).
  const visitBranch = pickedBranch || intakeBranch(lead.preferred_branch) || null;
  const wantsRep = given(sales_rep);
  let repRow = null;
  if (wantsRep) {
    if (typeof sales_rep !== 'string') return res.status(400).json({ error: 'السيلز ده مش من سيلز الفرع (أو متوقف) — اختار من القايمة', code: 'rep_not_in_branch' });
    if (!visitBranch) return res.status(400).json({ error: 'branch_required', message: 'اختار الفرع اللي إنت فيه الأول' });
    repRow = findBranchSalesRep(db, sales_rep, visitBranch);
    if (!repRow) {
      return res.status(400).json({ error: 'السيلز ده مش من سيلز الفرع (أو متوقف) — اختار من القايمة', code: 'rep_not_in_branch' });
    }
  }

  // Phase 2 r2: already checked in TODAY at this branch → the visit was
  // recorded (and Meta + the thank-you message were sent) by the first
  // confirm. A second one writes and sends nothing — no lead_profiles touch,
  // no FindLocation, no ManyChat flow; a named salesperson is linked like
  // POST /api/visits/set-sales (same Steps A–C + audit row).
  const already = visitBranch ? todayCheckin(db, lead.user_id, visitBranch) : null;
  if (already) {
    let relinked = null;
    if (repRow) {
      relinked = db.transaction(() => linkVisitSales(db, {
        userId: lead.user_id, branch: visitBranch, salesRep: repRow.name, operator: req.user?.name,
      }))();
    }
    const lvNow = db.prepare(`SELECT sales_rep, sales_rep_set_at FROM lead_visits WHERE user_id = ? AND branch = ?`)
      .get(lead.user_id, visitBranch);
    const repNow = lvNow && repSetThisVisit(lvNow.sales_rep, lvNow.sales_rep_set_at, already.checked_in_at)
      ? lvNow.sales_rep : null;
    const at = sqlUtcToDate(already.checked_in_at);
    console.log(`🏪 VISIT ALREADY CONFIRMED TODAY: ${lead.user_id} → ${visitBranch}${repRow ? ` (salesperson ${repRow.name})` : ''}`);
    return res.json({
      ok:                 true,
      already_checked_in: true,
      user_id:            lead.user_id,
      first_name:         lead.first_name || 'غير معروف',
      campaign_source:    lead.campaign_source || null,
      branch:             visitBranch,
      lead_class:         lead.lead_class || null,
      checked_in_at:      at && !isNaN(at) ? at.toISOString().slice(0, 19) + 'Z' : null,
      sales_rep:          repRow ? repRow.name : null,       // the one THIS request linked
      current_sales_rep:  repNow,                            // this visit's salesperson now
      pre_visit_rep:      relinked?.preVisitRep || null,
      was_lost_and_returned: false,
      prior_activity:     { multi_branch: false, other_visits: [], other_purchase: null },
      viewed:             visitIntent.viewedFor(db, [lead.user_id]).get(lead.user_id) || null,
    });
  }

  // Every write of the confirm — and the salesperson link when one was named —
  // in ONE transaction: either the visit is recorded with its salesperson, or
  // nothing is.
  let wasLostAndReturned = false;
  let linked = null;
  const newClass = lead.lead_class === 'purchased' ? 'purchased' : 'visited';
  db.transaction(() => {
  // Global "has visited at least one branch" flag — for scoring/funnel.
  // (Idempotent — won't downgrade a purchased lead.)
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
  // The lead's last intent goes through intakeBranch (C1, review r2) so a
  // polluted preferred_branch ('all_branches') never lands in lead_visits /
  // visit_checkins. (visitBranch is computed above, before the rep check.)
  if (visitBranch) {
    db.prepare(`
      INSERT OR IGNORE INTO lead_visits (user_id, branch) VALUES (?, ?)
    `).run(lead.user_id, visitBranch);
    // Today's arrival → reception's «قايمة العملاء زيارة اليوم» (returning
    // customers too — lead_visits above only keeps the first visit).
    recordCheckin(db, { userId: lead.user_id, branch: visitBranch, source: 'confirm', recordedBy: req.user?.name });
  }

  // Resurrect a "lost" lead — they were closed in the re-visit funnel but
  // walked back into the showroom, so put them back in the follow-up queue.
  const revisitRow = db.prepare(
    `SELECT revisit_status FROM lead_profiles WHERE user_id = ?`
  ).get(lead.user_id);
  wasLostAndReturned = revisitRow?.revisit_status === 'lost';
  if (wasLostAndReturned) {
    db.prepare(`
      UPDATE lead_profiles SET
        revisit_status     = NULL,
        revisit_note       = 'العميل عاد وزار المعرض مرة أخرى بعد إغلاقه',
        revisit_updated_at = datetime('now')
      WHERE user_id = ?
    `).run(lead.user_id);
  }

  // The salesperson he stands with (the same Steps A–C + audit row as
  // POST /api/visits/set-sales), after today's check-in exists.
  if (repRow) {
    linked = linkVisitSales(db, { userId: lead.user_id, branch: visitBranch, salesRep: repRow.name, operator: req.user?.name });
  }
  })();

  console.log(`🏪 VISIT CONFIRMED: ${lead.first_name || lead.user_id} → ${visitBranch || 'unknown branch'} (${lead.campaign_source || 'no campaign'})`);

  // Meta CAPI FindLocation — standard event for a confirmed showroom visit.
  // Sent with the DEFAULT action_source ('website') — same channel as Lead/
  // Purchase — so it lands in this Web/CRM dataset's surfaced channel (gets EMQ,
  // freshness, stats, audience usability). action_source: 'physical_store' was
  // dropped: it filed the event in the dataset's "offline" bucket, which this
  // web dataset doesn't surface, so the event kept vanishing from the views.
  // Fire-and-forget; never blocks the reception response.
  // Skipped for demo sessions so training visits never reach the ad dataset.
  if (!isDemoContext()) {
    const visitPhone = db.prepare(`
      SELECT COALESCE(lp.phone, (SELECT ph.phone FROM lead_phones ph
                                 WHERE ph.user_id = lp.user_id ORDER BY ph.id LIMIT 1)) AS phone
      FROM lead_profiles lp WHERE lp.user_id = ?
    `).get(lead.user_id)?.phone;
    sendMetaEvent('FindLocation',
      { phone: visitPhone, firstName: lead.first_name, lastName: lead.last_name,
        gender: lead.gender, branch: visitBranch, externalId: lead.user_id },
      `visit_confirm_${lead.user_id}_${Date.now()}`);
  }

  // Event-Triggered Flow: Visit Confirmed — through the 24 h window guard
  // (C1.9): a walk-in has no chat (no_manychat_id), and ManyChat's own
  // last_interaction must be < 23 h. Fire-and-forget; never blocks reception.
  const visitFlowSetting = db.prepare(`SELECT value FROM settings WHERE key = 'manychat_visit_flow'`).get();
  if (visitFlowSetting && visitFlowSetting.value && visitFlowSetting.value.trim() !== '') {
    guardedSendFlow(db, { user_id: lead.user_id, flow_id: visitFlowSetting.value.trim(), site: 'visit' })
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
  // Phase 0 r4: an account that may not open the customer (canSee, decided
  // before this confirm) gets nothing from another branch — no other visits,
  // no other purchase or its price, no rep of another branch's visit.
  const lastShowroomRow = canSee
    ? db.prepare(`
        SELECT sales_rep FROM lead_visits
        WHERE user_id = ? AND sales_rep IS NOT NULL
        ORDER BY visited_at DESC LIMIT 1
      `).get(lead.user_id)
    : (visitBranch ? db.prepare(`
        SELECT sales_rep FROM lead_visits
        WHERE user_id = ? AND branch = ? AND sales_rep IS NOT NULL
        ORDER BY visited_at DESC LIMIT 1
      `).get(lead.user_id, visitBranch) : null);

  // Cross-branch heads-up: did this customer already visit / buy in a DIFFERENT
  // branch? If so reception (and the sales rep) should know they're a comparer —
  // it prevents "you stole my customer" fights and helps them tailor the offer.
  const journey = canSee ? customerJourney(db, lead.user_id) : { visits: [], purchases: [] };
  const otherVisits   = journey.visits.filter(v => v.branch && v.branch !== visitBranch);
  const otherPurchase = journey.purchases.find(p => p.branch && p.branch !== visitBranch) || null;

  // O6 «شاف إيه»: what he looked at, the day he said he'd come, his ad.
  const viewed = visitIntent.viewedFor(db, [lead.user_id]).get(lead.user_id) || null;

  return res.json({
    ok:                   true,
    user_id:              lead.user_id,
    first_name:           lead.first_name || 'غير معروف',
    campaign_source:      lead.campaign_source || null,
    branch:               visitBranch || null,
    lead_class:           newClass,
    // When a salesperson was named: the pre-visit rep the link recorded (the
    // follow-up row now names the showroom salesperson).
    pre_visit_rep:        repRow ? (linked?.preVisitRep || null) : (preVisitRow?.assigned_sales || null),
    last_showroom_rep:    lastShowroomRow?.sales_rep || null,
    sales_rep:            repRow ? repRow.name : null,
    was_lost_and_returned: wasLostAndReturned,
    prior_activity: {
      multi_branch:   otherVisits.length > 0 || !!otherPurchase,
      other_visits:   otherVisits,      // [{ branch, sales_rep, visited_at }]
      other_purchase: otherPurchase,    // { branch, rep, price, ... } | null
    },
    viewed,               // { items[≤5], visit_planned{value, planned_day, when, said_at}|null, campaign_source }
  });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/customers/:userId/journey — the customer's full cross-branch journey
// (every visit + purchase + who served them) so everyone understands what
// happened when a customer compares branches. Visible to all staff roles.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/customers/:userId/journey', requireAuth,
  authorizeRoles('admin', 'branch_manager', 'sales', 'rep', 'reception'), (req, res) => {
  const db = getDb();
  const lead = db.prepare(`SELECT first_name FROM lead_profiles WHERE user_id = ?`).get(req.params.userId);
  if (!lead) return res.status(404).json({ error: 'lead_not_found' });
  // Phase 0 r2: the cross-branch detail (who served / bought where) only for
  // a lead the account may open at all — the same rule as GET /api/leads/:id.
  if (!canSeeLead(db, req.user, req.params.userId)) return res.status(404).json({ error: 'lead_not_found' });
  return res.json({ first_name: lead.first_name || null, ...customerJourney(db, req.params.userId) });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/reception/leads — customers who requested THIS branch's address.
// reception role → locked to its own branch. admin → ?branch=<id> required.
// Shows everyone who picked the branch (branch_selected event) even if they
// haven't visited yet; visited_here flags who already came.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/reception/leads', requireAuth, authorizeRoles('reception', 'admin', 'branch_manager'), (req, res) => {
  if (denyNonReceptionManager(req, res)) return;
  const branch = actsAsReception(req)
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
      AND EXISTS (SELECT 1 FROM lead_phones ph WHERE ph.user_id = lp.user_id)
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
//   reception / any branch manager → locked to own branch (a manager's
//   «البيعة تتحسب لمين؟» lists his own team). admin → all or ?branch=
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/sales/reps', requireAuth, authorizeRoles('reception', 'admin', 'sales', 'branch_manager'), (req, res) => {
  const branch = (actsAsReception(req) || req.user?.role === 'branch_manager')
    ? (req.user.branch || null) : (req.query.branch || null);
  if (req.user?.role === 'branch_manager' && !branch) return res.status(400).json({ error: 'branch_required' });
  const db = getDb();
  const rows = branch
    ? db.prepare(`SELECT name, branch FROM users WHERE role='sales' AND active=1 AND branch=? ORDER BY name`).all(branch)
    : db.prepare(`SELECT name, branch FROM users WHERE role='sales' AND active=1 ORDER BY name`).all();
  return res.json({ reps: rows });
});

// ════════════════════════════════════════════════════════════════════════════
// POST /api/visits/set-sales — reception attaches the salesperson who served.
// Body: { user_id, sales_rep }   (reception → own branch; admin → ?branch)
// ════════════════════════════════════════════════════════════════════════════
app.post('/api/visits/set-sales', requireAuth, authorizeRoles('reception', 'admin', 'branch_manager'), (req, res) => {
  if (denyNonReceptionManager(req, res)) return;
  const { user_id, sales_rep, branch: bodyBranch } = req.body || {};
  if (!user_id || !sales_rep) {
    return res.status(400).json({ error: 'user_id and sales_rep required' });
  }
  const branch = actsAsReception(req) ? (req.user.branch || null) : (bodyBranch || null);
  if (!branch) return res.status(400).json({ error: 'branch_required' });

  const db = getDb();

  // Phase 0 r4: an existing customer only (a link used to create a visit row
  // for any id typed), and — for a reception manager — one who checked in
  // TODAY at his branch, as POST /api/reception/sales asks: linking a
  // salesperson writes a visit + follow-up row, which ties the customer to the
  // branch (leadTiedToBranch), so it is never a way to open someone else's.
  if (typeof user_id !== 'string' || !db.prepare(`SELECT 1 FROM lead_profiles WHERE user_id = ?`).get(user_id)) {
    return res.status(404).json({ error: 'lead_not_found' });
  }
  if (req.user?.role === 'branch_manager' && !todayCheckin(db, user_id, branch)) {
    return res.status(409).json({ error: 'العميل ده مش مسجّل إنه وصل الفرع النهارده — أكّد زيارته الأول', code: 'not_checked_in_today' });
  }

  // Only an active salesperson of THIS branch (the names /api/sales/reps
  // offers) — the stored name is the DB's exact one, never the client's string.
  const repRow = findBranchSalesRep(db, sales_rep, branch);
  if (!repRow) {
    return res.status(400).json({
      error: 'السيلز ده مش من سيلز الفرع (أو متوقف) — اختار من القايمة',
      code:  'rep_not_in_branch',
    });
  }

  // Steps A–C (pre-visit rep, the visit row, the handoff/auto-assign) + the
  // revertable set_sales audit row — shared with the reception-recorded sale.
  const { preVisitRep } = db.transaction(() => linkVisitSales(db, {
    userId: user_id, branch, salesRep: repRow.name, operator: req.user?.name,
  }))();

  console.log(`👥 SALES LINK: ${user_id} @ ${branch} → ${repRow.name}` +
    (preVisitRep && preVisitRep !== repRow.name ? ` (pre-visit: ${preVisitRep})` : ''));
  return res.json({ ok: true, user_id, branch, sales_rep: repRow.name, pre_visit_rep: preVisitRep });
});

// ════════════════════════════════════════════════════════════════════════════
// POST /api/reception/walkin — register a walk-in customer who never came
// through ManyChat (found us on the street / by referral, etc.). Reception
// captures name + phone + interest + source, and the customer is created as a
// normal confirmed-visit lead so the rest of the system (sales linking,
// purchase logging, follow-up) treats them exactly like an online lead.
//   reception → locked to own branch. admin → body.branch
// ════════════════════════════════════════════════════════════════════════════
app.post('/api/reception/walkin', requireAuth, authorizeRoles('reception', 'admin', 'branch_manager'), (req, res) => {
  if (denyNonReceptionManager(req, res)) return;
  const { first_name, phone, interest, source, branch: bodyBranch } = req.body || {};
  // Phase 2 r2 — «مش هو؟ سجّله عميل جديد»: the number is known but the person
  // at the desk is someone else (a family phone). new_person:true always makes
  // a NEW profile with its own walk-in id that SHARES the number (added to
  // lead_phones; the other profiles keep it, nothing of theirs is touched).
  const newPerson = req.body?.new_person === true;

  const branch = actsAsReception(req) ? (req.user.branch || null) : (bodyBranch || null);
  if (!branch) return res.status(400).json({ error: 'branch_required' });

  const name = (first_name && String(first_name).trim()) || '';
  if (!name) return res.status(400).json({ error: 'first_name_required' });

  const np = normalizePhone(phone);
  if (!np) return res.status(400).json({ error: 'invalid_phone' });

  const interestVal = (interest && String(interest).trim()) || null;
  // C1.10: «زيارة مباشرة» is written only on a NEW walk-in profile. A known
  // chat customer walking in keeps a NULL campaign_source NULL (a later ad
  // event fills it) unless reception typed a source.
  const typedSource = (source && String(source).trim()) || null;
  const sourceVal   = typedSource || 'زيارة مباشرة';

  const db = getDb();

  // Re-use an existing lead if this phone is already known — avoid duplicates
  // (not for «مش هو؟»: new_person is a different person on the same number).
  const known = db.prepare(`
    SELECT lp.user_id FROM lead_phones ph
    JOIN lead_profiles lp ON lp.user_id = ph.user_id
    WHERE ph.phone = ? ORDER BY lp.last_activity DESC LIMIT 1
  `).get(np)
    || db.prepare(`SELECT user_id FROM lead_profiles WHERE phone = ? LIMIT 1`).get(np);
  const lead = newPerson ? null : known;
  const phoneKnownBefore = !!known;

  const existed = !!lead;
  const userId  = existed ? lead.user_id : `walkin_${crypto.randomUUID()}`;

  let phoneIsNew = false;
  const tx = db.transaction(() => {
    if (existed) {
      // Known customer walking in again — refresh + mark this visit. His name
      // is filled only when the profile has none: a typed name never renames
      // an existing customer (phase 2 r2 — that was another person's name).
      db.prepare(`
        UPDATE lead_profiles SET
          first_name      = COALESCE(NULLIF(first_name,''), NULLIF(?,'')),
          last_category   = COALESCE(?, last_category),
          campaign_source = COALESCE(campaign_source, ?),
          lead_class      = CASE WHEN lead_class = 'purchased' THEN 'purchased' ELSE 'visited' END,
          visit_confirmed = 1,
          visit_at        = CASE WHEN visit_at IS NULL THEN datetime('now') ELSE visit_at END,
          last_activity   = datetime('now')
        WHERE user_id = ?
      `).run(name, interestVal, typedSource, userId);
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

    const phoneIns = db.prepare(`INSERT OR IGNORE INTO lead_phones (user_id, phone, source) VALUES (?, ?, 'walkin')`).run(userId, np);
    phoneIsNew = phoneIns.changes > 0;

    // A NEW walk-in profile gets one branch_selected so it shows up where
    // online leads do (reception list, branch-manager customers). It is
    // marked source = 'walkin': funnels and demand counts leave it out — he
    // never chose a branch in a chat. A KNOWN customer (found by phone) gets
    // NO event (2026-11-22 «أرقام حقيقية»): that was a made-up chat step and
    // +30 points on a real chat lead. His visit is the check-in below, the
    // same as a reception confirm (which never wrote an event either), and
    // leadTiedToBranch already ties him to the branch through it.
    if (!existed) {
      db.prepare(`
        INSERT INTO events
          (event_id, user_id, first_name, event_type, event_value,
           score_delta, current_score, branch, category, source)
        VALUES (?, ?, ?, 'branch_selected', ?, 30, 30, ?, ?, 'walkin')
      `).run(crypto.randomUUID(), userId, name, branch, branch, interestVal);
    }

    // Record the actual showroom visit.
    db.prepare(`INSERT OR IGNORE INTO lead_visits (user_id, branch) VALUES (?, ?)`)
      .run(userId, branch);
    // …and today's arrival for reception's «قايمة العملاء زيارة اليوم».
    recordCheckin(db, { userId, branch, source: 'walkin', recordedBy: req.user?.name });
  });
  tx();

  // Meta CAPI "Lead" — walk-ins are real top-of-funnel signals too. Fire only
  // when this phone is NEW (mirrors the ManyChat path so a known customer
  // re-visiting never double-counts). reception always picks a branch → we also
  // get `ct` for free. Fire-and-forget — never blocks or fails the response.
  // A new person on an already-known number is not a new Lead for Meta (the
  // match key is the phone; it was counted with the first profile).
  if (phoneIsNew && !(newPerson && phoneKnownBefore)) {
    sendMetaEvent('Lead',
      { phone: np, firstName: name, branch, externalId: userId },
      leadEventId(userId, np));
  }

  // Meta CAPI FindLocation — standard event for a showroom walk-in. Sent with
  // the DEFAULT action_source ('website') like Lead/Purchase so it stays in this
  // Web/CRM dataset's surfaced channel (physical_store filed it in the offline
  // bucket, which kept vanishing). Fires for EVERY walk-in; time-based eventId
  // keeps each visit distinct. Skipped for demo sessions.
  if (!isDemoContext()) {
    sendMetaEvent('FindLocation',
      { phone: np, firstName: name, branch, externalId: userId },
      `visit_walkin_${userId}_${Date.now()}`);
  }

  const storedSource = db.prepare(`SELECT campaign_source FROM lead_profiles WHERE user_id = ?`).get(userId)?.campaign_source ?? null;
  console.log(`🚶 WALK-IN ${existed ? 'RE-VISIT' : 'CREATED'}: ${name} → ${branch} (${storedSource || 'no campaign'})`);

  return res.json({
    ok:              true,
    user_id:         userId,
    first_name:      name,
    campaign_source: storedSource,
    branch,
    lead_class:      'visited',
    walk_in:         true,
    existed,
    new_person:      newPerson,
  });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/reception/today-visits — «قايمة العملاء زيارة اليوم»: everyone whose
// visit was confirmed TODAY (Cairo day) at the branch — walk-ins and returning
// customers included (visit_checkins) — with the arrival time, the salesperson
// they stood with THIS visit, and the sales already recorded for them today.
//   reception / faisal + nasr_city managers → locked to own branch.
//   admin → ?branch=<id> required.
// Read-only: no CAPI, no ManyChat, no writes.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/reception/today-visits', requireAuth, authorizeRoles('reception', 'admin', 'branch_manager'), (req, res) => {
  if (denyNonReceptionManager(req, res)) return;
  const branch = actsAsReception(req)
    ? (req.user.branch || null)
    : ((typeof req.query.branch === 'string' && req.query.branch.trim()) || null);
  if (!branch) return res.status(400).json({ error: 'branch_required' });

  const db  = getDb();
  const day = cairoDay();
  const [start, end] = cairoDayBoundsSql(day);

  const rows = db.prepare(`
    SELECT c.user_id, c.checked_in_at, c.source,
           lp.first_name, lp.lead_class, lp.campaign_source, lp.phone AS profile_phone,
           (SELECT GROUP_CONCAT(ph.phone, ' ، ') FROM lead_phones ph WHERE ph.user_id = c.user_id) AS phones,
           lv.sales_rep AS lv_sales_rep, lv.sales_rep_set_at
    FROM visit_checkins c
    JOIN lead_profiles lp ON lp.user_id = c.user_id
    LEFT JOIN lead_visits lv ON lv.user_id = c.user_id AND lv.branch = c.branch
    WHERE c.branch = ? AND c.visit_day = ?
    ORDER BY c.checked_in_at DESC, c.id DESC
  `).all(branch, day);

  // Today's sales for these customers at this branch (Cairo-day bounds, UTC).
  const salesByUser = new Map();
  if (rows.length) {
    const ids = [...new Set(rows.map(r => r.user_id))];
    const sales = db.prepare(`
      SELECT id, user_id, contract_number, rep, price, created_at, entered_by, entered_via
      FROM purchases
      WHERE branch = ? AND user_id IN (${ids.map(() => '?').join(', ')})
        AND datetime(created_at) >= ? AND datetime(created_at) < ?
      ORDER BY created_at, id
    `).all(branch, ...ids, start, end);
    for (const p of sales) {
      if (!salesByUser.has(p.user_id)) salesByUser.set(p.user_id, []);
      salesByUser.get(p.user_id).push(p);
    }
  }

  const isoZ = (s) => { const d = sqlUtcToDate(s); return d && !isNaN(d) ? d.toISOString().slice(0, 19) + 'Z' : null; };
  // O6 «شاف إيه» for each arrival.
  const viewedByUser = visitIntent.viewedFor(db, rows.map(r => r.user_id));
  // Phase 2 «مشي من غير شراء»: today's answer per customer at this branch.
  const leftByUser = new Map(db.prepare(`
    SELECT user_id, reason, note, recorded_by, updated_at FROM visit_outcomes WHERE branch = ? AND visit_day = ?
  `).all(branch, day).map(o => [o.user_id, {
    reason: o.reason, reason_label: LEFT_REASONS[o.reason] || o.reason, note: o.note || null,
    by: o.recorded_by || null, at: isoZ(o.updated_at),
  }]));

  const visits = rows.map(r => {
    const setThisVisit = repSetThisVisit(r.lv_sales_rep, r.sales_rep_set_at, r.checked_in_at);
    const arrived      = sqlUtcToDate(r.checked_in_at);
    const salesToday   = (salesByUser.get(r.user_id) || []).map(p => ({
      purchase_id:     p.id,
      contract_number: p.contract_number || null,
      rep:             p.rep || null,
      price:           p.price ?? null,
      created_at:      isoZ(p.created_at),
      entered_by:      p.entered_by || null,
      entered_via:     p.entered_via || null,
    }));
    return {
      user_id:            r.user_id,
      first_name:         r.first_name || null,
      phones:             r.phones || r.profile_phone || null,
      lead_class:         r.lead_class || null,
      campaign_source:    r.campaign_source || null,
      walk_in:            r.source === 'walkin',
      checked_in_at:      isoZ(r.checked_in_at),
      arrival_time:       arrived && !isNaN(arrived) ? cairoHHMM(arrived) : null,
      sales_rep:          setThisVisit ? r.lv_sales_rep : null,
      previous_sales_rep: setThisVisit ? null : (r.lv_sales_rep || null),
      sales_today:        salesToday,
      sold_today:         salesToday.length > 0,
      viewed:             viewedByUser.get(r.user_id) || null,
      // { reason, reason_label, note, by, at } | null — never beside a sale today
      left:               salesToday.length ? null : (leftByUser.get(r.user_id) || null),
    };
  });

  return res.json({ branch, day, count: visits.length, visits });
});

// ════════════════════════════════════════════════════════════════════════════
// Phase 2 (2026-11-22) — reception's «هو ده؟» card and «مشي من غير شراء».
// ════════════════════════════════════════════════════════════════════════════

// The reasons a customer left without buying (the same list the sales
// «مش هيشتري» outcome will use in phase 3).
const LEFT_REASONS = {
  price:         'السعر',
  model_missing: 'الموديل مش موجود',
  comparing:     'بيقارن',
  will_return:   'هيرجع',
  other:         'سبب تاني',
};

// GET /api/reception/lookup?phone= — WHO is this number, before anything is
// written: the «هو ده؟» card. Read-only (no visit, no Meta, no ManyChat).
//   reception / faisal + nasr_city managers → their own branch;
//   admin → ?branch=<id> (optional; without it nothing branch-specific is said).
// → 200 { phone_known: true, branch, candidates: [ {user_id, first_name,
//          lead_class, campaign_source, viewed, planned_when, pre_visit_rep,
//          last_showroom_rep, checked_in_today: {at, sales_rep}|null,
//          sold_today} ] }   newest first, at most 3
// → 404 { error: 'phone_not_found' }  (the desk opens the new-customer form)
// → 400 { error: 'invalid_phone' }
app.get('/api/reception/lookup', requireAuth, authorizeRoles('reception', 'admin', 'branch_manager'), (req, res) => {
  if (denyNonReceptionManager(req, res)) return;
  const db = getDb();
  let branch = null;
  if (actsAsReception(req)) branch = req.user.branch || null;
  else if (req.user?.role === 'admin') {
    const raw = typeof req.query.branch === 'string' ? req.query.branch.trim() : '';
    if (raw) {
      branch = intakeBranch(raw, { db });
      if (!branch) return res.status(400).json({ error: 'invalid_branch', message: 'الفرع ده مش من فروع السيستم — اختار من القايمة' });
    }
  } else {
    return res.status(403).json({ error: 'forbidden' });
  }
  const np = normalizePhone(typeof req.query.phone === 'string' ? req.query.phone : '');
  if (!np || np.length < 10) return res.status(400).json({ error: 'invalid_phone' });

  // Every profile that ever gave this number (lead_phones) or carries it on the
  // profile (legacy), newest activity first — the same match as the confirm.
  const rows = db.prepare(`
    SELECT lp.user_id, lp.first_name, lp.lead_class, lp.campaign_source, lp.last_activity
    FROM lead_profiles lp
    WHERE lp.user_id IN (SELECT user_id FROM lead_phones WHERE phone = ?) OR lp.phone = ?
    ORDER BY datetime(lp.last_activity) DESC, lp.user_id
    LIMIT 3
  `).all(np, np);
  if (!rows.length) return res.status(404).json({ error: 'phone_not_found' });

  const ids = rows.map(r => r.user_id);
  const viewed = visitIntent.viewedFor(db, ids);
  const day = cairoDay();
  const [start, end] = cairoDayBoundsSql(day);
  const candidates = rows.map((r) => {
    const v = viewed.get(r.user_id) || null;
    const when = v && v.visit_planned ? v.visit_planned.when : null;
    let preVisitRep = null, lastShowroomRep = null, checkedIn = null, soldToday = false;
    if (branch) {
      preVisitRep = db.prepare(`SELECT assigned_sales FROM branch_customer_followups WHERE user_id = ? AND branch = ?`)
        .get(r.user_id, branch)?.assigned_sales || null;
      const lv = db.prepare(`SELECT sales_rep, sales_rep_set_at FROM lead_visits WHERE user_id = ? AND branch = ?`).get(r.user_id, branch);
      const ci = todayCheckin(db, r.user_id, branch);
      if (ci) {
        const thisVisit = lv && repSetThisVisit(lv.sales_rep, lv.sales_rep_set_at, ci.checked_in_at);
        const at = sqlUtcToDate(ci.checked_in_at);
        checkedIn = {
          at: at && !isNaN(at) ? at.toISOString().slice(0, 19) + 'Z' : null,
          sales_rep: thisVisit ? lv.sales_rep : null,
        };
        lastShowroomRep = thisVisit ? null : (lv?.sales_rep || null);
      } else {
        lastShowroomRep = lv?.sales_rep || null;
      }
      soldToday = !!db.prepare(`SELECT 1 FROM purchases WHERE user_id = ? AND branch = ?
                                AND datetime(created_at) >= ? AND datetime(created_at) < ? LIMIT 1`)
        .get(r.user_id, branch, start, end);
    }
    return {
      user_id:           r.user_id,
      first_name:        r.first_name || null,
      lead_class:        r.lead_class || null,
      campaign_source:   r.campaign_source || null,
      viewed:            v,
      planned_when:      when === 'today' || when === 'tomorrow' ? when : null,
      pre_visit_rep:     preVisitRep,
      last_showroom_rep: lastShowroomRep,
      checked_in_today:  checkedIn,
      sold_today:        soldToday,
    };
  });
  return res.json({ phone_known: true, branch, candidates });
});

// POST /api/visits/:userId/left — «مشي من غير شراء + السبب» for a customer
// checked in TODAY (Cairo day) at the branch. Body: { reason, note?, branch? }
//   reason ∈ LEFT_REASONS; note ≤ 300 chars (asked for when reason = 'other').
//   reception / faisal + nasr_city managers → own branch; admin → body.branch.
// A customer with a sale recorded today at the branch can't be marked «مشي»
// (409 sold_today). A second answer replaces the first.
// DELETE /api/visits/:userId/left — takes today's answer back (a wrong tap).
function leftBranch(req, res) {
  if (denyNonReceptionManager(req, res)) return null;
  const db = getDb();
  if (actsAsReception(req)) {
    if (!req.user.branch) { res.status(400).json({ error: 'branch_required' }); return null; }
    return req.user.branch;
  }
  if (req.user?.role !== 'admin') { res.status(403).json({ error: 'forbidden' }); return null; }
  const raw = req.body?.branch ?? req.query?.branch;
  const b = typeof raw === 'string' && raw.trim() ? intakeBranch(raw, { db }) : null;
  if (!b) { res.status(400).json({ error: 'branch_required', message: 'اختار الفرع الأول' }); return null; }
  return b;
}
app.post('/api/visits/:userId/left', requireAuth, authorizeRoles('reception', 'admin', 'branch_manager'), (req, res) => {
  const branch = leftBranch(req, res);
  if (!branch) return;
  const db = getDb();
  const userId = String(req.params.userId || '');
  const { reason } = req.body || {};
  let note = req.body?.note;
  if (typeof reason !== 'string' || !Object.prototype.hasOwnProperty.call(LEFT_REASONS, reason)) {
    return res.status(400).json({ error: 'اختار السبب من القايمة', code: 'invalid_reason' });
  }
  if (note != null && typeof note !== 'string') return res.status(400).json({ error: 'الملاحظة لازم تكون كلام', code: 'invalid_note' });
  note = note ? note.replace(/\s+/g, ' ').trim().slice(0, 300) : null;
  if (reason === 'other' && !note) return res.status(400).json({ error: 'اكتب السبب في كلمتين', code: 'note_required' });
  const checkin = todayCheckin(db, userId, branch);
  if (!checkin) {
    return res.status(409).json({ error: 'العميل ده مش مسجّل إنه وصل الفرع النهارده', code: 'not_checked_in_today' });
  }
  const [start, end] = cairoDayBoundsSql(checkin.visit_day);
  // the contract's day (created_at, corrected by the manager if he did), not the typing moment
  const sold = db.prepare(`SELECT 1 FROM purchases WHERE user_id = ? AND branch = ?
                           AND datetime(created_at) >= ? AND datetime(created_at) < ? LIMIT 1`).get(userId, branch, start, end);
  if (sold) return res.status(409).json({ error: 'العميل ده اتسجّلتله بيعة النهارده', code: 'sold_today' });
  db.prepare(`
    INSERT INTO visit_outcomes (checkin_id, user_id, branch, visit_day, reason, note, recorded_by)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(checkin_id) DO UPDATE SET reason = excluded.reason, note = excluded.note,
      recorded_by = excluded.recorded_by, updated_at = datetime('now')
  `).run(checkin.id, userId, branch, checkin.visit_day, reason, note, req.user?.name || null);
  console.log(`🚪 LEFT WITHOUT BUYING: ${userId} @ ${branch} (${reason})`);
  return res.json({ ok: true, user_id: userId, branch, reason, reason_label: LEFT_REASONS[reason], note });
});
app.delete('/api/visits/:userId/left', requireAuth, authorizeRoles('reception', 'admin', 'branch_manager'), (req, res) => {
  const branch = leftBranch(req, res);
  if (!branch) return;
  const db = getDb();
  const userId = String(req.params.userId || '');
  const checkin = todayCheckin(db, userId, branch);
  const info = checkin ? db.prepare(`DELETE FROM visit_outcomes WHERE checkin_id = ?`).run(checkin.id) : { changes: 0 };
  return res.json({ ok: true, removed: info.changes > 0 });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/reception/expected-visits — «جايين النهارده» (O6): customers whose
// LATEST visit_planned says today or tomorrow (Cairo day, events.planned_day)
// for THIS branch (the event's branch, else preferred_branch) and who haven't
// checked in since they said it. Each row: name, the phones reception already
// sees in «زيارة اليوم», planned_when ('today' | 'tomorrow'), the «شاف» data.
// Reception's action on a row is the same confirm as the desk
// (POST /api/visits/confirm with user_id).
//   reception / faisal + nasr_city managers → locked to own branch.
//   admin → ?branch=<id> required.
// Read-only: no CAPI, no ManyChat, no writes.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/reception/expected-visits', requireAuth, authorizeRoles('reception', 'admin', 'branch_manager'), (req, res) => {
  if (denyNonReceptionManager(req, res)) return;
  const branch = actsAsReception(req)
    ? (req.user.branch || null)
    : ((typeof req.query.branch === 'string' && req.query.branch.trim()) || null);
  if (!branch) return res.status(400).json({ error: 'branch_required' });

  const { day, tomorrow, rows } = visitIntent.expectedVisits(getDb(), branch);
  return res.json({
    branch, day, tomorrow,
    count:    rows.length,
    today_n:  rows.filter(r => r.planned_when === 'today').length,
    leads:    rows,
  });
});

// ════════════════════════════════════════════════════════════════════════════
// POST /api/reception/sales — reception records a sale FOR a salesperson
// (owner 2026-11-16: «الريسبشن هو اللي بيسجل البيع للسيلز وبيكتب بيانات العقد»).
// The sale is stored IN THE SALESPERSON'S NAME (purchases.rep — it counts for
// his target exactly as before) with who typed it in (purchases.entered_*).
// When no salesperson was linked at THIS visit yet, the visit is linked to the
// sale's salesperson in the same transaction (same handoff + revertable
// set_sales audit as /api/visits/set-sales). A visit that already has its
// salesperson from this visit is never moved by a sale — a second contract for
// another salesperson («+ عقد تاني») is credited to him and the visit, the
// follow-up and the customer's owner stay with the first one (changing the
// visit's salesperson is the list's explicit «غيّر» → set-sales).
// Body: { user_id, sales_rep?, product_ids[], contract_number, price?, notes?,
//         branch? (admin only) }
//   reception / faisal + nasr_city managers → locked to own branch.
// Only for a customer checked in TODAY (Cairo day) at the branch. Everything
// up to the commit is synchronous, so a double click is serialized and the
// second one hits the duplicate-contract guard (409).
// Errors: { error: <Arabic>, code }
// ════════════════════════════════════════════════════════════════════════════
app.post('/api/reception/sales', requireAuth, authorizeRoles('reception', 'admin', 'branch_manager'), async (req, res) => {
 try {
  if (denyNonReceptionManager(req, res)) return;
  const body = req.body || {};
  const fail = (status, code, error, extra = {}) => res.status(status).json({ error, code, ...extra });

  const branch = actsAsReception(req)
    ? (req.user.branch || null)
    : ((typeof body.branch === 'string' && body.branch.trim()) || null);
  if (!branch) return fail(400, 'branch_required', 'اختار الفرع');

  const userId = typeof body.user_id === 'string' ? body.user_id.trim() : '';
  if (!userId) return fail(400, 'user_id_required', 'اختار العميل');

  const db = getDb();
  const lead = db.prepare(`SELECT user_id FROM lead_profiles WHERE user_id = ?`).get(userId);
  if (!lead) return fail(404, 'lead_not_found', 'العميل ده مش موجود');

  // Only a customer who ARRIVED today at this branch (the «زيارة اليوم» list).
  const checkin = todayCheckin(db, userId, branch);
  if (!checkin) {
    // Never just «confirm it first»: a confirm sends the customer a ManyChat
    // visit message + a Meta event, so it is only for a customer who is here now.
    return fail(409, 'no_visit_today',
      'العميل ده مش متأكد وصوله النهارده في الفرع — لو هو موجود دلوقتي أكّد زيارته الأول، ' +
      'ولو البيعة من زيارة قبل كده مدير الفرع يسجّلها من صفحة العميل باسم السيلز');
  }

  // The salesperson linked at THIS visit (not an earlier one) is the default.
  const lv = db.prepare(`SELECT * FROM lead_visits WHERE user_id = ? AND branch = ?`).get(userId, branch);
  const visitRep = lv && repSetThisVisit(lv.sales_rep, lv.sales_rep_set_at, checkin.checked_in_at)
    ? lv.sales_rep : null;

  const wanted = (typeof body.sales_rep === 'string' && body.sales_rep.trim()) || visitRep;
  if (!wanted) return fail(400, 'sales_rep_required', 'اختار السيلز اللي البيعة تتحسب له');
  const repRow = findBranchSalesRep(db, wanted, branch);
  if (!repRow) return fail(400, 'rep_not_in_branch', 'السيلز ده مش من سيلز الفرع (أو متوقف) — اختار من القايمة');
  const rep = repRow.name; // the DB's exact name — never the client's string

  const products = validateProductIds(db, body.product_ids);
  if (products.code) return fail(400, products.code, products.error);
  // 2026-11-22: the prices system's models / pieces (items) — the only await:
  // everything after it up to the commit stays synchronous (double click → 409).
  const fromCatalog = await linesFromBody(body.items);
  if (fromCatalog.code) return fail(400, fromCatalog.code, fromCatalog.error);
  const lines = fromCatalog.lines;
  if (!products.ids.length && !lines.length) {
    return fail(400, 'products_required', 'اختار المنتج اللي اتباع للعميل قبل ما تسجّل البيعة');
  }

  const contractNumber = normalizeContractNumber(body.contract_number);
  if (!contractNumber) return fail(400, 'contract_required', 'اكتب رقم العقد');
  if (contractNumber.length > 60) return fail(400, 'contract_too_long', 'رقم العقد طويل أوي');

  const priceParsed = parseEgpPrice(body.price);
  if (priceParsed.error) return fail(400, 'bad_price', 'اكتب السعر أرقام بس (مثلاً 38500)');
  const price = priceParsed.value;
  const notes = (typeof body.notes === 'string' && body.notes.trim()) ? body.notes.trim().slice(0, 1000) : null;

  const dup = findDuplicatePurchase(db, { userId, contractNumber, rep, productIds: products.ids, lines });
  if (dup) return fail(409, dup.code, dup.error, { purchase_id: dup.purchase_id });

  // Legacy product_id text = the first product's name (old reports read it).
  const legacyLabel = (lines[0] ? lines[0].title : null)
    || (products.ids.length ? db.prepare(`SELECT name FROM products WHERE id = ?`).get(products.ids[0])?.name : null) || null;

  let linkedVisit = false;
  let purchaseId;
  db.transaction(() => {
    // (a) a visit with no salesperson from THIS visit gets the sale's one
    // (per-visit "bought" counts join pu.rep = v.sales_rep). One that already
    // has its salesperson from this visit is never moved by a sale.
    if (!visitRep) {
      linkVisitSales(db, { userId, branch, salesRep: rep, operator: req.user.name });
      linkedVisit = true;
    }
    // (b) the sale + its items + lead_class
    purchaseId = insertPurchaseRows(db, {
      userId, legacyLabel, price, branch, notes, rep, contractNumber, productIds: products.ids, lines,
      enteredBy: req.user.name, enteredById: req.user.id ?? null, enteredByRole: req.user.role,
      enteredVia: 'reception',
    });
    // (b2) he bought: today's «مشي» answer at this branch goes
    clearLeftOnSale(db, userId, branch);
    // (c) display-only ledger row (not in REVERTABLE_AUDIT_TABLES)
    auditLog(db, req.user.name, 'reception_sale', userId, {
      table: 'purchases', where: { id: purchaseId }, row: null,
      rep, branch, contract_number: contractNumber,
    });
  })();

  console.log(`💰 PURCHASE (reception ${req.user.name}): user:${userId} contract:${contractNumber} ` +
    `price:${price ?? '?'} rep:${rep} branch:${branch}${linkedVisit ? ' (visit linked)' : ''}`);

  afterPurchase(db, req, {
    userId, purchaseId, rep, branch, price, contractNumber, viaReception: true,
  });

  return res.json({
    ok: true, purchase_id: purchaseId, lead_class: 'purchased',
    rep, branch, contract_number: contractNumber, linked_visit: linkedVisit,
  });
 } catch (err) {
  console.error('[reception/sales] failed:', err && err.message);
  if (!res.headersSent) res.status(500).json({ error: 'حصلت مشكلة — جرّب تاني', code: 'internal' });
 }
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/sales/my — a salesperson's own customers + this-month KPIs.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/sales/my', requireAuth, authorizeRoles('sales'), (req, res) => {
  const me       = req.user.name;
  const myBranch = req.user.branch || null;
  const today    = req.query.today === '1';
  const db       = getDb();

  const todayFilter = today ? `AND date(v.visited_at) = date('now')` : '';

  // Only customers whose "owner branch" (where they closed their latest
  // interaction — purchase branch if bought, else most-recent visit) is THIS
  // rep's branch. Without it, a customer who bought in another branch but had a
  // stray visit logged here would leak into this rep's "عملائي" list too.
  const ownerBranchFilter = myBranch ? `
    AND COALESCE(
      (SELECT pu.branch FROM purchases pu WHERE pu.user_id = lp.user_id ORDER BY pu.created_at DESC, pu.id DESC LIMIT 1),
      (SELECT vv.branch FROM lead_visits vv WHERE vv.user_id = lp.user_id ORDER BY vv.visited_at DESC LIMIT 1)
    ) = ?` : '';

  const customers = db.prepare(`
    SELECT
      lp.user_id, lp.first_name, lp.lead_class, lp.total_score, lp.last_activity,
      v.branch, v.visited_at,
      (SELECT GROUP_CONCAT(ph.phone, ' ، ') FROM lead_phones ph
         WHERE ph.user_id = lp.user_id)                                  AS phones,
      (SELECT COUNT(*)        FROM purchases p
         WHERE p.user_id = lp.user_id AND p.rep = ?)                      AS my_purchases,
      (SELECT COALESCE(SUM(p.price),0) FROM purchases p
         WHERE p.user_id = lp.user_id AND p.rep = ?)                      AS my_sales_total,
      ${crossBranchCols('lp.user_id')}
    FROM lead_visits v
    JOIN lead_profiles lp ON lp.user_id = v.user_id
    WHERE v.sales_rep = ?
      AND COALESCE(lp.is_duplicate, 0) = 0
      ${ownerBranchFilter}
      ${todayFilter}
    ORDER BY (my_purchases > 0) ASC, v.visited_at DESC
  `).all(me, me, me, ...(myBranch ? [myBranch] : []));

  // This-month performance — flagged-duplicate visits don't count as "served".
  // The CAIRO month (2026-11-25), the month of his target card.
  const mVisit = cairoMonthSql('visited_at', currentMonth());
  const mBuy   = cairoMonthSql('p.created_at', currentMonth());
  const mSale  = cairoMonthSql('created_at', currentMonth());
  const servedMonth = db.prepare(`
    SELECT COUNT(DISTINCT user_id) AS n FROM lead_visits
    WHERE sales_rep = ?${mVisit.clause}
      AND ${NOT_DUPLICATE('lead_visits.user_id')}
  `).get(me, ...mVisit.params).n;
  const boughtMonth = db.prepare(`
    SELECT COUNT(DISTINCT v.user_id) AS n
    FROM lead_visits v
    JOIN purchases p ON p.user_id = v.user_id AND p.rep = ?
    WHERE v.sales_rep = ?${mBuy.clause}
  `).get(me, me, ...mBuy.params).n;
  const salesMonth = db.prepare(`
    SELECT COALESCE(SUM(price),0) AS total FROM purchases
    WHERE rep = ?${mSale.clause}
  `).get(me, ...mSale.params).total;

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
// Filters: ?sales= &branch= &from= &to=  (CAIRO days)
// 2026-11-22 «أرقام حقيقية» (r2): every number from the range — the rules are
// honest.salesByRep (services/honestNumbers.js):
//   served      — people with a visit (check-in) in the range at the branch,
//                 credited to the salesperson lead_visits names for them there
//                 (a customer who first came before the range and came back in
//                 it is served in it);
//   bought      — of those people, the ones who bought from him there in it;
//   total_sales — what was paid on HIS contracts in the range at the branch
//                 (once per contract — no join fan-out);
//   contracts   — his contracts in the range at the branch, even when that
//                 customer's first visit was before the range.
//   follow-ups  — with dates: the distinct customers he followed up in the
//                 range, from followup_log (2026-11-25: the manager's range
//                 rule; the showroom handoff's note never counts); without
//                 dates: the follow-ups the state rows hold (all-time rule).
// A stopped salesperson (users.active = 0) or a name with no account has no
// row (2026-11-25); `stopped_sales` says what of the range's contracts those
// rows held (only when one was hidden).
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/sales/analytics', requireAuth, requireRole('admin'), (req, res) => {
  const db = getDb();
  const { sales, branch, from, to } = req.query;
  if ((from && !honest.isDay(from)) || (to && !honest.isDay(to))) {
    return res.status(400).json({ error: 'التاريخ لازم يكون YYYY-MM-DD' });
  }
  const { bySales, byBranch } = honest.salesByRep(db, { from: from || null, to: to || null,
    sales: sales || null, branch: branch || null });

  const enriched = bySales.map(r => ({
    ...r,
    not_bought: r.served - r.bought,
    close_rate: r.served ? Math.round((r.bought / r.served) * 100) : 0,
    followed_up: 0, fu_visited: 0, fu_not_visited: 0,
  }));

  // Follow-up stats per (salesperson, branch).
  // With dates (2026-11-25, the manager's rule — branchOverviewRange): the
  // distinct customers he followed up in the range, from the append-only
  // followup_log (the state row keeps only the LAST follow-up and is reset by
  // a reassignment or the showroom handoff; the handoff's own note, kind
  // 'handoff', is not a call and never counts); fu_visited = of them, the ones
  // who visited that branch (any day). So the admin and the branch manager
  // count the same follow-ups for the same days.
  // Without dates: the follow-ups the state rows hold now (followed_up = 1) —
  // the manager's all-time answer's rule.
  const ranged = !!(from || to);
  let fuStats;
  if (ranged) {
    // NOT_DUPLICATE: a customer the manager flagged duplicate is no
    // follow-up, as in the manager's own range (2026-11-25 review).
    const lw = [`l.sales IS NOT NULL`, `TRIM(l.sales) <> ''`, `COALESCE(l.kind, '') <> 'handoff'`, NOT_DUPLICATE('l.user_id')];
    const lp = [];
    if (sales)  { lw.push(`TRIM(l.sales) = TRIM(?)`); lp.push(sales); }
    const lr = honest.rangeSql('l.followed_up_at', from || null, to || null);
    fuStats = db.prepare(`
      SELECT TRIM(l.sales) AS sales_rep, l.branch AS branch, l.user_id AS user_id,
        EXISTS (SELECT 1 FROM lead_visits lv WHERE lv.user_id = l.user_id AND lv.branch = l.branch) AS visited
      FROM followup_log l
      WHERE ${lw.join(' AND ')}${lr.clause}
    `).all(...lp, ...lr.params);
    // distinct customers per (salesperson, branch) — the branch normalized like the rows'
    const per = new Map();
    for (const f of fuStats) {
      const b = honest.normBranch(f.branch);
      if (branch && b !== honest.normBranch(branch)) continue;
      const k = `${f.sales_rep}|${b}`;
      if (!per.has(k)) per.set(k, { sales_rep: f.sales_rep, branch: b, people: new Map() });
      const p = per.get(k).people;
      p.set(f.user_id, (p.get(f.user_id) || 0) || f.visited);
    }
    fuStats = [...per.values()].map((g) => ({
      sales_rep: g.sales_rep, branch: g.branch, followed_up: g.people.size,
      fu_visited: [...g.people.values()].filter(Boolean).length,
    }));
  } else {
    const fuWhere  = [`f.assigned_sales IS NOT NULL`, `f.followed_up = 1`, NOT_DUPLICATE('f.user_id')];
    const fuParams = [];
    if (sales)  { fuWhere.push(`f.assigned_sales = ?`); fuParams.push(sales); }
    if (branch) { fuWhere.push(`f.branch = ?`);         fuParams.push(branch); }
    fuStats = db.prepare(`
      SELECT f.assigned_sales AS sales_rep, f.branch AS branch,
        COUNT(*) AS followed_up,
        SUM(CASE WHEN lv.user_id IS NOT NULL THEN 1 ELSE 0 END) AS fu_visited
      FROM branch_customer_followups f
      LEFT JOIN lead_visits lv
        ON lv.user_id = f.user_id AND lv.branch = f.branch
      WHERE ${fuWhere.join(' AND ')}
      GROUP BY f.assigned_sales, f.branch
    `).all(...fuParams);
  }

  const keyOf = (rep, br) => `${rep}|${honest.normBranch(br)}`;
  const idx = new Map(enriched.map(r => [keyOf(r.sales_rep, r.branch), r]));
  for (const s of fuStats) {
    const k = keyOf(s.sales_rep, s.branch);
    const row = idx.get(k) || {
      sales_rep: s.sales_rep, branch: honest.normBranch(s.branch), served: 0, bought: 0,
      not_bought: 0, close_rate: 0, total_sales: 0, contracts: 0,
      followed_up: 0, fu_visited: 0, fu_not_visited: 0,
    };
    row.followed_up    = s.followed_up;
    row.fu_visited     = s.fu_visited;
    row.fu_not_visited = s.followed_up - s.fu_visited;
    if (!idx.has(k)) { idx.set(k, row); enriched.push(row); }
  }

  // Stopped salespeople (2026-11-25): no row; byBranch (people per branch)
  // keeps them, and stopped_sales says their contracts in the range.
  const shown = hideStoppedRows(db, enriched);
  return res.json({ bySales: shown.rows, byBranch, ...shown.extra });
});

// ════════════════════════════════════════════════════════════════════════════
// Removed in phase 1 (2026-11-22, «شيل الزحمة», owner-approved): points /
// badges / levels (achievements + their weights), the call-rep analytics
// (0 rep users live), the admin AI pages (control + chat), the «مسح كل
// الزيارات» reset, the Meta «warm-up» of old customers. Each old URL answers
// 410 Gone with an Arabic line, so an old portal tab still open during the
// deploy shows a message instead of crashing. The AI brief inside the sales
// queue (/api/sales/customers/:userId/ai-brief) stays.
// ════════════════════════════════════════════════════════════════════════════
const PHASE1_REMOVED = [
  ['get',  '/api/admin/achievements/sales'],
  ['get',  '/api/admin/achievements/branches'],
  ['post', '/api/admin/achievements/award'],
  ['get',  '/api/settings/achievement-weights'],
  ['put',  '/api/settings/achievement-weights'],
  ['get',  '/api/admin/reps-analytics'],
  ['get',  '/api/admin/ai/status'],
  ['post', '/api/admin/ai/test'],
  ['get',  '/api/admin/ai/recent-briefs'],
  ['post', '/api/admin/ai/chat'],
  ['post', '/api/admin/reset-visits'],
  ['post', '/api/admin/meta/sync-historical'],
];
const removedRoute = (_req, res) => res.status(410).json({ error: 'removed', message: 'الخاصية دي اتشالت من السيستم' });
for (const [m, p] of PHASE1_REMOVED) app[m](p, requireAuth, removedRoute);

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



// ════════════════════════════════════════════════════════════════════════════
// GET /api/branch/overview — branch manager's read-only view of THEIR branch.
//   branch_manager → locked to its own branch (a ?branch is ignored). admin → ?branch=<id>
//   Returns branch KPIs + per-salesperson performance for that branch only.
//   Optional ?startDate=YYYY-MM-DD&endDate=YYYY-MM-DD (either may be empty;
//   Cairo days, 2026-11-25 «رجّعلي فلترة التاريخ للمديرين»): every period
//   number then counts only what happened in [startDate, endDate] and the
//   answer carries `range: { from, to }` — see branchOverviewRange below.
//   Without them the answer is the all-time one, unchanged.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/branch/overview', requireAuth, authorizeRoles('branch_manager', 'admin'), (req, res) => {
  const role = req.user?.role;
  const branch = role === 'branch_manager'
    ? (req.user.branch || null)
    : (req.query.branch || null);
  if (!branch) return res.status(400).json({ error: 'branch_required' });

  const startDate = String(req.query.startDate ?? '').trim() || null;
  const endDate   = String(req.query.endDate ?? '').trim() || null;
  if ((startDate && !honest.isDay(startDate)) || (endDate && !honest.isDay(endDate))) {
    return res.status(400).json({ error: 'التاريخ لازم يكون YYYY-MM-DD' });
  }
  if (startDate && endDate && startDate > endDate) {
    return res.status(400).json({ error: 'تاريخ البداية لازم يكون قبل تاريخ النهاية أو نفس اليوم' });
  }

  const db = getDb();
  if (startDate || endDate) return res.json(branchOverviewRange(db, branch, startDate, endDate));

  // Customers who requested this branch in the CHAT (branch_selected) — even if
  // not visited. The walk-in route's event is not a request (2026-11-22).
  const requested = db.prepare(`
    SELECT COUNT(DISTINCT e.user_id) AS n FROM events e
    WHERE e.event_type = 'branch_selected' AND (e.event_value = ? OR e.branch = ?) AND ${honest.CHAT_EVENT('e')}
  `).get(branch, branch).n;

  // Customers who actually visited this branch (one row per user/branch).
  // Flagged-duplicate leads are excluded so the funnel matches the rep KPIs.
  const visited = db.prepare(`
    SELECT COUNT(DISTINCT user_id) AS n FROM lead_visits
    WHERE branch = ? AND ${NOT_DUPLICATE('lead_visits.user_id')}
  `).get(branch).n;

  // Per-salesperson performance in this branch.
  // 2026-11-22 «أرقام حقيقية» (r2): contracts and total_sales are the SAME set
  // of contracts — his contracts written at this branch, the paid amount once
  // per contract (no join fan-out, no sale of his at another branch, none of
  // another rep's customer missing). A rep with contracts here but nobody
  // served here (yet) still has his row.
  //   served      — people who visited the branch with this salesperson;
  //   bought      — of them, the ones who bought from him.
  const bySales = db.prepare(`
    WITH served AS (
      SELECT DISTINCT v.sales_rep, v.user_id FROM lead_visits v
      WHERE v.branch = ? AND v.sales_rep IS NOT NULL AND ${NOT_DUPLICATE('v.user_id')}
    ),
    reps AS (
      SELECT sales_rep AS rep FROM served
      UNION SELECT pu.rep FROM purchases pu WHERE pu.branch = ? AND pu.rep IS NOT NULL AND TRIM(pu.rep) <> ''
    )
    SELECT r.rep AS sales_rep,
      (SELECT COUNT(*) FROM served s WHERE s.sales_rep = r.rep) AS served,
      (SELECT COUNT(*) FROM served s WHERE s.sales_rep = r.rep
         AND EXISTS (SELECT 1 FROM purchases pu WHERE pu.user_id = s.user_id AND pu.rep = r.rep)) AS bought,
      (SELECT COALESCE(SUM(pu.price), 0) FROM purchases pu WHERE pu.rep = r.rep AND pu.branch = ?) AS total_sales,
      (SELECT COUNT(*) FROM purchases pu WHERE pu.rep = r.rep AND pu.branch = ?) AS contracts
    FROM reps r
    ORDER BY total_sales DESC
  `).all(branch, branch, branch, branch).map(r => ({
    ...r,
    not_bought: r.served - r.bought,
    close_rate: r.served ? Math.round((r.bought / r.served) * 100) : 0,
    assigned: 0, followup_rate: 0,
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
      AND ${NOT_DUPLICATE('f.user_id')}
    GROUP BY f.assigned_sales
  `).all(branch, branch);

  const blankRow = (name) => ({
    sales_rep: name, served: 0, bought: 0, not_bought: 0,
    close_rate: 0, total_sales: 0, assigned: 0, followup_rate: 0,
    followed_up: 0, fu_visited: 0, fu_not_visited: 0,
  });

  const byName = new Map(bySales.map(r => [r.sales_rep, r]));
  for (const s of fuStats) {
    const row = byName.get(s.sales_rep) || blankRow(s.sales_rep);
    row.followed_up    = s.followed_up;
    row.fu_visited     = s.fu_visited;
    row.fu_not_visited = s.followed_up - s.fu_visited;
    if (!byName.has(s.sales_rep)) { byName.set(s.sales_rep, row); bySales.push(row); }
  }

  // Total customers ASSIGNED to each rep (regardless of follow-up). This is what
  // lets the manager see, per rep: "assigned N → followed up M (rate %)". Reps
  // with assignments but no visit/follow-up yet still surface here. TRIM keeps it
  // resilient to any stray whitespace in the stored name.
  const assignedStats = db.prepare(`
    SELECT TRIM(assigned_sales) AS sales_rep, COUNT(*) AS assigned
    FROM branch_customer_followups
    WHERE branch = ? AND assigned_sales IS NOT NULL AND TRIM(assigned_sales) <> ''
      AND ${NOT_DUPLICATE('branch_customer_followups.user_id')}
    GROUP BY TRIM(assigned_sales)
  `).all(branch);
  for (const a of assignedStats) {
    const row = byName.get(a.sales_rep) || blankRow(a.sales_rep);
    row.assigned = a.assigned;
    if (!byName.has(a.sales_rep)) { byName.set(a.sales_rep, row); bySales.push(row); }
  }

  // Attach each rep's CURRENT-MONTH target + achievement (contracts this
  // Cairo month — the month the «الشهر ده» filter counts), and the follow-up
  // rate (followed-up ÷ assigned).
  const tMonth = cairoMonth();
  for (const r of bySales) {
    r.contracts    = r.contracts || 0;
    r.target       = getTarget(db, 'sales_rep', r.sales_rep, tMonth);   // a CONTRACTS target now
    r.target_pct   = pctAchieved(cairoMonthContracts(db, { rep: r.sales_rep, branch, month: tMonth }), r.target);
    r.followup_rate = r.assigned ? Math.round((r.followed_up / r.assigned) * 100) : 0;
  }

  const served      = bySales.reduce((s, r) => s + r.served, 0);
  const bought      = bySales.reduce((s, r) => s + r.bought, 0);
  // ALL the branch's contracts and their value = «التعاقدات» › «كل الشهور»
  // (2026-11-25 review: the total was the rows' sum, so a contract with no
  // salesperson was in the count beside it but not in «إجمالي البيع»); the
  // rows stay his own contracts, no_rep_* = the rest (as with a range).
  const totals = db.prepare(
    `SELECT COUNT(*) AS count, COALESCE(SUM(price), 0) AS total FROM purchases WHERE branch = ?`
  ).get(branch);
  const repContracts = bySales.reduce((s, r) => s + (r.contracts || 0), 0);
  const repSales     = bySales.reduce((s, r) => s + (r.total_sales || 0), 0);

  // Branch target progress — this Cairo month's target vs its CONTRACTS.
  const branchTarget = getTarget(db, 'branch', branch, tMonth);
  const branchMonthContracts = cairoMonthContracts(db, { branch, month: tMonth });

  // Stopped salespeople (2026-11-25): no row; their contracts stay in the
  // totals above (computed from every row) and are said in stopped_sales.
  const shown = hideStoppedRows(db, bySales);

  return res.json({
    branch,
    target_month: tMonth,
    ...shown.extra,
    kpis: {
      requested,
      visited,
      bought,
      total_sales: totals.total,
      contracts_count: totals.count,
      no_rep_contracts: totals.count - repContracts,
      no_rep_sales: totals.total - repSales,
      close_rate: served ? Math.round((bought / served) * 100) : 0,
      target:          branchTarget,
      month_contracts: branchMonthContracts,
      target_pct:      pctAchieved(branchMonthContracts, branchTarget),
    },
    bySales: shown.rows,
  });
});

// Per-salesperson rows without the stopped ones (honest.sellers / hideStopped)
// → { rows, extra }: extra = { stopped_sales: { contracts, total_sales,
// removed } } — what the hidden rows held of the totals — only when a row was
// hidden (with nobody stopped the answer is the one it always was).
function hideStoppedRows(db, rows, nameOf = (r) => r.sales_rep) {
  const { rows: kept, hidden } = honest.hideStopped(rows, honest.sellers(db), nameOf,
    { contracts: (r) => r.contracts, total_sales: (r) => r.total_sales });
  return {
    rows: kept,
    extra: hidden.rows ? { stopped_sales: { contracts: hidden.contracts, total_sales: hidden.total_sales, removed: hidden.removed } } : {},
  };
}

// /api/branch/overview with a range (2026-11-25). Every number counts what
// happened in [from, to] Cairo days (either end may be open):
//   requested    — chat people with a branch_selected for this branch in the range
//   visited      — people with a visit at the branch in the range (honest.branchPeriod)
//   per salesperson (honest.branchPeriod):
//     bought       — distinct customers with a contract from him at the branch
//                  dated in the range (so «اشتروا» never misses a contract
//                  whose visit was in an earlier period)
//     served       — the people he served at the branch in the range ∪ his
//                  buyers (bought ≤ served); the branch's visited also holds
//                  everyone with a contract there in the range
//     contracts / total_sales — his contracts at this branch dated in the
//                  range: the SQL of GET /api/contracts (p.branch = ? + the
//                  same Cairo-day bounds), so the rows add up to that page
//     followed_up / fu_visited — distinct customers he followed up in the
//                  range, from the append-only followup_log (the state row
//                  keeps only the LAST follow-up and is reset by a
//                  reassignment / the showroom handoff; the handoff's own log
//                  row, kind 'handoff', is not a call and never counts);
//                  fu_visited = of them, visited the branch (any day)
//     assigned     — customers assigned to him NOW (a state, not an event: the
//                  follow-up table keeps one row per customer, so «assigned in
//                  the range» would hide the ones still waiting)
//   contracts_count / total_sales (branch) — ALL the branch's contracts in the
//                  range = the contracts page's «N تعاقد — إجمالي X» for the
//                  same days; no_rep_* = the ones with no salesperson (in the
//                  total, in no row)
//   The target is this CAIRO month's (cairoMonthContracts), like the all-time
//   answer, so under «الشهر ده» month_contracts = contracts_count.
// Duplicates the manager flagged (is_duplicate) stay out of visited / served /
// follow-ups, as in the all-time answer; contracts never leave a total.
function branchOverviewRange(db, branch, from, to) {
  const isDup = new Set(db.prepare(`SELECT user_id FROM lead_profiles WHERE is_duplicate = 1`).all().map((r) => r.user_id));
  const skip = (uid) => isDup.has(uid);

  const er = honest.rangeSql('e.created_at', from, to);
  const requested = db.prepare(`
    SELECT COUNT(DISTINCT e.user_id) AS n FROM events e
    WHERE e.event_type = 'branch_selected' AND (e.event_value = ? OR e.branch = ?) AND ${honest.CHAT_EVENT('e')}${er.clause}
  `).get(branch, branch, ...er.params).n;

  const period = honest.branchPeriod(db, { branch, from, to, skip });

  const pr = honest.rangeSql('p.created_at', from, to);
  const contractsBy = db.prepare(`
    SELECT p.rep AS rep, COUNT(*) AS contracts, COALESCE(SUM(p.price), 0) AS total_sales
    FROM purchases p WHERE p.branch = ?${pr.clause}
    GROUP BY p.rep
  `).all(branch, ...pr.params);
  const totals = db.prepare(`
    SELECT COUNT(*) AS count, COALESCE(SUM(p.price), 0) AS total FROM purchases p WHERE p.branch = ?${pr.clause}
  `).get(branch, ...pr.params);

  const blankRow = (name) => ({
    sales_rep: name, served: 0, bought: 0, not_bought: 0,
    close_rate: 0, total_sales: 0, contracts: 0, assigned: 0, followup_rate: 0,
    followed_up: 0, fu_visited: 0, fu_not_visited: 0,
  });
  const byName = new Map();
  const rowOf = (name) => { if (!byName.has(name)) byName.set(name, blankRow(name)); return byName.get(name); };
  for (const r of period.bySales) {
    const row = rowOf(r.sales_rep);
    row.served = r.served; row.bought = r.bought;
  }
  let noRepContracts = 0, noRepSales = 0;
  for (const c of contractsBy) {
    if (c.rep == null || String(c.rep).trim() === '') { noRepContracts += c.contracts; noRepSales += c.total_sales; continue; }
    const row = rowOf(c.rep);
    row.contracts += c.contracts; row.total_sales += c.total_sales;
  }

  const fr = honest.rangeSql('l.followed_up_at', from, to);
  const fuStats = db.prepare(`
    SELECT
      TRIM(l.sales)                                                         AS sales_rep,
      COUNT(DISTINCT l.user_id)                                             AS followed_up,
      COUNT(DISTINCT CASE WHEN lv.user_id IS NOT NULL THEN l.user_id END)   AS fu_visited
    FROM followup_log l
    LEFT JOIN (
      SELECT DISTINCT user_id FROM lead_visits WHERE branch = ?
    ) lv ON lv.user_id = l.user_id
    WHERE l.branch = ? AND l.sales IS NOT NULL AND TRIM(l.sales) <> ''
      AND COALESCE(l.kind, '') <> 'handoff'
      AND ${NOT_DUPLICATE('l.user_id')}${fr.clause}
    GROUP BY TRIM(l.sales)
  `).all(branch, branch, ...fr.params);
  for (const s of fuStats) {
    const row = rowOf(s.sales_rep);
    row.followed_up    = s.followed_up;
    row.fu_visited     = s.fu_visited;
    row.fu_not_visited = s.followed_up - s.fu_visited;
  }
  const assignedStats = db.prepare(`
    SELECT TRIM(assigned_sales) AS sales_rep, COUNT(*) AS assigned
    FROM branch_customer_followups
    WHERE branch = ? AND assigned_sales IS NOT NULL AND TRIM(assigned_sales) <> ''
      AND ${NOT_DUPLICATE('branch_customer_followups.user_id')}
    GROUP BY TRIM(assigned_sales)
  `).all(branch);
  for (const a of assignedStats) rowOf(a.sales_rep).assigned = a.assigned;

  const bySales = [...byName.values()];
  const tMonth = cairoMonth();
  for (const r of bySales) {
    r.not_bought    = r.served - r.bought;
    r.close_rate    = r.served ? Math.round((r.bought / r.served) * 100) : 0;
    r.target        = getTarget(db, 'sales_rep', r.sales_rep, tMonth);
    r.target_pct    = pctAchieved(cairoMonthContracts(db, { rep: r.sales_rep, branch, month: tMonth }), r.target);
    r.followup_rate = r.assigned ? Math.round((r.followed_up / r.assigned) * 100) : 0;
  }
  bySales.sort((a, b) => b.total_sales - a.total_sales || b.contracts - a.contracts || b.served - a.served);

  // distinct people across the rows (one customer can be in two salespeople's rows)
  const served = period.served;
  const bought = period.bought;
  const branchTarget = getTarget(db, 'branch', branch, tMonth);
  const branchMonthContracts = cairoMonthContracts(db, { branch, month: tMonth });
  const shown = hideStoppedRows(db, bySales);   // stopped salespeople: no row (2026-11-25)
  return {
    branch,
    range: { from: from || null, to: to || null },
    target_month: tMonth,
    ...shown.extra,
    kpis: {
      requested,
      visited: period.visited,
      bought,
      total_sales: totals.total,
      contracts_count: totals.count,
      no_rep_contracts: noRepContracts,
      no_rep_sales: noRepSales,
      close_rate: served ? Math.round((bought / served) * 100) : 0,
      target:          branchTarget,
      month_contracts: branchMonthContracts,
      target_pct:      pctAchieved(branchMonthContracts, branchTarget),
    },
    bySales: shown.rows,
  };
}

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

  // Page size. Generous default so big branches (e.g. Nasr City with 500+)
  // aren't silently truncated at 200; clamped so one request can't pull tens of
  // thousands. The frontend paginates client-side over what it gets.
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 1000, 1), 2000);

  // Total cohort size (ignores the page limit) so the UI can tell the manager
  // how many there really are.
  const total = db.prepare(`
    SELECT COUNT(*) AS n FROM (
      SELECT DISTINCT e.user_id FROM events e
      WHERE e.event_type = 'branch_selected'
        AND (e.event_value = ? OR e.branch = ?)
        AND EXISTS (SELECT 1 FROM lead_phones ph WHERE ph.user_id = e.user_id)
    )
  `).get(branch, branch).n;

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
      COALESCE(f.attempt_count, 0)   AS attempt_count,
      f.last_attempt_at,
      COALESCE(f.auto_assigned, 0) AS auto_assigned,
      CASE WHEN lv.user_id IS NOT NULL THEN 1 ELSE 0 END AS visited,
      lv.sales_rep AS showroom_rep,
      -- phase 1: «لسه ما اتوزعوش» leaves out whoever already came (any
      -- branch, or a confirmed visit) or bought — they are not to distribute.
      CASE WHEN EXISTS (SELECT 1 FROM lead_visits av WHERE av.user_id = req.user_id)
             OR COALESCE(lp.visit_confirmed, 0) = 1 THEN 1 ELSE 0 END AS visited_any,
      CASE WHEN EXISTS (SELECT 1 FROM purchases bp WHERE bp.user_id = req.user_id) THEN 1 ELSE 0 END AS bought,
      ${crossBranchCols('req.user_id')}
    FROM (
      SELECT DISTINCT e.user_id
      FROM events e
      WHERE e.event_type = 'branch_selected'
        AND (e.event_value = ? OR e.branch = ?)
        AND EXISTS (SELECT 1 FROM lead_phones ph WHERE ph.user_id = e.user_id)
    ) req
    LEFT JOIN lead_profiles lp ON lp.user_id = req.user_id
    LEFT JOIN branch_customer_followups f
      ON f.user_id = req.user_id AND f.branch = ?
    LEFT JOIN (
      SELECT user_id, sales_rep FROM lead_visits WHERE branch = ?
    ) lv ON lv.user_id = req.user_id
    -- Newest-activity first (by time), not by score. SQLite sorts NULLs last in
    -- DESC, so leads without a profile row fall to the bottom. Score is only a
    -- tie-breaker now.
    ORDER BY lp.last_activity DESC, COALESCE(lp.total_score, 0) DESC
    LIMIT ?
  `).all(branch, branch, branch, branch, limit);

  // O4: «جاي النهارده / بكره» from the latest visit_planned (this branch's or no branch).
  addPlannedBadges(db, customers, () => branch);

  return res.json({ branch, customers, total, limit });
});

// O4 — puts planned_when ('today' | 'tomorrow' | null) and planned_day on each
// row (in place) from the customer's LATEST visit_planned: only when he hasn't
// come since and the plan's branch is the row's branch (branchOf(row)) or unknown.
function addPlannedBadges(db, rows, branchOf) {
  if (!rows || !rows.length) return rows;
  const plans = visitIntent.latestPlans(db, rows.map(r => r.user_id));
  for (const r of rows) {
    const p = plans.get(r.user_id);
    const when = visitIntent.plannedBadge(p, branchOf(r));
    r.planned_when = when;
    r.planned_day  = when ? p.planned_day : null;
  }
  return rows;
}

// Records a completed follow-up in the append-only log (history survives
// reassignment). Only called when a follow-up is actually marked done.
// `kind`: NULL = a follow-up someone did; 'handoff' = the showroom handoff's
// note (the customer visited, the follow-up moved to the showroom rep) — not a
// call, so the manager's range «تابع» never counts it (db.js backfills it).
function logFollowup(db, branch, userId, sales, summary, kind = null) {
  db.prepare(`
    INSERT INTO followup_log (branch, user_id, sales, call_summary, followed_up_at, kind)
    VALUES (?, ?, ?, ?, datetime('now'), ?)
  `).run(branch, userId, sales || null, (summary && String(summary).trim()) || null, kind);
}

// Full cross-branch journey of a customer: every visit (which branch, which rep)
// and every purchase, plus the derived current "owner" (the rep/branch that gets
// the customer per our rule — purchase wins, else most-recent visit). This is the
// transparency layer so reception, sales and management all SEE what happened when
// a customer compares branches — and nobody fights over who owns whom.
function customerJourney(db, userId) {
  const visits = db.prepare(`
    SELECT branch, sales_rep, pre_visit_rep, visited_at
    FROM lead_visits WHERE user_id = ? ORDER BY visited_at ASC, id ASC
  `).all(userId);
  const purchases = db.prepare(`
    SELECT branch, rep, price, contract_number, created_at
    FROM purchases WHERE user_id = ? ORDER BY created_at ASC, id ASC
  `).all(userId);
  const branches = [...new Set([
    ...visits.map(v => v.branch),
    ...purchases.map(p => p.branch),
  ].filter(Boolean))];
  const lastPurchase = purchases.length ? purchases[purchases.length - 1] : null;
  const lastVisit    = visits.length    ? visits[visits.length - 1]       : null;
  const owner = lastPurchase
    ? { branch: lastPurchase.branch, rep: lastPurchase.rep, via: 'purchase' }
    : lastVisit
      ? { branch: lastVisit.branch, rep: lastVisit.sales_rep, via: 'visit' }
      : null;
  return { visits, purchases, branches, multi_branch: branches.length > 1, owner };
}

// Compact cross-branch SELECT columns for customer LISTS, so a rep sees a
// "قارن فروع" tag right on the card without opening the profile. `uid` is the
// row's user_id column reference (e.g. 'f.user_id'). Returns:
//   branches_count — distinct branches the customer visited/bought in.
//   bought_branch  — the branch of their latest purchase (null if none).
const crossBranchCols = (uid) => `
  (SELECT COUNT(*) FROM (
     SELECT branch FROM lead_visits WHERE user_id = ${uid} AND branch IS NOT NULL
     UNION SELECT branch FROM purchases  WHERE user_id = ${uid} AND branch IS NOT NULL
  ))                                                                  AS branches_count,
  (SELECT branch FROM purchases WHERE user_id = ${uid}
     ORDER BY created_at DESC, id DESC LIMIT 1)                       AS bought_branch`;

// The "owner" branch/rep of a visited customer (purchase wins, else most-recent
// visit). Used for BOTH who-sees-them (RBAC) and how-they're-shown/grouped, so a
// customer who bought in Maadi shows under Maadi/their seller — not under the
// Nasr City rep they merely passed by. Assumes the row aliases lead_profiles `lp`.
const OWNER_BRANCH_SQL = `COALESCE(
  (SELECT pu.branch FROM purchases pu  WHERE pu.user_id = lp.user_id ORDER BY pu.created_at DESC, pu.id DESC LIMIT 1),
  (SELECT v.branch  FROM lead_visits v WHERE v.user_id  = lp.user_id ORDER BY v.visited_at DESC LIMIT 1))`;
const OWNER_REP_SQL = `COALESCE(
  (SELECT pu.rep      FROM purchases pu  WHERE pu.user_id = lp.user_id ORDER BY pu.created_at DESC, pu.id DESC LIMIT 1),
  (SELECT v.sales_rep FROM lead_visits v WHERE v.user_id  = lp.user_id ORDER BY v.visited_at DESC LIMIT 1))`;

// Duplicate exclusion — the SINGLE choke point that keeps a manager-flagged
// duplicate out of every sales-rep queue and KPI. Drop this predicate into the
// WHERE of any rep-facing query; `uid` is that query's user_id column reference
// (e.g. 'v.user_id', 'f.user_id', 'lead_visits.user_id'). Correlated NOT EXISTS
// so it works whether or not lead_profiles is already joined. When lead_profiles
// IS already aliased `lp`, prefer the cheaper inline `COALESCE(lp.is_duplicate,0)=0`.
const NOT_DUPLICATE = (uid) => `NOT EXISTS (
  SELECT 1 FROM lead_profiles ddup
  WHERE ddup.user_id = ${uid} AND ddup.is_duplicate = 1)`;

// Records an admin/manager action in the undo ledger. `oldState` describes how
// to restore the affected row: { table, where: {...}, row: {...}|null }. Only
// types listed in REVERTABLE_AUDIT_TABLES can actually be undone; any other
// type shows in the ledger as display-only.
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
// Current month as 'YYYY-MM' — the CAIRO month (2026-11-25: every month
// counter is a Cairo month, CLAUDE.md «Day boundaries are Cairo days»; it was
// the UTC month, so from 00:00 to 02:00/03:00 Cairo on the 1st the target
// card, the salesperson's own target and the targets screen still showed the
// month before). Targets stay stored per 'YYYY-MM' key.
function currentMonth() {
  return cairoMonth();
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

// Revenue (SUM of purchase price) generated WITHIN a Cairo month, optionally
// scoped to a branch or a sales rep. `month` defaults to the current month.
function monthRevenue(db, { branch, rep, month } = {}) {
  const r = cairoMonthSql('created_at', month || currentMonth());
  let where = '1=1'; const params = [];
  if (branch) { where += ` AND branch = ?`; params.push(branch); }
  if (rep)    { where += ` AND rep = ?`;    params.push(rep); }
  return db.prepare(
    `SELECT COALESCE(SUM(price), 0) AS r FROM purchases WHERE ${where}${r.clause}`
  ).get(...params, ...r.params).r || 0;
}

// Count of CONTRACTS (purchases) recorded WITHIN a Cairo month, optionally
// scoped to a branch or rep. This replaces revenue as the headline metric — the
// business tracks number of contracts, not money. `month` defaults to current.
// The same count as cairoMonthContracts (the branch overview's target).
function monthContracts(db, { branch, rep, month } = {}) {
  return cairoMonthContracts(db, { branch, rep, month: month || currentMonth() });
}

function pctAchieved(actual, target) {
  return target > 0 ? Math.round(((actual || 0) / target) * 100) : 0;
}

// ── Cairo months (2026-11-25 review) ────────────────────────────────────────
// The branch overview's target month and the contracts page's month picker
// are CAIRO months (the 1st 00:00 Cairo → the last day 24:00 Cairo, through
// honest.rangeSql), so «الشهر ده» / «نوفمبر» count the same contracts as «من
// يوم لـ يوم» over the same days. A contract at 00:40 Cairo on the 1st (22:40
// UTC the day before) is the new month's. Since 2026-11-25 every other month
// counter is too (currentMonth, monthRevenue / monthContracts above: the admin
// home's target, /api/sales/my-target, /api/sales/my, the targets screen, MCP).
function cairoMonth(d = new Date()) { return cairoDay(d).slice(0, 7); }
function lastDayOfMonth(month) {
  const [y, mo] = month.split('-').map(Number);
  return new Date(Date.UTC(y, mo, 0)).toISOString().slice(0, 10);
}
// ` AND …` — `col` inside the Cairo month 'YYYY-MM'.
function cairoMonthSql(col, month) { return honest.rangeSql(col, `${month}-01`, lastDayOfMonth(month)); }
// Contracts in a Cairo month (default: this one), optionally by branch / rep.
function cairoMonthContracts(db, { branch, rep, month } = {}) {
  const r = cairoMonthSql('created_at', month || cairoMonth());
  let where = '1=1'; const params = [];
  if (branch) { where += ' AND branch = ?'; params.push(branch); }
  if (rep)    { where += ' AND rep = ?';    params.push(rep); }
  return db.prepare(`SELECT COUNT(*) AS c FROM purchases WHERE ${where}${r.clause}`).get(...params, ...r.params).c || 0;
}

// (dateRangeClause — a UTC `date(col)` range — was removed 2026-11-22: every
// date filter is a Cairo-day range now, honest.rangeSql / cairoRangeClause.)

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

  // Phase 0 r3: an assignment ties the lead to the branch and the rep (they
  // may open it from then on) — so the lead must exist and, for a branch
  // manager, already have its OWN tie to his branch (leadOwnBranchTie: never
  // a follow-up / assignment row). Out of scope = 404, like an unknown id.
  if (!branchCustomerKnown(db, userId) || (role === 'branch_manager' && !leadOwnBranchTie(db, userId, branch))) {
    return res.status(404).json({ error: 'lead_not_found' });
  }

  // Guard: the chosen rep must actually be an active sales rep IN this branch.
  // Stops a STALE dropdown (e.g. right after a rep swap, when an open page still
  // lists a rep who has since moved to another branch) from writing a wrong
  // assignment — the customer would otherwise land in the wrong rep's list.
  const repInBranch = db.prepare(
    `SELECT 1 FROM users WHERE TRIM(name) = TRIM(?) AND role IN ('sales','rep') AND branch = ? AND active = 1`
  ).get(sales, branch);
  if (!repInBranch) {
    return res.status(400).json({
      error: 'السيلز ده مش في الفرع ده — حدّث الصفحة واختار من القائمة الجديدة',
    });
  }

  // Full old row — kept for the audit/undo ledger.
  const cur = db.prepare(
    `SELECT * FROM branch_customer_followups WHERE branch = ? AND user_id = ?`
  ).get(branch, userId);

  // Changing the owner → start a brand-new follow-up cycle.
  const resetCycle = cur && cur.assigned_sales && cur.assigned_sales !== sales;

  db.prepare(`
    INSERT INTO branch_customer_followups
      (branch, user_id, assigned_sales, assigned_at, assigned_by, followed_up, followed_up_at, followed_up_by, call_summary, auto_assigned)
    VALUES (?, ?, ?, datetime('now'), ?, 0, NULL, NULL, NULL, 0)
    ON CONFLICT(branch, user_id) DO UPDATE SET
      assigned_sales = excluded.assigned_sales,
      assigned_at    = excluded.assigned_at,
      assigned_by    = excluded.assigned_by,
      auto_assigned  = 0
      ${resetCycle ? `,
      followed_up    = 0,
      followed_up_at = NULL,
      followed_up_by = NULL,
      call_summary   = NULL,
      snoozed_until  = NULL` : ''}
  `).run(branch, userId, sales, req.user?.name || null);

  auditLog(db, req.user?.name, 'assign_customer', userId, {
    table: 'branch_customer_followups',
    where: { branch, user_id: userId },
    row:   cur || null,
  });

  return res.json({ ok: true, assigned_sales: sales, reset: !!resetCycle });
});

// ════════════════════════════════════════════════════════════════════════════
// PATCH /api/branch/customers/bulk-reassign — move a SET of specific pre-visit
// customers to a new sales rep in one call. Two entry points, same mechanism:
//   1) redistribute load off a rep who's still active but overloaded
//   2) unstick a rep who's been deactivated — their customers stay fully
//      assigned/visible (see /api/admin/users/sales-rep archive mode +
//      toggle-active — neither clears assigned_sales) until a human moves them
// The SOURCE rep's active status is deliberately NOT checked — that's the
// whole point of case (2). The DESTINATION rep must be active, in-branch,
// sales/rep role — identical guard to the single-row /assign endpoint.
// Body: { user_ids: string[], sales, branch? (admin only) }
// ════════════════════════════════════════════════════════════════════════════
app.patch('/api/branch/customers/bulk-reassign', requireAuth, authorizeRoles('branch_manager', 'admin'), (req, res) => {
  const role = req.user?.role;
  const branch = role === 'branch_manager'
    ? (req.user.branch || null)
    : (req.body?.branch || null);
  if (!branch) return res.status(400).json({ error: 'branch_required' });

  const userIds = Array.isArray(req.body?.user_ids)
    ? [...new Set(req.body.user_ids.map(String))]
    : [];
  if (!userIds.length) return res.status(400).json({ error: 'user_ids_required' });
  if (userIds.length > 1000) return res.status(400).json({ error: 'too_many_ids' });

  const sales = (req.body?.sales && String(req.body.sales).trim()) || null;
  if (!sales) return res.status(400).json({ error: 'sales_required' });

  const db = getDb();

  // Destination guard — byte-identical to the single-row /assign endpoint's
  // repInBranch check. Requires active=1: you can move customers OUT of an
  // inactive rep, never INTO one.
  const repInBranch = db.prepare(
    `SELECT 1 FROM users WHERE TRIM(name) = TRIM(?) AND role IN ('sales','rep') AND branch = ? AND active = 1`
  ).get(sales, branch);
  if (!repInBranch) {
    return res.status(400).json({
      error: 'السيلز ده مش في الفرع ده — حدّث الصفحة واختار من القائمة الجديدة',
    });
  }

  // Current state of exactly the requested ids, scoped to THIS branch (a
  // branch_manager can never touch another branch's rows). No filter on
  // assigned_sales, no join to users.active — this is what ALLOWS the source
  // rep to be inactive.
  const placeholders = userIds.map(() => '?').join(',');
  const curRows = db.prepare(`
    SELECT * FROM branch_customer_followups
    WHERE branch = ? AND user_id IN (${placeholders})
  `).all(branch, ...userIds);
  const curByUser = new Map(curRows.map(r => [r.user_id, r]));

  // IDs with no existing branch_customer_followups row in this branch would
  // otherwise silently get a brand-new row inserted by the upsert below —
  // that's how a crafted user_id list (bypassing both UIs, which only ever
  // send ids already scoped to the branch's own customer list) could plant a
  // customer who never actually engaged with this branch into a rep's queue.
  // Require the lead's OWN tie to this branch (leadOwnBranchTie — a
  // branch_selected event, a visit / sale there, or its preferred branch; the
  // same test the single-row /assign and /followup use since phase 0 r3).
  const newIds = userIds.filter(uid => !curByUser.has(uid));
  const validNewIds = new Set(newIds.filter(uid => leadOwnBranchTie(db, uid, branch)));

  // Moving to the rep they're already with is a no-op.
  const toMove = userIds.filter(uid => {
    const cur = curByUser.get(uid);
    if (cur) return !cur.assigned_sales || cur.assigned_sales.trim() !== sales;
    return validNewIds.has(uid);
  });
  const rejected = userIds.filter(uid => !curByUser.has(uid) && !validNewIds.has(uid));

  if (!toMove.length) {
    return res.json({
      ok: true, branch, sales,
      requested: userIds.length, moved: 0,
      already_assigned: userIds.length - rejected.length,
      rejected: rejected.length, rejected_user_ids: rejected,
      moved_user_ids: [],
    });
  }

  // Same upsert + same reset-on-owner-change field set as the single-row
  // /assign endpoint's resetCycle branch — new owner starts a fresh
  // follow-up cycle; prior call summaries stay in followup_log.
  const upsertReset = db.prepare(`
    INSERT INTO branch_customer_followups
      (branch, user_id, assigned_sales, assigned_at, assigned_by, followed_up, followed_up_at, followed_up_by, call_summary, auto_assigned)
    VALUES (?, ?, ?, datetime('now'), ?, 0, NULL, NULL, NULL, 0)
    ON CONFLICT(branch, user_id) DO UPDATE SET
      assigned_sales = excluded.assigned_sales,
      assigned_at    = excluded.assigned_at,
      assigned_by    = excluded.assigned_by,
      auto_assigned  = 0,
      followed_up    = 0,
      followed_up_at = NULL,
      followed_up_by = NULL,
      call_summary   = NULL,
      snoozed_until  = NULL
  `);

  const by = req.user?.name || null;
  const movedRows = [];
  db.transaction(() => {
    for (const uid of toMove) {
      upsertReset.run(branch, uid, sales, by);
      movedRows.push({ user_id: uid, from: curByUser.get(uid)?.assigned_sales || null });
    }
  })();

  const fromCounts = movedRows.reduce((acc, r) => {
    const k = r.from || '(غير مسند)';
    acc[k] = (acc[k] || 0) + 1;
    return acc;
  }, {});

  auditLog(db, req.user?.name, 'bulk_reassign_customers', `${branch}:${sales}`, {
    type: 'bulk_reassign_customers',
    branch, to: sales,
    rows: movedRows.map(r => ({
      table: 'branch_customer_followups',
      where: { branch, user_id: r.user_id },
      row: curByUser.get(r.user_id) || null,
    })),
  });

  const fromSummary = Object.entries(fromCounts).map(([k, v]) => `${v} من ${k}`).join('، ');
  createNotification(db, 'admin', 'bulk_reassign_customers',
    `${by || 'مدير الفرع'} نقل ${movedRows.length} عميل (${fromSummary}) إلى ${sales} في فرع ${branch}`);

  return res.json({
    ok: true, branch, sales,
    requested: userIds.length,
    moved: movedRows.length,
    already_assigned: userIds.length - movedRows.length - rejected.length,
    rejected: rejected.length, rejected_user_ids: rejected,
    from_counts: fromCounts,
    moved_user_ids: movedRows.map(r => r.user_id),
  });
});

// ════════════════════════════════════════════════════════════════════════════
// POST /api/branch/customers/bulk-assign — "وزّع تلقائياً": distributes every
// UNASSIGNED pre-visit customer in the branch across its active sales reps in
// one shot, balancing against each rep's CURRENT pending load (the rep with
// the lightest load receives first). Customers are dealt hottest-first so no
// single rep hoards all the hot leads.
//
// Body: { dry_run?: true, branch? (admin) }
//   dry_run → returns the exact plan (counts per rep) WITHOUT writing.
// Never steals: only rows with no assigned_sales are touched.
// ════════════════════════════════════════════════════════════════════════════
app.post('/api/branch/customers/bulk-assign', requireAuth, authorizeRoles('branch_manager', 'admin'), (req, res) => {
  const branch = branchScopeOf(req);
  if (!branch) return res.status(400).json({ error: 'branch_required' });
  const dryRun = !!req.body?.dry_run;
  const db = getDb();

  // Active sales reps of this branch + their current pending (pre-visit) load.
  const reps = db.prepare(`
    SELECT u.name,
      (SELECT COUNT(*) FROM branch_customer_followups f
        JOIN lead_profiles lp ON lp.user_id = f.user_id
        WHERE TRIM(f.assigned_sales) = TRIM(u.name) AND f.branch = ?
          AND COALESCE(f.followed_up, 0) = 0
          AND COALESCE(lp.visit_confirmed, 0) = 0) AS load
    FROM users u
    WHERE u.role = 'sales' AND u.active = 1 AND u.branch = ?
    ORDER BY load ASC, u.name ASC
  `).all(branch, branch);
  if (!reps.length) return res.status(400).json({ error: 'مفيش سيلز نشطين في الفرع ده' });

  // Unassigned universe — same driver as /api/branch/customers (requested the
  // branch + left a phone), still pre-visit, not duplicate, and NO owner yet
  // (no bcf row for this branch, or a row whose assigned_sales is empty).
  const customers = db.prepare(`
    SELECT req.user_id, COALESCE(lp.total_score, 0) AS total_score
    FROM (
      SELECT DISTINCT e.user_id
      FROM events e
      WHERE e.event_type = 'branch_selected'
        AND (e.event_value = ? OR e.branch = ?)
        AND EXISTS (SELECT 1 FROM lead_phones ph WHERE ph.user_id = e.user_id)
    ) req
    JOIN lead_profiles lp ON lp.user_id = req.user_id
    LEFT JOIN branch_customer_followups f
      ON f.user_id = req.user_id AND f.branch = ?
    WHERE COALESCE(lp.is_duplicate, 0) = 0
      AND COALESCE(lp.visit_confirmed, 0) = 0
      AND NOT EXISTS (SELECT 1 FROM lead_visits av WHERE av.user_id = req.user_id)   -- phase 1: came already
      AND NOT EXISTS (SELECT 1 FROM purchases bp WHERE bp.user_id = req.user_id)     -- phase 1: bought already
      AND (f.id IS NULL OR f.assigned_sales IS NULL OR TRIM(f.assigned_sales) = '')
    ORDER BY total_score DESC
  `).all(branch, branch, branch);

  // Greedy deal, hottest-first, always to the rep with the smallest running
  // total — evens out pre-existing imbalance instead of freezing it.
  const running = reps.map(r => ({ name: r.name, load: r.load, receive: 0 }));
  const plan = new Map(running.map(r => [r.name, r]));
  const assignments = [];
  for (const c of customers) {
    running.sort((a, b) => (a.load + a.receive) - (b.load + b.receive));
    const target = running[0];
    target.receive++;
    assignments.push({ user_id: c.user_id, rep: target.name });
  }

  const planOut = [...plan.values()].map(r => ({
    rep: r.name, current_load: r.load, will_receive: r.receive,
  }));

  if (dryRun) {
    return res.json({ ok: true, dry_run: true, branch,
      unassigned: customers.length, plan: planOut });
  }

  const upsert = db.prepare(`
    INSERT INTO branch_customer_followups
      (branch, user_id, assigned_sales, assigned_at, assigned_by, followed_up, auto_assigned)
    VALUES (?, ?, ?, datetime('now'), ?, 0, 1)
    ON CONFLICT(branch, user_id) DO UPDATE SET
      assigned_sales = excluded.assigned_sales,
      assigned_at    = excluded.assigned_at,
      assigned_by    = excluded.assigned_by,
      auto_assigned  = 1
    WHERE assigned_sales IS NULL OR TRIM(assigned_sales) = ''
  `);
  const by = req.user?.name || 'bulk';
  let written = 0;
  db.transaction(() => {
    for (const a of assignments) {
      const r = upsert.run(branch, a.user_id, a.rep, by);
      written += r.changes;
    }
  })();

  auditLog(db, req.user?.name, 'bulk_assign', branch, {
    type: 'bulk_assign', branch, assigned: written, plan: planOut,
  });
  createNotification(db, 'admin', 'bulk_assign',
    `توزيع تلقائي في فرع ${branch}: ${written} عميل اتوزعوا على ${reps.length} سيلز بواسطة ${by}`);

  console.log(`📦 BULK ASSIGN: ${written} customers → ${reps.length} reps @ ${branch} by ${by}`);
  return res.json({ ok: true, branch, assigned: written, plan: planOut });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/branch/sla-alerts — "الإدارة بالاستثناء": computed on demand (no
// cron, no schema) so the manager sees ONLY what needs intervention:
//   hot_untouched — hot/high-score customers assigned >48h with ZERO effort
//                   (no follow-up, no attempt, no WhatsApp sent); FIRST, any
//                   customer whose latest visit_planned says today/tomorrow
//                   here, with the same zero effort for sla_hours_planned
//                   (setting, default 4) since the later of the assignment and
//                   his plan (O4). Each row: sla_hours, planned_when.
//   idle_reps     — reps holding pending customers with no recorded activity
//                   in the last 24h
//   visits_today  — reception-confirmed arrivals today (0 on a workday usually
//                   means reception forgot to confirm, not that nobody came)
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/branch/sla-alerts', requireAuth, authorizeRoles('branch_manager', 'admin'), (req, res) => {
  const branch = branchScopeOf(req);
  if (!branch) return res.status(400).json({ error: 'branch_required' });
  const db = getDb();

  const hotUntouched = db.prepare(`
    SELECT f.user_id, lp.first_name, TRIM(f.assigned_sales) AS rep,
      COALESCE(lp.total_score, 0) AS total_score,
      COALESCE(lp.lead_class, 'cold') AS lead_class,
      f.assigned_at,
      CAST((julianday('now') - julianday(f.assigned_at)) * 24 AS INTEGER) AS hours_waiting
    FROM branch_customer_followups f
    JOIN lead_profiles lp ON lp.user_id = f.user_id
    WHERE f.branch = ?
      AND f.assigned_sales IS NOT NULL AND TRIM(f.assigned_sales) != ''
      AND COALESCE(f.followed_up, 0) = 0
      AND COALESCE(f.attempt_count, 0) = 0
      AND COALESCE(f.sent, 0) = 0
      AND COALESCE(lp.visit_confirmed, 0) = 0
      AND COALESCE(lp.is_duplicate, 0) = 0
      AND (lp.lead_class = 'hot' OR COALESCE(lp.total_score, 0) >= 40)
      AND f.assigned_at <= datetime('now', '-48 hours')
    ORDER BY lp.total_score DESC
    LIMIT 25
  `).all(branch);
  for (const r of hotUntouched) { r.sla_hours = 48; r.planned_when = null; }

  // O4 — a shorter SLA (setting sla_hours_planned, default 4) for a customer
  // whose latest visit_planned says today / tomorrow at this branch: the same
  // «zero effort» rule, any score, and the clock starts at the later of the
  // assignment and the moment he said it. Listed first; a lead is listed once.
  const slaPlanned = visitIntent.slaHoursPlanned(getSetting('sla_hours_planned'));
  const today = visitIntent.cairoDayOf(), tomorrow = visitIntent.nextDay(today);
  const plannedCand = db.prepare(`
    SELECT f.user_id, lp.first_name, TRIM(f.assigned_sales) AS rep,
      COALESCE(lp.total_score, 0) AS total_score,
      COALESCE(lp.lead_class, 'cold') AS lead_class,
      f.assigned_at
    FROM branch_customer_followups f
    JOIN lead_profiles lp ON lp.user_id = f.user_id
    WHERE f.branch = ?
      AND f.assigned_sales IS NOT NULL AND TRIM(f.assigned_sales) != ''
      AND COALESCE(f.followed_up, 0) = 0
      AND COALESCE(f.attempt_count, 0) = 0
      AND COALESCE(f.sent, 0) = 0
      AND COALESCE(lp.visit_confirmed, 0) = 0
      AND COALESCE(lp.is_duplicate, 0) = 0
      AND EXISTS (SELECT 1 FROM events e WHERE e.user_id = f.user_id
                    AND e.event_type = 'visit_planned' AND e.planned_day IN (?, ?))
  `).all(branch, today, tomorrow);
  const plans = visitIntent.latestPlans(db, plannedCand.map(r => r.user_id));
  const nowMs = Date.now();
  const plannedLate = [];
  for (const r of plannedCand) {
    const p = plans.get(r.user_id);
    const when = visitIntent.plannedBadge(p, branch);
    if (!when) continue;
    const from = Math.max(sqlUtcToDate(r.assigned_at)?.getTime() || 0, sqlUtcToDate(p.said_at)?.getTime() || 0);
    if (!from) continue;
    const hours = (nowMs - from) / 3600000;
    if (hours < slaPlanned) continue;
    plannedLate.push({ ...r, hours_waiting: Math.floor(hours), sla_hours: slaPlanned, planned_when: when });
  }
  plannedLate.sort((a, b) => (a.planned_when === b.planned_when ? b.hours_waiting - a.hours_waiting
                                                                 : a.planned_when === 'today' ? -1 : 1));
  const plannedIds = new Set(plannedLate.map(r => r.user_id));
  const hotList = [...plannedLate, ...hotUntouched.filter(r => !plannedIds.has(r.user_id))];

  // Idle reps — pending work but no recorded action in 24h. Timestamps are a
  // mix of ISO-T and SQLite formats, so compare in JS (robust to both).
  const repRows = db.prepare(`
    SELECT u.name,
      (SELECT COUNT(*) FROM branch_customer_followups f
        JOIN lead_profiles lp ON lp.user_id = f.user_id
        WHERE TRIM(f.assigned_sales) = TRIM(u.name) AND f.branch = ?
          AND COALESCE(f.followed_up, 0) = 0
          AND COALESCE(lp.visit_confirmed, 0) = 0)          AS pending,
      (SELECT MAX(followed_up_at)  FROM branch_customer_followups WHERE TRIM(assigned_sales) = TRIM(u.name)) AS t1,
      (SELECT MAX(last_attempt_at) FROM branch_customer_followups WHERE TRIM(assigned_sales) = TRIM(u.name)) AS t2,
      (SELECT MAX(sent_at)         FROM branch_customer_followups WHERE TRIM(assigned_sales) = TRIM(u.name)) AS t3,
      (SELECT MAX(created_at)      FROM revisit_followups        WHERE TRIM(followed_up_by) = TRIM(u.name)) AS t4
    FROM users u
    WHERE u.role = 'sales' AND u.active = 1 AND u.branch = ?
  `).all(branch, branch);

  const parseTs = (s) => {
    if (!s) return 0;
    const iso = String(s).includes('T') ? s : s.replace(' ', 'T') + 'Z';
    const t = new Date(iso).getTime();
    return Number.isFinite(t) ? t : 0;
  };
  const dayAgo = Date.now() - 24 * 3600000;
  const idleReps = repRows
    .filter(r => r.pending > 0)
    .map(r => ({ rep: r.name, pending: r.pending,
      last_action: [r.t1, r.t2, r.t3, r.t4].map(parseTs).reduce((a, b) => Math.max(a, b), 0) }))
    .filter(r => r.last_action < dayAgo)
    .map(r => ({ ...r, last_action: r.last_action ? new Date(r.last_action).toISOString() : null }));

  const visitsToday = db.prepare(`
    SELECT COUNT(DISTINCT user_id) AS n FROM lead_visits
    WHERE branch = ? AND date(visited_at) = date('now')
  `).get(branch).n;

  return res.json({ branch, hot_untouched: hotList, idle_reps: idleReps, visits_today: visitsToday,
                    sla_hours_planned: slaPlanned });
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
  // Phase 0 r3: a branch manager's follow-up is stamped with HIS name (the
  // portal sends it anyway) — a typed name would give that person the lead
  // (followup_log in leadIsMine). The admin may still name who called.
  const byName = newVal
    ? (role === 'branch_manager' ? req.user?.name || null
       : (followed_up_by && String(followed_up_by).trim()) || req.user?.name || null)
    : null;
  const summary = newVal ? (call_summary && String(call_summary).trim()) || null : null;

  const db = getDb();
  // 2026-11-25 review: the admin may name who called, but only an ACTIVE
  // account (a stopped or free-typed name would be credited a follow-up in
  // followup_log — the range «تابع» and leadIsMine — the same rule as every
  // picker, rep_not_active). His own name (what the portal sends) is fine.
  if (newVal && role !== 'branch_manager' && byName
      && byName !== String(req.user?.name || '').trim()
      && !db.prepare(`SELECT 1 FROM users WHERE TRIM(name) = TRIM(?) AND active = 1
                      AND role IN ('sales','rep','branch_manager','admin')`).get(byName)) {
    return res.status(400).json({ error: 'السيلز ده متوقف أو مش موجود — اختار من القايمة', code: 'rep_not_active' });
  }
  // Phase 0 r3: same scope as …/assign — the lead exists and, for a branch
  // manager, has its own tie to his branch; checked before the row is written.
  if (!branchCustomerKnown(db, userId) || (role === 'branch_manager' && !leadOwnBranchTie(db, userId, branch))) {
    return res.status(404).json({ error: 'lead_not_found' });
  }
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
// PATCH /api/branch/customers/:userId/contact — branch manager / admin fixes a
// reception customer's NAME and/or PHONE (e.g. a typo taken at the desk). A
// manager can only edit customers that belong to their own branch.
// Body: { first_name?, phone? }
// ════════════════════════════════════════════════════════════════════════════
app.patch('/api/branch/customers/:userId/contact', requireAuth, authorizeRoles('branch_manager', 'admin'), (req, res) => {
  const role = req.user?.role;
  const { userId } = req.params;
  const db = getDb();

  const lead = db.prepare(`SELECT user_id FROM lead_profiles WHERE user_id = ?`).get(userId);
  if (!lead) return res.status(404).json({ error: 'العميل مش موجود' });

  // A manager may only touch customers in their own branch (same universe as the
  // branch-customers list: a branch_selected event, an assignment, or a visit).
  if (role === 'branch_manager') {
    const b = req.user.branch || null;
    if (!b) return res.status(400).json({ error: 'branch_required' });
    const inBranch = db.prepare(`
      SELECT 1 AS ok WHERE
        EXISTS (SELECT 1 FROM events e WHERE e.user_id = ? AND e.event_type = 'branch_selected' AND (e.event_value = ? OR e.branch = ?))
        OR EXISTS (SELECT 1 FROM branch_customer_followups f WHERE f.user_id = ? AND f.branch = ?)
        OR EXISTS (SELECT 1 FROM lead_visits v WHERE v.user_id = ? AND v.branch = ?)
    `).get(userId, b, b, userId, b, userId, b);
    if (!inBranch) return res.status(403).json({ error: 'العميل ده مش في فرعك' });
  }

  const rawName = req.body?.first_name;
  const rawPhone = req.body?.phone;
  const name = rawName != null ? String(rawName).trim() : null;

  const updates = [];
  const params  = [];
  if (name) { updates.push('first_name = ?'); params.push(name); }

  let np = null;
  if (rawPhone != null && String(rawPhone).trim() !== '') {
    np = normalizePhone(rawPhone);
    // Must be a valid Egyptian mobile (11 digits starting with 01) — this is a
    // correction tool, so reject obvious garbage like "123".
    if (!np || !/^01\d{9}$/.test(np)) {
      return res.status(400).json({ error: 'رقم تليفون غير صحيح — لازم 11 رقم يبدأ بـ 01' });
    }
    updates.push('phone = ?'); params.push(np);
  }
  if (!updates.length) return res.status(400).json({ error: 'مفيش حاجة تتعدّل' });

  db.transaction(() => {
    params.push(userId);
    db.prepare(`UPDATE lead_profiles SET ${updates.join(', ')} WHERE user_id = ?`).run(...params);
    // Keep the new number in lead_phones too so confirm-by-phone still matches.
    // source 'staff': a number a manager typed is never «ساب رقم» in the chat.
    if (np) db.prepare(`INSERT OR IGNORE INTO lead_phones (user_id, phone, source) VALUES (?, ?, 'staff')`).run(userId, np);
  })();

  return res.json({ ok: true, first_name: name || null, phone: np || null });
});

// ════════════════════════════════════════════════════════════════════════════
// "عملاء الفرع" — the branch manager's full lead list for their branch:
// everyone who REQUESTED the branch online (branch_selected) OR WALKED IN
// (lead_visits). Shows both follow-up reps (pre-visit = assigned_sales,
// post-visit = latest showroom sales_rep) and the duplicate flag. Unlike the
// rep-facing queues, this list INTENTIONALLY includes flagged duplicates (with
// the flag) so the manager can review and un-flag them.
//   branch_manager → locked to own branch. admin → ?branch=<id>.
//   ?q=  optional — flexible LIKE search over name OR any phone.
// ════════════════════════════════════════════════════════════════════════════
function branchScopeOf(req) {
  return req.user?.role === 'branch_manager'
    ? (req.user.branch || null)
    : (req.query.branch || req.body?.branch || null);
}

// True iff `userId` belongs to `branch` (requested it, was assigned in it, or
// visited it). Mirrors the /contact RBAC so a manager can only touch own-branch
// leads.
function leadInBranch(db, userId, branch) {
  return !!db.prepare(`
    SELECT 1 AS ok WHERE
      EXISTS (SELECT 1 FROM events e WHERE e.user_id = ? AND e.event_type = 'branch_selected' AND (e.event_value = ? OR e.branch = ?))
      OR EXISTS (SELECT 1 FROM branch_customer_followups f WHERE f.user_id = ? AND f.branch = ?)
      OR EXISTS (SELECT 1 FROM lead_visits v WHERE v.user_id = ? AND v.branch = ?)
  `).get(userId, branch, branch, userId, branch, userId, branch);
}

// ── Name / phone search terms ───────────────────────────────────────────────
// ONE dialect for every "ابحث بالاسم أو رقم التليفون" box (عملاء الفرع +
// متابعات بعد الزيارة) so typing behaves the same on every page:
//   • the phone term goes through normalizePhone → "+2 0100-123 4567",
//     "0100 123 4567" and "01001234567" all hit the same stored number,
//     while a partial ("234567") stays as typed so LIKE still matches it.
//   • % and _ are escaped (the SQL must say ESCAPE '\') → a manager who types
//     "%" gets zero results instead of the whole branch.
//   • no digits typed (an Arabic name) → the phone term falls back to the text,
//     so the phone LIKEs simply never match instead of becoming '%%' = everyone.
//   • Arabic-Indic digits (٠١٢…) are folded to ASCII first: the Egyptian Arabic
//     keyboard types them by default. Since 2026-11-22 normalizePhone folds them
//     itself too (storage and intake); folding here as well is harmless and keeps
//     the partial-term LIKE path, which doesn't go through normalizePhone.
// Returns null when there's nothing usable to search for (empty / spaces only).
const SEARCH_MAX_LEN = 100;   // a customer name or phone is never longer
const asciiDigits = (s) => s
  .replace(/[٠-٩]/g, (d) => d.charCodeAt(0) - 0x0660)   // ٠-٩
  .replace(/[۰-۹]/g, (d) => d.charCodeAt(0) - 0x06F0);  // ۰-۹ (extended)
function searchTerms(raw) {
  const q = String(raw ?? '').trim().slice(0, SEARCH_MAX_LEN);
  if (!q) return null;
  const esc   = (s) => s.replace(/[\\%_]/g, '\\$&');
  const phone = normalizePhone(asciiDigits(q));
  return {
    q, like: `%${esc(q)}%`, phoneLike: `%${esc(phone || q)}%`,
    phoneDigits: phone ? phone.length : 0,   // how selective the typed number is
  };
}

app.get('/api/branch/leads', requireAuth, authorizeRoles('branch_manager', 'admin'), (req, res) => {
  const branch = branchScopeOf(req);
  if (!branch) return res.status(400).json({ error: 'branch_required' });

  const db = getDb();
  const search = searchTerms(req.query.q);   // { like, phoneLike } | null

  const rows = db.prepare(`
    SELECT
      u.user_id,
      lp.first_name,
      COALESCE(lp.phone, (SELECT ph.phone FROM lead_phones ph
                          WHERE ph.user_id = u.user_id ORDER BY ph.id LIMIT 1)) AS phone,
      COALESCE(lp.lead_class, 'cold')  AS lead_class,
      COALESCE(lp.total_score, 0)      AS total_score,
      COALESCE(lp.visit_confirmed, 0)  AS visit_confirmed,
      COALESCE(lp.is_duplicate, 0)     AS is_duplicate,
      lp.last_activity,
      lp.manychat_source,
      -- Pre-visit follow-up rep = who the manager handed the lead to.
      f.assigned_sales                 AS pre_visit_rep,
      COALESCE(f.auto_assigned, 0)     AS pre_auto_assigned,
      -- Post-visit follow-up rep = the showroom rep on their latest visit here.
      (SELECT v.sales_rep FROM lead_visits v
         WHERE v.user_id = u.user_id AND v.branch = ?
         ORDER BY v.visited_at DESC, v.id DESC LIMIT 1) AS post_visit_rep,
      CASE WHEN EXISTS (SELECT 1 FROM lead_visits v
                        WHERE v.user_id = u.user_id AND v.branch = ?) THEN 1 ELSE 0 END AS visited
    FROM (
      SELECT e.user_id FROM events e
        WHERE e.event_type = 'branch_selected' AND (e.event_value = ? OR e.branch = ?)
          AND EXISTS (SELECT 1 FROM lead_phones ph WHERE ph.user_id = e.user_id)
      UNION
      SELECT v.user_id FROM lead_visits v WHERE v.branch = ?
    ) u
    LEFT JOIN lead_profiles lp ON lp.user_id = u.user_id
    LEFT JOIN branch_customer_followups f ON f.user_id = u.user_id AND f.branch = ?
    ${search ? `WHERE (
      lp.first_name LIKE ? ESCAPE '\\'
      OR EXISTS (SELECT 1 FROM lead_phones ph WHERE ph.user_id = u.user_id AND ph.phone LIKE ? ESCAPE '\\')
      OR COALESCE(lp.phone,'') LIKE ? ESCAPE '\\'
    )` : ''}
    ORDER BY lp.last_activity DESC, lp.total_score DESC
    LIMIT 1000
  `).all(...[
    branch, branch, branch, branch, branch, branch,
    ...(search ? [search.like, search.phoneLike, search.phoneLike] : []),
  ]);

  addPlannedBadges(db, rows, () => branch);   // O4 badges

  return res.json({ branch, count: rows.length, customers: rows });
});

// ════════════════════════════════════════════════════════════════════════════
// PATCH /api/branch/leads/:userId/duplicate — flag (or un-flag) a lead as a
// duplicate. Flagged leads vanish from every sales-rep queue + KPI immediately
// (the exclusion is enforced in those queries), but the row is preserved so the
// action is fully reversible. Body: { is_duplicate: true|false }
// ════════════════════════════════════════════════════════════════════════════
app.patch('/api/branch/leads/:userId/duplicate', requireAuth, authorizeRoles('branch_manager', 'admin'), (req, res) => {
  const branch = branchScopeOf(req);
  if (!branch) return res.status(400).json({ error: 'branch_required' });
  const { userId } = req.params;
  const db = getDb();

  const lead = db.prepare(`SELECT user_id, is_duplicate FROM lead_profiles WHERE user_id = ?`).get(userId);
  if (!lead) return res.status(404).json({ error: 'العميل مش موجود' });
  if (req.user?.role === 'branch_manager' && !leadInBranch(db, userId, branch)) {
    return res.status(403).json({ error: 'العميل ده مش في فرعك' });
  }

  const newVal = req.body?.is_duplicate ? 1 : 0;
  db.prepare(`UPDATE lead_profiles SET is_duplicate = ? WHERE user_id = ?`).run(newVal, userId);

  auditLog(db, req.user?.name, 'mark_duplicate', userId, {
    table: 'lead_profiles',
    where: { user_id: userId },
    row:   { is_duplicate: lead.is_duplicate ?? 0 },
  });

  return res.json({ ok: true, is_duplicate: newVal });
});

// ════════════════════════════════════════════════════════════════════════════
// PATCH /api/branch/leads/:userId/assign-post — reassign the POST-visit (show-
// room) follow-up rep. This is stored as lead_visits.sales_rep on the lead's
// latest visit in this branch, which is exactly what the post-visit /revisit
// list derives the owner from. (Pre-visit reassignment reuses the existing
// /api/branch/customers/:userId/assign, which sets assigned_sales.)
// Body: { sales }
// ════════════════════════════════════════════════════════════════════════════
app.patch('/api/branch/leads/:userId/assign-post', requireAuth, authorizeRoles('branch_manager', 'admin'), (req, res) => {
  const branch = branchScopeOf(req);
  if (!branch) return res.status(400).json({ error: 'branch_required' });
  const { userId } = req.params;
  const sales = (req.body?.sales && String(req.body.sales).trim()) || null;
  if (!sales) return res.status(400).json({ error: 'sales_required' });

  const db = getDb();

  // The chosen rep must be an active sales rep in this branch (same guard as the
  // pre-visit assign — stops a stale dropdown writing a cross-branch rep).
  const repInBranch = db.prepare(
    `SELECT 1 FROM users WHERE TRIM(name) = TRIM(?) AND role IN ('sales','rep') AND branch = ? AND active = 1`
  ).get(sales, branch);
  if (!repInBranch) {
    return res.status(400).json({ error: 'السيلز ده مش في الفرع ده — حدّث الصفحة واختار من القائمة الجديدة' });
  }

  // Latest visit row for this lead in this branch — that's the post-visit owner.
  const visit = db.prepare(
    `SELECT * FROM lead_visits WHERE user_id = ? AND branch = ? ORDER BY visited_at DESC, id DESC LIMIT 1`
  ).get(userId, branch);
  if (!visit) return res.status(400).json({ error: 'العميل ده لسه مزارش الفرع — مفيش متابعة بعد الزيارة' });

  db.prepare(`UPDATE lead_visits SET sales_rep = ? WHERE id = ?`).run(sales, visit.id);

  auditLog(db, req.user?.name, 'assign_post_visit', userId, {
    table: 'lead_visits',
    where: { id: visit.id },
    row:   { sales_rep: visit.sales_rep ?? null },
  });

  return res.json({ ok: true, post_visit_rep: sales });
});

// ════════════════════════════════════════════════════════════════════════════
// Sales follow-ups — the sales rep sees customers the branch manager assigned
// to them, splits pending vs done, and writes a call summary on completion.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/sales/followups', requireAuth, authorizeRoles('sales'), (req, res) => {
  const me     = req.user.name;
  const branch = req.user.branch || null;

  // A rep's customers are identified by WHO they're assigned to (assigned_sales),
  // NOT by the rep's current branch string. Matching on the rep's branch used to
  // silently hide customers whenever the branch was stored with a slightly
  // different spelling (e.g. "المعادي" vs "المعادى") on the rep vs the assignment
  // row.
  //
  // This is the PRE-visit list: it only holds customers who have NOT visited yet
  // (visit_confirmed = 0). Once a customer visits, visit_confirmed flips to 1 and
  // they move out of here into the post-visit "متابعة بعد الزيارة" (revisit) flow
  // — which selects on exactly the same `visit_confirmed = 1`, so the two lists
  // are clean complements and no customer ever shows in both.
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
      f.sent,
      f.sent_at,
      COALESCE(f.attempt_count, 0) AS attempt_count,
      f.last_attempt_at,
      f.snoozed_until,
      lp.visit_at AS visited_at,
      (SELECT GROUP_CONCAT(ph.phone, ' ، ') FROM lead_phones ph
         WHERE ph.user_id = f.user_id)                              AS phones,
      CASE WHEN COALESCE(lp.visit_confirmed, 0) = 1 OR EXISTS (
        SELECT 1 FROM lead_visits v
         WHERE v.user_id = f.user_id AND v.branch = f.branch
      ) THEN 1 ELSE 0 END                                          AS visited,
      ${crossBranchCols('f.user_id')}
    FROM branch_customer_followups f
    -- INNER JOIN (not LEFT): an assignment row whose customer profile no longer
    -- exists (e.g. the lead was deleted) is an orphan — never surface it, or it
    -- shows up as a nameless ghost (the raw walkin_ id) in the rep's list.
    JOIN lead_profiles lp ON lp.user_id = f.user_id
    WHERE TRIM(f.assigned_sales) = TRIM(?)
      -- Duplicate leads the branch manager flagged never reach the rep's queue.
      AND COALESCE(lp.is_duplicate, 0) = 0
      AND (
        -- still pre-visit (the normal case), OR
        COALESCE(lp.visit_confirmed, 0) = 0
        -- the customer VISITED but didn't buy/close yet AND the rep actually
        -- engaged with them — they FOLLOWED them up, or they SERVED them in the
        -- showroom. Surfaces them in the "زاروا المعرض" handoff tab. Without the
        -- engagement check a rep who was merely BULK-assigned hundreds of leads by
        -- the manager would see every one of those that happened to walk in, even
        -- ones he never touched (the "42 visited but only served 2" bug).
        OR (
          lp.lead_class != 'purchased' AND lp.purchased_at IS NULL
          AND COALESCE(lp.revisit_status, '') != 'lost'
          AND (
            f.followed_up = 1
            OR EXISTS (SELECT 1 FROM lead_visits v
                       WHERE v.user_id = f.user_id AND TRIM(v.sales_rep) = TRIM(?))
          )
        )
      )
    ORDER BY f.followed_up ASC, f.assigned_at DESC
  `).all(me, me);

  return res.json({ branch, customers });
});

app.patch('/api/sales/followups/:userId', requireAuth, authorizeRoles('sales'), (req, res) => {
  const me     = req.user.name;

  const { userId } = req.params;
  const { followed_up, call_summary } = req.body || {};
  const newVal = followed_up ? 1 : 0;

  // Match by assignee (resilient to branch-spelling drift); take the branch from
  // the matched row itself for the follow-up log.
  const db  = getDb();
  const own = db.prepare(`
    SELECT branch FROM branch_customer_followups
    WHERE user_id = ? AND TRIM(assigned_sales) = TRIM(?)
  `).get(userId, me);
  if (!own) return res.status(404).json({ error: 'العميل ده مش مسنود ليك' });
  const branch = own.branch;

  const summary = newVal ? (call_summary && String(call_summary).trim()) || null : null;
  db.prepare(`
    UPDATE branch_customer_followups SET
      followed_up    = ?,
      followed_up_at = ?,
      followed_up_by = ?,
      call_summary   = ?
    WHERE user_id = ? AND TRIM(assigned_sales) = TRIM(?)
  `).run(newVal, newVal ? new Date().toISOString() : null, newVal ? me : null, summary, userId, me);

  if (newVal) logFollowup(db, branch, userId, me, summary);

  return res.json({ ok: true, followed_up: newVal });
});

// ════════════════════════════════════════════════════════════════════════════
// PATCH /api/sales/followups/:userId/sent — the rep ticks/unticks "بعت" (sent the
// first outreach message). A lightweight marker, separate from followed_up, so
// the rep can track who they've already messaged. Matched by assignee (TRIM) so
// branch-spelling drift doesn't hide it.
// ════════════════════════════════════════════════════════════════════════════
app.patch('/api/sales/followups/:userId/sent', requireAuth, authorizeRoles('sales'), (req, res) => {
  const me        = req.user.name;
  const { userId } = req.params;
  const sent      = req.body?.sent ? 1 : 0;

  const db  = getDb();
  const own = db.prepare(`
    SELECT 1 FROM branch_customer_followups
    WHERE user_id = ? AND TRIM(assigned_sales) = TRIM(?)
  `).get(userId, me);
  if (!own) return res.status(404).json({ error: 'العميل ده مش مسنود ليك' });

  db.prepare(`
    UPDATE branch_customer_followups
       SET sent = ?, sent_at = ?
     WHERE user_id = ? AND TRIM(assigned_sales) = TRIM(?)
  `).run(sent, sent ? new Date().toISOString() : null, userId, me);

  return res.json({ ok: true, sent });
});

// ════════════════════════════════════════════════════════════════════════════
// POST /api/sales/followups/:userId/attempt — the rep records "اتصلت — العميل
// لم يرد": a real contact ATTEMPT that couldn't become a follow-up because the
// customer didn't answer. Increments a counter (a customer may be tried several
// times) + stamps the last attempt, so managers/admin can tell "never called"
// apart from "called but no answer" instead of blaming the rep for both.
// Matched by assignee (TRIM) like the other rep endpoints.
// ════════════════════════════════════════════════════════════════════════════
app.post('/api/sales/followups/:userId/attempt', requireAuth, authorizeRoles('sales'), (req, res) => {
  const me         = req.user.name;
  const { userId } = req.params;

  const db  = getDb();
  const own = db.prepare(`
    SELECT 1 FROM branch_customer_followups
    WHERE user_id = ? AND TRIM(assigned_sales) = TRIM(?)
  `).get(userId, me);
  if (!own) return res.status(404).json({ error: 'العميل ده مش مسنود ليك' });

  const now = new Date().toISOString();
  db.prepare(`
    UPDATE branch_customer_followups
       SET attempt_count = COALESCE(attempt_count, 0) + 1, last_attempt_at = ?
     WHERE user_id = ? AND TRIM(assigned_sales) = TRIM(?)
  `).run(now, userId, me);

  const row = db.prepare(`
    SELECT COALESCE(attempt_count, 0) AS attempt_count, last_attempt_at
    FROM branch_customer_followups
    WHERE user_id = ? AND TRIM(assigned_sales) = TRIM(?)
  `).get(userId, me);

  return res.json({ ok: true, ...row });
});

// ════════════════════════════════════════════════════════════════════════════
// PATCH /api/sales/followups/:userId/snooze — "اتصل بعدين". The rep defers the
// customer for N days: hidden from the daily queue until snoozed_until passes,
// then RESURFACES with a boost (see /api/sales/queue) so nobody is forgotten.
// Body: { days } — 1..30. days=0 clears the snooze (bring back now).
// ════════════════════════════════════════════════════════════════════════════
app.patch('/api/sales/followups/:userId/snooze', requireAuth, authorizeRoles('sales'), (req, res) => {
  const me         = req.user.name;
  const { userId } = req.params;
  const days       = parseInt(req.body?.days, 10);
  if (!Number.isFinite(days) || days < 0 || days > 30) {
    return res.status(400).json({ error: 'المدة لازم تكون من 0 لـ 30 يوم' });
  }

  const db  = getDb();
  const own = db.prepare(`
    SELECT 1 FROM branch_customer_followups
    WHERE user_id = ? AND TRIM(assigned_sales) = TRIM(?)
  `).get(userId, me);
  if (!own) return res.status(404).json({ error: 'العميل ده مش مسنود ليك' });

  // SQLite datetime format ('YYYY-MM-DD HH:MM:SS', UTC) — NOT ISO-with-T — so
  // lexical comparison against datetime('now') is always correct. An ISO 'T'
  // sorts AFTER a space, which silently broke same-day comparisons.
  const until = days === 0 ? null
    : new Date(Date.now() + days * 86400000).toISOString().slice(0, 19).replace('T', ' ');
  db.prepare(`
    UPDATE branch_customer_followups SET snoozed_until = ?
    WHERE user_id = ? AND TRIM(assigned_sales) = TRIM(?)
  `).run(until, userId, me);

  return res.json({ ok: true, snoozed_until: until });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/sales/queue — "طابور النهاردة": the rep's TOP pending customers,
// ranked server-side so the rep executes a short list instead of scanning
// hundreds. Deterministic + explainable — every entry carries `reasons`.
//
//   priority = total_score
//            + recency bonus     (active <1h +30 / <6h +20 / <24h +10)
//            + resurface bonus   (+35 snooze just expired, +25 unanswered
//                                 attempt >48h ago — time to retry)
//            + task-due bonus    (+40 a pending task for this customer is due
//                                 today or overdue — merges tasks into the queue)
//            - staleness penalty (-15 assigned >30 days ago AND still cold)
//
// Excludes: visited customers (post-visit flow owns them), duplicates, and
// customers snoozed into the future. followed_up=1 rows are excluded too —
// the queue is "who needs a FIRST successful touch today".
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/sales/queue', requireAuth, authorizeRoles('sales'), (req, res) => {
  const me    = req.user.name;
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 5), 50);
  const db    = getDb();

  const rows = db.prepare(`
    SELECT
      f.user_id,
      lp.first_name,
      COALESCE(lp.total_score, 0)     AS total_score,
      COALESCE(lp.lead_class, 'cold') AS lead_class,
      lp.location_requested,
      lp.last_activity,
      lp.last_category,
      lp.last_product,
      lp.last_input_text,
      f.assigned_at,
      f.branch,
      f.sent, f.sent_at,
      COALESCE(f.attempt_count, 0) AS attempt_count,
      f.last_attempt_at,
      f.snoozed_until,
      (SELECT GROUP_CONCAT(ph.phone, ' ، ') FROM lead_phones ph
         WHERE ph.user_id = f.user_id)                              AS phones,
      (SELECT MIN(t.due_at) FROM tasks t
         WHERE t.lead_id = f.user_id AND t.rep_name = ? AND t.status = 'pending'
           AND t.due_at <= date('now'))                             AS task_due
    FROM branch_customer_followups f
    JOIN lead_profiles lp ON lp.user_id = f.user_id
    WHERE TRIM(f.assigned_sales) = TRIM(?)
      AND COALESCE(lp.is_duplicate, 0) = 0
      AND COALESCE(lp.visit_confirmed, 0) = 0
      AND COALESCE(f.followed_up, 0) = 0
      -- Normalize legacy ISO-T values before comparing (T sorts after space).
      AND (f.snoozed_until IS NULL
           OR datetime(replace(replace(f.snoozed_until,'T',' '),'Z','')) <= datetime('now'))
  `).all(me, me);

  // O4: «جاي النهارده / بكره» (the plan's branch = the follow-up's branch, or unknown).
  addPlannedBadges(db, rows, (r) => r.branch);

  const now = Date.now();
  const scored = rows.map((r) => {
    const reasons = [];
    let priority  = r.total_score;

    // He said he comes today / tomorrow — call him before he walks in.
    if (r.planned_when === 'today')    { priority += 60; reasons.push('قال جاي النهارده'); }
    if (r.planned_when === 'tomorrow') { priority += 40; reasons.push('قال جاي بكره'); }

    // Recency — reuse the same tiers as the dashboard priority engine.
    const rec = computeRecencyBonus(r.last_activity);
    if (rec > 0) { priority += rec; reasons.push(rec >= 20 ? 'نشط دلوقتي' : 'نشط النهاردة'); }

    // Resurfaced snooze — its date passed, it's DUE now.
    if (r.snoozed_until) { priority += 35; reasons.push('معاد المتابعة اللي أجّلته'); }

    // Unanswered attempts older than 48h — time to retry.
    if (r.attempt_count > 0 && r.last_attempt_at) {
      const hrs = (now - new Date(r.last_attempt_at).getTime()) / 3600000;
      if (hrs >= 48) { priority += 25; reasons.push(`لم يرد ×${r.attempt_count} — جرّب تاني`); }
    }

    // A due/overdue task for this customer merges into the queue.
    if (r.task_due) { priority += 40; reasons.push('عندك مهمة مستحقة معاه'); }

    // Stale cold lead — don't let it crowd out fresh ones.
    if (r.assigned_at) {
      const days = (now - new Date(r.assigned_at).getTime()) / 86400000;
      if (days > 30 && r.total_score < 40) priority -= 15;
    }

    if (!reasons.length) {
      reasons.push(r.lead_class === 'hot' ? 'عميل ساخن' :
                   r.lead_class === 'warm' ? 'عميل دافئ' : 'لسه ما اتلمسش');
    }
    return { ...r, priority, reasons };
  })
  .sort((a, b) => b.priority - a.priority)
  .slice(0, limit);

  // How many pending are hidden by an active snooze (for the "مؤجّلين" chip).
  const snoozedCount = db.prepare(`
    SELECT COUNT(*) AS n FROM branch_customer_followups f
    JOIN lead_profiles lp ON lp.user_id = f.user_id
    WHERE TRIM(f.assigned_sales) = TRIM(?)
      AND COALESCE(lp.visit_confirmed, 0) = 0
      AND COALESCE(f.followed_up, 0) = 0
      AND datetime(replace(replace(f.snoozed_until,'T',' '),'Z','')) > datetime('now')
  `).get(me).n;

  return res.json({ queue: scored, total_pending: rows.length, snoozed: snoozedCount });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/message-templates — WhatsApp openers the rep can one-tap send via
// wa.me deep links. Defaults below; the admin can override the whole list by
// saving a JSON array to settings key 'whatsapp_templates'
// ([{id,label,text}] — {name} is replaced with the customer's first name).
// Open to any authenticated user (sales need it constantly).
// ════════════════════════════════════════════════════════════════════════════
const DEFAULT_WA_TEMPLATES = [
  { id: 'intro',   label: 'أول تواصل',
    text: 'أهلاً {name} 🌟 معاك من جراند للأثاث — شفنا اهتمامك بمعروضاتنا وحابين نساعدك تختار الأنسب. أقدر أعرف إيه اللي كان شادّك أكتر؟' },
  { id: 'noreply', label: 'بعد ما لم يرد',
    text: 'أهلاً {name} 👋 حاولنا نتواصل معاك من جراند للأثاث بس يمكن الوقت ما كانش مناسب. لو تحب تعرف تفاصيل أو أسعار، ابعتلنا هنا وهنرد عليك فوراً.' },
  { id: 'invite',  label: 'دعوة زيارة',
    text: 'أهلاً {name} 🛋️ تشكيلتنا الجديدة وصلت المعرض — تحب تحجز معاد زيارة تشوفها على الطبيعة؟ هنستناك ومعاك عروض خاصة لزوار المعرض.' },
  { id: 'revisit', label: 'بعد الزيارة',
    text: 'أهلاً {name} 🙏 اتشرفنا بزيارتك لجراند للأثاث! لو لسه بتفكر في اللي شفته، قولنا وهنظبطلك أحسن عرض. رأيك يهمنا في كل الأحوال.' },
];

app.get('/api/message-templates', requireAuth, (req, res) => {
  let templates = DEFAULT_WA_TEMPLATES;
  try {
    const raw = getSetting('whatsapp_templates');
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed) && parsed.length && parsed.every(t => t && t.text)) {
        templates = parsed.map((t, i) => ({
          id: t.id || `custom_${i}`, label: t.label || `قالب ${i + 1}`, text: String(t.text),
        }));
      }
    }
  } catch (_) { /* bad JSON in settings — serve defaults */ }
  return res.json({ templates });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/sales/customers/:userId/ai-brief — "ملخص ما قبل المكالمة".
// Turns the customer's raw history (events, categories, typed text, previous
// call summaries, unanswered attempts) into a 3-line Arabic brief + a ready
// WhatsApp draft the rep REVIEWS AND SENDS HIMSELF (never auto-sent).
//
// Cached in ai_briefs keyed by a data fingerprint — one paid generation serves
// everyone until the customer does something new. ?refresh=1 forces regen.
// RBAC: sales → must own the customer (assigned pre-visit or served the visit);
//       branch_manager → own-branch customers; admin → anyone.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/sales/customers/:userId/ai-brief', requireAuth,
  authorizeRoles('sales', 'branch_manager', 'admin'), async (req, res) => {
  const { userId } = req.params;
  const db   = getDb();
  const role = req.user?.role;
  const me   = req.user?.name;

  const lead = db.prepare(`SELECT * FROM lead_profiles WHERE user_id = ?`).get(userId);
  if (!lead) return res.status(404).json({ error: 'العميل مش موجود' });

  // ── RBAC ──────────────────────────────────────────────────────────────────
  if (role === 'sales') {
    const owns = db.prepare(`
      SELECT 1 FROM branch_customer_followups WHERE user_id = ? AND TRIM(assigned_sales) = TRIM(?)
      UNION SELECT 1 FROM lead_visits WHERE user_id = ? AND TRIM(sales_rep) = TRIM(?)
    `).get(userId, me, userId, me);
    // Phase 0 r3: out of scope answers 404 — the same as an unknown id.
    if (!owns) return res.status(404).json({ error: 'العميل مش موجود' });
  } else if (role === 'branch_manager') {
    if (!req.user.branch || !leadInBranch(db, userId, req.user.branch)) {
      return res.status(404).json({ error: 'العميل مش موجود' });
    }
  }

  // ── Fingerprint: regenerate only when the underlying data changed ─────────
  const fp = db.prepare(`
    SELECT
      (SELECT MAX(id)    FROM events WHERE user_id = ?)            AS last_event,
      (SELECT COUNT(*)   FROM events WHERE user_id = ?)            AS ev_n,
      (SELECT COUNT(*)   FROM followup_log WHERE user_id = ?)      AS fu_n,
      (SELECT COUNT(*)   FROM revisit_followups WHERE user_id = ?) AS rv_n,
      (SELECT COALESCE(MAX(attempt_count),0) FROM branch_customer_followups WHERE user_id = ?) AS att_n
  `).get(userId, userId, userId, userId, userId);
  const eventsHash = `${fp.last_event || 0}:${fp.ev_n}:${fp.fu_n}:${fp.rv_n}:${fp.att_n}`;

  const cached = db.prepare(`SELECT * FROM ai_briefs WHERE user_id = ?`).get(userId);
  if (cached && cached.events_hash === eventsHash && req.query.refresh !== '1') {
    return res.json({ ok: true, cached: true, brief: cached.brief,
      draft_message: cached.draft_message, updated_at: cached.updated_at });
  }

  // Fail fast (before gathering) when the key isn't configured.
  if (!getAiConfig().configured) {
    return res.status(400).json({ error: 'الذكاء الاصطناعي مش متظبط — حط مفتاح z.ai في الإعدادات → API', unconfigured: true });
  }

  // ── Gather ONLY real data (the prompt forbids inventing anything) ─────────
  const events = db.prepare(`
    SELECT event_type, event_value, category, created_at
    FROM events WHERE user_id = ? ORDER BY created_at DESC LIMIT 15
  `).all(userId);
  const fuLog = db.prepare(`
    SELECT sales, call_summary, followed_up_at
    FROM followup_log WHERE user_id = ? AND call_summary IS NOT NULL
    ORDER BY followed_up_at DESC LIMIT 5
  `).all(userId);
  const rvLog = db.prepare(`
    SELECT followed_up_by, note, created_at
    FROM revisit_followups WHERE user_id = ? AND note IS NOT NULL
    ORDER BY created_at DESC LIMIT 5
  `).all(userId);
  const bcf = db.prepare(`
    SELECT attempt_count, last_attempt_at, sent FROM branch_customer_followups
    WHERE user_id = ? ORDER BY id DESC LIMIT 1
  `).get(userId);

  const CLASS_AR = { cold: 'بارد', warm: 'دافئ', hot: 'ساخن 🔥', visited: 'زار المعرض', purchased: 'اشترى' };
  // C1.11: no phone reaches z.ai. Typed text (what he wrote, call summaries,
  // notes) is masked here with the bare-10-digit rule too; callAi masks the
  // rest by shape with the same masker, and the reply is unmasked below.
  const masker = createPhoneMasker();
  const typed = (t) => masker.maskText(String(t), { typed: true });
  const lines = [
    `الاسم: ${lead.first_name || 'غير معروف'}`,
    `التصنيف: ${CLASS_AR[lead.lead_class] || lead.lead_class} (نقاط: ${lead.total_score || 0})`,
    lead.last_category   ? `الفئة اللي بيهتم بيها: ${lead.last_category}` : null,
    lead.last_product    ? `آخر منتج شافه: ${lead.last_product}` : null,
    lead.preferred_branch ? `الفرع المفضّل: ${lead.preferred_branch}` : null,
    lead.platform        ? `جه من: ${lead.platform}` : null,
    lead.last_input_text ? `آخر حاجة كتبها بنفسه: "${typed(lead.last_input_text)}"` : null,
    bcf?.attempt_count   ? `محاولات اتصال بدون رد: ${bcf.attempt_count} (آخرها ${bcf.last_attempt_at || '؟'})` : null,
    bcf?.sent            ? `اتبعتله رسالة واتساب قبل كده` : null,
    events.length ? `آخر تحركاته:\n${events.map(e =>
      `- ${e.created_at}: ${e.event_type}${e.event_value ? ` (${e.event_value})` : ''}${e.category ? ` [${e.category}]` : ''}`).join('\n')}` : null,
    fuLog.length ? `ملخصات مكالمات سابقة:\n${fuLog.map(f => `- ${f.sales || '؟'}: ${typed(f.call_summary)}`).join('\n')}` : null,
    rvLog.length ? `متابعات بعد الزيارة:\n${rvLog.map(f => `- ${f.followed_up_by || '؟'}: ${typed(f.note)}`).join('\n')}` : null,
  ].filter(Boolean).join('\n');

  const result = await callAi([
    { role: 'system', content:
      'انت مساعد مبيعات لمعرض أثاث في مصر. بتجهّز السيلز قبل ما يكلم العميل. ' +
      'اعتمد فقط وحصرياً على المعلومات المكتوبة — ممنوع تخترع أي معلومة مش موجودة. ' +
      'رد بـ JSON فقط بالشكل ده: {"brief": "...", "draft": "..."} — ' +
      'brief = ملخص 2-3 سطور بالعامية المصرية: مين العميل، مهتم بإيه، وإيه أحسن مدخل للكلام معاه. ' +
      'draft = رسالة واتساب قصيرة وودودة بالعامية (سطرين بالكتير) مناسبة لحالته، من غير مبالغة ومن غير وعود بأسعار.' },
    { role: 'user', content: lines },
  ], { maxTokens: 2000, masker });

  if (!result.ok) {
    return res.status(result.unconfigured ? 400 : 502).json({ error: result.error, unconfigured: !!result.unconfigured });
  }

  const replyText = masker.unmaskText(result.text);
  const parsed = extractJson(replyText);
  const brief  = (parsed?.brief && String(parsed.brief).trim()) || replyText.slice(0, 600);
  const draft  = (parsed?.draft && String(parsed.draft).trim()) || null;

  db.prepare(`
    INSERT INTO ai_briefs (user_id, brief, draft_message, events_hash, model, updated_at)
    VALUES (?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(user_id) DO UPDATE SET
      brief = excluded.brief, draft_message = excluded.draft_message,
      events_hash = excluded.events_hash, model = excluded.model, updated_at = excluded.updated_at
  `).run(userId, brief, draft, eventsHash, result.model);

  return res.json({ ok: true, cached: false, brief, draft_message: draft });
});



// ════════════════════════════════════════════════════════════════════════════
// Pre-visit follow-up LOG — the rep can record SEVERAL follow-ups over time for
// a customer who hasn't visited yet (updates/timeline), not just one. Append-only
// (followup_log), scoped to the rep the customer is assigned to.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/sales/followups/:userId/log', requireAuth, authorizeRoles('sales'), (req, res) => {
  const me = req.user.name;
  const { userId } = req.params;
  const db = getDb();
  const own = db.prepare(`
    SELECT 1 FROM branch_customer_followups
    WHERE user_id = ? AND TRIM(assigned_sales) = TRIM(?)
  `).get(userId, me);
  if (!own || !canSeeLead(db, req.user, userId)) return res.status(404).json({ error: 'العميل ده مش مسنود ليك' });
  const log = db.prepare(`
    SELECT id, sales, call_summary, followed_up_at
    FROM followup_log WHERE user_id = ?
    ORDER BY followed_up_at DESC, id DESC
  `).all(userId);
  return res.json({ log });
});

app.post('/api/sales/followups/:userId/log', requireAuth, authorizeRoles('sales'), (req, res) => {
  const me   = req.user.name;
  const { userId } = req.params;
  const note = (req.body?.note && String(req.body.note).trim()) || null;
  if (!note) return res.status(400).json({ error: 'اكتب نص المتابعة' });

  const db  = getDb();
  const own = db.prepare(`
    SELECT branch FROM branch_customer_followups
    WHERE user_id = ? AND TRIM(assigned_sales) = TRIM(?)
  `).get(userId, me);
  if (!own || !canSeeLead(db, req.user, userId)) return res.status(404).json({ error: 'العميل ده مش مسنود ليك' });

  // Keep the customer in the followed-up list and surface the latest note on the
  // row, while appending this update to the permanent history.
  db.prepare(`
    UPDATE branch_customer_followups
       SET followed_up = 1, followed_up_at = ?, followed_up_by = ?, call_summary = ?
     WHERE user_id = ? AND TRIM(assigned_sales) = TRIM(?)
  `).run(new Date().toISOString(), me, note, userId, me);
  logFollowup(db, own.branch, userId, me, note);

  return res.json({ ok: true });
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
  let { name, email, password } = req.body || {};
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'الاسم والإيميل والباسورد مطلوبين' });
  }
  // Trim the name — a trailing/leading space silently breaks every name-based
  // match later (assignments store the trimmed value, so a padded users.name
  // would never equal it and the rep "loses" all their customers).
  name = String(name).trim();
  const db = getDb();
  // Names are unique system-wide — a twin in another branch would share its history.
  const nameError = staffCreateError(db, name);
  if (nameError) return res.status(409).json({ error: nameError });
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
  const cur = db.prepare(`SELECT id, name FROM users WHERE id = ?`).get(req.params.id);
  let { name, email, password, active } = req.body || {};
  // Phase 0 r2: same rule as PUT /api/users/:id in a sandbox session.
  if (isDemoContext() && (email || password)) {
    return res.status(403).json({ error: 'demo_readonly_login', message: 'وضع التدريب: مينفعش تغيّر الإيميل أو الباسورد' });
  }
  if (name != null) name = String(name).trim();
  const updates = [];
  const params  = [];
  if (name)               { updates.push('name = ?');          params.push(name); }
  if (email)              { updates.push('email = ?');         params.push(email); }
  if (password)           { updates.push('password_hash = ?'); params.push(bcrypt.hashSync(password, 10)); }
  if (active !== undefined) { updates.push('active = ?');       params.push(active ? 1 : 0); }
  if (!updates.length) return res.status(400).json({ error: 'مفيش حاجة تتعدّل' });
  // Only a real name change can collide / cascade (the edit modal always resends the name).
  if (name && cur && name !== cur.name) {
    const renameError = staffRenameError(db, cur, name);
    if (renameError) return res.status(409).json({ error: renameError });
  }
  params.push(req.params.id);
  try {
    // Renaming a rep must carry their assignments with them, or they orphan.
    db.transaction(() => {
      db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...params);
      if (name && cur && name !== cur.name) renameRepReferences(db, cur.name, name);
    })();
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
  // Archive (freeze), don't hard-delete: a deleted rep leaves customers, visits
  // and purchases orphaned under a name. Freezing keeps that history attached and
  // the name reserved — reversible via toggle-active, the manager UI's only "remove".
  db.prepare(`UPDATE users SET active = 0 WHERE id = ?`).run(req.params.id);
  return res.json({ ok: true, archived: true });
});

// ════════════════════════════════════════════════════════════════════════════
// PATCH /api/branch/users/:id/toggle-active — flip a user's active flag.
// Admin → any non-admin user. Branch manager → users in their own branch only.
// This is the ONLY way a branch manager can "remove" a user (soft, reversible).
// ════════════════════════════════════════════════════════════════════════════
app.patch('/api/branch/users/:id/toggle-active', requireAuth, authorizeRoles('admin', 'branch_manager'), (req, res) => {
  const db = getDb();
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id)) return res.status(400).json({ error: 'bad_id' });
  if (id === req.user.id)   return res.status(400).json({ error: 'cannot_toggle_self' });

  const u = db.prepare(`SELECT id, role, branch, active FROM users WHERE id = ?`).get(id);
  if (!u) return res.status(404).json({ error: 'user_not_found' });
  if (u.role === 'admin') return res.status(403).json({ error: 'cannot_toggle_admin' });
  if (req.user.role === 'branch_manager' && u.branch !== req.user.branch) {
    return res.status(403).json({ error: 'forbidden' });
  }

  // The wanted state (2026-11-25 review): «رجّعه» sends active 1, «إيقاف»
  // active 0, so a page opened before someone else's change never does the
  // opposite of its button (a repeat press changes nothing). No body = the
  // old flip, for a portal that has not updated yet.
  const want = req.body?.active;
  if (want !== undefined && ![0, 1, true, false].includes(want)) return res.status(400).json({ error: 'bad_active' });
  const next = want === undefined ? (u.active ? 0 : 1) : (want ? 1 : 0);
  db.prepare(`UPDATE users SET active = ? WHERE id = ?`).run(next, id);
  console.log(`🔄 USER ${next ? 'ACTIVATED' : 'DEACTIVATED'}: id:${id} by ${req.user?.name}`);
  return res.json({ ok: true, id, active: next });
});

// ── Shared purchase helpers ─────────────────────────────────────────────────
// Used by POST /api/purchases (staff) and POST /api/reception/sales (reception
// records the sale for a salesperson), so both write a sale the same way.

// ٠-٩ / ۰-۹ → 0-9 (reception types on Arabic keyboards).
const toWesternDigits = (s) => String(s).replace(/[٠-٩]/g, d => String(d.charCodeAt(0) - 0x0660))
                                         .replace(/[۰-۹]/g, d => String(d.charCodeAt(0) - 0x06F0));
// Contract number: Western digits, single spaces, trimmed → string | null.
function normalizeContractNumber(v) {
  if (v == null) return null;
  const s = toWesternDigits(v).replace(/\s+/g, ' ').trim();
  return s || null;
}
// Whole EGP > 0 → { value } | { error }; null/'' → { value: null }.
// Thousands separators and «ج.م»/«جنيه» are dropped; '38.500' is refused as
// ambiguous (38.5 or 38,500?).
function parseEgpPrice(v) {
  if (v == null || v === '') return { value: null };
  const s = toWesternDigits(v).replace(/[\s,،٬']/g, '').replace(/ج\.?م|جنيه/g, '');
  if (!/^\d+$/.test(s)) return { error: true };
  const n = Number(s);
  return (n > 0 && n <= 100000000) ? { value: n } : { error: true };
}
// Catalog product ids → { ids } (deduped, positive ints) | { code, error } when
// one is not in the catalog — checked BEFORE anything is written.
function validateProductIds(db, raw) {
  const ids = [...new Set((Array.isArray(raw) ? raw : []).map(v => parseInt(v, 10)).filter(n => Number.isFinite(n) && n > 0))];
  const missing = ids.filter(id => !db.prepare(`SELECT 1 FROM products WHERE id = ?`).get(id));
  if (missing.length) return { code: 'unknown_product', error: 'فيه منتج مش موجود في الكتالوج — حدّث الصفحة واختار تاني' };
  return { ids };
}
// Double-entry guard → { code, error, purchase_id } | null.
//   With a contract number: the same customer + the same contract (any case,
//   trimmed) is the same sale. Without one: only an identical resubmit (same rep
//   + same product set) within 60 s. A different contract / product set is a
//   real second sale and goes through (multi-contract customers).
function findDuplicatePurchase(db, { userId, contractNumber, rep, productIds, lines = [] }) {
  if (contractNumber) {
    const row = db.prepare(`SELECT id FROM purchases WHERE user_id = ? AND LOWER(TRIM(contract_number)) = LOWER(?)
                            ORDER BY id DESC LIMIT 1`).get(userId, contractNumber);
    if (row) return { code: 'duplicate_contract', purchase_id: row.id,
      // \u2068…\u2069 isolate the (LTR) number so «123-A» doesn't flip inside the Arabic line
      error: `العقد رقم \u2068${contractNumber}\u2069 متسجّل قبل كده للعميل ده — مش هيتسجّل تاني` };
    return null;
  }
  const want = [...productIds].sort((a, b) => a - b).join(',');
  const wantLines = linesSignature(lines);
  const recent = db.prepare(`SELECT id FROM purchases WHERE user_id = ? AND rep IS ? AND COALESCE(TRIM(contract_number),'') = ''
                             AND datetime(${RECORDED_AT()}) >= datetime('now','-60 seconds')`).all(userId, rep);
  for (const r of recent) {
    const have = db.prepare(`SELECT product_id FROM purchase_items WHERE purchase_id = ? ORDER BY product_id`).all(r.id)
                   .map(x => x.product_id).join(',');
    const haveLines = linesSignature(readPurchaseLines(db, [r.id]).get(r.id) || []);
    if (have === want && haveLines === wantLines) return { code: 'duplicate_recent', purchase_id: r.id, error: 'البيعة دي اتسجلت من ثواني — حدّث الصفحة' };
  }
  return null;
}

// ── A sale's lines from the prices system (2026-11-22, «قسم الأسعار») ────────
// items → purchase_lines (ids + titles, visible to staff); the estimate →
// purchase_estimates (admin only, services/grandCatalog.js estimate()).
function linesSignature(lines) {
  return (lines || []).map(l => [l.kind, l.model_id || '', l.variant_id || '', [...(l.with || [])].sort().join('+'), l.qty].join('|'))
    .sort().join(',');
}
function writePurchaseLines(db, purchaseId, lines) {
  db.prepare(`DELETE FROM purchase_lines WHERE purchase_id = ?`).run(purchaseId);
  const ins = db.prepare(`INSERT INTO purchase_lines (purchase_id, line_index, kind, model_id, variant_id, with_json, with_titles_json,
                            qty, title, model_title, category, category_ar) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`);
  lines.forEach((l, i) => ins.run(purchaseId, i, l.kind, l.model_id || null, l.variant_id || null,
    l.with && l.with.length ? JSON.stringify(l.with) : null,
    l.with_titles && l.with_titles.length ? JSON.stringify(l.with_titles) : null,
    l.qty, l.title || null, l.model_title || null, l.category || null, l.category_ar || null));
}
// Which write of a sale's lines is current: every writePurchaseLines deletes
// and re-inserts, and AUTOINCREMENT never reuses an id, so MAX(id) only grows.
// 0 = no lines.
function purchaseLinesVersion(db, purchaseId) {
  const r = db.prepare(`SELECT MAX(id) AS v FROM purchase_lines WHERE purchase_id = ?`).get(purchaseId);
  return (r && r.v) || 0;
}
const parseJsonArr = (s) => { try { const v = JSON.parse(s || '[]'); return Array.isArray(v) ? v : []; } catch (_) { return []; } };
// purchase ids → Map(id → [{ kind, model_id, variant_id, with[], with_titles[], qty, title, model_title }])
function readPurchaseLines(db, ids) {
  const out = new Map();
  if (!ids.length) return out;
  for (let i = 0; i < ids.length; i += 500) {
    const chunk = ids.slice(i, i + 500);
    const rows = db.prepare(`SELECT purchase_id, kind, model_id, variant_id, with_json, with_titles_json, qty, title, model_title
                             FROM purchase_lines WHERE purchase_id IN (${chunk.map(() => '?').join(',')})
                             ORDER BY purchase_id, line_index`).all(...chunk);
    for (const r of rows) {
      if (!out.has(r.purchase_id)) out.set(r.purchase_id, []);
      out.get(r.purchase_id).push({
        kind: r.kind, model_id: r.model_id, variant_id: r.variant_id, with: parseJsonArr(r.with_json),
        with_titles: parseJsonArr(r.with_titles_json), qty: r.qty, title: r.title, model_title: r.model_title,
      });
    }
  }
  return out;
}
// ADMIN ONLY — purchase ids → Map(id → { total, complete, version, source, computed_at, lines[] }).
// Call it only on a branch that already checked role === 'admin'.
function readPurchaseEstimates(db, ids) {
  const out = new Map();
  for (let i = 0; i < ids.length; i += 500) {
    const chunk = ids.slice(i, i + 500);
    const rows = db.prepare(`SELECT * FROM purchase_estimates WHERE purchase_id IN (${chunk.map(() => '?').join(',')})`).all(...chunk);
    for (const r of rows) {
      out.set(r.purchase_id, {
        total: r.list_total_estimate, complete: r.estimate_complete === 1, version: r.catalog_version, source: r.source,
        computed_at: r.computed_at, lines: parseJsonArr(r.lines_json), warnings: parseJsonArr(r.warnings_json),
      });
    }
  }
  return out;
}
// → true when stored. An estimate of an older write of the lines is never
// stored over a newer one (lines_version; review 2026-11-22: a contract edited
// while the first estimate was still waiting on the quote).
function storePurchaseEstimate(db, purchaseId, est, linesVersion) {
  const info = db.prepare(`INSERT INTO purchase_estimates (purchase_id, list_total_estimate, estimate_complete, catalog_version, source,
                lines_json, warnings_json, lines_version, computed_at) VALUES (?,?,?,?,?,?,?,?,datetime('now'))
              ON CONFLICT(purchase_id) DO UPDATE SET list_total_estimate = excluded.list_total_estimate,
                estimate_complete = excluded.estimate_complete, catalog_version = excluded.catalog_version,
                source = excluded.source, lines_json = excluded.lines_json, warnings_json = excluded.warnings_json,
                lines_version = excluded.lines_version, computed_at = excluded.computed_at
              WHERE COALESCE(excluded.lines_version, 0) >= COALESCE(purchase_estimates.lines_version, 0)`)
    .run(purchaseId, est.total == null ? null : Math.round(est.total), est.complete ? 1 : 0, est.version || null,
         est.source || 'none', JSON.stringify(est.lines || []), JSON.stringify(est.warnings || []), linesVersion || 0);
  return info.changes > 0;
}
// After the commit: today's LIST-price estimate of a sale's lines, stored on it.
// → the estimate ({ total, complete, … }) or null (a sale with no lines: the old
// manual catalogue). Never throws. A sale deleted meanwhile stores nothing; a
// sale whose lines were written again meanwhile (a contract edit) stores
// nothing either — the newer write's own estimate is the one kept.
const estimatesInFlight = new Set();   // purchase ids being estimated now (the backfill skips them)
async function estimatePurchase(db, purchaseId) {
  estimatesInFlight.add(purchaseId);
  try {
    // the lines and their version read together (one synchronous step)
    const version = purchaseLinesVersion(db, purchaseId);
    const lines = readPurchaseLines(db, [purchaseId]).get(purchaseId) || [];
    if (!lines.length) return null;
    const est = await grandCatalog.estimate(lines);
    if (!db.prepare(`SELECT 1 FROM purchases WHERE id = ?`).get(purchaseId)) return null;
    if (purchaseLinesVersion(db, purchaseId) !== version || !storePurchaseEstimate(db, purchaseId, est, version)) {
      console.log(`[estimate] purchase ${purchaseId}: its lines changed meanwhile — this older estimate is not stored`);
      return est;
    }
    console.log(`[estimate] purchase ${purchaseId}: ${est.source}${est.complete ? '' : ' (not complete)'}`);
    return est;
  } catch (e) {
    console.error(`[estimate] purchase ${purchaseId} failed: ${e && e.message}`);
    return null;
  } finally {
    estimatesInFlight.delete(purchaseId);
  }
}
// Every row hanging off the sales that `idsSql` selects (purchase_lines,
// purchase_estimates, purchase_items) — run it INSIDE the caller's transaction,
// before the purchases rows go. purchase_lines / purchase_estimates carry no
// foreign key (nothing cascades to them); purchase_items' ON DELETE CASCADE
// needs PRAGMA foreign_keys, so it is deleted explicitly too (r2, 2026-11-22).
function deletePurchaseRows(db, idsSql, ...params) {
  for (const t of ['purchase_lines', 'purchase_estimates', 'purchase_items']) {
    db.prepare(`DELETE FROM ${t} WHERE purchase_id IN (${idsSql})`).run(...params);
  }
}
// The body's items → { lines } | { code, error } (validated against the cached
// catalogue). No items → { lines: [] }. Never waits on the prices system while
// there is a copy (getCatalogNow: an old copy is refreshed in the background).
async function linesFromBody(items) {
  if (items == null || (Array.isArray(items) && items.length === 0)) return { lines: [] };
  if (!Array.isArray(items)) return { code: 'bad_item', error: 'فيه منتج مش مفهوم — اختاره تاني من القايمة' };
  const v = await grandCatalog.getCatalogNow();
  return grandCatalog.normalizeItems(items, v.catalog);
}
// Meta Purchase value (owner Q2, 2026-11-22; always sent since 2026-11-23, Meta's
// «Send value parameters for your purchase events»: every Purchase must carry
// value + currency). The SYSTEM's number only — owner 2026-11-24: «اللي بيكتبه
// ساعات بيبقي المقدم فقط عايزك انت تحسب ملكش دعوة باللي بيتكتب»: the amount
// staff type (purchases.price) is often just the deposit and is NEVER the value.
// In order: the sale's list-price estimate, else the typical sale
// (typicalSaleValue: the median estimate of the last 90 days), else 0. Always a
// whole number, never null. Setting capi_purchase_value = 'off' sends 0 (no
// amount of ours goes to Meta, the parameter is still there).
function purchaseValueFor(est, db) {
  if (getSetting('capi_purchase_value', 'on') === 'off') return 0;
  const e = est && Number(est.total);
  if (Number.isFinite(e) && e > 0) return Math.round(e);
  return typicalSaleValue(db || getDb());
}
// The median COMPLETE estimate of the last 90 days' sales (never the typed
// amount — see purchaseValueFor), when at least TYPICAL_SALE_MIN sales have
// one; else 0.
// Kept 10 minutes. Never throws.
const TYPICAL_SALE_MIN = 5;
const TYPICAL_SALE_TTL_MS = 10 * 60 * 1000;
let typicalSaleCache = null;   // { at, value }
function typicalSaleValue(db) {
  if (typicalSaleCache && Date.now() - typicalSaleCache.at < TYPICAL_SALE_TTL_MS) return typicalSaleCache.value;
  let value = 0;
  try {
    const vals = db.prepare(`
      SELECT e.list_total_estimate AS v
      FROM purchases p JOIN purchase_estimates e ON e.purchase_id = p.id
      WHERE datetime(p.created_at) >= datetime('now', '-90 days') AND e.list_total_estimate > 0
        AND e.estimate_complete = 1
      ORDER BY v`).all().map(r => Number(r.v)).filter(v => Number.isFinite(v) && v > 0);
    if (vals.length >= TYPICAL_SALE_MIN) {
      const m = vals.length >> 1;
      value = Math.round(vals.length % 2 ? vals[m] : (vals[m - 1] + vals[m]) / 2);
    }
  } catch (e) {
    console.error('[meta-capi] typical sale value failed:', e && e.message);
  }
  typicalSaleCache = { at: Date.now(), value };
  return value;
}
// The sale row + its catalog items + lead_class 'purchased'. Call it INSIDE a
// db.transaction, so a failure never leaves a counted sale without its items.
//   p: { userId, legacyLabel, price, branch, notes, rep, contractNumber, productIds,
//        enteredBy, enteredById, enteredByRole, enteredVia }  → purchaseId
function insertPurchaseRows(db, p) {
  const r = db.prepare(`INSERT INTO purchases (user_id, product_id, price, branch, notes, rep, contract_number,
                          entered_by, entered_by_id, entered_by_role, entered_via) VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
    .run(p.userId, p.legacyLabel, p.price, p.branch, p.notes, p.rep, p.contractNumber,
         p.enteredBy, p.enteredById, p.enteredByRole, p.enteredVia);
  const ins = db.prepare(`INSERT INTO purchase_items (purchase_id, product_id) VALUES (?, ?)`);
  for (const pid of p.productIds) ins.run(r.lastInsertRowid, pid);
  if (p.lines && p.lines.length) writePurchaseLines(db, Number(r.lastInsertRowid), p.lines);
  // Mark lead as purchased (terminal state — won't be overridden by scoring)
  db.prepare(`UPDATE lead_profiles SET lead_class = 'purchased',
      purchased_at = CASE WHEN purchased_at IS NULL THEN datetime('now') ELSE purchased_at END,
      last_activity = datetime('now') WHERE user_id = ?`).run(p.userId);
  return Number(r.lastInsertRowid);
}
// What follows a recorded sale, AFTER the commit, in this order:
//   1) Meta CAPI "Purchase" — offline conversion back to the ad account so Meta
//      can optimize toward real buyers. Skipped entirely for demo/training
//      sandbox sessions (a demo_ user works on the demo DB — never pollute the
//      ad data). Fire-and-forget — never blocks the response. Always value + EGP
//      (purchaseValueFor).
//   2) the admin war-room notification (reception's sale says who entered it)
//   3) the ManyChat purchase flow (Event-Triggered Flow: Purchase Made)
// Meta's Purchase for one sale: the same event_id (purchase_<id>) on every
// send, so Meta dedups a resend. opts.eventTime (UNIX s) for a backfilled sale.
function capiLeadOf(db, userId) {
  return db.prepare(`
      SELECT COALESCE(lp.phone, (SELECT ph.phone FROM lead_phones ph
                                 WHERE ph.user_id = lp.user_id ORDER BY ph.id LIMIT 1)) AS phone,
             lp.first_name, lp.last_name, lp.gender, lp.preferred_branch
      FROM lead_profiles lp WHERE lp.user_id = ?
    `).get(userId);
}
function sendPurchaseEvent(capiLead, { userId, purchaseId, value, eventTime }) {
  sendMetaEvent('Purchase',
    { phone: capiLead?.phone, firstName: capiLead?.first_name, lastName: capiLead?.last_name,
      gender: capiLead?.gender, branch: capiLead?.preferred_branch, externalId: userId },
    `purchase_${purchaseId}`,
    { value: Number.isFinite(Number(value)) && Number(value) >= 0 ? Math.round(Number(value)) : 0, currency: 'EGP' },
    eventTime ? { eventTime } : {});
}
// How long Meta's Purchase waits for the sale's estimate (2026-11-24: every sale
// waits — the typed amount is never the value). Longer than the quote's own
// timeout (grandCatalog TIMEOUT_MS, 8 s), so a quote that times out still gives
// the cached-catalogue estimate in time; past it the event goes with the typical
// sale (a restart is covered by backfillPurchaseEstimates). The response has
// already gone, so nobody waits on it. PURCHASE_ESTIMATE_WAIT_MS env: tests only.
const PURCHASE_ESTIMATE_WAIT_MS = (() => {
  const v = Number(process.env.PURCHASE_ESTIMATE_WAIT_MS);
  return Number.isFinite(v) && v >= 100 && v <= 60000 ? v : 20000;
})();
function afterPurchase(db, req, { userId, purchaseId, rep, branch, price, contractNumber, viaReception, creditedByOther = false }) {
  // Meta's Purchase (the response has already gone): it waits at most
  // PURCHASE_ESTIMATE_WAIT_MS for the sale's estimate and goes with
  // purchaseValueFor (the estimate, else the typical sale). The typed amount
  // (`price`) is never sent — it is often only the deposit (owner 2026-11-24).
  // One send per sale here; the backfill (backfillPurchaseEstimates) re-sends
  // with the same event_id only for a sale whose estimate never got stored
  // (a restart mid-estimate) — Meta dedups.
  const demo = isDemoContext();
  const capiLead = demo ? null : capiLeadOf(db, userId);
  let sent = false;
  const sendOnce = (value) => {
    if (sent || demo) return;
    sent = true;
    // a sale deleted during the wait (wrong customer) is no purchase for Meta
    if (!db.prepare(`SELECT 1 FROM purchases WHERE id = ?`).get(purchaseId)) {
      console.log(`[meta-capi] purchase ${purchaseId} deleted before its Purchase — not sent`);
      return;
    }
    try { sendPurchaseEvent(capiLead, { userId, purchaseId, value }); }
    catch (err) { console.error('[meta-capi] Purchase failed:', err && err.message); }
  };
  const timer = setTimeout(() => sendOnce(purchaseValueFor(null, db)), PURCHASE_ESTIMATE_WAIT_MS);
  if (typeof timer.unref === 'function') timer.unref();
  estimatePurchase(db, purchaseId).then((est) => {
    clearTimeout(timer);
    sendOnce(purchaseValueFor(est, db));
  }).catch(err => {
    clearTimeout(timer);
    sendOnce(purchaseValueFor(null, db));
    console.error('[meta-capi] Purchase after estimate failed:', err && err.message);
  });

  // Every purchase → macro alert for the admin war-room.
  createNotification(db, 'admin', 'new_purchase',
    `تم إغلاق تعاقد جديد (عقد: ${contractNumber || '—'}) بقيمة ` +
    `${new Intl.NumberFormat('en-US').format(Number(price) || 0)} ج.م بواسطة ` +
    `${rep || '؟'} في فرع ${branch || '—'}` +
    (viaReception ? ` — اتسجّل من الاستقبال بواسطة ${req.user?.name || '؟'}`
      : creditedByOther ? ` — سجّلها ${req.user?.name || '؟'} باسم السيلز` : ''));

  // Event-Triggered Flow: Purchase Made — through the 24 h window guard (C1.9).
  // A walk-in sale (walkin_…) is skipped as no_manychat_id with no API call.
  const purchaseFlowSetting = db.prepare(`SELECT value FROM settings WHERE key = 'manychat_purchase_flow'`).get();
  if (purchaseFlowSetting && purchaseFlowSetting.value && purchaseFlowSetting.value.trim() !== '') {
    guardedSendFlow(db, { user_id: userId, flow_id: purchaseFlowSetting.value.trim(), site: 'purchase' })
      .catch(err => console.error('[Event-Trigger] Purchase Flow failed:', err.message));
  } else {
    console.warn('[Event-Trigger] ⚠️ Purchase recorded but manychat_purchase_flow is empty — no message sent. Set it in Settings → API.');
  }
}

// ── The estimate backfill (r2, 2026-11-22) ─────────────────────────────────
// A sale with lines but no stored estimate (the CRM restarted while its
// estimate was waiting on the quote, or the estimate failed) is estimated at
// boot and every 10 minutes. When that first estimate lands, Meta's Purchase
// is sent again with the same event_id (purchase_<id>, so Meta dedups one it
// already has) and the sale's own time — only for sales younger than
// PURCHASE_RESEND_WINDOW_H (Meta dedups by event_id within 48 h; older sales
// get the estimate only, no Meta event). Live DB only; never a demo sale.
const PURCHASE_BACKFILL_MS = 10 * 60 * 1000;
const PURCHASE_RESEND_WINDOW_H = 48;
const PURCHASE_BACKFILL_BATCH = 200;
let purchaseBackfillRunning = false;
async function backfillPurchaseEstimates(db) {
  if (purchaseBackfillRunning) return { skipped: true };
  purchaseBackfillRunning = true;
  const out = { estimated: 0, resent: 0, failed: 0 };
  try {
    const rows = db.prepare(`
      SELECT p.id, p.user_id, p.price, CAST(strftime('%s', ${RECORDED_AT('p')}) AS INTEGER) AS ts,
             (datetime(${RECORDED_AT('p')}) >= datetime('now', '-${PURCHASE_RESEND_WINDOW_H} hours')) AS in_window
      FROM purchases p
      WHERE EXISTS (SELECT 1 FROM purchase_lines pl WHERE pl.purchase_id = p.id)
        AND NOT EXISTS (SELECT 1 FROM purchase_estimates e WHERE e.purchase_id = p.id)
      ORDER BY p.id LIMIT ${PURCHASE_BACKFILL_BATCH}`).all();
    for (const r of rows) {
      if (estimatesInFlight.has(r.id)) continue;           // its own afterPurchase is on it
      const est = await estimatePurchase(db, r.id);
      const stored = !!db.prepare(`SELECT 1 FROM purchase_estimates WHERE purchase_id = ?`).get(r.id);
      if (!stored) { out.failed++; continue; }
      out.estimated++;
      if (r.in_window === 1) {
        sendPurchaseEvent(capiLeadOf(db, r.user_id), { userId: r.user_id, purchaseId: r.id,
          value: purchaseValueFor(est, db), eventTime: Number(r.ts) || undefined });
        out.resent++;
      }
    }
    if (rows.length) console.log(`[estimate-backfill] ${out.estimated} estimated, ${out.resent} Purchase re-sent (same event_id), ${out.failed} still waiting`);
  } catch (e) {
    console.error('[estimate-backfill] failed:', e && e.message);
  } finally {
    purchaseBackfillRunning = false;
  }
  return out;
}

// ════════════════════════════════════════════════════════════════════════════
// POST /api/purchases — staff record an offline purchase for a lead, credited
// to THEMSELVES (rep = the logged-in user). Used by admin + branch managers
// (LeadDetail «تسجيل شراء», RevisitView «اشترى»), who may instead credit an
// active salesperson of the sale's branch (body.sales_rep — «البيعة تتحسب
// لمين؟»: a deal closed by phone or after the visit day, which reception's
// today list can't take; a branch manager only for his own branch). Sales /
// legacy rep are still accepted here (the portal before 2026-11-16 posts here;
// their buttons are gone from the new portal — reception now records their
// sales through POST /api/reception/sales), but not for a customer reception
// already recorded a sale for today (an old tab's second entry of the same
// sale, often with no contract number). Reception gets 403: a sale posted here
// would be credited to the receptionist.
// Body: { user_id, product_ids[], product_id?, price?, branch?, notes?, contract_number?,
//         sales_rep? (admin / branch_manager) }
// Guards: unknown catalog product → 400; the same contract for the same
// customer (or an identical resubmit within 60 s) → 409 { error, code, purchase_id }.
// The sale, its items and lead_class are written in ONE transaction.
// Returns: { ok, purchase_id, lead_class, rep }
// ════════════════════════════════════════════════════════════════════════════
app.post('/api/purchases', requireAuth, async (req, res) => {
 try {
  const { user_id, product_id, product_ids, branch, notes, contract_number, sales_rep, items } = req.body || {};
  const role = req.user?.role;
  if (role === 'reception') {
    return res.status(403).json({ error: 'الاستقبال بيسجّل البيع من قايمة العملاء زيارة اليوم', code: 'reception_use_today_list' });
  }
  if (!user_id || typeof user_id !== 'string') {
    return res.status(400).json({ error: 'user_id is required' });
  }
  const db  = getDb();
  let rep = req.user?.name || req.headers['x-rep'] || null;

  const lead = db.prepare(`SELECT user_id FROM lead_profiles WHERE user_id = ?`).get(user_id);
  if (!lead) return res.status(404).json({ error: 'lead_not_found' });
  // Phase 0 r3: a sale credited to him makes the lead his (purchases in
  // leadIsMine / leadTiedToBranch) — only for a lead he may already open.
  // r4: not through a rep's read-only dashboard grant (canActOnLead).
  if (!canActOnLead(db, req.user, user_id)) return res.status(404).json({ error: 'lead_not_found' });

  // An old tab of a salesperson (buttons cached from before 2026-11-16) must not
  // enter a sale reception already recorded for this customer today.
  if (role === 'sales' || role === 'rep') {
    const [dayStart, dayEnd] = cairoDayBoundsSql(cairoDay());
    const already = db.prepare(`SELECT id FROM purchases WHERE user_id = ? AND entered_via = 'reception'
                                  AND datetime(${RECORDED_AT()}) >= ? AND datetime(${RECORDED_AT()}) < ?
                                ORDER BY id DESC LIMIT 1`).get(user_id, dayStart, dayEnd);
    if (already) {
      return res.status(409).json({
        error: 'الاستقبال سجّل بيعة للعميل ده النهارده — البيع بقى بيسجّله الاستقبال، حدّث الصفحة',
        code: 'reception_already_recorded', purchase_id: already.id,
      });
    }
  }

  // Normalize product_ids: accept array of numeric IDs from the new catalog —
  // every id must exist BEFORE anything is written (an unknown id used to fail
  // the item insert after the sale row was already counted).
  const checked = validateProductIds(db, product_ids);
  if (checked.code) return res.status(400).json({ error: checked.error, code: checked.code });
  const productIds = checked.ids;

  // 2026-11-22: the prices system's models / pieces (items) — checked against
  // the cached catalogue BEFORE anything is written. The only await in this
  // route: everything after it up to the commit is synchronous, so a double
  // click is still serialized by the duplicate guard.
  const fromCatalog = await linesFromBody(items);
  if (fromCatalog.code) return res.status(400).json({ error: fromCatalog.error, code: fromCatalog.code });
  const lines = fromCatalog.lines;

  // The paid amount staff typed (optional, never required): whole EGP.
  const priceParsed = parseEgpPrice(req.body?.price);
  if (priceParsed.error) return res.status(400).json({ error: 'اكتب المبلغ أرقام بس (مثلاً 38500)', code: 'bad_price' });
  const price = priceParsed.value;

  // Legacy product_id text field is kept for backward compat; for new flows
  // we store the first selected product's name there so old reports still work.
  let legacyProductLabel = product_id || (lines[0] ? lines[0].title : null) || null;
  if (!legacyProductLabel && productIds.length) {
    const firstProduct = db.prepare(`SELECT name FROM products WHERE id = ?`).get(productIds[0]);
    if (firstProduct) legacyProductLabel = firstProduct.name;
  }

  // A sale must record WHAT was sold — otherwise best-selling analytics are
  // blind. Require at least one product (catalog selection preferred).
  if (!productIds.length && !lines.length && !legacyProductLabel) {
    return res.status(400).json({ error: 'اختار المنتج اللي اشتراه العميل قبل ما تسجّل البيعة' });
  }

  // Branch fallback — never store a branch-less contract (it would be invisible
  // to every branch manager). If the client didn't send one, use the rep's
  // current branch, else the customer's most-recent visit branch, else their
  // preferred branch.
  // Phase 1 (2026-11-22): a sales / branch-manager sale is ALWAYS in his own
  // branch (a typed other branch is refused, never stored); an admin's typed
  // branch must be one of the system's (intakeBranch — the 6 codes, their
  // aliases, an active_branches id), else 400 — never free text as a branch.
  const typedBranch = branch != null && String(branch).trim() !== '' ? String(branch).trim() : null;
  let branchVal = null;
  if (role === 'sales' || role === 'branch_manager') {
    const own = req.user.branch || null;
    if (!own) {
      return res.status(400).json({ error: 'حسابك مش متربط بفرع — كلّم مدير النظام', code: 'no_own_branch' });
    }
    if (typedBranch && intakeBranch(typedBranch, { db }) !== own && typedBranch !== own) {
      return res.status(403).json({ error: 'تقدر تسجّل البيعة في فرعك بس', code: 'other_branch' });
    }
    branchVal = own;
  } else if (typedBranch) {
    branchVal = intakeBranch(typedBranch, { db });
    if (!branchVal) {
      return res.status(400).json({ error: 'الفرع ده مش من فروع السيستم — اختار من القايمة', code: 'invalid_branch' });
    }
  }
  if (!branchVal && rep) {
    branchVal = db.prepare(`SELECT branch FROM users WHERE TRIM(name) = TRIM(?) LIMIT 1`).get(rep)?.branch || null;
  }
  if (!branchVal) {
    branchVal = db.prepare(`SELECT branch FROM lead_visits WHERE user_id = ? ORDER BY visited_at DESC LIMIT 1`).get(user_id)?.branch
      || db.prepare(`SELECT preferred_branch FROM lead_profiles WHERE user_id = ?`).get(user_id)?.preferred_branch
      || null;
  }

  // «البيعة تتحسب لمين؟» — admin / branch manager credit a salesperson of the
  // sale's branch (the DB's exact name, never the client's string).
  const creditName = (role === 'admin' || role === 'branch_manager') && typeof sales_rep === 'string'
    ? sales_rep.trim() : '';
  let creditedByOther = false;
  if (creditName && creditName !== String(req.user?.name || '').trim()) {
    if (role === 'branch_manager' && branchVal !== req.user.branch) {
      return res.status(403).json({
        error: 'تقدر تسجّل البيعة باسم سيلز فرعك بس، وفي فرعك', code: 'other_branch',
      });
    }
    const repRow = branchVal ? findBranchSalesRep(db, creditName, branchVal) : null;
    if (!repRow) {
      return res.status(400).json({
        error: 'السيلز ده مش من سيلز الفرع (أو متوقف) — اختار من القايمة', code: 'rep_not_in_branch',
      });
    }
    rep = repRow.name;
    creditedByOther = true;
  }

  const contractNumber = normalizeContractNumber(contract_number);

  // Double entry (the same contract, or a double click) → 409, nothing written.
  const dup = findDuplicatePurchase(db, { userId: user_id, contractNumber, rep, productIds, lines });
  if (dup) return res.status(409).json({ error: dup.error, code: dup.code, purchase_id: dup.purchase_id });

  const purchaseId = db.transaction(() => {
    const id = insertPurchaseRows(db, {
      userId: user_id, legacyLabel: legacyProductLabel, price, branch: branchVal,
      notes: notes || null, rep, contractNumber, productIds, lines,
      enteredBy: req.user?.name || null, enteredById: req.user?.id ?? null,
      enteredByRole: req.user?.role || null, enteredVia: 'staff',
    });
    // Phase 2 r2: he bought — today's «مشي» answer at the sale's branch goes.
    clearLeftOnSale(db, user_id, branchVal);
    return id;
  })();

  console.log(`💰 PURCHASE: user:${user_id} product:${product_id || '?'} price:${price || '?'} rep:${rep || '?'}` +
    (creditedByOther ? ` (entered by ${req.user?.name})` : ''));

  afterPurchase(db, req, {
    userId: user_id, purchaseId, rep, branch: branchVal, price, contractNumber, viaReception: false, creditedByOther,
  });

  return res.json({ ok: true, purchase_id: purchaseId, lead_class: 'purchased', rep });
 } catch (err) {
  console.error('[purchases] failed:', err && err.message);
  if (!res.headersSent) res.status(500).json({ error: 'حصلت مشكلة — جرّب تاني' });
 }
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

  // One clause per tab — a function because the cross-tab counter below needs
  // the other two tabs' clauses with the SAME search + role scoping.
  const statusClause = (s) => {
    if (s === 'bought') return `(lp.lead_class = 'purchased' OR lp.purchased_at IS NOT NULL)`;
    if (s === 'lost')   return `lp.lead_class != 'purchased' AND lp.purchased_at IS NULL
                                AND lp.revisit_status = 'lost'`;
    return `lp.lead_class != 'purchased' AND lp.purchased_at IS NULL
            AND (lp.revisit_status IS NULL OR lp.revisit_status = 'pending')`;
  };
  const statusWhere = statusClause(status);

  let rbacWhere = '1=1';
  const params = [];
  if (role === 'branch_manager') {
    const b = req.user.branch || null;
    if (!b) return res.status(400).json({ error: 'branch_required' });
    // A visited customer belongs to the branch where they closed their LATEST
    // interaction (purchase branch if bought, else most-recent visit branch), so
    // a customer who bought in another branch never shows for this manager.
    rbacWhere = `COALESCE(
      (SELECT pu.branch FROM purchases pu WHERE pu.user_id = lp.user_id ORDER BY pu.created_at DESC, pu.id DESC LIMIT 1),
      (SELECT v.branch FROM lead_visits v WHERE v.user_id = lp.user_id ORDER BY v.visited_at DESC LIMIT 1)
    ) = ?`;
    params.push(b);
  } else if (role === 'sales' || role === 'rep') {
    const me       = req.user.name;
    const myBranch = req.user.branch || null;
    // A visited customer's post-visit OWNER is whoever closed their LATEST
    // showroom interaction: the purchase's rep if they bought, otherwise their
    // most-recent visit's sales_rep — scoped to that owner's branch. This stops a
    // customer who bought in one branch from appearing for a rep in another branch
    // just because a stray visit got logged there, and supersedes the old
    // assigned_rep / any-visit matching that leaked across reps and branches.
    rbacWhere = `
      TRIM(COALESCE(
        (SELECT pu.rep FROM purchases pu WHERE pu.user_id = lp.user_id ORDER BY pu.created_at DESC, pu.id DESC LIMIT 1),
        (SELECT v.sales_rep FROM lead_visits v WHERE v.user_id = lp.user_id ORDER BY v.visited_at DESC LIMIT 1)
      )) = TRIM(?)${myBranch ? ` AND COALESCE(
        (SELECT pu.branch FROM purchases pu WHERE pu.user_id = lp.user_id ORDER BY pu.created_at DESC, pu.id DESC LIMIT 1),
        (SELECT v.branch FROM lead_visits v WHERE v.user_id = lp.user_id ORDER BY v.visited_at DESC LIMIT 1)
      ) = ?` : ''}`;
    params.push(me);
    if (myBranch) params.push(myBranch);
  }

  // Optional name/phone search (?q=) — same dialect as عملاء الفرع, so a number
  // typed with spaces / dashes / +2 still matches. It sits INSIDE the same WHERE
  // as the status + RBAC clauses (never widening either), so the manager searches
  // the WHOLE scoped set — not just the newest 300 rows the list shows.
  // ?rep= (2026-11-25 review): one person's post-visit customers — the
  // «نقل» tool's second group, so a STOPPED salesperson's waiting visited
  // customers can be moved off him (they have no performance row any more).
  // The admin also gives ?branch= (his scope is every branch). It only
  // narrows the role scoping above, never widens it.
  const repFilter = (req.query.rep && String(req.query.rep).trim()) || null;
  if (repFilter) {
    rbacWhere += ` AND TRIM(${OWNER_REP_SQL}) = TRIM(?)`;
    params.push(repFilter);
    if (role === 'admin' && req.query.branch) {
      rbacWhere += ` AND ${OWNER_BRANCH_SQL} = ?`;
      params.push(String(req.query.branch));
    }
  }

  const search = searchTerms(req.query.q);
  // A 1-3 digit fragment isn't a phone search: '%50%' hits nearly every number
  // in the branch and floods the 300-row list — pushing the row the manager
  // actually typed (a NAME containing "50") out of it. Only run the phone LIKEs
  // once the typed number is selective enough to mean something.
  const byPhone = !!search && search.phoneDigits >= 4;
  const searchWhere = search ? `(
        lp.first_name LIKE ? ESCAPE '\\'${byPhone ? `
        OR COALESCE(lp.phone,'') LIKE ? ESCAPE '\\'
        OR EXISTS (SELECT 1 FROM lead_phones ph
                   WHERE ph.user_id = lp.user_id AND ph.phone LIKE ? ESCAPE '\\')` : ''}
      )` : '1=1';
  if (search) {
    params.push(search.like);
    if (byPhone) params.push(search.phoneLike, search.phoneLike);
  }

  const customers = db.prepare(`
    SELECT
      lp.user_id, lp.first_name,
      -- The phone usually lives in lead_phones, not lp.phone — fall back to it
      -- so the number actually shows (the branch manager couldn't see it before).
      COALESCE(lp.phone, (SELECT ph.phone FROM lead_phones ph
                          WHERE ph.user_id = lp.user_id ORDER BY ph.id LIMIT 1)) AS phone,
      lp.total_score, lp.lead_class,
      lp.last_product, lp.last_category, lp.last_activity, lp.visit_at,
      lp.campaign_source, lp.manychat_source, lp.preferred_branch,
      lp.revisit_status, lp.revisit_note, lp.revisit_updated_by, lp.revisit_updated_at,
      lp.purchased_at,
      ${OWNER_BRANCH_SQL} AS branch,
      ${OWNER_REP_SQL}    AS sales_rep,
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
         ORDER BY rf.created_at DESC LIMIT 1) AS last_followup_note,
      ${crossBranchCols('lp.user_id')}
    FROM lead_profiles lp
    WHERE lp.visit_confirmed = 1
      -- Duplicate leads the branch manager flagged never reach the rep's queue.
      AND COALESCE(lp.is_duplicate, 0) = 0
      AND ${statusWhere}
      AND ${rbacWhere}
      AND ${searchWhere}
    ORDER BY COALESCE(lp.revisit_updated_at, lp.purchased_at, lp.last_activity) DESC
    LIMIT 300
  `).all(...params);
  // A work-queue flag, not a performance row (2026-11-25 review): the owner
  // (sales_rep) has no ACTIVE account — stopped, or a removed name — so
  // nobody's queue holds this customer until a person moves him («نقل» /
  // assign-post). The same rule as every hidden performance row.
  const who = honest.sellers(db);
  for (const c of customers) c.owner_stopped = c.sales_rep && !who.shown(c.sales_rep) ? 1 : 0;

  // Searching? Tell the UI how many rows the SAME search (and the SAME role
  // scoping) hits in each tab — that's what lets the page say "لقيته في: اشتروا"
  // when the manager types a number while standing on the wrong tab.
  const otherTabMatches = search ? {} : null;
  if (search) {
    for (const s of ['pending', 'bought', 'lost']) {
      otherTabMatches[s] = db.prepare(`
        SELECT COUNT(*) AS n FROM lead_profiles lp
        WHERE lp.visit_confirmed = 1
          AND COALESCE(lp.is_duplicate, 0) = 0
          AND ${statusClause(s)}
          AND ${rbacWhere}
          AND ${searchWhere}
      `).get(...params).n;
    }
  }

  return res.json({
    status, count: customers.length, customers, other_tab_matches: otherTabMatches,
    // The list is capped at 300 rows. When the search matches more, send the REAL
    // total (already counted just above) so the page can say "بيظهر أول 300 من N"
    // — otherwise a manager whose customer fell past the cap reads "300 عميل" as
    // "everyone" and concludes the customer isn't in the CRM.
    total: otherTabMatches ? otherTabMatches[status] : null,
  });
});

// POST /api/revisit/:userId/close — sales/manager closes a customer who won't
// buy (e.g. bought elsewhere). Body: { note }.
app.post('/api/revisit/:userId/close', requireAuth, authorizeRoles('admin', 'branch_manager', 'sales', 'rep'), (req, res) => {
  const { userId } = req.params;
  const note = (req.body?.note && String(req.body.note).trim()) || null;
  const db = getDb();
  const lead = db.prepare(`SELECT user_id FROM lead_profiles WHERE user_id = ?`).get(userId);
  if (!lead) return res.status(404).json({ error: 'lead_not_found' });
  if (!canActOnLead(db, req.user, userId)) return res.status(404).json({ error: 'lead_not_found' });   // phase 0 r2

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
  if (!canActOnLead(db, req.user, userId)) return res.status(404).json({ error: 'lead_not_found' });   // phase 0 r2

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
  if (!canActOnLead(db, req.user, userId)) return res.status(404).json({ error: 'lead_not_found' });   // phase 0 r2

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
  // Phase 0 r2: another branch's / rep's customer → 404, as GET /api/leads/:id.
  if (!canSeeLead(db, req.user, req.params.userId)) return res.status(404).json({ error: 'lead_not_found' });
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
    // A visited customer belongs to the branch where they closed their LATEST
    // interaction (purchase branch if bought, else most-recent visit branch), so
    // a customer who bought in another branch never shows for this manager.
    rbacWhere = `COALESCE(
      (SELECT pu.branch FROM purchases pu WHERE pu.user_id = lp.user_id ORDER BY pu.created_at DESC, pu.id DESC LIMIT 1),
      (SELECT v.branch FROM lead_visits v WHERE v.user_id = lp.user_id ORDER BY v.visited_at DESC LIMIT 1)
    ) = ?`;
    params.push(b);
  } else if (role === 'sales' || role === 'rep') {
    const me       = req.user.name;
    const myBranch = req.user.branch || null;
    // A visited customer's post-visit OWNER is whoever closed their LATEST
    // showroom interaction: the purchase's rep if they bought, otherwise their
    // most-recent visit's sales_rep — scoped to that owner's branch. This stops a
    // customer who bought in one branch from appearing for a rep in another branch
    // just because a stray visit got logged there, and supersedes the old
    // assigned_rep / any-visit matching that leaked across reps and branches.
    rbacWhere = `
      TRIM(COALESCE(
        (SELECT pu.rep FROM purchases pu WHERE pu.user_id = lp.user_id ORDER BY pu.created_at DESC, pu.id DESC LIMIT 1),
        (SELECT v.sales_rep FROM lead_visits v WHERE v.user_id = lp.user_id ORDER BY v.visited_at DESC LIMIT 1)
      )) = TRIM(?)${myBranch ? ` AND COALESCE(
        (SELECT pu.branch FROM purchases pu WHERE pu.user_id = lp.user_id ORDER BY pu.created_at DESC, pu.id DESC LIMIT 1),
        (SELECT v.branch FROM lead_visits v WHERE v.user_id = lp.user_id ORDER BY v.visited_at DESC LIMIT 1)
      ) = ?` : ''}`;
    params.push(me);
    if (myBranch) params.push(myBranch);
  }

  // One row per customer who visited the showroom.
  const rows = db.prepare(`
    SELECT
      lp.user_id, lp.lead_class, lp.purchased_at, lp.revisit_status,
      ${OWNER_BRANCH_SQL} AS branch,
      ${OWNER_REP_SQL}    AS sales_rep,
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

  // Stopped salespeople (2026-11-25): no row; their customers stay in the
  // summary and the branches, stopped_sales.customers says how many.
  const { rows: salesRows, hidden } = honest.hideStopped([...salesMap.values()], honest.sellers(db), (r) => r.sales_rep,
    { customers: (r) => r.pending + r.bought + r.lost });
  return res.json({
    summary,
    byBranch: [...branchMap.values()].map(withRate).sort((a, b) => b.bought - a.bought),
    bySales:  salesRows.map(withRate).sort((a, b) => b.bought - a.bought),
    ...(hidden.rows ? { stopped_sales: { customers: hidden.customers, removed: hidden.removed } } : {}),
  });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/admin/sales-followup-monitor — admin oversight of every sales rep's
// follow-up work. Returns, per rep, the PRE-visit and POST-visit follow-up
// activity kept SEPARATE so the admin can tell at a glance who is actually
// following up vs not, and read what they wrote:
//   pre  → assigned / followed / pending (+ the customers still pending and the
//          latest follow-up notes they logged in followup_log)
//   post → revisit owned / followed / pending (+ the customers still pending and
//          the latest revisit notes from revisit_followups)
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/admin/sales-followup-monitor', requireAuth, authorizeRoles('admin', 'branch_manager'), (req, res) => {
  const db = getDb();

  // Admin sees every showroom rep; a branch manager sees ONLY their own branch's
  // reps — the active ones (2026-11-25; before, the stopped ones were listed too).
  const myBranch = req.user?.role === 'branch_manager' ? (req.user.branch || null) : null;
  if (req.user?.role === 'branch_manager' && !myBranch) {
    return res.status(400).json({ error: 'branch_required' });
  }
  // 2026-11-25 (owner: «اللي يتوقف يتأرشف وميبانش تاني»): ACTIVE ones only — a
  // stopped salesperson's history stays in the data, never as a row here.
  const reps = myBranch
    ? db.prepare(`SELECT name, branch FROM users WHERE role IN ('sales','rep') AND active = 1 AND branch = ? ORDER BY name`).all(myBranch)
    : db.prepare(`SELECT name, branch FROM users WHERE role IN ('sales','rep') AND active = 1 ORDER BY branch, name`).all();

  // ── PRE-visit (branch_customer_followups, customer not yet visited) ─────────
  const preAgg = db.prepare(`
    SELECT
      COUNT(*) AS assigned,
      COALESCE(SUM(CASE WHEN f.followed_up = 1 THEN 1 ELSE 0 END), 0) AS followed,
      -- attempted: still pending, but the rep DID try to reach the customer —
      -- either called with no answer (attempt_count) OR sent the WhatsApp
      -- outreach (sent=1) and is waiting for a reply. Both are real effort, so
      -- "لسه" splits into "حاول التواصل" vs "لم يحاول خالص".
      COALESCE(SUM(CASE WHEN f.followed_up = 0
        AND (COALESCE(f.attempt_count, 0) > 0 OR COALESCE(f.sent, 0) = 1)
        THEN 1 ELSE 0 END), 0) AS attempted
    FROM branch_customer_followups f
    JOIN lead_profiles lp ON lp.user_id = f.user_id
    WHERE TRIM(f.assigned_sales) = TRIM(?)
      AND COALESCE(lp.visit_confirmed, 0) = 0
  `);
  const prePending = db.prepare(`
    SELECT f.user_id, lp.first_name, f.assigned_at, f.sent,
      COALESCE(f.attempt_count, 0) AS attempt_count, f.last_attempt_at,
      (SELECT ph.phone FROM lead_phones ph WHERE ph.user_id = f.user_id ORDER BY ph.id LIMIT 1) AS phone
    FROM branch_customer_followups f
    JOIN lead_profiles lp ON lp.user_id = f.user_id
    WHERE TRIM(f.assigned_sales) = TRIM(?)
      AND COALESCE(lp.visit_confirmed, 0) = 0
      AND f.followed_up = 0
    -- Being-worked first (unanswered calls OR sent WhatsApp), then newest.
    ORDER BY (COALESCE(f.attempt_count, 0) > 0 OR COALESCE(f.sent, 0) = 1) DESC, f.assigned_at DESC
    LIMIT 25
  `);
  const preRecent = db.prepare(`
    SELECT fl.user_id, lp.first_name, fl.call_summary, fl.followed_up_at
    FROM followup_log fl
    LEFT JOIN lead_profiles lp ON lp.user_id = fl.user_id
    WHERE TRIM(fl.sales) = TRIM(?) AND fl.call_summary IS NOT NULL
    ORDER BY fl.followed_up_at DESC, fl.id DESC
    LIMIT 15
  `);

  // ── POST-visit (revisit; owner-based; still pending = not bought/lost) ──────
  const postAgg = db.prepare(`
    SELECT
      COUNT(*) AS total,
      COALESCE(SUM(CASE WHEN (SELECT COUNT(*) FROM revisit_followups rf WHERE rf.user_id = lp.user_id) > 0 THEN 1 ELSE 0 END), 0) AS followed
    FROM lead_profiles lp
    WHERE lp.visit_confirmed = 1
      AND lp.lead_class != 'purchased' AND lp.purchased_at IS NULL
      AND (lp.revisit_status IS NULL OR lp.revisit_status = 'pending')
      AND TRIM(${OWNER_REP_SQL}) = TRIM(?)
  `);
  const postPending = db.prepare(`
    SELECT lp.user_id, lp.first_name, lp.last_activity,
      COALESCE(lp.phone, (SELECT ph.phone FROM lead_phones ph WHERE ph.user_id = lp.user_id ORDER BY ph.id LIMIT 1)) AS phone
    FROM lead_profiles lp
    WHERE lp.visit_confirmed = 1
      AND lp.lead_class != 'purchased' AND lp.purchased_at IS NULL
      AND (lp.revisit_status IS NULL OR lp.revisit_status = 'pending')
      AND TRIM(${OWNER_REP_SQL}) = TRIM(?)
      AND (SELECT COUNT(*) FROM revisit_followups rf WHERE rf.user_id = lp.user_id) = 0
    ORDER BY lp.last_activity DESC
    LIMIT 25
  `);
  const postRecent = db.prepare(`
    SELECT rf.user_id, lp.first_name, rf.note, rf.created_at
    FROM revisit_followups rf
    LEFT JOIN lead_profiles lp ON lp.user_id = rf.user_id
    WHERE TRIM(rf.followed_up_by) = TRIM(?)
    ORDER BY rf.created_at DESC, rf.id DESC
    LIMIT 15
  `);

  const out = reps.map((r) => {
    const pa  = preAgg.get(r.name)  || { assigned: 0, followed: 0, attempted: 0 };
    const poa = postAgg.get(r.name) || { total: 0, followed: 0 };
    return {
      sales_rep: r.name,
      branch: r.branch || null,
      pre: {
        assigned:  pa.assigned || 0,
        followed:  pa.followed || 0,
        // Tried to call but the customer didn't answer (still pending).
        attempted: pa.attempted || 0,
        pending:   (pa.assigned || 0) - (pa.followed || 0),
        // Pending customers the rep never even TRIED to reach.
        untouched: (pa.assigned || 0) - (pa.followed || 0) - (pa.attempted || 0),
        pending_list: prePending.all(r.name),
        recent:       preRecent.all(r.name),
      },
      post: {
        total:    poa.total || 0,
        followed: poa.followed || 0,
        pending:  (poa.total || 0) - (poa.followed || 0),
        pending_list: postPending.all(r.name),
        recent:       postRecent.all(r.name),
      },
    };
  });

  // Hide reps with literally nothing (assignment or activity) to cut noise — but
  // if that empties the list, fall back to showing everyone so the page isn't blank.
  const active = out.filter(
    (r) => r.pre.assigned || r.post.total || r.pre.recent.length || r.post.recent.length
  );
  return res.json({ reps: active.length ? active : out });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/admin/sales-daily-activity — the SIMPLE per-rep, per-DAY activity
// view: on which day each rep followed up, how many, and how many they reached
// out to (WhatsApp sent / called with no answer) — plus their pending backlog.
// Grouped queries across ALL reps (no per-rep loops), merged in JS.
// Query param: days (int, default 14, clamped 1..60).
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/admin/sales-daily-activity', requireAuth, authorizeRoles('admin', 'branch_manager'), (req, res) => {
  const db = getDb();

  // Same scoping as the follow-up monitor above: admin sees every showroom rep;
  // a branch manager sees ONLY their own branch's reps — active ones only
  // (2026-11-25: a stopped salesperson gets no row).
  const myBranch = req.user?.role === 'branch_manager' ? (req.user.branch || null) : null;
  if (req.user?.role === 'branch_manager' && !myBranch) {
    return res.status(400).json({ error: 'branch_required' });
  }
  const reps = myBranch
    ? db.prepare(`SELECT name, branch, active FROM users WHERE role IN ('sales','rep') AND active = 1 AND branch = ? ORDER BY name`).all(myBranch)
    : db.prepare(`SELECT name, branch, active FROM users WHERE role IN ('sales','rep') AND active = 1 ORDER BY branch, name`).all();

  const days = Math.min(60, Math.max(1, parseInt(req.query.days, 10) || 14));
  // CAIRO days (2026-11-22 «أرقام حقيقية» r2): the window is the last `days`
  // Cairo days, today included, and every row lands on its Cairo day — a
  // follow-up at 00:30 Cairo is on that day, never the UTC day before. The
  // rows are read with their timestamps and bucketed here (honest.dayOf).
  const today = cairoDay();
  const fromDay = honest.addDays(today, -(days - 1));
  const since = cairoDayBoundsSql(fromDay)[0];
  const perDay = (rows, extra) => {
    const m = new Map();
    for (const r of rows) {
      const day = honest.dayOf(r.at);
      if (!day || day < fromDay || day > today) continue;
      const k = `${r.rep}\u0000${day}`;
      if (!m.has(k)) m.set(k, { rep: r.rep, day, n: 0, contacted: 0 });
      const o = m.get(k); o.n += 1; if (extra) o.contacted += extra(r) ? 1 : 0;
    }
    return [...m.values()];
  };

  // 1) Completed PRE-visit follow-ups per rep/day (append-only followup_log).
  const preRows = perDay(db.prepare(`
    SELECT TRIM(sales) AS rep, followed_up_at AS at FROM followup_log
    WHERE datetime(followed_up_at) >= ?
  `).all(since));

  // 2) Completed POST-visit follow-ups per rep/day (append-only revisit_followups).
  const postRows = perDay(db.prepare(`
    SELECT TRIM(followed_up_by) AS rep, created_at AS at FROM revisit_followups
    WHERE datetime(created_at) >= ?
  `).all(since));

  // 3) WhatsApp outreach sends per rep/day. sent_at holds the LATEST send per
  //    customer, so this counts customers whose latest send fell on that day.
  const sentRows = perDay(db.prepare(`
    SELECT TRIM(assigned_sales) AS rep, sent_at AS at FROM branch_customer_followups
    WHERE sent = 1 AND sent_at IS NOT NULL AND datetime(sent_at) >= ?
  `).all(since));

  // 4) Unanswered call attempts per rep/day. Only the LAST attempt's timestamp
  //    is stored per customer, so this counts customers whose latest unanswered
  //    attempt fell on that day — an acceptable approximation of daily effort.
  const attemptRows = perDay(db.prepare(`
    SELECT TRIM(assigned_sales) AS rep, last_attempt_at AS at FROM branch_customer_followups
    WHERE COALESCE(attempt_count, 0) > 0 AND last_attempt_at IS NOT NULL
      AND datetime(last_attempt_at) >= ?
  `).all(since));

  // 5) Pending backlog per rep (assigned, not yet visited, not yet followed up)
  //    — same shape as the monitor's preAgg, but grouped across all reps.
  const pendingRows = db.prepare(`
    SELECT TRIM(f.assigned_sales) AS rep, COUNT(*) AS n
    FROM branch_customer_followups f
    JOIN lead_profiles lp ON lp.user_id = f.user_id
    WHERE COALESCE(lp.visit_confirmed, 0) = 0 AND f.followed_up = 0
    GROUP BY TRIM(f.assigned_sales)
  `).all();

  // 6) Customers ASSIGNED to each rep per day (by assignment date), plus how
  //    many of that day's batch the rep has contacted. NOTE: "contacted" is the
  //    customer's CURRENT state (followed up OR WhatsApp'd OR attempted a call
  //    at any point since), NOT their state on the assignment day itself — so
  //    the counter keeps climbing as the rep works through that day's batch.
  const assignedRows = perDay(db.prepare(`
    SELECT TRIM(assigned_sales) AS rep, assigned_at AS at,
           CASE WHEN followed_up = 1 OR COALESCE(sent, 0) = 1 OR COALESCE(attempt_count, 0) > 0 THEN 1 ELSE 0 END AS c
    FROM branch_customer_followups
    WHERE assigned_sales IS NOT NULL AND TRIM(assigned_sales) != ''
      AND assigned_at IS NOT NULL AND datetime(assigned_at) >= ?
  `).all(since), (r) => r.c === 1);

  // Merge, keyed by TRIMMED rep name (codebase convention for name matching).
  const byRep = new Map();
  for (const r of reps) {
    byRep.set((r.name || '').trim(), {
      sales_rep: r.name,
      branch: r.branch || null,
      active: r.active,
      pending: 0,
      totals: { followed: 0, post_followed: 0, sent: 0, attempts: 0, assigned: 0, assigned_contacted: 0 },
      dayMap: new Map(),
    });
  }
  // Get-or-create the day object for a rep (shared by bump + the two-count merge).
  const dayOf = (rep, day) => {
    let d = rep.dayMap.get(day);
    if (!d) {
      d = { day, followed: 0, post_followed: 0, sent: 0, attempts: 0, assigned: 0, assigned_contacted: 0 };
      rep.dayMap.set(day, d);
    }
    return d;
  };
  const bump = (rows, field) => {
    for (const row of rows) {
      const rep = byRep.get(row.rep);
      if (!rep || !row.day) continue;
      const d = dayOf(rep, row.day);
      d[field] += row.n;
      rep.totals[field] += row.n;
    }
  };
  bump(preRows, 'followed');
  bump(postRows, 'post_followed');
  bump(sentRows, 'sent');
  bump(attemptRows, 'attempts');
  // Two-count merge for the assignment query: n → assigned, contacted → assigned_contacted.
  for (const row of assignedRows) {
    const rep = byRep.get(row.rep);
    if (!rep || !row.day) continue;
    const d = dayOf(rep, row.day);
    d.assigned += row.n;
    d.assigned_contacted += row.contacted;
    rep.totals.assigned += row.n;
    rep.totals.assigned_contacted += row.contacted;
  }
  for (const row of pendingRows) {
    const rep = byRep.get(row.rep);
    if (rep) rep.pending = row.n;
  }

  // Every rep is included even with zero activity — the admin needs to SEE who
  // did nothing. Days: only days with activity, newest first.
  const out = [...byRep.values()].map(({ dayMap, ...rep }) => ({
    ...rep,
    days: [...dayMap.values()].sort((a, b) => (a.day < b.day ? 1 : -1)),
  }));
  return res.json({ days, from: fromDay, to: today, timezone: CAIRO_TZ, reps: out });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/leads/:user_id/purchases — Purchase history for a lead
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/leads/:user_id/purchases', requireAuth, (req, res) => {
  const db = getDb();
  // Same scope as the profile itself (phase 0) — its only caller is LeadDetail.
  if (!canSeeLead(db, req.user, req.params.user_id)) return res.status(404).json({ error: 'Lead not found' });
  const purchases = db.prepare(`
    SELECT * FROM purchases WHERE user_id = ? ORDER BY created_at DESC
  `).all(req.params.user_id);

  // Attach catalog items to each purchase (may be empty for legacy rows).
  if (purchases.length) {
    const itemsByPurchase = db.prepare(`
      SELECT pi.purchase_id, p.id, p.name, c.name AS category_name
      FROM purchase_items pi
      JOIN products p             ON p.id = pi.product_id
      JOIN product_categories c   ON c.id = p.category_id
      WHERE pi.purchase_id IN (${purchases.map(() => '?').join(',')})
      ORDER BY c.sort_order, p.name
    `).all(...purchases.map(p => p.id));
    const grouped = {};
    for (const it of itemsByPurchase) {
      if (!grouped[it.purchase_id]) grouped[it.purchase_id] = [];
      grouped[it.purchase_id].push({ id: it.id, name: it.name, category_name: it.category_name });
    }
    for (const p of purchases) p.items = grouped[p.id] || [];
    // 2026-11-22: the prices system's lines; the estimate for the admin only.
    const pids = purchases.map(p => p.id);
    const linesBy = readPurchaseLines(db, pids);
    const estBy = req.user?.role === 'admin' ? readPurchaseEstimates(db, pids) : null;
    for (const p of purchases) {
      p.lines = linesBy.get(p.id) || [];
      if (estBy) p.estimate = estBy.get(p.id) || null;
    }
  }

  return res.json({ purchases });
});

// ── «فلترة التعاقدات» (2026-11-25, «اعملي فلترة في التعاقدات … ويبقي في تعديل
// لتاريخ التعاقد لمدير الفرع») ───────────────────────────────────────────────
// GET /api/contracts narrows by salesperson (?rep=, «من غير سيلز» = ?rep=__none__),
// searches the contract number (?number=, part of it) and sorts (?sort=) — all
// in SQL, before the 500-row LIMIT, so the list, the header's «N تعاقد —
// إجمالي X» and the cap agree. Every one only NARROWS the caller's role scope
// (sales → his own, a manager → his branch): ?rep / ?branch / ?number never
// reach a contract the role can't see. Checked by scripts/smoke-contracts-filters.js.
const CONTRACT_SORTS = {
  // newest = the order the page always had (the contract's date, newest first)
  newest:      () => `datetime(p.created_at) DESC, p.id DESC`,
  oldest:      () => `datetime(p.created_at) ASC, p.id ASC`,
  // the number's DIGITS as a number (2 < 10 < 100: shorter digit string first,
  // then the digits), a contract with no digits last in both directions; ties
  // (the same number) newest first. Digit strings are compared as text after
  // the leading zeros go, so a 25-digit number never overflows.
  number_asc:  () => `(contract_no_digits(p.contract_number) IS NULL), LENGTH(contract_no_digits(p.contract_number)) ASC,
                      contract_no_digits(p.contract_number) ASC, datetime(p.created_at) DESC, p.id DESC`,
  number_desc: () => `(contract_no_digits(p.contract_number) IS NULL), LENGTH(contract_no_digits(p.contract_number)) DESC,
                      contract_no_digits(p.contract_number) DESC, datetime(p.created_at) DESC, p.id DESC`,
};
const CONTRACT_NO_REP = '__none__';      // ?rep= for «من غير سيلز»
const CONTRACT_NUMBER_MAX = 30;          // characters of a searched number (after the cleanup)
const CONTRACT_REP_MAX = 100;
// Arabic-Indic (٠-٩) and extended (۰-۹) digits → 0-9.
const westernDigits = (v) => String(v)
  .replace(/[٠-٩]/g, (c) => String(c.charCodeAt(0) - 0x0660))
  .replace(/[۰-۹]/g, (c) => String(c.charCodeAt(0) - 0x06F0));
// What a contract number is searched on: Western digits, no spaces, dashes,
// underscores or direction marks, lower-case («١٢٣ - ٤» = «1234» = «12-34»).
function contractNoKey(v) {
  if (v == null) return '';
  return westernDigits(v).replace(/[\s\-_‐-―−‎‏‪-‮⁦-⁩]/g, '').toLowerCase();
}
// What a contract number is SORTED on: its digits (Western), leading zeros
// dropped («007» = 7); no digit at all → null (sorted last).
function contractNoDigits(v) {
  if (v == null) return null;
  const d = westernDigits(v).replace(/[^0-9]/g, '');
  return d ? d.replace(/^0+(?=\d)/, '') : null;
}
const contractSqlFnsOn = new WeakSet();
function contractSqlFns(db) {
  if (contractSqlFnsOn.has(db)) return;
  db.function('contract_no_key', { deterministic: true }, (v) => contractNoKey(v));
  db.function('contract_no_digits', { deterministic: true }, (v) => contractNoDigits(v));
  contractSqlFnsOn.add(db);
}
// The query's filters → { sort, number, rep, noRep, branch } | { error, code }.
// A value sent twice (?rep=a&rep=b → an array) is a 400, never a guess.
function parseContractFilters(db, q, role) {
  const one = (k) => {
    const v = q[k];
    if (v == null) return '';
    if (typeof v !== 'string') return null;
    return v.trim();
  };
  const bad = (error, code) => ({ error, code });
  const sortIn = one('sort');
  if (sortIn === null) return bad('الترتيب ده مش معروف', 'bad_sort');
  const sort = sortIn || 'newest';
  if (!Object.prototype.hasOwnProperty.call(CONTRACT_SORTS, sort)) return bad('الترتيب ده مش معروف — اختار من القايمة', 'bad_sort');
  const numIn = one('number');
  if (numIn === null) return bad('رقم العقد مش مفهوم', 'bad_number');
  const number = contractNoKey(numIn);
  // review r2: a box of dashes / underscores / direction marks only cleans down
  // to nothing — said, never a silent «every contract matched».
  if (numIn && !number) return bad('اكتب رقم العقد أو جزء منه — الشَرطة والمسافات لوحدها مش بتدوّر على حاجة', 'bad_number');
  if (numIn.length > CONTRACT_NUMBER_MAX * 2 || number.length > CONTRACT_NUMBER_MAX) {
    return bad(`رقم العقد طويل أوي — اكتب ${CONTRACT_NUMBER_MAX} حرف بالكتير`, 'bad_number');
  }
  const repIn = one('rep');
  if (repIn === null || (repIn && repIn.length > CONTRACT_REP_MAX)) return bad('اسم السيلز مش مفهوم — اختار من القايمة', 'bad_rep');
  // sales / rep: always their own contracts — ?rep is ignored (never widens).
  const canPickRep = role === 'admin' || role === 'branch_manager';
  const rep = canPickRep && repIn && repIn !== CONTRACT_NO_REP ? repIn : null;
  const noRep = canPickRep && repIn === CONTRACT_NO_REP;
  // ?branch — the admin only (a manager stays on his own branch): a system
  // branch (or an alias of one), or a branch that contracts carry.
  let branch = null;
  const brIn = one('branch');
  if (brIn === null) return bad('الفرع ده مش من فروع السيستم — اختار من القايمة', 'invalid_branch');
  if (role === 'admin' && brIn) {
    branch = intakeBranch(brIn, { db })
      || (db.prepare(`SELECT 1 FROM purchases WHERE branch = ? LIMIT 1`).get(brIn) ? brIn : null);
    if (!branch) return bad('الفرع ده مش من فروع السيستم — اختار من القايمة', 'invalid_branch');
  }
  return { sort, number: number || null, rep, noRep, branch };
}
// The admin's «الفرع» choices on «التعاقدات» (review r2): the configured
// branches + every branch a contract carries — each one passes
// parseContractFilters' ?branch= rule (an events-only value never shows).
function contractBranchChoices(db) {
  const names = branchLabelMap(db);
  const out = new Map();
  for (const b of activeBranchIds(db)) out.set(b.id, { id: b.id, name: names[b.id] || null });
  for (const r of db.prepare(`SELECT DISTINCT branch FROM purchases WHERE branch IS NOT NULL AND TRIM(branch) <> ''`).all()) {
    if (!out.has(r.branch)) out.set(r.branch, { id: r.branch, name: names[r.branch] || null });
  }
  return [...out.values()];
}
// «فلتر السيلز»'s choices: the ACTIVE sellers of the branch (all branches for
// the admin with no branch picked) — the active salespeople there, plus an
// active manager / admin who has contracts there in his own name. A stopped
// salesperson is in no list (honest.sellers, owner 2026-11-25 «اللي يتوقف
// يتأرشف وميبانش تاني»): his contracts stay in the list and every total.
function contractRepChoices(db, branch) {
  const who = honest.sellers(db);
  const branchOf = new Map(db.prepare(`SELECT name, branch FROM users WHERE active = 1`).all()
    .map((u) => [String(u.name || '').trim(), u.branch || null]));
  const out = new Map();
  const users = branch
    ? db.prepare(`SELECT name, branch FROM users WHERE role IN ('sales', 'rep') AND active = 1 AND branch = ?`).all(branch)
    : db.prepare(`SELECT name, branch FROM users WHERE role IN ('sales', 'rep') AND active = 1`).all();
  for (const u of users) {
    const n = String(u.name || '').trim();
    if (n && who.shown(n)) out.set(n, { name: n, branch: u.branch || null });
  }
  const onContracts = branch
    ? db.prepare(`SELECT DISTINCT TRIM(rep) AS n FROM purchases WHERE branch = ? AND rep IS NOT NULL AND TRIM(rep) <> ''`).all(branch)
    : db.prepare(`SELECT DISTINCT TRIM(rep) AS n FROM purchases WHERE rep IS NOT NULL AND TRIM(rep) <> ''`).all();
  for (const r of onContracts) {
    if (r.n && who.shown(r.n) && !out.has(r.n)) out.set(r.n, { name: r.n, branch: branchOf.get(r.n) || null });
  }
  return [...out.values()].sort((a, b) => a.name.localeCompare(b.name, 'ar'));
}

// ── «تعديل تاريخ التعاقد» (2026-11-25) ─────────────────────────────────────
// A day the contract may be moved to: a real day, 2020-01-01 … today (Cairo).
const CONTRACT_DAY_MIN = '2020-01-01';
// The UTC SQL text of a Cairo wall time on `day` (summer time aware); null when
// that wall time does not exist on that day (the spring-forward hour).
function cairoWallToSqlUtc(day, hh, mm, ss) {
  const [y, m, d] = day.split('-').map(Number);
  const want = Date.UTC(y, m - 1, d, hh, mm, ss);
  let t = want;
  for (let i = 0; i < 3; i++) t = want - cairoOffsetMs(new Date(t));
  const p = cairoParts(new Date(t));
  if (`${p.year}-${p.month}-${p.day}` !== day || +p.hour !== hh || +p.minute !== mm) return null;
  return toSqlUtc(new Date(t));
}
// The contract's new time: the NEW Cairo day at the contract's OWN Cairo time
// of day (a contract typed at 19:40 stays at 19:40), so its place among the
// day's contracts and every Cairo-day count are what they would have been. A
// time of day that does not exist on the new day (summer time) → 12:00; a
// time later than now (the new day is today) → now. → 'YYYY-MM-DD HH:MM:SS' UTC.
function movedContractTime(oldAt, newDay, now = new Date()) {
  const old = sqlUtcToDate(oldAt);
  let hh = 12, mm = 0, ss = 0;
  if (old && !Number.isNaN(old.getTime())) { const p = cairoParts(old); hh = +p.hour; mm = +p.minute; ss = +p.second; }
  let at = cairoWallToSqlUtc(newDay, hh, mm, ss) || cairoWallToSqlUtc(newDay, 12, 0, 0);
  if (at > toSqlUtc(now)) at = toSqlUtc(now);
  return at;
}
// The body's contract_date → { day } | { error, code } (null when not sent).
function parseContractDay(v) {
  if (v == null || v === '') return null;
  if (typeof v !== 'string') return { error: 'تاريخ التعاقد لازم يكون يوم بالشكل ده: 2026-11-20', code: 'bad_contract_date' };
  const day = westernDigits(v.trim());
  if (!honest.isDay(day)) return { error: 'تاريخ التعاقد لازم يكون يوم بالشكل ده: 2026-11-20', code: 'bad_contract_date' };
  if (day < CONTRACT_DAY_MIN) return { error: 'مينفعش تاريخ تعاقد قبل 2020', code: 'contract_date_too_old' };
  if (day > cairoDay()) return { error: 'مينفعش تاريخ التعاقد يبقى بعد النهارده', code: 'contract_date_future' };
  return { day };
}
// A customer's purchased_at = his FIRST contract's date (insertPurchaseRows
// writes it once, at the first sale): after a date edit it follows the
// contracts' dates. Inside the caller's transaction.
function syncPurchasedAt(db, userId) {
  const first = db.prepare(`SELECT created_at FROM purchases WHERE user_id = ? ORDER BY datetime(created_at), id LIMIT 1`).get(userId);
  if (first) db.prepare(`UPDATE lead_profiles SET purchased_at = ? WHERE user_id = ? AND purchased_at IS NOT NULL`).run(first.created_at, userId);
}

// ════════════════════════════════════════════════════════════════════════════
// Contracts module — purchases viewed as contracts.
//   GET    /api/contracts      — RBAC: sales→own, branch_manager→branch, admin→all
//                                ?month=YYYY-MM → that calendar month only.
//                                ?rep= ?number= ?sort= ?branch= (2026-11-25,
//                                parseContractFilters above: they only narrow).
//   PUT    /api/contracts/:id  — admin / branch_manager (manager → own branch)
//                                + contract_date (2026-11-25, the Cairo day)
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

  // Role scope on its own — the months list below must stay on THIS clause so
  // the picker keeps showing every month the caller is allowed to see.
  const roleWhere  = where;
  const roleParams = [...params];

  // Optional filters — month, date range, branch & rep (admin/manager scoping
  // above already constrains non-admins, so these only narrow further).
  const { startDate, endDate } = req.query;
  // 2026-11-25 «فلترة التعاقدات»: salesperson / number / sort / admin branch.
  const f = parseContractFilters(db, req.query, role);
  if (f.error) return res.status(400).json({ error: f.error, code: f.code });
  contractSqlFns(db);

  // month=YYYY-MM → التعاقدات بتاعة الشهر ده بس. A month here is a CAIRO month
  // (2026-11-25 review: the UTC month put a contract made at 00:10 Cairo on
  // the 1st in the month before, so «نوفمبر» and «من يوم لـ يوم» 11-01 → 11-30
  // listed different contracts, and the branch overview's «الشهر ده» a third
  // set). Bad input is a 400, never a silent "here's everything".
  const monthRaw = String(req.query.month ?? '').trim();
  let month = null;
  if (monthRaw) {
    if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(monthRaw)) {
      return res.status(400).json({ error: 'الشهر لازم يكون بصيغة YYYY-MM (مثال: 2026-09)' });
    }
    month = monthRaw;
    // datetime(…) in rangeSql reads BOTH date formats living in this table
    // ("YYYY-MM-DD HH:MM:SS" written by us, and ISO "…T…Z" from older rows).
    const mr = cairoMonthSql('p.created_at', month);
    where += mr.clause;
    params.push(...mr.params);
  }

  if ((startDate && !honest.isDay(startDate)) || (endDate && !honest.isDay(endDate))) {
    return res.status(400).json({ error: 'التاريخ لازم يكون YYYY-MM-DD' });
  }
  const dr = honest.rangeSql('p.created_at', startDate || null, endDate || null);   // Cairo days
  where += dr.clause;
  params.push(...dr.params);
  // the admin's branch (a manager is already on his own; sales on their own)
  if (f.branch) { where += ' AND p.branch = ?'; params.push(f.branch); }
  // part of the number, its digits/spaces/dashes cleaned on both sides
  if (f.number) { where += ' AND instr(contract_no_key(p.contract_number), ?) > 0'; params.push(f.number); }
  // review r2: «من غير سيلز (N)» counts what choosing it would show — every
  // filter (month, days, branch, number) but the salesperson.
  const pickWhere = where; const pickParams = [...params];
  if (f.rep)   { where += ' AND TRIM(p.rep) = ?'; params.push(f.rep); }
  if (f.noRep) { where += ` AND (p.rep IS NULL OR TRIM(p.rep) = '')`; }

  // Listing cap — sent back to the client so the page can say "دي أول 500" بدل
  // ما يبان إن الباقي اتمسح (الملخص تحت بيعدّ من غير الحد ده).
  const LIST_LIMIT = 500;

  const contracts = db.prepare(`
    SELECT p.id, p.user_id, p.price, p.contract_number, p.branch, p.rep,
           p.product_id, p.notes, p.created_at, p.recorded_at,
           p.entered_by, p.entered_by_role, p.entered_via,
           lp.first_name, lp.phone
    FROM purchases p
    LEFT JOIN lead_profiles lp ON lp.user_id = p.user_id
    WHERE ${where}
    ORDER BY ${CONTRACT_SORTS[f.sort]()}
    LIMIT ${LIST_LIMIT}
  `).all(...params);
  // A re-dated contract says so: the latest date change still standing (not
  // undone in «سجل العمليات») — from which day, by whom, when.
  if (contracts.length) {
    const byId = new Map();
    const ph = contracts.map(() => '?').join(',');
    for (const a of db.prepare(`
      SELECT id, operator_name, created_at, old_state, CAST(json_extract(old_state, '$.where.id') AS INTEGER) AS pid
      FROM system_audit_log
      WHERE action_type = 'contract_date_change' AND COALESCE(reverted, 0) = 0
        AND CAST(json_extract(old_state, '$.where.id') AS INTEGER) IN (${ph})
      ORDER BY id DESC`).all(...contracts.map((c) => c.id))) {
      if (byId.has(a.pid)) continue;
      let st = null; try { st = JSON.parse(a.old_state); } catch (_) {}
      const d = sqlUtcToDate(a.created_at);
      byId.set(a.pid, { from: st?.from || null, to: st?.to || null, by: a.operator_name || null,
        at: d && !isNaN(d) ? d.toISOString().slice(0, 19) + 'Z' : null });
    }
    for (const c of contracts) c.date_change = byId.get(c.id) || null;
  }

  // Attach the products on each contract (what the customer actually took), so
  // the contracts table can show it and the manager can edit it.
  const ids = contracts.map(c => c.id);
  if (ids.length) {
    const ph    = ids.map(() => '?').join(',');
    const items = db.prepare(`
      SELECT pi.purchase_id, pr.id, pr.name, pr.category_id
      FROM purchase_items pi
      JOIN products pr ON pr.id = pi.product_id
      WHERE pi.purchase_id IN (${ph})
      ORDER BY pr.name
    `).all(...ids);
    const byPurchase = {};
    for (const it of items) (byPurchase[it.purchase_id] ||= []).push({ id: it.id, name: it.name });
    for (const c of contracts) c.products = byPurchase[c.id] || [];
  } else {
    for (const c of contracts) c.products = [];
  }
  // 2026-11-22: the prices system's lines (everyone in scope) and — ADMIN ONLY —
  // the estimate («تقريبي»: today's list prices when the sale was recorded).
  const linesBy = readPurchaseLines(db, ids);
  const estBy = role === 'admin' ? readPurchaseEstimates(db, ids) : null;
  for (const c of contracts) {
    c.lines = linesBy.get(c.id) || [];
    if (estBy) c.estimate = estBy.get(c.id) || null;
  }

  // Header summary for the SAME filter set — counted WITHOUT the 500-row LIMIT,
  // so a busy month still reports the true number instead of a flat "500".
  // (lead_profiles.user_id is the PK, so dropping the LEFT JOIN can't change
  //  the count.)
  const totals = db.prepare(`
    SELECT COUNT(*) AS count, COALESCE(SUM(p.price), 0) AS total
    FROM purchases p
    WHERE ${where}
  `).get(...params);

  // Every month that actually HAS contracts for this user — feeds the month
  // picker (and the "أقرب شهر فيه تعاقدات" shortcut when the chosen month is
  // empty), so it's scoped by role only and ignores the month filter itself.
  // Grouped by each contract's CAIRO month (honest.dayOf), the month= filter's.
  const monthAgg = new Map();
  for (const r of db.prepare(`SELECT p.created_at, p.price FROM purchases p WHERE ${roleWhere}`).all(...roleParams)) {
    const day = honest.dayOf(r.created_at);
    if (!day) continue;
    const m = day.slice(0, 7);
    if (!monthAgg.has(m)) monthAgg.set(m, { month: m, count: 0, total: 0 });
    const a = monthAgg.get(m); a.count += 1; a.total += Number(r.price) || 0;
  }
  const months = [...monthAgg.values()].sort((a, b) => (a.month < b.month ? 1 : a.month > b.month ? -1 : 0));

  // ADMIN ONLY: the same filter set's estimate summary (no LIMIT).
  let estimateSummary = {};
  if (role === 'admin') {
    const e = db.prepare(`
      SELECT COUNT(e.purchase_id) AS n, COALESCE(SUM(e.list_total_estimate), 0) AS total,
             SUM(CASE WHEN e.purchase_id IS NOT NULL AND (e.estimate_complete = 0 OR e.list_total_estimate IS NULL) THEN 1 ELSE 0 END) AS incomplete,
             COALESCE(SUM(CASE WHEN p.price > 0 THEN p.price ELSE COALESCE(e.list_total_estimate, 0) END), 0) AS value
      FROM purchases p LEFT JOIN purchase_estimates e ON e.purchase_id = p.id
      WHERE ${where}
    `).get(...params);
    estimateSummary = { estimate_total: e.total, estimate_count: e.n, estimate_incomplete: e.incomplete || 0, value_total: e.value };
  }

  return res.json({
    contracts,                       // unchanged shape — old callers keep working
    month,                           // the applied month, or null when unfiltered
    count: totals.count,
    total: totals.total,
    ...estimateSummary,
    // count/total describe the whole filter set while `contracts` stops at
    // LIST_LIMIT — تقول للواجهة إن القائمة اتقصّت عشان ما تناقضش العدّاد فوقها.
    limit: LIST_LIMIT,
    truncated: totals.count > contracts.length,
    months,
    // 2026-11-25: the filters applied, and the salesperson picker's choices
    // (admin / manager only: the active sellers of the branch in scope) +
    // how many contracts in that scope carry no salesperson («من غير سيلز»).
    filters: { sort: f.sort, number: f.number, rep: f.rep, no_rep: f.noRep, branch: f.branch },
    ...((role === 'admin' || role === 'branch_manager') ? {
      rep_choices: contractRepChoices(db, role === 'branch_manager' ? req.user.branch : f.branch),
      no_rep_count: db.prepare(`SELECT COUNT(*) AS n FROM purchases p WHERE ${pickWhere} AND (p.rep IS NULL OR TRIM(p.rep) = '')`)
        .get(...pickParams).n,
    } : {}),
    // review r2: the admin's «الفرع» choices = exactly what ?branch= accepts —
    // the system's branches + any branch a contract carries (never an events
    // value such as a stale bot answer, which ?branch= refuses with a 400).
    ...(role === 'admin' ? { branch_choices: contractBranchChoices(db) } : {}),
  });
});

app.put('/api/contracts/:id', requireAuth, authorizeRoles('admin', 'branch_manager'), async (req, res) => {
 try {
  const db  = getDb();
  const row = db.prepare(`SELECT id, user_id, branch, contract_number, rep, price, created_at FROM purchases WHERE id = ?`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'contract_not_found' });
  if (req.user?.role === 'branch_manager' && row.branch !== req.user.branch) {
    return res.status(403).json({ error: 'forbidden' });
  }

  const body = req.body || {};
  const { price, contract_number, product_ids, rep: repIn, items } = body;
  // 2026-11-25: price / number are written only when the body carries them (the
  // portal always sends both; a date-only or rep-only edit keeps them).
  const has = (k) => Object.prototype.hasOwnProperty.call(body, k);
  const newNumber = has('contract_number') ? ((contract_number && String(contract_number).trim()) || null) : row.contract_number;
  const newPrice  = has('price') ? (price != null && price !== '' ? Number(price) : null) : row.price;
  if (newPrice != null && !Number.isFinite(newPrice)) return res.status(400).json({ error: 'المبلغ لازم يكون رقم', code: 'bad_price' });

  // «تعديل تاريخ التعاقد» (2026-11-25): the admin, or the branch manager of the
  // contract's branch (checked above). A Cairo day 2020-01-01 … today; the
  // contract keeps its own Cairo time of day (movedContractTime).
  const dayIn = parseContractDay(body.contract_date);
  if (dayIn && dayIn.error) return res.status(400).json({ error: dayIn.error, code: dayIn.code });
  const oldDay = honest.dayOf(row.created_at);
  const newAt = dayIn && dayIn.day !== oldDay ? movedContractTime(row.created_at, dayIn.day) : null;

  // Optional: the salesperson the sale counts for (a sale entered for the wrong
  // one). Only an active salesperson of the contract's branch, by the DB's exact
  // name; absent / unchanged → the rep stays as it is.
  let newRep = null;
  if (typeof repIn === 'string' && repIn.trim() && repIn.trim() !== String(row.rep || '').trim()) {
    const repRow = row.branch ? findBranchSalesRep(db, repIn, row.branch) : null;
    if (!repRow) {
      return res.status(400).json({
        error: 'السيلز ده مش من سيلز فرع العقد (أو متوقف) — اختار من القايمة', code: 'rep_not_in_branch',
      });
    }
    if (repRow.name !== row.rep) newRep = repRow.name;
  }

  // Validate the products edit (when provided) BEFORE writing anything. A
  // contract must keep at least one product (product selection is mandatory).
  let validIds = null;
  if (Array.isArray(product_ids) && !Array.isArray(items)) {
    const wanted = product_ids.map(v => parseInt(v, 10)).filter(n => Number.isFinite(n) && n > 0);
    validIds = wanted.filter(id => db.prepare(`SELECT 1 FROM products WHERE id = ?`).get(id));
    if (!validIds.length) {
      return res.status(400).json({ error: 'لازم تختار منتج واحد على الأقل' });
    }
  }
  // 2026-11-22: the prices system's lines replace the contract's lines (the old
  // manual-catalogue products stay as they were: read-only history). The
  // estimate is recomputed after the commit.
  let newLines = null;
  if (Array.isArray(items)) {
    const fromCatalog = await linesFromBody(items);
    if (fromCatalog.code) return res.status(400).json({ error: fromCatalog.error, code: fromCatalog.code });
    if (!fromCatalog.lines.length) return res.status(400).json({ error: 'لازم تختار منتج واحد على الأقل', code: 'products_required' });
    newLines = fromCatalog.lines;
  }
  // a row deleted while the catalogue was read
  if (!db.prepare(`SELECT 1 FROM purchases WHERE id = ?`).get(row.id)) return res.status(404).json({ error: 'contract_not_found' });

  db.transaction(() => {
    db.prepare(`UPDATE purchases SET price = ?, contract_number = ? WHERE id = ?`).run(
      newPrice,
      newNumber,
      row.id
    );
    if (newAt) {
      // recorded_at keeps the moment it was typed (the first edit stores it);
      // the right-hand side reads the row as it was before this UPDATE.
      db.prepare(`UPDATE purchases SET created_at = ?, recorded_at = COALESCE(recorded_at, created_at) WHERE id = ?`).run(newAt, row.id);
      syncPurchasedAt(db, row.user_id);
      // the undo ledger: «رجّع» puts created_at back (REVERTABLE_AUDIT_TABLES)
      auditLog(db, req.user?.name, 'contract_date_change', row.user_id, {
        table: 'purchases', where: { id: row.id }, row: { created_at: row.created_at },
        from: oldDay, to: dayIn.day, from_at: row.created_at, to_at: newAt,
        contract_number: newNumber || row.contract_number || null, branch: row.branch || null,
      });
    }
    if (validIds) {
      // Replace the product lines wholesale with the new selection.
      db.prepare(`DELETE FROM purchase_items WHERE purchase_id = ?`).run(row.id);
      const ins = db.prepare(`INSERT INTO purchase_items (purchase_id, product_id) VALUES (?, ?)`);
      for (const id of validIds) ins.run(row.id, id);
      // Keep the legacy single product_id in sync (first item) for older views.
      db.prepare(`UPDATE purchases SET product_id = ? WHERE id = ?`).run(validIds[0], row.id);
    }
    if (newLines) {
      writePurchaseLines(db, row.id, newLines);
      db.prepare(`UPDATE purchases SET product_id = ? WHERE id = ?`).run(newLines[0].title || null, row.id);
    }
    if (newRep) {
      db.prepare(`UPDATE purchases SET rep = ? WHERE id = ?`).run(newRep, row.id);
      // display-only ledger row (not in REVERTABLE_AUDIT_TABLES)
      auditLog(db, req.user?.name, 'contract_rep_change', row.user_id, {
        table: 'purchases', where: { id: row.id }, row: null, from: row.rep || null, to: newRep,
      });
    }
  })();

  // Macro alert for the admin war-room.
  createNotification(db, 'admin', 'contract_modified',
    `تم تعديل تعاقد رقم [${newNumber || row.contract_number || row.id}] بواسطة [${req.user?.name || '؟'}]` +
    (newRep ? ` — البيعة بقت باسم [${newRep}] بدل [${row.rep || '—'}]` : '') +
    (newAt ? ` — التاريخ بقى [${dayIn.day}] بدل [${oldDay || '—'}]` : ''));

  // The estimate stays the list price of the day it was recorded (a date edit
  // never re-prices it); Meta's Purchase already sent is never sent again.
  if (newLines) estimatePurchase(db, row.id).catch(() => {});

  return res.json({ ok: true, rep: newRep || row.rep || null, created_at: newAt || row.created_at,
    date_changed: newAt ? { from: oldDay, to: dayIn.day } : null });
 } catch (err) {
  console.error('[contracts] update failed:', err && err.message);
  if (!res.headersSent) res.status(500).json({ error: 'حصلت مشكلة — جرّب تاني' });
 }
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
    deletePurchaseRows(db, `SELECT ?`, row.id);
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
    // Phase 0 r3: a sent flow makes the lead «his» (messages_sent in
    // leadIsMine) — only for a lead he may already open; checked before
    // anything is sent or recorded. r4: canActOnLead (no read-only grant).
    if (!canActOnLead(db, req.user, user_id)) return res.status(404).json({ error: 'lead_not_found' });

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

    // The 24 h window guard (C1.9) — ManyChat's own last_interaction, asked
    // right now; fail closed. A skip is answered with its reason and the line
    // SendFlowButton shows; nothing is recorded as sent.
    const sent = await guardedSendFlow(db, { user_id, flow_id: chosenFlow, site: 'rep' });
    if (!sent.sent && sent.reason) {
      return res.status(409).json({ error: 'not_sent', reason: sent.reason,
        message: SKIP_MESSAGES_AR[sent.reason] || 'مش هيتبعت' });
    }
    if (!sent.sent) {
      return res.status(502).json({ error: 'مش اتبعتت — ManyChat رفض الإرسال، جرّب تاني بعد شوية', reason: 'send_failed' });
    }

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
    // Phase 0 r3: an unknown or out-of-scope lead → 404, before
    // getStateRotated writes a follow_up_state row for the id.
    const db = getDb();
    const known = db.prepare(`SELECT 1 FROM lead_profiles WHERE user_id = ?`).get(req.params.user_id);
    if (!known || !canSeeLead(db, req.user, req.params.user_id)) return res.status(404).json({ error: 'lead_not_found' });
    const state = getStateRotated(req.params.user_id);
    return res.json({ state });
  } catch (err) {
    console.error('[follow-up-state]', err);
    return res.status(500).json({ error: 'state_failed' });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/analytics — «تحليلات المنتجات»: what customers looked at in the chat
// and what was sold. Query: from, to (CAIRO days; default the last 30 Cairo
// days with today), branch, campaign.
// 2026-11-22 «أرقام حقيقية»:
//   • days are Cairo days; the walk-in route's events are not chat demand;
//   • demand (views, category picks, the daily events) carries no branch:
//     the branch filter applies to the SALES only (the contract's branch) —
//     meta.branch_applies_to says so and the page prints «كل الفروع»;
//   • campaign = the customer's campaign_source (where he first came from);
//   • the lead-class sections (the «ساخن/زار/اشترى» snapshot, the campaign
//     and ad tables, the branch and platform tables — today's class of people
//     created in the range, walk-ins shown as a campaign) are gone: the
//     weekly «من الإعلان للبيعة» (GET /api/admin/ad-funnel) replaces them.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/analytics', requireAuth, requireRole('admin'), (req, res) => {
  const db = getDb();
  const { from, to, branch, campaign } = req.query;
  if ((from && !honest.isDay(from)) || (to && !honest.isDay(to))) {
    return res.status(400).json({ error: 'التاريخ لازم يكون YYYY-MM-DD' });
  }
  const today    = cairoDay();
  const fromDate = from || honest.addDays(today, -29);
  const toDate   = to   || today;

  // Demand filters: the campaign only (views carry no branch).
  const campaignClause = campaign ? `AND lp.campaign_source = ?`  : '';
  const campaignParam  = campaign ? [campaign] : [];
  const evR = honest.rangeSql('e.created_at', fromDate, toDate);
  const evWhere = `${honest.CHAT_EVENT('e')}${evR.clause} ${campaignClause}`;
  const evArgs  = [...evR.params, ...campaignParam];

  // Daily events by type (Cairo day). SQLite has no time zones: the rows are
  // read in the range and put on their Cairo day here.
  const evRows = db.prepare(`
    SELECT e.created_at, e.event_type
    FROM events e
    JOIN lead_profiles lp ON e.user_id = lp.user_id
    WHERE ${evWhere}
  `).all(...evArgs);
  const seriesMap = new Map();
  for (const r of evRows) {
    const day = honest.dayOf(r.created_at);
    const k = `${day}|${r.event_type}`;
    seriesMap.set(k, (seriesMap.get(k) || 0) + 1);
  }
  const eventsSeries = [...seriesMap].map(([k, count]) => { const [day, event_type] = k.split('|'); return { day, event_type, count }; })
    .sort((a, b) => (a.day < b.day ? -1 : a.day > b.day ? 1 : 0));

  // Top products in range — DISTINCT customers (not raw repeated views)
  const topProducts = db.prepare(`
    SELECT e.event_value AS product, COUNT(DISTINCT e.user_id) AS views
    FROM events e
    JOIN lead_profiles lp ON e.user_id = lp.user_id
    WHERE e.event_type = 'product_details' AND ${evWhere}
    GROUP BY e.event_value
    ORDER BY views DESC
    LIMIT 10
  `).all(...evArgs);

  // ── Category demand breakdown ─────────────────────────────────────────
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
      AND ${evWhere}
    GROUP BY e.category
    ORDER BY product_views DESC, category_requests DESC
  `).all(...evArgs);

  // ── Top products PER category ─────────────────────────────────────────
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
      AND ${evWhere}
    GROUP BY e.category, e.event_value
    ORDER BY e.category, views DESC
  `).all(...evArgs);

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

  // Sales filters: the contract's own branch + the customer's campaign.
  const branchClause = branch ? `AND pur.branch = ?` : '';
  const branchParam  = branch ? [branch] : [];
  const purR = honest.rangeSql('pur.created_at', fromDate, toDate);

  // ── SALES analytics — best-selling products. Mirrors the "most viewed"
  // analysis above but sourced from ACTUAL purchases, not view events:
  //   • the prices system's lines (purchase_lines, since 2026-11-22): a room /
  //     set by its model, a single piece by its variant; the category is the
  //     catalogue's, written on the line at sale time (category_ar);
  //   • the old manual catalogue (purchase_items → products → categories): one
  //     unit per row, as before.
  // "units" = SUM(qty) (a purchase_items row is 1), the clean, unambiguous
  // "best-seller" metric. We deliberately do NOT split a contract's price
  // across its products (one contract can bundle several products under a
  // single total), so we rank by units, not by revenue. The admin-only
  // estimate (purchase_estimates) is never read here.
  const salesArgs = [...purR.params, ...branchParam, ...campaignParam, ...purR.params, ...branchParam, ...campaignParam];
  const soldCte = `
    WITH sold AS (
      SELECT 'item:' || pi.product_id                 AS k,
             p.name                                    AS product,
             COALESCE(NULLIF(TRIM(pc.name), ''), 'بدون فئة') AS category,
             1                                         AS qty,
             pur.user_id                               AS buyer,
             0                                         AS rid
      FROM purchase_items pi
      JOIN purchases pur     ON pur.id = pi.purchase_id
      JOIN lead_profiles lp  ON lp.user_id = pur.user_id
      JOIN products p        ON p.id = pi.product_id
      LEFT JOIN product_categories pc ON pc.id = p.category_id
      WHERE 1=1 ${purR.clause}
        ${branchClause} ${campaignClause}
      UNION ALL
      SELECT CASE WHEN pl.kind = 'set' AND pl.variant_id IS NULL THEN 'model:' || pl.model_id
                  WHEN pl.kind = 'set' THEN 'set:' || pl.variant_id
                  ELSE 'piece:' || pl.variant_id END,
             COALESCE(NULLIF(pl.title, ''), pl.model_title, '—'),
             COALESCE(NULLIF(TRIM(pl.category_ar), ''), 'بدون فئة'),
             pl.qty,
             pur.user_id,
             pl.id
      FROM purchase_lines pl
      JOIN purchases pur     ON pur.id = pl.purchase_id
      JOIN lead_profiles lp  ON lp.user_id = pur.user_id
      WHERE 1=1 ${purR.clause}
        ${branchClause} ${campaignClause}
    )`;
  // Best-selling overall (all categories). The product's name and category
  // come from its newest line (MAX(rid): SQLite takes the bare columns from it).
  const topSelling = db.prepare(`
    ${soldCte}
    SELECT product, category, units, buyers FROM (
      SELECT k, product, category, MAX(rid) AS newest, SUM(qty) AS units, COUNT(DISTINCT buyer) AS buyers
      FROM sold GROUP BY k
    )
    ORDER BY units DESC, buyers DESC
    LIMIT 10
  `).all(...salesArgs);
  // Sales rolled up per category
  const salesByCategory = db.prepare(`
    ${soldCte}
    SELECT category,
           SUM(qty)          AS units,
           COUNT(DISTINCT k) AS products_sold,
           COUNT(DISTINCT buyer) AS buyers
    FROM sold
    GROUP BY category
    ORDER BY units DESC
  `).all(...salesArgs);
  // Best-selling products inside each category (nested, like productsByCategory)
  const sellingByCategoryRows = db.prepare(`
    ${soldCte}
    SELECT category, product, units, buyers FROM (
      SELECT category, k, product, MAX(rid) AS newest, SUM(qty) AS units, COUNT(DISTINCT buyer) AS buyers
      FROM sold GROUP BY category, k
    )
    ORDER BY category, units DESC, buyers DESC
  `).all(...salesArgs);
  const sellingByCategory = {};
  for (const r of sellingByCategoryRows) {
    if (!sellingByCategory[r.category]) sellingByCategory[r.category] = [];
    sellingByCategory[r.category].push({ product: r.product, units: r.units, buyers: r.buyers });
  }

  return res.json({
    eventsSeries,
    topProducts,
    categories,
    productsByCategory,
    topSelling,
    salesByCategory,
    sellingByCategory,
    meta: { from: fromDate, to: toDate, timezone: CAIRO_TZ, branch: branch || null, campaign: campaign || null,
            branch_applies_to: 'sales' },
  });
});

// ════════════════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════════════════
// GET /api/reps — Returns name list of ACTIVE sales reps (role != admin).
// Deactivated reps are excluded so they no longer receive new leads.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/reps', requireAuth, (req, res) => {
  const db   = getDb();
  const reps = db.prepare(
    `SELECT name FROM users WHERE role != 'admin' AND active = 1 ORDER BY name`
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

// ════════════════════════════════════════════════════════════════════════════
// GET /api/scoring-rules — the admin-editable per-event-type point values that
//                          drive backend/scoring.js's classification. Admin
//                          only (unlike /api/branches, this is business config,
//                          not something reception needs to read).
// PUT /api/scoring-rules — replace the full rule list.
// Stored in settings under 'scoring_rules' as JSON — see scoring.getScoringConfig.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/scoring-rules', requireAuth, requireRole('admin'), (req, res) => {
  const db  = getDb();
  const row = db.prepare(`SELECT value FROM settings WHERE key = 'scoring_rules'`).get();
  let rules = null;
  try {
    const parsed = JSON.parse(row?.value || 'null');
    if (Array.isArray(parsed)) rules = parsed;
  } catch (_) { rules = null; }
  const defaults = Object.entries(DEFAULT_SCORE_MAP).map(([event_type, points]) => ({ event_type, points, active: true }));
  return res.json({ rules: rules || defaults, defaults });
});

app.put('/api/scoring-rules', requireAuth, requireRole('admin'), (req, res) => {
  const { rules } = req.body || {};
  if (!Array.isArray(rules) || rules.length > 50) {
    return res.status(400).json({ error: 'rules must be an array of at most 50 entries' });
  }
  const seen = new Set();
  const clean = [];
  for (const r of rules) {
    const eventType = String(r?.event_type ?? '').trim();
    if (!eventType || !/^[a-z0-9_]+$/i.test(eventType)) {
      return res.status(400).json({ error: `اسم الحدث غير صالح: "${eventType}"` });
    }
    if (seen.has(eventType)) {
      return res.status(400).json({ error: `اسم الحدث مكرر: "${eventType}"` });
    }
    seen.add(eventType);
    const points = parseInt(r?.points, 10);
    if (!Number.isFinite(points) || points < 0 || points > 500) {
      return res.status(400).json({ error: `نقاط "${eventType}" لازم تكون رقم من 0 لـ 500` });
    }
    clean.push({ event_type: eventType, points, active: r?.active !== false });
  }
  const db = getDb();
  db.prepare(`
    INSERT INTO settings (key, value, updated_at) VALUES ('scoring_rules', ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
  `).run(JSON.stringify(clean));
  return res.json({ ok: true, rules: clean });
});

// Settings endpoints — GET /api/settings, PUT /api/settings/:key
// ════════════════════════════════════════════════════════════════════════════
// Phase 0: secret rows (API keys, webhook_secret, …) come back MASKED
// («••••••••» + the last 4 of a long key, '' when unset) and jwt_secret not at
// all — the value itself never leaves the server. The portal's key fields
// still show «set / غير مُعَيَّن»; a new key is saved by typing over the mask
// (PUT below ignores a mask sent back unchanged). services/secrets.js.
// Phase 1 (2026-11-22): settings that no code reads any more — not shown, not
// written (PUT answers 410). Their rows stay in the table untouched.
//   company_name / manychat_page_id / openai_api_key / facebook_pixel_id —
//     never read anywhere; reminder_job_enabled / manychat_reminder_flow —
//     the 3-day reminder job (removed); achievement_* — points & badges
//     (removed). The trigger-engine flows (manychat_flow_*) and
//     weekly_message_limit stay readable: POST /api/trigger-message stays
//     until phase 8, though no portal page calls it now.
const RETIRED_SETTINGS = new Set([
  'company_name', 'manychat_page_id', 'openai_api_key', 'facebook_pixel_id',
  'reminder_job_enabled', 'manychat_reminder_flow',
  'achievement_followup_weight', 'achievement_visit_weight', 'achievement_close_weight',
]);
app.get('/api/settings', requireAuth, requireRole('admin'), (req, res) => {
  const db   = getDb();
  const rows = db.prepare(`SELECT key, value FROM settings`).all().filter(r => !RETIRED_SETTINGS.has(r.key));
  return res.json(secrets.settingsForClient(rows));
});

// ── Integration status — drives the dashboard ManyChat banner ────────────────
// Admin-only (exposes the webhook secret so it can be pasted into ManyChat).
app.get('/api/integration-status', requireAuth, requireRole('admin'), (req, res) => {
  const apiKey = (getSetting('manychat_api_key') || '').trim();
  // Phase 1: only the flows something still sends (visit confirmed, purchase).
  const flowKeys = ['manychat_visit_flow', 'manychat_purchase_flow'];
  const missing_flows = flowKeys.filter(k => !(getSetting(k) || '').trim());

  return res.json({
    manychat: apiKey ? 'live' : 'mock',
    missing_flows,
    webhook: {
      // The one place a secret is shown, on purpose: the live admin copies it
      // into ManyChat's External Request header. Never in a demo_ session
      // (phase 0) — its DB is scrubbed and the env secret is the live one.
      secret:   isDemoContext() ? '' : (process.env.WEBHOOK_SECRET || getSetting('webhook_secret') || ''),
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
  // Phase 0: the session signing key is never written through the API.
  // (r3) nor the flag of its one-time rotation.
  if (secrets.NEVER_LISTED.has(key) || key === ROTATED_FLAG) return res.status(400).json({ error: 'not_editable' });
  if (RETIRED_SETTINGS.has(key)) return res.status(410).json({ error: 'removed', message: 'الإعداد ده اتشال — مالوش تأثير' });
  const db = getDb();
  // A secret field saved without typing a new value sends back the mask GET
  // gave it — keep the stored key (answer ok, as a save of the same value).
  // Phase 0 r2: ONLY the exact mask of the stored value counts as unchanged;
  // any other value holding «•» (a key pasted after the mask, a mask with a
  // character typed into it) is refused, never stored or silently dropped.
  if (secrets.isSecretSettingKey(key)) {
    const v = String(value);
    if (v.includes('•')) {
      const stored = db.prepare(`SELECT value FROM settings WHERE key = ?`).get(key);
      const mask = secrets.maskSecret(stored ? stored.value : '');
      if (mask && v === mask) return res.json({ ok: true, unchanged: true });
      return res.status(400).json({ error: 'mask_edited', message: 'امسح النجوم واكتب المفتاح الجديد كامل' });
    }
  }
  // zai_base_url: only z.ai's or BigModel's own API (phase 0 r2) — the AI
  // prompt (lead names, typed messages) and the z.ai key go to this URL.
  if (key === 'zai_base_url' && String(value).trim() !== '' && !isAllowedAiBaseUrl(String(value).trim())) {
    return res.status(400).json({ error: 'base_url_not_allowed',
      message: 'الرابط لازم يبدأ بـ https://api.z.ai/ أو https://open.bigmodel.cn/ — أو سيبه فاضي للافتراضي' });
  }
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
  let { name, email, password, role = 'sales', branch } = req.body || {};
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'name, email, and password are required' });
  }
  name = String(name).trim(); // padded names break name-based assignment matching
  // Branch only meaningful for reception accounts
  const branchVal = ['reception', 'sales', 'branch_manager'].includes(role) ? (branch || null) : null;
  const db   = getDb();
  // History is linked by name — a duplicate would share / steal another rep's work.
  const nameError = staffCreateError(db, name);
  if (nameError) return res.status(409).json({ error: nameError });
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
  let { name, email, role, password, branch, active } = req.body || {};
  // Phase 0 r2: a sandbox session never changes who can log in (email /
  // password / role) — the sandbox holds cloned copies of live accounts.
  if (isDemoContext() && (email || password || role)) {
    return res.status(403).json({ error: 'demo_readonly_login', message: 'وضع التدريب: مينفعش تغيّر الإيميل أو الباسورد أو الدور' });
  }
  if (name != null) name = String(name).trim();
  const db      = getDb();
  const updates = [];
  const params  = [];

  if (name)     { updates.push('name = ?');          params.push(name); }
  if (email)    { updates.push('email = ?');         params.push(email); }
  if (role)     { updates.push('role = ?');          params.push(role); }
  if (password) { updates.push('password_hash = ?'); params.push(bcrypt.hashSync(password, 10)); }
  // active: 1 = can log in, 0 = frozen (reversible suspension). Reject freezing
  // the last remaining admin so the system can never lock itself out.
  if (active !== undefined) {
    const next = active ? 1 : 0;
    if (next === 0) {
      const target = db.prepare(`SELECT role FROM users WHERE id = ?`).get(req.params.id);
      if (target?.role === 'admin') {
        const otherAdmins = db.prepare(
          `SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND active = 1 AND id != ?`
        ).get(req.params.id).n;
        if (otherAdmins === 0) {
          return res.status(400).json({ error: 'مينفعش توقف آخر مدير نظام نشط' });
        }
      }
    }
    updates.push('active = ?'); params.push(next);
  }
  // Set branch for reception accounts; clear it for any other role
  if (role)     { updates.push('branch = ?');        params.push(['reception','sales','branch_manager'].includes(role) ? (branch || null) : null); }
  else if (branch !== undefined) { updates.push('branch = ?'); params.push(branch || null); }

  if (!updates.length) {
    return res.status(400).json({ error: 'Nothing to update' });
  }
  const cur = db.prepare(`SELECT id, name FROM users WHERE id = ?`).get(req.params.id);
  // Only a real name change can collide / cascade (the edit modal always resends the name).
  if (name && cur && name !== cur.name) {
    const renameError = staffRenameError(db, cur, name);
    if (renameError) return res.status(409).json({ error: renameError });
  }
  params.push(req.params.id);
  // Renaming a rep must carry their assignments/history with them, or they orphan.
  db.transaction(() => {
    db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...params);
    if (name && cur && name !== cur.name) renameRepReferences(db, cur.name, name);
  })();
  return res.json({ ok: true });
});

// Scrub every reference to a (departed) sales / call rep. Visits and purchases
// are real events — they're KEPT but un-attributed (rep column set to NULL),
// so the departed rep stops appearing in performance analytics.
function scrubRepReferences(db, name, { authored = true } = {}) {
  db.prepare(`UPDATE lead_profiles SET assigned_rep = NULL WHERE assigned_rep = ?`).run(name);
  db.prepare(`UPDATE lead_visits   SET sales_rep = NULL    WHERE sales_rep = ?`).run(name);
  db.prepare(`UPDATE lead_visits   SET pre_visit_rep = NULL WHERE pre_visit_rep = ?`).run(name);
  db.prepare(
    `UPDATE branch_customer_followups SET assigned_sales = NULL, followed_up = 0 WHERE assigned_sales = ?`
  ).run(name);
  db.prepare(`UPDATE purchases SET rep = NULL WHERE rep = ?`).run(name);
  db.prepare(`DELETE FROM followup_log      WHERE sales = ?`).run(name);
  db.prepare(`DELETE FROM revisit_followups WHERE followed_up_by = ?`).run(name);
  db.prepare(`DELETE FROM sales_targets WHERE scope_type = 'sales_rep' AND scope_name = ?`).run(name);
  if (authored) scrubAuthoredWork(db, name);
}

// Phase 0 r4: the name-keyed rows ANY role writes (a task, a sent flow) —
// both make a lead «his» (leadIsMine). Cleared when any account is deleted
// (DELETE /api/users/:id, whatever its role), so a new account given the
// freed name never inherits those customers. A deleted person's open
// reminders are dropped (tasks.rep_name is NOT NULL); a sent message stays in
// the history without a name.
function scrubAuthoredWork(db, name) {
  if (!name) return;
  db.prepare(`DELETE FROM tasks WHERE rep_name = ?`).run(name);
  db.prepare(`UPDATE messages_sent SET sent_by_rep = NULL WHERE sent_by_rep = ?`).run(name);
}

// Cascade a sales / call-rep RENAME across every table that references the rep
// by their display name. Without this, renaming an account ORPHANS all of that
// rep's work: the rows keep the old name while the rep now logs in under the new
// one, so they suddenly "lose" every assigned customer. Mirrors the table set in
// scrubRepReferences (history-carrying columns updated too, not deleted).
function renameRepReferences(db, oldName, newName) {
  if (!oldName || !newName || oldName === newName) return;
  db.prepare(`UPDATE lead_profiles SET assigned_rep = ? WHERE assigned_rep = ?`).run(newName, oldName);
  db.prepare(`UPDATE lead_visits   SET sales_rep = ?    WHERE sales_rep = ?`).run(newName, oldName);
  db.prepare(`UPDATE lead_visits   SET pre_visit_rep = ? WHERE pre_visit_rep = ?`).run(newName, oldName);
  db.prepare(`UPDATE branch_customer_followups SET assigned_sales = ? WHERE assigned_sales = ?`).run(newName, oldName);
  db.prepare(`UPDATE branch_customer_followups SET assigned_by = ?    WHERE assigned_by = ?`).run(newName, oldName);
  db.prepare(`UPDATE branch_customer_followups SET followed_up_by = ? WHERE followed_up_by = ?`).run(newName, oldName);
  db.prepare(`UPDATE purchases SET rep = ? WHERE rep = ?`).run(newName, oldName);
  // Who typed a sale in / confirmed an arrival — display only (never ownership),
  // but it should still name the account as it is called now.
  db.prepare(`UPDATE purchases SET entered_by = ? WHERE entered_by = ?`).run(newName, oldName);
  db.prepare(`UPDATE visit_checkins SET recorded_by = ? WHERE recorded_by = ?`).run(newName, oldName);
  db.prepare(`UPDATE visit_outcomes SET recorded_by = ? WHERE recorded_by = ?`).run(newName, oldName);
  db.prepare(`UPDATE followup_log SET sales = ? WHERE sales = ?`).run(newName, oldName);
  db.prepare(`UPDATE revisit_followups SET followed_up_by = ? WHERE followed_up_by = ?`).run(newName, oldName);
  db.prepare(`UPDATE sales_targets SET scope_name = ? WHERE scope_type = 'sales_rep' AND scope_name = ?`).run(newName, oldName);
  // Phase 0 r4: his tasks and sent flows go with him (both count in leadIsMine).
  db.prepare(`UPDATE tasks SET rep_name = ? WHERE rep_name = ?`).run(newName, oldName);
  db.prepare(`UPDATE messages_sent SET sent_by_rep = ? WHERE sent_by_rep = ?`).run(newName, oldName);
}

// ── Unique staff names ──────────────────────────────────────────────────────
// Every column above is keyed by display name, so two accounts with the same
// name share — and on rename, SWEEP — each other's customers, visits and
// purchases. That happened Aug/Sep 2026: new Alexandria accounts got temp names
// identical to Ain Shams / Faisal reps, and renaming them carried those reps'
// history away. So a name belongs to ONE account system-wide (any role, active
// or frozen), compared loosely: NFKC + trim + collapsed spaces + case-insensitive.
function normalizeStaffName(s) {
  return String(s ?? '').normalize('NFKC').trim().replace(/\s+/g, ' ').toLowerCase();
}

// → { id, name, role, branch } of ANOTHER account whose name collides, or null.
// excludeId = the account being edited, so it can re-case / re-space its own name.
// users is a small table, so normalizing every row in JS is fine.
function findStaffNameConflict(db, name, excludeId = null) {
  const target = normalizeStaffName(name);
  const skipId = excludeId == null ? null : Number(excludeId);
  return db.prepare(`SELECT id, name, role, branch FROM users`).all()
    .find(u => u.id !== skipId && normalizeStaffName(u.name) === target) || null;
}

function staffNameTakenMessage(conflict) {
  return `الاسم ده مستخدم لحساب تاني (${String(conflict.name).trim()}) — اختار اسم مختلف (زوّد اسم العيلة مثلاً)`;
}

// A name no account carries can still be written on history rows (the columns
// renameRepReferences cascades), left by a deleted account: plain deletes, and
// scrubs that keep assigned_by / followed_up_by. A new or renamed account taking
// it would inherit those customers, visits and purchases, and its next rename
// would sweep them away. → the 409 message, or null.
// Rare admin action and the DISTINCT name lists are short → normalize in JS.
function staffNameHistoryError(db, name) {
  const target = normalizeStaffName(name);
  const sources = [
    `SELECT DISTINCT assigned_rep   AS n FROM lead_profiles             WHERE assigned_rep IS NOT NULL`,
    `SELECT DISTINCT sales_rep      AS n FROM lead_visits               WHERE sales_rep IS NOT NULL`,
    `SELECT DISTINCT pre_visit_rep  AS n FROM lead_visits               WHERE pre_visit_rep IS NOT NULL`,
    `SELECT DISTINCT assigned_sales AS n FROM branch_customer_followups WHERE assigned_sales IS NOT NULL`,
    `SELECT DISTINCT assigned_by    AS n FROM branch_customer_followups WHERE assigned_by IS NOT NULL`,
    `SELECT DISTINCT followed_up_by AS n FROM branch_customer_followups WHERE followed_up_by IS NOT NULL`,
    `SELECT DISTINCT rep            AS n FROM purchases                 WHERE rep IS NOT NULL`,
    `SELECT DISTINCT sales          AS n FROM followup_log              WHERE sales IS NOT NULL`,
    `SELECT DISTINCT followed_up_by AS n FROM revisit_followups         WHERE followed_up_by IS NOT NULL`,
    `SELECT DISTINCT scope_name     AS n FROM sales_targets             WHERE scope_type = 'sales_rep' AND scope_name IS NOT NULL`,
    // phase 0 r4: a task / sent flow also makes a lead his (leadIsMine)
    `SELECT DISTINCT rep_name       AS n FROM tasks                     WHERE rep_name IS NOT NULL`,
    `SELECT DISTINCT sent_by_rep    AS n FROM messages_sent             WHERE sent_by_rep IS NOT NULL`,
  ];
  const taken = sources.some(q => db.prepare(q).all().some(r => normalizeStaffName(r.n) === target));
  return taken
    ? 'الاسم ده لسه متسجّل على شغل قديم (عملاء / زيارات / مبيعات) لحساب اتحذف — اختار اسم مختلف، أو خلّي مدير النظام يشغّل «تنظيف بيانات السيلز المحذوفين» الأول'
    : null;
}

// Create guard for POST /api/users and POST /api/branch/sales.
// Returns the 409 message, or null when the name is free.
function staffCreateError(db, name) {
  const conflict = findStaffNameConflict(db, name);
  if (conflict) return staffNameTakenMessage(conflict);
  return staffNameHistoryError(db, name);
}

// Rename guard for PUT /api/users/:id and PUT /api/branch/sales/:id — run it
// BEFORE the write transaction. cur = the account's current { id, name }.
// Returns the 409 message, or null when the rename is safe.
function staffRenameError(db, cur, newName) {
  const conflict = findStaffNameConflict(db, newName, cur.id);
  if (conflict) return staffNameTakenMessage(conflict);
  // Re-casing / re-spacing its own name can't land on someone else's history.
  if (normalizeStaffName(newName) !== normalizeStaffName(cur.name)) {
    const historyError = staffNameHistoryError(db, newName);
    if (historyError) return historyError;
  }
  // Legacy twins (from before this guard): another account still carries the
  // exact current name, so the rename cascade would move THAT account's work too.
  const twin = db.prepare(
    `SELECT id FROM users WHERE id != ? AND TRIM(name) = TRIM(?) LIMIT 1`
  ).get(cur.id, cur.name);
  if (twin) return 'مينفعش تغيير الاسم: في حساب تاني بنفس الاسم الحالي، وتغيير الاسم هينقل شغل الحساب التاني كمان';
  return null;
}

// DELETE /api/users/:id — admin removes a user account permanently.
// Safety: admin cannot delete their OWN account (prevents self-lockout).
// If the user was a sales/call rep, their footprint is scrubbed too.
app.delete('/api/users/:id', requireAuth, requireRole('admin'), (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  if (!Number.isFinite(targetId)) return res.status(400).json({ error: 'bad_id' });
  if (targetId === req.user.id)   return res.status(400).json({ error: 'cannot_delete_self' });

  const db = getDb();
  const row = db.prepare(`SELECT id, role, name FROM users WHERE id = ?`).get(targetId);
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

  db.transaction(() => {
    db.prepare(`DELETE FROM users WHERE id = ?`).run(targetId);
    // A departed sales / call rep → scrub their footprint so they vanish
    // from performance analytics.
    if (['sales', 'rep'].includes(row.role)) scrubRepReferences(db, row.name);
    else scrubAuthoredWork(db, row.name);   // r4: any role's tasks / sent flows
  })();

  return res.json({ ok: true });
});

// ════════════════════════════════════════════════════════════════════════════
// DELETE /api/admin/users/sales-rep/:name?mode=archive|scrub
//   archive (default, SAFE) → just set active = 0. No leads/visits/purchases
//                             are touched — full history is preserved.
//   scrub   (DESTRUCTIVE)   → hard-delete the user + nullify all their history.
// ════════════════════════════════════════════════════════════════════════════
app.delete('/api/admin/users/sales-rep/:name', requireAuth, requireRole('admin'), (req, res) => {
  const name = String(req.params.name || '').trim();
  if (!name) return res.status(400).json({ error: 'name_required' });
  const mode = req.query.mode === 'scrub' ? 'scrub' : 'archive'; // default = safe archive

  const db   = getDb();
  const user = db.prepare(`SELECT id, role FROM users WHERE name = ?`).get(name);
  if (!user) return res.status(404).json({ error: 'user_not_found' });
  if (user.role === 'admin') return res.status(403).json({ error: 'cannot_offboard_admin' });

  if (mode === 'archive') {
    // Soft offboarding — disable login only, keep every record intact.
    db.prepare(`UPDATE users SET active = 0 WHERE name = ? AND role != 'admin'`).run(name);
    console.log(`📦 USER ARCHIVED: ${name}`);
    return res.json({ ok: true, mode: 'archive', name });
  }

  // Hard scrub — full destructive reset: delete the rep's visits & purchases,
  // reset every affected customer back to a fresh state, delete the user.
  db.transaction(() => {
    // Capture customers who visited via this rep BEFORE deleting their visits.
    const visitedByRep = db.prepare(
      `SELECT DISTINCT user_id FROM lead_visits WHERE sales_rep = ? OR pre_visit_rep = ?`
    ).all(name, name).map(r => r.user_id);

    // 1. Delete the rep's visits entirely.
    db.prepare(`DELETE FROM lead_visits WHERE sales_rep = ? OR pre_visit_rep = ?`).run(name, name);

    // 2. Reset the rep's ASSIGNED leads back to a cold/new state.
    db.prepare(`
      UPDATE lead_profiles
      SET assigned_rep = NULL, lead_class = 'cold', purchased_at = NULL, revisit_status = NULL
      WHERE assigned_rep = ?
    `).run(name);

    // 2b. Customers who VISITED with this rep but now have NO visits left →
    //     clear their visit state so the dashboards/analytics truly reset.
    const clearVisit = db.prepare(`
      UPDATE lead_profiles
      SET visit_confirmed = 0, visit_at = NULL, revisit_status = NULL,
          lead_class = CASE WHEN lead_class IN ('visited','purchased') THEN 'cold' ELSE lead_class END
      WHERE user_id = ?
    `);
    for (const uid of visitedByRep) {
      const stillHasVisit = db.prepare(`SELECT 1 FROM lead_visits WHERE user_id = ? LIMIT 1`).get(uid);
      if (!stillHasVisit) clearVisit.run(uid);
    }

    // 3. Delete the rep's purchases entirely — their lines, estimates and items
    //    with them (r2: lines / estimates have no foreign key to cascade).
    deletePurchaseRows(db, `SELECT id FROM purchases WHERE rep = ?`, name);
    db.prepare(`DELETE FROM purchases WHERE rep = ?`).run(name);

    // 4. Reset follow-ups they owned.
    db.prepare(
      `UPDATE branch_customer_followups SET assigned_sales = NULL, followed_up = 0 WHERE assigned_sales = ?`
    ).run(name);

    // 5. Delete their logs + monthly target.
    db.prepare(`DELETE FROM followup_log      WHERE sales = ?`).run(name);
    db.prepare(`DELETE FROM revisit_followups WHERE followed_up_by = ?`).run(name);
    db.prepare(`DELETE FROM sales_targets WHERE scope_type = 'sales_rep' AND scope_name = ?`).run(name);
    scrubAuthoredWork(db, name);   // r4: his tasks / sent flows (leadIsMine) — the name is freed below

    // 6. Delete the user.
    db.prepare(`DELETE FROM users WHERE name = ? AND role != 'admin'`).run(name);
  })();

  console.log(`🗑️  USER SCRUBBED (hard reset): ${name}`);
  return res.json({ ok: true, mode: 'scrub', name });
});

// ════════════════════════════════════════════════════════════════════════════
// POST /api/admin/cleanup-orphan-reps — scrub leftover data from sales/call
// reps who were deleted WITHOUT scrubbing (e.g. via the old plain delete).
// Finds rep names referenced in the data that no longer exist as users.
// ════════════════════════════════════════════════════════════════════════════
app.post('/api/admin/cleanup-orphan-reps', requireAuth, requireRole('admin'), (req, res) => {
  const db = getDb();
  const valid = new Set(
    db.prepare(`SELECT name FROM users WHERE role IN ('sales', 'rep')`).all().map(r => r.name)
  );
  const referenced = new Set();
  const sources = [
    `SELECT DISTINCT sales_rep      AS n FROM lead_visits WHERE sales_rep IS NOT NULL`,
    `SELECT DISTINCT pre_visit_rep  AS n FROM lead_visits WHERE pre_visit_rep IS NOT NULL`,
    `SELECT DISTINCT rep            AS n FROM purchases   WHERE rep IS NOT NULL`,
    `SELECT DISTINCT assigned_sales AS n FROM branch_customer_followups WHERE assigned_sales IS NOT NULL`,
    `SELECT DISTINCT assigned_rep   AS n FROM lead_profiles WHERE assigned_rep IS NOT NULL`,
  ];
  for (const q of sources) {
    for (const r of db.prepare(q).all()) if (r.n) referenced.add(r.n);
  }
  const orphans = [...referenced].filter(n => !valid.has(n));
  // r4: tasks / sent flows can be written by any role — a name there is an
  // orphan only when NO account (any role) carries it.
  const anyName = new Set(db.prepare(`SELECT name FROM users`).all().map(r => r.name));
  const authoredOrphans = new Set();
  for (const q of [`SELECT DISTINCT rep_name AS n FROM tasks WHERE rep_name IS NOT NULL`,
                   `SELECT DISTINCT sent_by_rep AS n FROM messages_sent WHERE sent_by_rep IS NOT NULL`]) {
    for (const r of db.prepare(q).all()) if (r.n && !anyName.has(r.n)) authoredOrphans.add(r.n);
  }
  for (const n of authoredOrphans) if (!orphans.includes(n)) orphans.push(n);

  db.transaction(() => {
    for (const n of orphans) {
      if (referenced.has(n) && !valid.has(n)) scrubRepReferences(db, n, { authored: !anyName.has(n) });
      else scrubAuthoredWork(db, n);
    }
  })();

  console.log(`🧹 ORPHAN REP CLEANUP: ${orphans.length} — ${orphans.join(', ') || 'none'}`);
  return res.json({ ok: true, cleaned_count: orphans.length, cleaned: orphans });
});

// ════════════════════════════════════════════════════════════════════════════
// Admin undo ledger — list recent assignment actions and revert human errors.
// ════════════════════════════════════════════════════════════════════════════

// Action types the ledger can undo → the only table their old_state may restore.
//   assign_customer / set_sales stored the FULL pre-action row (null when the
//     action created it) → put that row back verbatim, or delete the new row.
//   assign_post_visit changed only lead_visits.sales_rep and stored just that
//     column ({ where: { id }, row: { sales_rep } }) → UPDATE it back in place
//     (INSERT OR REPLACE with that partial row fails NOT NULL on user_id).
// Every other type — bulk_assign, bulk_reassign_customers, swap_reps,
// transfer_rep, mark_duplicate, rep_history_repair (one-off repair trace, no
// table by design) — is display-only: its old_state is a summary, not a row.
//   contract_date_change (2026-11-25) changed only purchases.created_at and
//     stored it ({ where: { id }, row: { created_at }, to_at }) → UPDATE it back,
//     only while the contract still has the date this change gave it (a later
//     change is undone first), and the customer's purchased_at follows.
const REVERTABLE_AUDIT_TABLES = {
  assign_customer:   'branch_customer_followups',
  set_sales:         'lead_visits',
  assign_post_visit: 'lead_visits',
  contract_date_change: 'purchases',
};

// old_state keys are interpolated into SQL as column names → only a non-empty
// plain object of identifiers is accepted.
function isAuditColumnMap(obj) {
  return !!obj && typeof obj === 'object' && !Array.isArray(obj) &&
    Object.keys(obj).length > 0 && Object.keys(obj).every(k => /^[A-Za-z_]\w*$/.test(k));
}

// Shared by the list (its `revertable` flag gates the UI's undo button) and the
// revert endpoint, so the button only shows when the revert can really run.
// → { revert(db) } — which returns false when the target row is gone — or { error }.
function planAuditRevert(log) {
  const table = REVERTABLE_AUDIT_TABLES[log.action_type];
  if (!table) return { error: 'action_not_revertable' };

  let state;
  try { state = JSON.parse(log.old_state || 'null'); } catch (_) { state = null; }
  if (!state || state.table !== table || !isAuditColumnMap(state.where) ||
      (state.row != null && !isAuditColumnMap(state.row))) {
    return { error: 'bad_old_state' };
  }
  const { where, row } = state;

  if (log.action_type === 'contract_date_change') {
    if (where.id == null || !row || typeof row.created_at !== 'string' || typeof state.to_at !== 'string') return { error: 'bad_old_state' };
    return {
      revert: (db) => {
        const cur = db.prepare(`SELECT user_id, created_at FROM purchases WHERE id = ?`).get(where.id);
        if (!cur) return false;
        // review r2: a later change that landed back on this change's day has
        // the same to_at (the time of day is kept) — any newer change still
        // standing on this contract must be undone first.
        const newer = db.prepare(`SELECT 1 FROM system_audit_log
          WHERE action_type = 'contract_date_change' AND COALESCE(reverted, 0) = 0 AND id > ?
            AND CAST(json_extract(old_state, '$.where.id') AS INTEGER) = ? LIMIT 1`).get(log.id, where.id);
        if (newer || cur.created_at !== state.to_at) return 'تاريخ العقد ده اتغيّر تاني بعد التعديل ده — رجّع التعديل الأحدث الأول';
        db.prepare(`UPDATE purchases SET created_at = ? WHERE id = ?`).run(row.created_at, where.id);
        syncPurchasedAt(db, cur.user_id);
        return true;
      },
    };
  }

  if (log.action_type === 'assign_post_visit') {
    if (where.id == null || !row || !('sales_rep' in row)) return { error: 'bad_old_state' };
    return {
      revert: (db) => db.prepare(`UPDATE lead_visits SET sales_rep = ? WHERE id = ?`)
        .run(row.sales_rep, where.id).changes > 0,
    };
  }

  return {
    revert: (db) => {
      if (!row) {
        // The row did not exist before the action → undo = delete it.
        const keys = Object.keys(where);
        db.prepare(`DELETE FROM ${table} WHERE ${keys.map(k => `${k} = ?`).join(' AND ')}`)
          .run(...keys.map(k => where[k]));
      } else {
        // Restore the row exactly as it was (row includes the primary key).
        const cols = Object.keys(row);
        db.prepare(
          `INSERT OR REPLACE INTO ${table} (${cols.join(', ')}) VALUES (${cols.map(() => '?').join(', ')})`
        ).run(...cols.map(c => row[c]));
      }
      return true;
    },
  };
}

app.get('/api/admin/audit-logs', requireAuth, requireRole('admin'), (req, res) => {
  const db = getDb();
  const logs = db.prepare(`
    SELECT id, operator_name, action_type, target_id, old_state, created_at, reverted
    FROM system_audit_log
    ORDER BY created_at DESC, id DESC
    LIMIT 200
  `).all().map(log => ({ ...log, revertable: !planAuditRevert(log).error }));
  return res.json({ logs });
});

app.post('/api/admin/audit-logs/:id/revert', requireAuth, requireRole('admin'), (req, res) => {
  const db  = getDb();
  const log = db.prepare(`SELECT * FROM system_audit_log WHERE id = ?`).get(req.params.id);
  if (!log) return res.status(404).json({ error: 'log_not_found' });
  if (log.reverted) return res.status(400).json({ error: 'already_reverted' });

  const plan = planAuditRevert(log);
  if (plan.error) return res.status(400).json({ error: plan.error });

  const restored = db.transaction(() => {
    const done = plan.revert(db);
    if (typeof done === 'string') return done;   // a conflict, said in Arabic
    if (!done) return false;
    // Mark the ledger entry as reverted so the UI reflects it.
    db.prepare(`UPDATE system_audit_log SET reverted = 1 WHERE id = ?`).run(log.id);
    return true;
  })();
  if (typeof restored === 'string') return res.status(409).json({ error: restored, code: 'changed_since' });
  if (!restored) {
    return res.status(409).json({ error: 'البيانات اللي الإجراء ده عدّلها اتمسحت — مفيش حاجة ترجع' });
  }

  console.log(`↩️  AUDIT REVERT: log#${log.id} (${log.action_type}) by ${req.user?.name}`);
  return res.json({ ok: true, reverted: log.action_type, target_id: log.target_id });
});

// Resolve a branch id (e.g. 'nasr_city') to its Arabic label from the
// active_branches setting; falls back to the raw value. Used by CSV export.
function branchLabelMap(db) {
  try {
    const row = db.prepare(`SELECT value FROM settings WHERE key='active_branches'`).get();
    const arr = JSON.parse(row?.value || '[]');
    const m = {};
    for (const b of arr) if (b && b.id) m[b.id] = b.name || b.id;
    return m;
  } catch (_) { return {}; }
}

// ════════════════════════════════════════════════════════════════════════════
// Removed 2026-11-22 («أرقام حقيقية»): «التحليلات العميقة».
//   GET /api/analytics/advanced — its four numbers were not true:
//     «حجم الأموال المعلقة» = hot × a fixed ticket + warm × a fixed ticket (a
//     made-up «avg ticket», never a sale); «معدل الإغلاق الحقيقي» = all-time
//     contracts ÷ all-time assignments (two different groups of people, no
//     date); «سرعة التعاقد» mixed walk-ins who buy on day 0; «الفرص الضائعة»
//     counted today's «بارد» class, its branch «غير محدد» by construction.
//     Nothing true was left: the page is gone and its URL opens «من الإعلان
//     للبيعة». The only money on the analytics screens is real sales (paid, or
//     the admin-only list estimate marked «تقريبي»).
//   GET /api/predictions, GET|PUT /api/settings/forecast-weights — a «visit
//     forecast» from fixed weights (80% with a phone / 35% without), on no
//     screen. Gone with them.
// Each answers 410 with an Arabic line (an old tab still open shows a message).
// ════════════════════════════════════════════════════════════════════════════
for (const [m, p] of [
  ['get', '/api/analytics/advanced'],
  ['get', '/api/predictions'],
  ['get', '/api/settings/forecast-weights'],
  ['put', '/api/settings/forecast-weights'],
]) app[m](p, requireAuth, removedRoute);

// ════════════════════════════════════════════════════════════════════════════
// GET /api/admin/search?q= — fast global lead lookup for the Ctrl+K command
// palette. Matches by customer name OR any phone number. Admin-only.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/admin/search', requireAuth, requireRole('admin'), (req, res) => {
  const q = String(req.query.q || '').trim();
  if (q.length < 2) return res.json({ results: [] });
  const db   = getDb();
  const like = `%${q}%`;
  const results = db.prepare(`
    SELECT lp.user_id, lp.first_name, lp.lead_class,
      COALESCE(lp.phone, (SELECT ph.phone FROM lead_phones ph
                          WHERE ph.user_id = lp.user_id ORDER BY ph.id LIMIT 1)) AS phone
    FROM lead_profiles lp
    WHERE lp.first_name LIKE ?
       OR lp.phone LIKE ?
       OR lp.user_id IN (SELECT user_id FROM lead_phones WHERE phone LIKE ?)
    ORDER BY lp.last_activity DESC
    LIMIT 8
  `).all(like, like, like);
  return res.json({ results });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/search?q= — the top bar's search, for EVERY role, each within its
// own scope (phase 1, 2026-11-22). By name or any phone (Arabic digits and
// «+20 / 0100-…» spellings fold the same way as the other boxes: searchTerms).
//   admin     → every customer;
//   reception → every customer it may open (canSeeLead: reception opens any
//               profile; the profile itself trims other branches away);
//   branch_manager → customers tied to his branch (leadTiedToBranch);
//   sales / rep    → his own customers (leadIsMine).
// The SQL narrows to the scope first (so a common name can't push his own
// customers out of the page), and every row returned is re-checked with the
// same predicate the profile uses — a result always opens.
// ════════════════════════════════════════════════════════════════════════════
const SEARCH_SCOPE_MINE = `
  SELECT user_id FROM lead_profiles WHERE assigned_rep = @n
  UNION SELECT user_id FROM branch_customer_followups WHERE TRIM(assigned_sales) = TRIM(@n)
  UNION SELECT user_id FROM lead_visits WHERE TRIM(sales_rep) = TRIM(@n) OR pre_visit_rep = @n
  UNION SELECT user_id FROM followup_log WHERE sales = @n
  UNION SELECT user_id FROM purchases WHERE TRIM(rep) = TRIM(@n)
  UNION SELECT user_id FROM revisit_followups WHERE followed_up_by = @n
  UNION SELECT lead_id FROM tasks WHERE rep_name = @n
  UNION SELECT user_id FROM messages_sent WHERE sent_by_rep = @n`;
const SEARCH_SCOPE_BRANCH = `
  SELECT user_id FROM lead_profiles WHERE preferred_branch = @b
  UNION SELECT user_id FROM events WHERE branch = @b
          OR (event_type IN ('branch_selected','location_request') AND event_value = @b)
  UNION SELECT user_id FROM lead_visits WHERE branch = @b
  UNION SELECT user_id FROM visit_checkins WHERE branch = @b
  UNION SELECT user_id FROM branch_customer_followups WHERE branch = @b
  UNION SELECT user_id FROM followup_log WHERE branch = @b
  UNION SELECT user_id FROM purchases WHERE branch = @b
  UNION SELECT lp.user_id FROM lead_profiles lp JOIN users su ON su.name = lp.assigned_rep WHERE su.branch = @b`;
const SEARCH_PAGE = 20;
function searchScopeOf(user) {
  const role = user?.role;
  if (role === 'admin' || role === 'reception') return { sql: null, check: (db, id) => canSeeLead(db, user, id) };
  if (role === 'branch_manager') {
    if (!user.branch) return null;
    return { sql: SEARCH_SCOPE_BRANCH, params: { b: user.branch }, check: (db, id) => leadTiedToBranch(db, id, user.branch) };
  }
  if (role === 'sales' || role === 'rep') {
    if (!user.name) return null;
    return { sql: SEARCH_SCOPE_MINE, params: { n: user.name }, check: (db, id) => leadIsMine(db, id, user.name) };
  }
  return null;
}
app.get('/api/search', requireAuth, (req, res) => {
  const t = searchTerms(req.query.q);
  if (!t || t.q.length < 2) return res.json({ results: [] });
  const scope = searchScopeOf(req.user);
  if (!scope) return res.json({ results: [] });
  const db = getDb();
  const rows = db.prepare(`
    SELECT lp.user_id, lp.first_name, lp.lead_class, lp.preferred_branch, lp.last_activity,
      COALESCE(NULLIF(lp.phone, ''), (SELECT ph.phone FROM lead_phones ph
                          WHERE ph.user_id = lp.user_id ORDER BY ph.id LIMIT 1)) AS phone
    FROM lead_profiles lp
    WHERE (lp.first_name LIKE @like ESCAPE '\\'
       OR lp.phone LIKE @phoneLike ESCAPE '\\'
       OR lp.user_id IN (SELECT user_id FROM lead_phones WHERE phone LIKE @phoneLike ESCAPE '\\'))
      ${scope.sql ? `AND lp.user_id IN (${scope.sql})` : ''}
    ORDER BY lp.last_activity DESC
    LIMIT ${SEARCH_PAGE * 3}
  `).all({ like: t.like, phoneLike: t.phoneLike, ...(scope.params || {}) });
  const results = rows.filter(r => scope.check(db, r.user_id)).slice(0, SEARCH_PAGE)
    .map(({ last_activity, ...r }) => r);
  return res.json({ results });
});

// ════════════════════════════════════════════════════════════════════════════
// CSV export — Leads & Contracts as UTF-8 (with BOM, so Arabic opens correctly
// in Excel). Admin-only. Streams an attachment.
// ════════════════════════════════════════════════════════════════════════════
const CSV_BOM = '﻿';
const csvCell = (v) => {
  const s = v == null ? '' : String(v);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};
const csvRow = (arr) => arr.map(csvCell).join(',');
function sendCsv(res, filename, headerRow, rows) {
  const body = CSV_BOM + [csvRow(headerRow), ...rows.map(csvRow)].join('\r\n') + '\r\n';
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  return res.send(body);
}

app.get('/api/admin/export/leads.csv', requireAuth, requireRole('admin'), (req, res) => {
  const db   = getDb();
  const blm  = branchLabelMap(db);
  const rows = db.prepare(`
    SELECT lp.user_id, lp.first_name, lp.lead_class, lp.total_score,
      lp.preferred_branch, lp.last_category, lp.campaign_source, lp.platform,
      lp.created_at, lp.last_activity,
      COALESCE(lp.phone, (SELECT ph.phone FROM lead_phones ph
                          WHERE ph.user_id = lp.user_id ORDER BY ph.id LIMIT 1)) AS phone
    FROM lead_profiles lp
    ORDER BY lp.created_at DESC
    LIMIT 50000
  `).all();
  const CLASS_AR = { cold: 'بارد', warm: 'دافئ', hot: 'ساخن', visited: 'زار', purchased: 'اشترى' };
  const out = rows.map((r) => [
    r.user_id, r.first_name || '', r.phone || '', CLASS_AR[r.lead_class] || r.lead_class || '',
    r.total_score ?? 0, blm[r.preferred_branch] || r.preferred_branch || '', r.last_category || '',
    r.campaign_source || '', r.platform || '', r.created_at || '', r.last_activity || '',
  ]);
  return sendCsv(res, 'leads-export.csv',
    ['معرّف العميل', 'الاسم', 'التليفون', 'التصنيف', 'النقاط', 'الفرع', 'آخر فئة',
     'مصدر الحملة', 'المنصة', 'تاريخ التسجيل', 'آخر نشاط'], out);
});

app.get('/api/admin/export/contracts.csv', requireAuth, requireRole('admin'), (req, res) => {
  const db   = getDb();
  const blm  = branchLabelMap(db);
  const rows = db.prepare(`
    SELECT p.contract_number, p.created_at, p.branch, p.rep, p.price,
      lp.first_name,
      COALESCE(lp.phone, (SELECT ph.phone FROM lead_phones ph
                          WHERE ph.user_id = p.user_id ORDER BY ph.id LIMIT 1)) AS phone,
      (SELECT GROUP_CONCAT(COALESCE(pl.title, '') || CASE WHEN pl.qty > 1 THEN ' ×' || pl.qty ELSE '' END, ' + ')
         FROM purchase_lines pl WHERE pl.purchase_id = p.id) AS lines_text,
      e.list_total_estimate, e.estimate_complete
    FROM purchases p
    LEFT JOIN lead_profiles lp ON lp.user_id = p.user_id
    LEFT JOIN purchase_estimates e ON e.purchase_id = p.id
    ORDER BY p.created_at DESC
    LIMIT 50000
  `).all();
  // admin only (this route): the estimate column says «تقريبي» in its header
  const out = rows.map((r) => [
    r.contract_number || '', r.first_name || '', r.phone || '',
    blm[r.branch] || r.branch || '', r.rep || '', r.created_at || '',
    r.lines_text || '', r.price > 0 ? r.price : '',
    r.list_total_estimate != null ? `${r.list_total_estimate}${r.estimate_complete ? '' : ' (ناقص)'}` : '',
  ]);
  return sendCsv(res, 'contracts-export.csv',
    ['رقم التعاقد', 'العميل', 'التليفون', 'الفرع', 'السيلز', 'تاريخ التعاقد', 'المنتجات', 'المدفوع', 'تقريبي (أسعار القايمة يوم البيعة)'], out);
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/admin/system-health — infrastructure vitals so the admin can spot a
// growing DB / runaway table before it bites. DB file size, per-table row
// counts, server uptime & memory. Admin-only.
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/admin/system-health', requireAuth, requireRole('admin'), (req, res) => {
  const fs = require('fs');
  const db = getDb();

  let db_bytes = null;
  try { db_bytes = fs.statSync(db.name).size; } catch (_) { /* path may be unavailable */ }

  const TABLES = [
    'lead_profiles', 'lead_phones', 'lead_visits', 'events', 'purchases',
    'purchase_items', 'branch_customer_followups', 'followup_log',
    'revisit_followups', 'users', 'products', 'tasks',
  ];
  const tables = {};
  let total_rows = 0;
  for (const t of TABLES) {
    try {
      const n = db.prepare(`SELECT COUNT(*) AS n FROM ${t}`).get().n;
      tables[t] = n;
      total_rows += n;
    } catch (_) { tables[t] = null; }
  }

  const mem = process.memoryUsage();
  return res.json({
    db_bytes,
    db_mb: db_bytes != null ? Math.round((db_bytes / 1048576) * 100) / 100 : null,
    total_rows,
    tables,
    uptime_seconds: Math.round(process.uptime()),
    memory_rss_mb: Math.round((mem.rss / 1048576) * 10) / 10,
    node_version: process.version,
    now: new Date().toISOString(),
  });
});

// ════════════════════════════════════════════════════════════════════════════
// POST /api/admin/swap-reps — swap two sales reps: exchange their BRANCH and
// their PRE-VISIT customer assignments (branch_customer_followups). Each rep
// ends up in the other's branch holding the other's customer list.
// Post-visit / revisit ownership is intentionally LEFT UNTOUCHED — it's
// owner-based (whoever actually served the customer keeps them, per the
// commission design). Body: { repA, repB } = user ids.
// ════════════════════════════════════════════════════════════════════════════
app.post('/api/admin/swap-reps', requireAuth, requireRole('admin'), (req, res) => {
  const db  = getDb();
  const aId = req.body?.repA, bId = req.body?.repB;
  if (!aId || !bId || String(aId) === String(bId)) {
    return res.status(400).json({ error: 'اختار سيلزين مختلفين' });
  }
  const a = db.prepare(`SELECT id, name, branch, role, active FROM users WHERE id = ?`).get(aId);
  const b = db.prepare(`SELECT id, name, branch, role, active FROM users WHERE id = ?`).get(bId);
  if (!a || !b) return res.status(404).json({ error: 'سيلز مش موجود' });
  if (!['sales', 'rep'].includes(a.role) || !['sales', 'rep'].includes(b.role)) {
    return res.status(400).json({ error: 'التبديل للسيلز بس' });
  }
  if (Number(a.active) !== 1 || Number(b.active) !== 1) {   // 2026-11-25: a stopped one is never picked
    return res.status(400).json({ error: 'السيلز ده متوقف — رجّعه الأول من «متوقفين»', code: 'rep_not_active' });
  }
  if (a.name.trim() === b.name.trim()) {
    return res.status(400).json({ error: 'الاتنين بنفس الاسم — مينفعش التبديل' });
  }

  const countFor = (nm) => db.prepare(`
    SELECT COUNT(*) AS total,
      SUM(CASE WHEN COALESCE((SELECT visit_confirmed FROM lead_profiles lp
            WHERE lp.user_id = branch_customer_followups.user_id), 0) = 0 THEN 1 ELSE 0 END) AS previsit
    FROM branch_customer_followups WHERE TRIM(assigned_sales) = TRIM(?)`).get(nm);
  const beforeA = countFor(a.name), beforeB = countFor(b.name);

  const rows_swapped = db.transaction(() => {
    // CASE swap → atomic, no temp value needed. Only assigned_sales changes, so
    // each customer keeps their follow-up status, notes and original assign date.
    const moved = db.prepare(`
      UPDATE branch_customer_followups
      SET assigned_sales = CASE WHEN TRIM(assigned_sales) = TRIM(@a) THEN @b ELSE @a END
      WHERE TRIM(assigned_sales) IN (TRIM(@a), TRIM(@b))
    `).run({ a: a.name, b: b.name }).changes;
    // Swap their branch (values captured before the tx).
    db.prepare(`UPDATE users SET branch = ? WHERE id = ?`).run(b.branch, a.id);
    db.prepare(`UPDATE users SET branch = ? WHERE id = ?`).run(a.branch, b.id);
    return moved;
  })();

  auditLog(db, req.user?.name, 'swap_reps', `${a.id}-${b.id}`, {
    type: 'swap_reps',
    a: { id: a.id, name: a.name, branch: a.branch },
    b: { id: b.id, name: b.name, branch: b.branch },
  });
  createNotification(db, 'admin', 'swap_reps',
    `تم تبديل ${a.name} (${a.branch || '—'}) و ${b.name} (${b.branch || '—'}) وعملائهم قبل الزيارة`);

  const afterA = countFor(a.name), afterB = countFor(b.name);
  return res.json({
    ok: true,
    rows_swapped,
    a: { name: a.name, old_branch: a.branch, new_branch: b.branch, before: beforeA.total, after: afterA.total, previsit_after: afterA.previsit },
    b: { name: b.name, old_branch: b.branch, new_branch: a.branch, before: beforeB.total, after: afterB.total, previsit_after: afterB.previsit },
  });
});

// ════════════════════════════════════════════════════════════════════════════
// POST /api/admin/transfer-rep — move a sales rep to another branch WITHOUT
// dragging their customers along. Their old-branch PRE-visit customers are
// released to the unassigned pool (so that branch's manager redistributes them);
// history (visits, purchases, followup_log) is untouched; post-visit/revisit
// customers naturally fall under the old branch (owner-based by where they were
// served). Body: { repId, newBranch }.
// ════════════════════════════════════════════════════════════════════════════
app.post('/api/admin/transfer-rep', requireAuth, requireRole('admin'), (req, res) => {
  const db = getDb();
  const repId = req.body?.repId;
  const newBranch = (req.body?.newBranch && String(req.body.newBranch).trim()) || null;
  if (!repId || !newBranch) return res.status(400).json({ error: 'اختار السيلز والفرع الجديد' });

  const rep = db.prepare(`SELECT id, name, branch, role, active FROM users WHERE id = ?`).get(repId);
  if (!rep) return res.status(404).json({ error: 'السيلز مش موجود' });
  if (!['sales', 'rep'].includes(rep.role)) return res.status(400).json({ error: 'النقل للسيلز بس' });
  if (Number(rep.active) !== 1) {   // 2026-11-25: a stopped one is never picked
    return res.status(400).json({ error: 'السيلز ده متوقف — رجّعه الأول من «متوقفين»', code: 'rep_not_active' });
  }
  if ((rep.branch || null) === newBranch) return res.status(400).json({ error: 'هو أصلاً في الفرع ده' });

  const oldBranch = rep.branch || null;

  const released = db.transaction(() => {
    // Release the rep's PRE-visit customers in the OLD branch back to the pool
    // (clear assignment + reset the cycle; prior calls stay in followup_log).
    const rows = db.prepare(`
      SELECT f.id FROM branch_customer_followups f
      JOIN lead_profiles lp ON lp.user_id = f.user_id
      WHERE TRIM(f.assigned_sales) = TRIM(?)
        AND f.branch IS ${oldBranch === null ? 'NULL' : '?'}
        AND COALESCE(lp.visit_confirmed, 0) = 0
    `).all(...(oldBranch === null ? [rep.name] : [rep.name, oldBranch])).map(r => r.id);
    if (rows.length) {
      const ph = rows.map(() => '?').join(',');
      db.prepare(`
        UPDATE branch_customer_followups
        SET assigned_sales = NULL, assigned_by = NULL, auto_assigned = 0,
            followed_up = 0, followed_up_at = NULL, followed_up_by = NULL, call_summary = NULL
        WHERE id IN (${ph})
      `).run(...rows);
    }
    db.prepare(`UPDATE users SET branch = ? WHERE id = ?`).run(newBranch, rep.id);
    return rows.length;
  })();

  auditLog(db, req.user?.name, 'transfer_rep', String(rep.id), {
    type: 'transfer_rep', rep: { id: rep.id, name: rep.name }, from: oldBranch, to: newBranch, released,
  });
  createNotification(db, 'admin', 'transfer_rep',
    `تم نقل ${rep.name} من ${oldBranch || '—'} لـ ${newBranch} — ${released} عميل قبل الزيارة رجعوا "مش متوزّع" في الفرع القديم`);

  return res.json({ ok: true, rep: rep.name, from: oldBranch, to: newBranch, released });
});

// ════════════════════════════════════════════════════════════════════════════
// The demo sandbox («وضع التدريب») — REMOVED (owner, 2026-11-22).
// It cloned production (every customer and phone) into a second DB for four
// demo_* training logins; the phase 0 reviews kept finding ways across it.
// Both buttons are gone from the portal; the routes answer 410 «اتشال» so an
// old portal tab gets a plain answer. Nothing makes, clones or seeds the
// sandbox any more: demo_ logins are 401, a demo token is refused
// (middleware/auth.js) and the old file is deleted at boot (db.js).
// ════════════════════════════════════════════════════════════════════════════
const DEMO_REMOVED = { error: 'وضع التدريب اتشال — الحسابات التجريبية مبقتش موجودة', code: 'demo_removed' };
app.post('/api/admin/generate-demo-accounts', requireAuth, requireRole('admin'), (req, res) => res.status(410).json(DEMO_REMOVED));
app.post('/api/admin/wipe-demo-accounts', requireAuth, requireRole('admin'), (req, res) => res.status(410).json(DEMO_REMOVED));

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
  // Defaults to the current CAIRO month when ?month is not given.
  const month = (req.query.month && String(req.query.month).trim()) || currentMonth();
  const db = getDb();
  const rows = db.prepare(`
    SELECT scope_type, scope_name, target_month, target_amount
    FROM sales_targets WHERE target_month = ?
  `).all(month);
  // A stopped salesperson's target (2026-11-25) is not listed — it stays
  // stored, and comes back with him when he is re-activated.
  const who = honest.sellers(db);
  return res.json({ month, targets: rows.filter((t) => t.scope_type !== 'sales_rep' || who.shown(t.scope_name)) });
});

app.post('/api/admin/targets', requireAuth, requireRole('admin'), (req, res) => {
  const { scope_type, scope_name, target_amount, target_month } = req.body || {};
  if (!['branch', 'sales_rep'].includes(scope_type)) {
    return res.status(400).json({ error: 'bad_scope_type' });
  }
  const name = (scope_name && String(scope_name).trim()) || '';
  if (!name) return res.status(400).json({ error: 'scope_name_required' });
  // A salesperson's target is for an ACTIVE salesperson (2026-11-25): never a
  // stopped one, never a free-typed name.
  if (scope_type === 'sales_rep' && !getDb().prepare(
    `SELECT 1 FROM users WHERE TRIM(name) = ? AND role IN ('sales','rep') AND active = 1`).get(name)) {
    return res.status(400).json({ error: 'السيلز ده متوقف أو مش موجود — اختار من القايمة', code: 'rep_not_active' });
  }
  const amount = Number(target_amount);
  if (!Number.isFinite(amount) || amount < 0) {
    return res.status(400).json({ error: 'bad_target_amount' });
  }
  // Default to the current Cairo month; validate the 'YYYY-MM' shape.
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
// GET /api/admin/kpis — the admin home's cards and charts. Filters: startDate,
// endDate (CAIRO days, 'YYYY-MM-DD'; none = all time), branch, rep.
// 2026-11-22 «أرقام حقيقية» — every number on the screen follows the SAME
// filter (services/honestNumbers.js):
//   contracts_count   — contracts recorded in the range at the branch;
//   total_visits      — people who came to a showroom in the range (check-ins,
//                       every day they came — a returning customer counts),
//                       walk-ins included; visit_count = the visits themselves;
//   closing_rate      — of THOSE visitors, how many bought in the range (the
//                       same people, so never above 100%);
//   funnel            — people, not events: the customers whose first chat
//                       fell in the range and how far they got by today
//                       (كلّموا → سابوا رقم → اختاروا فرع / قالوا جايين → زاروا
//                       → اشتروا). Chats and phones carry no branch: with a
//                       branch filter they stay «كل الفروع» (branch_scoped:false);
//                       walk-ins are their own line, never a chat step;
//   branch_demand     — chat customers who asked for each branch in the range
//                       (walk-in events left out);
//   branch_visits     — people who came to each branch in the range.
// rep narrows the contracts and the target only. The class pie («توزيع
// العملاء»: today's class of people created in the range) is gone: «ساخن» was
// points, not a step.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/admin/kpis', requireAuth, requireRole('admin'), (req, res) => {
  const db = getDb();
  const { startDate, endDate, branch, rep } = req.query;
  if ((startDate && !honest.isDay(startDate)) || (endDate && !honest.isDay(endDate))) {
    return res.status(400).json({ error: 'التاريخ لازم يكون YYYY-MM-DD' });
  }
  const from = startDate || null;
  const to   = endDate || null;

  // Contracts + buyers from purchases (Cairo days).
  const purDate = honest.rangeSql('created_at', from, to);
  let purWhere = '1=1' + purDate.clause;
  const purParams = [...purDate.params];
  if (branch) { purWhere += ' AND branch = ?'; purParams.push(branch); }
  if (rep)    { purWhere += ' AND rep = ?';    purParams.push(rep); }
  const purRow = db.prepare(`
    SELECT COALESCE(SUM(price), 0) AS revenue, COUNT(DISTINCT user_id) AS buyers,
           COUNT(*) AS contracts
    FROM purchases WHERE ${purWhere}
  `).get(...purParams);

  // Visitors (and buyers among them) — every check-in day, Cairo.
  const pv = honest.periodVisits(db, { from, to, branch: branch || null });

  // Target progress — strictly the CURRENT Cairo month: this month's
  // target vs contracts this month (independent of the filter range).
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
  const monthRev  = monthRevenue(db, { branch, rep, month: curMonth });
  const monthCnts = monthContracts(db, { branch, rep, month: curMonth });

  // Branch demand — chat customers who asked for each branch (no walk-in event).
  const evDate = honest.rangeSql('e.created_at', from, to);
  let bdWhere = `e.event_type IN ('branch_selected', 'location_request')
    AND COALESCE(NULLIF(e.branch,''), e.event_value) IS NOT NULL AND ${honest.CHAT_EVENT('e')}` + evDate.clause;
  const bdParams = [...evDate.params];
  if (branch) { bdWhere += ` AND COALESCE(NULLIF(e.branch,''), e.event_value) = ?`; bdParams.push(branch); }
  const branch_demand = db.prepare(`
    SELECT COALESCE(NULLIF(e.branch,''), e.event_value) AS branch, COUNT(DISTINCT e.user_id) AS requests
    FROM events e WHERE ${bdWhere}
    GROUP BY COALESCE(NULLIF(e.branch,''), e.event_value)
    ORDER BY requests DESC
  `).all(...bdParams);

  const funnel = honest.homeFunnel(db, { from, to, branch: branch || null });

  return res.json({
    from, to, branch: branch || null, timezone: CAIRO_TZ,
    total_revenue:    purRow.revenue || 0,     // kept for backward-compat
    contracts_count:  purRow.contracts || 0,   // headline metric now
    total_visits:     pv.visitors,
    visit_count:      pv.checkins,
    bought_of_visitors: pv.bought_of_visitors,
    closing_rate:     pv.visitors ? Math.round((pv.bought_of_visitors / pv.visitors) * 100) : 0,
    target,                                     // a CONTRACTS target now
    target_month:     curMonth,
    month_revenue:    monthRev,
    month_contracts:  monthCnts,
    percent_achieved: pctAchieved(monthCnts, target),
    funnel,
    branch_demand,
    branch_visits:    pv.by_branch,
  });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/sales/my-target — a sales rep sees their OWN target + achievement.
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/sales/my-target', requireAuth, authorizeRoles('sales', 'rep'), (req, res) => {
  const db = getDb();
  const me = req.user.name;
  // Current Cairo month: this month's target vs this month's contracts.
  const target    = getTarget(db, 'sales_rep', me);
  const revenue   = monthRevenue(db, { rep: me });
  const contracts = monthContracts(db, { rep: me });
  return res.json({
    target,                                  // a CONTRACTS target now
    revenue,                                 // kept for backward-compat
    contracts,
    percent:      pctAchieved(contracts, target),
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
// BUILD_VERSION is declared at the top of this file (the boot backup uses it).
// How many old rows still hold 'all_branches' (never rewritten — review r2)
// and how many profiles the one-time cleanup backed up. Counts only, cached
// 5 minutes (Railway pings /health constantly).
let _allBranchesCache = { at: 0, value: null };
function allBranchesCounts() {
  if (_allBranchesCache.value && Date.now() - _allBranchesCache.at < 5 * 60 * 1000) return _allBranchesCache.value;
  try {
    const db = getDb();
    const n = (sql) => db.prepare(sql).get().n;
    const hasBackup = !!db.prepare(`SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'migr_all_branches_backup'`).get();
    const value = {
      lead_visits:    n(`SELECT COUNT(*) AS n FROM lead_visits WHERE LOWER(TRIM(branch)) = 'all_branches'`),
      visit_checkins: n(`SELECT COUNT(*) AS n FROM visit_checkins WHERE LOWER(TRIM(branch)) = 'all_branches'`),
      events:         n(`SELECT COUNT(*) AS n FROM events WHERE LOWER(TRIM(branch)) = 'all_branches'`),
      lead_profiles:  n(`SELECT COUNT(*) AS n FROM lead_profiles WHERE LOWER(TRIM(preferred_branch)) = 'all_branches'`),
      backup_rows:    hasBackup ? n(`SELECT COUNT(*) AS n FROM migr_all_branches_backup`) : 0,
    };
    _allBranchesCache = { at: Date.now(), value };
    return value;
  } catch (_) {
    return null;
  }
}
// Counts only, since boot (C1.12) — no ids, names, phones or keys. They make
// the bot's test mode, the window guard and the ManyChat key checkable from
// outside with a plain GET.
// Phase 0 additions — booleans and counts only, never a value, path or name:
//   jwt_secret_from_env — true when JWT_SECRET is set in the environment
//                         (false = the signing key lives in the DB settings);
//   jwt_rotated         — true once the DB-stored key was replaced by the
//                         one-time r3 rotation (never with JWT_SECRET in env);
//   users_by_role       — active staff accounts per role (live DB);
//   zai_key_set / mcp_key_set — whether the z.ai key (live settings) and
//                         MCP_SECRET_KEY (env) are set;
//   usage               — hits since boot (see USAGE_ROUTES);
//   outbound_blocked_demo — outgoing calls a demo_ session tried, refused;
//   backup              — last_backup_at, backup_count (+ last_error);
//   node                — the running Node version (the 22.x pin).
let _rolesCache = { at: 0, value: null };
function usersByRole() {
  if (_rolesCache.value && Date.now() - _rolesCache.at < 5 * 60 * 1000) return _rolesCache.value;
  try {
    const rows = getLiveDb().prepare(`SELECT role, COUNT(*) AS n FROM users WHERE active = 1 GROUP BY role`).all();
    const value = { admin: 0, branch_manager: 0, sales: 0, reception: 0, rep: 0 };
    for (const r of rows) {
      const k = Object.prototype.hasOwnProperty.call(value, r.role) ? r.role : 'other';
      value[k] = (value[k] || 0) + r.n;
    }
    _rolesCache = { at: Date.now(), value };
    return value;
  } catch (_) { return null; }
}
function liveSettingSet(key) {
  try {
    const row = getLiveDb().prepare(`SELECT value FROM settings WHERE key = ?`).get(key);
    return !!(row && row.value && String(row.value).trim());
  } catch (_) { return null; }
}
// ════════════════════════════════════════════════════════════════════════════
// «قسم الأسعار» (owner, 2026-11-22): «مش عايزه يظهرله غير الاسعار بس في الجنب
// مع الملاحظات … قسم في سيستم ال crm اسمه قسم الاسعار فيه اسعار المنتجات
// بالملاحظات بتاعتها … السيلز يقدر يطبع الكتالوج لو اتحدث الاسعار».
//   GET /api/prices        — every logged-in role: the models by category with
//                            the set price, the pieces and their prices, photo,
//                            «على الموقع», his sales note (staff scope only),
//                            and «اطبع الكتالوج» (the nightly catalogue PDF).
//   GET /api/prices/picker — the same models WITHOUT any price or note: the
//                            contract form's picker (staff see no total).
// From services/grandCatalog.js (cached 60 s, ETag, last good copy when the
// prices system is down). Read-only. 503 only when there never was a copy.
// ════════════════════════════════════════════════════════════════════════════
const PRICES_DOWN = { error: 'catalog_unavailable', message: 'الأسعار مش متاحة دلوقتي — جرّب كمان شوية' };
app.get('/api/prices', requireAuth, async (req, res) => {
  try {
    const [v, pdf] = await Promise.all([grandCatalog.getCatalog(), grandCatalog.catalogueStatus()]);
    if (!v.catalog) return res.status(503).json(PRICES_DOWN);
    const body = grandCatalog.pricesView(v);
    body.catalogue = { url: pdf.url, status: pdf.status, checked_at: pdf.checked_at };
    // the admin is told why notes are missing (env names only, never a value)
    if (req.user?.role === 'admin' && !body.notes_available) {
      body.setup = v.staff_configured
        ? { notes: 'refused', message: 'سيستم الأسعار رفض المفتاح — اتأكد إن CRM_CATALOG_SECRET هو هو في المشروعين على Railway' }
        : { notes: 'missing_secret', message: 'الملاحظات محتاجة CRM_CATALOG_SECRET في Railway (نفس القيمة في سيستم الأسعار وسيستم العملاء)' };
    }
    res.set('Cache-Control', 'private, no-store');
    return res.json(body);
  } catch (err) {
    console.error('[prices] failed:', err && err.message);
    return res.status(503).json(PRICES_DOWN);
  }
});
app.get('/api/prices/picker', requireAuth, async (_req, res) => {
  try {
    const v = await grandCatalog.getCatalog();
    if (!v.catalog) return res.status(503).json(PRICES_DOWN);
    res.set('Cache-Control', 'private, no-store');
    return res.json(grandCatalog.pricesView(v, { picker: true }));
  } catch (err) {
    console.error('[prices/picker] failed:', err && err.message);
    return res.status(503).json(PRICES_DOWN);
  }
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/admin/sales-value?period=week|month|last|all — ADMIN ONLY.
//     (or ?from=YYYY-MM-DD&to=YYYY-MM-DD)
// «اشترى بكام تقريبياً» per branch, per salesperson, per ad/campaign, for the
// sales recorded in the range. Days and months are CAIRO days (Intl
// Africa/Cairo, review 2026-11-22): a sale at 00:30 Cairo on the 1st counts in
// that month, not the last one. period is worked out here, on Cairo's today
// (week = the last 7 Cairo days with today; month = this Cairo month to today;
// last = last Cairo month); from/to are Cairo days too. Per group: contracts,
// paid_total (what staff typed), estimate_total (today's list prices when
// recorded — «تقريبي»), value_total (paid when typed, else the estimate), how
// many have no estimate or an incomplete one.
// ════════════════════════════════════════════════════════════════════════════
function cairoPeriod(key, now = new Date()) {
  const today = cairoDay(now);
  const [y, m] = today.split('-').map(Number);
  const ymd = (d) => d.toISOString().slice(0, 10);
  if (key === 'week') {
    const [ty, tm, td] = today.split('-').map(Number);
    return { from: ymd(new Date(Date.UTC(ty, tm - 1, td - 6))), to: today };
  }
  if (key === 'month') return { from: ymd(new Date(Date.UTC(y, m - 1, 1))), to: today };
  if (key === 'last') return { from: ymd(new Date(Date.UTC(y, m - 2, 1))), to: ymd(new Date(Date.UTC(y, m - 1, 0))) };
  if (key === 'all') return { from: null, to: null };
  return null;
}
// [from, to] Cairo days → ` AND datetime(col) >= ? AND datetime(col) < ?` (UTC bounds).
function cairoRangeClause(column, from, to) {
  const parts = [];
  const params = [];
  if (from) { parts.push(`datetime(${column}) >= ?`); params.push(cairoDayBoundsSql(from)[0]); }
  if (to)   { parts.push(`datetime(${column}) < ?`);  params.push(cairoDayBoundsSql(to)[1]); }
  return { clause: parts.length ? ' AND ' + parts.join(' AND ') : '', params };
}
app.get('/api/admin/sales-value', requireAuth, requireRole('admin'), (req, res) => {
  const db = getDb();
  const day = (v) => (typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v) && !Number.isNaN(Date.parse(v + 'T00:00:00Z'))
    && new Date(v + 'T00:00:00Z').toISOString().slice(0, 10) === v ? v : null);
  let from = null;
  let to = null;
  if (req.query.period != null && req.query.period !== '') {
    const p = cairoPeriod(String(req.query.period));
    if (!p) return res.status(400).json({ error: 'الفترة لازم تكون week أو month أو last أو all' });
    ({ from, to } = p);
  } else {
    from = day(req.query.from);
    to   = day(req.query.to);
    if ((req.query.from && !from) || (req.query.to && !to)) return res.status(400).json({ error: 'التاريخ لازم يكون YYYY-MM-DD' });
  }
  const dr = cairoRangeClause('p.created_at', from, to);
  const agg = (groupSql, keySql) => db.prepare(`
    SELECT ${keySql}
           COUNT(*) AS contracts,
           COALESCE(SUM(CASE WHEN p.price > 0 THEN p.price ELSE 0 END), 0) AS paid_total,
           SUM(CASE WHEN p.price > 0 THEN 1 ELSE 0 END) AS paid_count,
           COALESCE(SUM(e.list_total_estimate), 0) AS estimate_total,
           SUM(CASE WHEN e.list_total_estimate IS NOT NULL THEN 1 ELSE 0 END) AS estimate_count,
           SUM(CASE WHEN e.purchase_id IS NOT NULL AND (e.estimate_complete = 0 OR e.list_total_estimate IS NULL) THEN 1 ELSE 0 END) AS estimate_incomplete,
           COALESCE(SUM(CASE WHEN p.price > 0 THEN p.price ELSE COALESCE(e.list_total_estimate, 0) END), 0) AS value_total,
           SUM(CASE WHEN NOT (p.price > 0) AND e.list_total_estimate IS NULL THEN 1 ELSE 0 END) AS no_value
    FROM purchases p
    LEFT JOIN purchase_estimates e ON e.purchase_id = p.id
    LEFT JOIN lead_profiles lp ON lp.user_id = p.user_id
    WHERE 1=1 ${dr.clause}
    ${groupSql}
  `);
  const totals    = agg('', '').get(...dr.params);
  const byBranch  = agg('GROUP BY p.branch ORDER BY value_total DESC', `p.branch AS branch,`).all(...dr.params);
  const byRep     = agg('GROUP BY p.rep, p.branch ORDER BY value_total DESC', `p.rep AS rep, p.branch AS branch,`).all(...dr.params);
  const byCampaign = agg('GROUP BY lp.campaign_source ORDER BY value_total DESC', `lp.campaign_source AS campaign_source,`).all(...dr.params);
  // Stopped salespeople (2026-11-25): no row in «السيلز» (a contract with no
  // salesperson keeps its «—» row); the totals keep their contracts, and
  // stopped_sales says how many and their value.
  const who = honest.sellers(db);
  const noRep = (r) => r.rep == null || String(r.rep).trim() === '';
  const { rows: repRows, hidden } = honest.hideStopped(byRep, { ...who, shown: (n) => n == null || String(n).trim() === '' || who.shown(n) },
    (r) => (noRep(r) ? null : r.rep), { contracts: (r) => r.contracts, value_total: (r) => r.value_total });
  return res.json({
    from, to, timezone: CAIRO_TZ, currency: 'EGP', approximate: true,
    totals, by_branch: byBranch, by_rep: repRows, by_campaign: byCampaign,
    ...(hidden.rows ? { stopped_sales: { contracts: hidden.contracts, value_total: hidden.value_total, removed: hidden.removed } } : {}),
  });
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/admin/ad-funnel?week=YYYY-MM-DD&mode=period|cohort — ADMIN ONLY.
// «من الإعلان للبيعة» (2026-11-22): one CAIRO week (Saturday → Friday, the one
// holding `week`; default this week, up to today) per ad source and per
// branch: كلّموا → سابوا رقم → اختاروا فرع / قالوا جايين → زاروا → اشتروا, the
// contracts and their value (paid when typed, else the list estimate —
// «تقريبي»). Each step counts PEOPLE; walk-ins who never chatted are their own
// row («زيارة مباشرة»), never a campaign. What each step counts, the walk-in
// marker and the two views are in services/honestNumbers.js:
//   mode=period (default) — what happened this week, each step by its own day;
//   mode=cohort           — this week's new chats, and how far they got by today;
//                           NESTED (r2): a person counts at every step up to the
//                           furthest he reached, so no step is bigger than the
//                           one before (`steps_rule: 'reached_or_further'`).
// `week_sales` is every contract written in the week by its own Cairo day
// (chat + walk-in), the same in both views — «قيمة البيع في الأسبوع».
// `previous` is the week before: the SAME days of it while this week is still
// running (Saturday → the same weekday), else the whole week. Ad spend is not
// in the CRM yet: there is no cost column here (the page says it comes later).
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/admin/ad-funnel', requireAuth, requireRole('admin'), (req, res) => {
  const db = getDb();
  const today = cairoDay();
  const asked = req.query.week == null || req.query.week === '' ? today : String(req.query.week);
  if (!honest.isDay(asked)) return res.status(400).json({ error: 'الأسبوع لازم يكون تاريخ YYYY-MM-DD' });
  const mode = req.query.mode == null || req.query.mode === '' ? 'period' : String(req.query.mode);
  if (!['period', 'cohort'].includes(mode)) return res.status(400).json({ error: 'mode لازم يكون period أو cohort' });
  const wk = honest.weekOf(asked);
  if (wk.from > today) return res.status(400).json({ error: 'الأسبوع ده لسه مجاش' });
  const running = wk.to >= today;
  const to = running ? today : wk.to;
  const prev = { from: honest.addDays(wk.from, -7), to: honest.addDays(to, -7) };
  const current = honest.weekly(db, { from: wk.from, to, mode });
  const before  = honest.weekly(db, { from: prev.from, to: prev.to, mode });
  res.set('Cache-Control', 'private, no-store');
  return res.json({
    timezone: CAIRO_TZ, mode, currency: 'EGP',
    week: { from: wk.from, to: wk.to, counted_to: to, running },
    previous: { from: prev.from, to: prev.to, same_days: running,
                chat_totals: before.chat_totals, walkin_totals: before.walkin_totals, week_sales: before.week_sales },
    ...current,
    cost: null,      // ad spend is not connected yet
  });
});

app.get('/health', (req, res) => {
  const c = counters.snapshot();
  const b = backup.snapshot();
  res.json({
    status:    'ok',
    timestamp: new Date().toISOString(),
    version:   BUILD_VERSION,
    migr_all_branches_done: getSetting('migr_all_branches_done', 'false') === 'true',
    all_branches_rows: allBranchesCounts(),
    counters_since: c.since,
    test_events:    c.test_events,
    manychat_api:   c.manychat_api,
    window_skips:   c.window_skips,
    lead_rule:      c.lead_rule,
    branch_repeats: c.branch_repeats,
    rate_limited:   c.rate_limited,
    node:           process.versions.node,          // the Node 22 pin is checkable after a deploy
    jwt_secret_from_env: !!process.env.JWT_SECRET,
    jwt_rotated:    jwtRotated(),
    users_by_role:  usersByRole(),
    zai_key_set:    liveSettingSet('zai_api_key'),
    mcp_key_set:    !!process.env.MCP_SECRET_KEY,
    usage:          c.usage,
    outbound_blocked_demo: outbound.blockedSnapshot(),
    last_backup_at: b.last_backup_at,
    backup_count:   b.count,
    backup_last_error: b.last_error,
    grand_catalog:  grandCatalog.snapshot(),
  });
});

// ════════════════════════════════════════════════════════════════════════════
// Product catalog — categories & products
// Read endpoints are open to any authenticated user (sales reps need to see
// the catalog when recording a purchase). Write endpoints are restricted to
// admin and branch_manager.
// ════════════════════════════════════════════════════════════════════════════
// 2026-11-22 («قسم الأسعار»): products come from the prices system now. This
// manual table stays READ-ONLY until the new contract form has shipped (old
// contracts keep their products); its writes answer 410 for everyone.
const canEditCatalog = (_req, res) => res.status(410).json({
  error: 'المنتجات بقت من «الأسعار» (سيستم الأسعار) — الجدول القديم للقراءة بس', code: 'catalog_read_only',
});

// ─── Categories ─────────────────────────────────────────────────────────────
app.get('/api/products/categories', requireAuth, (_req, res) => {
  const db = getDb();
  const rows = db.prepare(`
    SELECT c.id, c.name, c.sort_order, c.active,
           (SELECT COUNT(*) FROM products p WHERE p.category_id = c.id AND p.active = 1) AS product_count
    FROM product_categories c
    WHERE c.active = 1
    ORDER BY c.sort_order, c.name
  `).all();
  return res.json({ categories: rows });
});

app.post('/api/products/categories', requireAuth, canEditCatalog, (req, res) => {
  const name = (req.body?.name || '').trim();
  if (!name) return res.status(400).json({ error: 'name_required' });
  const db = getDb();
  const result = db.prepare(`
    INSERT INTO product_categories (name) VALUES (?)
  `).run(name);
  return res.json({ ok: true, id: result.lastInsertRowid, name });
});

app.put('/api/products/categories/:id', requireAuth, canEditCatalog, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const name = (req.body?.name || '').trim();
  if (!id || !name) return res.status(400).json({ error: 'id_and_name_required' });
  const db = getDb();
  const result = db.prepare(`
    UPDATE product_categories SET name = ? WHERE id = ? AND active = 1
  `).run(name, id);
  if (result.changes === 0) return res.status(404).json({ error: 'category_not_found' });
  return res.json({ ok: true });
});

app.delete('/api/products/categories/:id', requireAuth, canEditCatalog, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'id_required' });
  const db = getDb();
  // Soft-delete: archive the category AND archive its products so historical
  // purchase_items references stay intact (no FK cascade pain).
  const tx = db.transaction(() => {
    db.prepare(`UPDATE product_categories SET active = 0 WHERE id = ?`).run(id);
    db.prepare(`UPDATE products SET active = 0 WHERE category_id = ?`).run(id);
  });
  tx();
  return res.json({ ok: true });
});

// ─── Products ───────────────────────────────────────────────────────────────
app.get('/api/products', requireAuth, (req, res) => {
  const db = getDb();
  const categoryId = req.query.category_id ? parseInt(req.query.category_id, 10) : null;
  let where = `WHERE p.active = 1 AND c.active = 1`;
  const params = [];
  if (categoryId) {
    where += ` AND p.category_id = ?`;
    params.push(categoryId);
  }
  const rows = db.prepare(`
    SELECT p.id, p.name, p.category_id, c.name AS category_name
    FROM products p
    JOIN product_categories c ON c.id = p.category_id
    ${where}
    ORDER BY c.sort_order, c.name, p.name
  `).all(...params);
  return res.json({ products: rows });
});

app.post('/api/products', requireAuth, canEditCatalog, (req, res) => {
  const { category_id, name } = req.body || {};
  const catId = parseInt(category_id, 10);
  const trimmed = (name || '').trim();
  if (!catId || !trimmed) return res.status(400).json({ error: 'category_id_and_name_required' });
  const db = getDb();
  const cat = db.prepare(`SELECT id FROM product_categories WHERE id = ? AND active = 1`).get(catId);
  if (!cat) return res.status(404).json({ error: 'category_not_found' });
  const result = db.prepare(`
    INSERT INTO products (category_id, name) VALUES (?, ?)
  `).run(catId, trimmed);
  return res.json({ ok: true, id: result.lastInsertRowid });
});

app.put('/api/products/:id', requireAuth, canEditCatalog, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { name, category_id } = req.body || {};
  if (!id) return res.status(400).json({ error: 'id_required' });
  const db = getDb();
  const sets = [];
  const params = [];
  if (typeof name === 'string' && name.trim()) {
    sets.push('name = ?');
    params.push(name.trim());
  }
  if (category_id) {
    const catId = parseInt(category_id, 10);
    if (catId) {
      sets.push('category_id = ?');
      params.push(catId);
    }
  }
  if (!sets.length) return res.status(400).json({ error: 'nothing_to_update' });
  params.push(id);
  const result = db.prepare(
    `UPDATE products SET ${sets.join(', ')} WHERE id = ? AND active = 1`
  ).run(...params);
  if (result.changes === 0) return res.status(404).json({ error: 'product_not_found' });
  return res.json({ ok: true });
});

app.delete('/api/products/:id', requireAuth, canEditCatalog, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'id_required' });
  const db = getDb();
  // Soft-delete keeps historical purchase_items links intact.
  db.prepare(`UPDATE products SET active = 0 WHERE id = ?`).run(id);
  return res.json({ ok: true });
});

// ── Background Jobs ───────────────────────────────────────────────────────
// The 3-day «abandoned intent» reminder (runAbandonedIntentJob) was removed in
// phase 1 (2026-11-22): it was off (C1.9) and its targets are outside Meta's
// 24 h window anyway. Its settings rows (reminder_job_enabled,
// manychat_reminder_flow) stay in the table, unread.

// ── Score decay reclassification job ──────────────────────────────────────
// lead_class only gets recomputed when a NEW event arrives (see processScore
// call site above) — a lead that goes silent keeps its stale hot/warm class
// forever otherwise. This job periodically re-evaluates dormant leads using
// an analytically decayed score (never mutates total_score/last_activity, so
// a lead that re-engages is instantly re-promoted from its full raw score).
// Ships a no-op until an admin enables scoring_decay_enabled.
function runScoreDecayForDb(db) {
  const config = getScoringConfig(db);
  if (!config.decay.enabled) return;

  const rows = db.prepare(`
    SELECT user_id, first_name, total_score, lead_class, last_activity, visit_confirmed
    FROM lead_profiles
    WHERE lead_class IN ('warm','hot')
      AND last_activity < datetime('now', '-' || ? || ' days')
  `).all(config.decay.graceDays);

  for (const row of rows) {
    const decayedScore = computeDecayedScore(row.total_score, row.last_activity, config.decay);
    const newClass = classifyLead(
      decayedScore,
      row.visit_confirmed === 1,
      row.lead_class,
      config.thresholds
    );
    if (newClass !== row.lead_class) {
      db.prepare(`UPDATE lead_profiles SET lead_class = ? WHERE user_id = ?`).run(newClass, row.user_id);
      console.log(`[Cron] Decay: ${row.first_name || row.user_id} ${row.lead_class}→${newClass} (score ${row.total_score}, decayed ${Math.round(decayedScore)})`);
    }
  }
}

function runScoreDecayJob() {
  try {
    runScoreDecayForDb(getLiveDb());   // the live DB only (the demo sandbox is removed)
  } catch (err) {
    console.error('[Cron] Error running score decay job:', err);
  }
}

setTimeout(() => {
  runScoreDecayJob();
  setInterval(runScoreDecayJob, 60 * 60 * 1000);
}, 5000);

// ── MCP Cloud SSE Server ──────────────────────────────────────────────────────
// Exposes the CRM to Claude Desktop via HTTP Server-Sent Events.
// No local script, no bridge — Claude connects directly to the live Railway DB.
// Auth: every request must carry  x-mcp-key: <MCP_SECRET_KEY>  in its headers.
(function setupMcpSseServer() {
  let McpServerCls, SSEServerTransport, z;
  try {
    McpServerCls       = require('@modelcontextprotocol/sdk/server/mcp.js').McpServer;
    SSEServerTransport = require('@modelcontextprotocol/sdk/server/sse.js').SSEServerTransport;
    z                  = require('zod').z;
  } catch (e) {
    console.error('[MCP] SDK missing — SSE endpoint disabled:', e.message);
    return;
  }

  // sessionId → SSEServerTransport  (one entry per open Claude Desktop tab)
  const mcpSessions = new Map();

  // Auth guard — 401 if header is absent or wrong
  function mcpAuth(req, res, next) {
    const expected = process.env.MCP_SECRET_KEY;
    if (!expected) {
      return res.status(503).json({ error: 'MCP_SECRET_KEY not configured on server.' });
    }
    if (req.headers['x-mcp-key'] !== expected) {
      return res.status(401).json({ error: 'Unauthorized: invalid or missing x-mcp-key header.' });
    }
    next();
  }

  // Build a fresh McpServer + register all 4 CRM tools
  function buildMcpServer() {
    const srv = new McpServerCls({ name: 'grand-furniture-crm', version: '1.0.0' });
    const db  = getDb();
    // the Cairo month (2026-11-25), like every month counter of the API
    const ok  = (obj) => ({ content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }] });
    const fail = (msg) => ({ content: [{ type: 'text', text: 'خطأ: ' + msg }], isError: true });

    // ── Tool A: Branch KPIs ─────────────────────────────────────────────────
    srv.registerTool('get_branch_kpis', {
      description: 'مؤشرات أداء فرع: إجمالي المبيعات، عدد الزيارات، ونسبة تحقيق المستهدف لشهر معيّن.',
      inputSchema: {
        branch:       z.string().optional().describe('اسم/مُعرّف الفرع — فارغ = كل الفروع'),
        target_month: z.string().optional().describe('الشهر YYYY-MM (افتراضي: الشهر الحالي)'),
      },
    }, async ({ branch, target_month }) => {
      try {
        const month = (target_month && /^\d{4}-\d{2}$/.test(target_month))
          ? target_month : currentMonth();

        const revenue = monthRevenue(db, { branch: branch || null, month });

        const vm = cairoMonthSql('visited_at', month);
        let visWhere = '1=1';
        const visP = [];
        if (branch) { visWhere += ' AND branch = ?'; visP.push(branch); }
        const visits = db.prepare(
          `SELECT COUNT(DISTINCT user_id) AS n FROM lead_visits WHERE ${visWhere}${vm.clause}`
        ).get(...visP, ...vm.params).n;

        const target = branch
          ? (() => {
              const r = db.prepare(
                `SELECT target_amount FROM sales_targets WHERE scope_type='branch' AND scope_name=? AND target_month=?`
              ).get(branch, month);
              return r ? Number(r.target_amount) || 0 : 0;
            })()
          : (db.prepare(
              `SELECT COALESCE(SUM(target_amount), 0) AS t FROM sales_targets WHERE scope_type='branch' AND target_month=?`
            ).get(month).t || 0);

        return ok({
          branch: branch || 'كل الفروع',
          target_month: month,
          total_revenue: revenue,
          visit_count: visits,
          target_amount: target,
          target_achievement_pct: target > 0 ? Math.round((revenue / target) * 100) : 0,
        });
      } catch (e) { return fail(e.message); }
    });

    // ── Tool B: Leads by status ─────────────────────────────────────────────
    srv.registerTool('get_leads_by_status', {
      description: 'قائمة العملاء (id/name/phone/class) مع فلترة بالمندوب أو التصنيف.',
      inputSchema: {
        assigned_rep: z.string().optional().describe('فلترة بالمندوب المسؤول'),
        lead_class:   z.string().optional().describe('cold / warm / hot / visited / purchased'),
      },
    }, async ({ assigned_rep, lead_class }) => {
      try {
        let where = '1=1'; const params = [];
        if (assigned_rep) { where += ' AND assigned_rep = ?'; params.push(assigned_rep); }
        if (lead_class)   { where += ' AND lead_class = ?';   params.push(lead_class); }
        const leads = db.prepare(`
          SELECT user_id AS id, first_name AS name, phone,
                 lead_class AS class, assigned_rep, revisit_status
          FROM lead_profiles WHERE ${where}
          ORDER BY last_activity DESC LIMIT 300
        `).all(...params);
        return ok({ count: leads.length, leads });
      } catch (e) { return fail(e.message); }
    });

    // ── Tool C: SELECT SQL ──────────────────────────────────────────────────
    srv.registerTool('run_select_sql', {
      description: 'تنفيذ استعلام SELECT للقراءة وتحليل البيانات.',
      inputSchema: { sql_query: z.string().describe('استعلام SELECT فقط') },
    }, async ({ sql_query }) => {
      // Phase 0: a read-only connection + the table allowlist (services/sqlGuard.js):
      // settings, the audit log, sqlite_master and users.password_hash are refused.
      try {
        counters.countUsage('mcp_tool', 'mcp');
        const r = sqlGuard.runGuardedSelect(getReadonlyDb(), sql_query, 500);
        if (r.error) return fail(r.error);
        return ok(r);
      } catch (e) { return fail(e.message); }
    });

    // ── Tool D: Write SQL — OFF (phase 0, 2026-11-22) ───────────────────────
    // Kept registered so a client that calls it gets a clear answer instead of
    // «unknown tool»; it never runs SQL. Whether it is removed or brought back
    // is the owner's call (overhaul PLAN.md, the MCP question).
    srv.registerTool('execute_write_sql', {
      description: 'مقفولة: الكتابة على قاعدة البيانات من MCP متوقفة (المرحلة 0). اعمل التعديل من السيستم نفسه.',
      inputSchema: { sql_query: z.string().describe('غير مستخدم — الأداة مقفولة') },
    }, async () => {
      counters.countUsage('mcp_tool', 'mcp');
      return fail('أداة الكتابة مقفولة (المرحلة 0 — الحماية). مفيش أي تعديل اتعمل. التعديلات من السيستم نفسه.');
    });

    return srv;
  }

  // GET /api/mcp/sse — Claude Desktop connects here to open the SSE stream
  app.get('/api/mcp/sse', mcpAuth, async (req, res) => {
    try {
      const transport = new SSEServerTransport('/api/mcp/messages', res);
      const mcpServer = buildMcpServer();
      mcpSessions.set(transport.sessionId, transport);
      transport.onclose = () => {
        mcpSessions.delete(transport.sessionId);
        console.log(`[MCP] session closed: ${transport.sessionId}`);
      };
      console.log(`[MCP] new session: ${transport.sessionId}`);
      await mcpServer.connect(transport);
    } catch (e) {
      console.error('[MCP SSE] connection error:', e.message);
      if (!res.headersSent) res.status(500).json({ error: 'MCP server error.' });
    }
  });

  // POST /api/mcp/messages — receives JSON-RPC messages from Claude Desktop
  app.post('/api/mcp/messages', mcpAuth, async (req, res) => {
    const sessionId = req.query.sessionId;
    const transport = mcpSessions.get(sessionId);
    if (!transport) {
      return res.status(404).json({ error: 'MCP session not found. Re-open the SSE connection.' });
    }
    try {
      await transport.handlePostMessage(req, res, req.body);
    } catch (e) {
      console.error('[MCP SSE] message error:', e.message);
      if (!res.headersSent) res.status(500).json({ error: 'MCP message handling error.' });
    }
  });

  console.log('🤖 MCP SSE endpoint ready → /api/mcp/sse  (auth: x-mcp-key header)');
})();

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
// The events and profiles passes go through intakeBranch (C1.3): they never
// write a value that isn't intake-valid ('all_branches', unknown text) — such
// a row is skipped, so the one-time cleanup below is not undone on the next
// boot. The visits and active_branches passes keep normalizeBranch.
(function normalizeHistoricalBranches() {
  try {
    const db = getDb();
    const ids = activeBranchIds(db);

    const eventRows = db.prepare(`
      SELECT id, event_value, branch FROM events
      WHERE event_type IN ('branch_selected', 'location_request', 'entry_location')
    `).all();
    const updEvent = db.prepare(`UPDATE events SET branch = ? WHERE id = ?`);
    let eventsFixed = 0;
    db.transaction(() => {
      for (const r of eventRows) {
        const source    = (r.branch && r.branch.trim()) || r.event_value;
        const canonical = intakeBranch(source, { ids });
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

    // purchases too (2026-11-25 review): a legacy contract under an alias
    // ('المعادي') was in honest's normalized «اشتروا» but out of every raw
    // `p.branch = ?` (the overview's contracts / total, GET /api/contracts).
    // Current writes are canonical already; no unique key, so a plain UPDATE.
    const purchaseRows = db.prepare(`SELECT id, branch FROM purchases WHERE branch IS NOT NULL`).all();
    const updPurchase  = db.prepare(`UPDATE purchases SET branch = ? WHERE id = ?`);
    let purchasesFixed = 0;
    db.transaction(() => {
      for (const r of purchaseRows) {
        const canonical = normalizeBranch(r.branch);
        if (canonical && canonical !== r.branch) { updPurchase.run(canonical, r.id); purchasesFixed++; }
      }
    })();

    // followup_log too (2026-11-25 review): a legacy follow-up under an alias
    // ('المعادي') was in the admin's normalized «أداء السيلز» but out of the
    // manager's exact `l.branch = ?` range «تابع». Append-only, no unique key.
    const fuLogRows = db.prepare(`SELECT id, branch FROM followup_log WHERE branch IS NOT NULL`).all();
    const updFuLog  = db.prepare(`UPDATE followup_log SET branch = ? WHERE id = ?`);
    let fuLogFixed = 0;
    db.transaction(() => {
      for (const r of fuLogRows) {
        const canonical = normalizeBranch(r.branch);
        if (canonical && canonical !== r.branch) { updFuLog.run(canonical, r.id); fuLogFixed++; }
      }
    })();

    const profileRows = db.prepare(
      `SELECT user_id, preferred_branch FROM lead_profiles WHERE preferred_branch IS NOT NULL`
    ).all();
    const updProfile = db.prepare(`UPDATE lead_profiles SET preferred_branch = ? WHERE user_id = ?`);
    let profilesFixed = 0;
    db.transaction(() => {
      for (const r of profileRows) {
        const canonical = intakeBranch(r.preferred_branch, { ids });
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

    if (eventsFixed || visitsFixed || purchasesFixed || fuLogFixed || profilesFixed || configFixed) {
      console.log(`✅ Migration: normalized branch ids — events:${eventsFixed} visits:${visitsFixed} purchases:${purchasesFixed} followup_log:${fuLogFixed} profiles:${profilesFixed} config:${configFixed}`);
    }
  } catch (e) {
    console.error('[migration] branch normalize failed:', e.message);
  }
})();

// ── One-time cleanup: the bot's 'all_branches' (C1.5, review r2) ──────────
// The gallery sent location_request 'all_branches' (the old §06a body); it
// passed normalizeBranch and overwrote real branches. Runs ONCE (settings flag
// migr_all_branches_done), never through normalizeBranch, and changes ONE
// thing: a preferred_branch that is not intake-valid ('all_branches', unknown
// text) → the latest intake-valid branch in ANY of the lead's events
// (visit_confirmed's JSON branch included), else his latest lead_visits
// branch, else NULL.
// Reversible: before a row changes, (user_id, old preferred_branch, old
// location_requested) is copied into migr_all_branches_backup in the SAME
// transaction. /health shows counts only.
// NOT done here, on purpose: location_requested (📍) is never cleared — the
// old bot taught 'all_branches' for real location asks, and the reset waits
// for F0's reading of what the old bot sends. events / lead_visits /
// visit_checkins rows are not rewritten either; /health reports how many
// still hold 'all_branches'.
(function cleanupAllBranches() {
  try {
    const db = getDb();
    if (getSetting('migr_all_branches_done', 'false') === 'true') return;
    const ids = activeBranchIds(db);
    let profilesFixed = 0, profilesNulled = 0;
    db.transaction(() => {
      db.exec(`
        CREATE TABLE IF NOT EXISTS migr_all_branches_backup (
          id                     INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id                TEXT NOT NULL,
          old_preferred_branch   TEXT,
          old_location_requested INTEGER,
          new_preferred_branch   TEXT,
          backed_up_at           DATETIME NOT NULL DEFAULT (datetime('now'))
        )
      `);
      const evStmt = db.prepare(`
        SELECT event_type, branch, event_value FROM events
        WHERE user_id = ? ORDER BY datetime(created_at) DESC, id DESC
      `);
      const visitStmt = db.prepare(`
        SELECT branch FROM lead_visits WHERE user_id = ? ORDER BY datetime(visited_at) DESC, id DESC
      `);
      const LOCATION_TYPES = new Set(['branch_selected', 'location_request', 'entry_location', 'map_click']);
      const eventBranch = (e) => {
        let b = intakeBranch(e.branch, { ids });
        if (!b && LOCATION_TYPES.has(e.event_type)) b = intakeBranch(e.event_value, { ids });
        if (!b && e.event_type === 'visit_confirmed' && e.event_value) {
          try { const v = JSON.parse(e.event_value); if (v && typeof v === 'object') b = intakeBranch(v.branch, { ids }); }
          catch (_) { b = intakeBranch(e.event_value, { ids }); }
        }
        return b;
      };
      const backup = db.prepare(`
        INSERT INTO migr_all_branches_backup (user_id, old_preferred_branch, old_location_requested, new_preferred_branch)
        VALUES (?, ?, ?, ?)
      `);
      const updPref = db.prepare(`UPDATE lead_profiles SET preferred_branch = ? WHERE user_id = ?`);
      const rows = db.prepare(`
        SELECT user_id, preferred_branch, location_requested FROM lead_profiles
        WHERE preferred_branch IS NOT NULL AND TRIM(preferred_branch) <> ''
      `).all();
      for (const r of rows) {
        if (intakeBranch(r.preferred_branch, { ids })) continue;      // already a real branch
        let best = null;
        for (const e of evStmt.all(r.user_id)) { best = eventBranch(e); if (best) break; }
        if (!best) {
          for (const v of visitStmt.all(r.user_id)) { best = intakeBranch(v.branch, { ids }); if (best) break; }
        }
        backup.run(r.user_id, r.preferred_branch, r.location_requested, best);
        updPref.run(best, r.user_id);
        if (best) profilesFixed++; else profilesNulled++;
      }
      db.prepare(`
        INSERT INTO settings (key, value, updated_at) VALUES ('migr_all_branches_done', 'true', datetime('now'))
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
      `).run();
    })();
    console.log(`✅ Migration (once): preferred_branch cleaned — re-pointed:${profilesFixed} emptied:${profilesNulled} ` +
      `(backed up in migr_all_branches_backup; 📍 flags untouched)`);
  } catch (e) {
    console.error('[migration] all_branches cleanup failed:', e.message);
  }
})();

// ── One-time data migration: today's arrivals → visit_checkins ─────────────
// visit_checkins starts empty on deploy day, so customers confirmed EARLIER
// that day (Cairo) would be missing from reception's «قايمة العملاء زيارة
// اليوم». Back-fill them once from lead_visits rows first visited today, and
// mark a salesperson already linked to them as set at the visit time. Guarded
// by the settings marker visit_checkins_backfill_v1 (value = the day it ran).
// Known gap: a RETURNING customer confirmed before the deploy that same day
// can't be recovered (lead_visits keeps only the first visit per branch).
(function backfillTodayCheckins() {
  try {
    const db = getDb();
    const done = db.prepare(`SELECT value FROM settings WHERE key = 'visit_checkins_backfill_v1'`).get();
    if (done) return;
    const today = cairoDay();
    const [start, end] = cairoDayBoundsSql(today);
    let checkins = 0, reps = 0;
    db.transaction(() => {
      checkins = db.prepare(`
        INSERT OR IGNORE INTO visit_checkins (user_id, branch, visit_day, checked_in_at, source, recorded_by)
        SELECT v.user_id, v.branch, ?, datetime(v.visited_at),
               CASE WHEN lp.manychat_source = 'walkin' THEN 'walkin' ELSE 'confirm' END, NULL
        FROM lead_visits v
        JOIN lead_profiles lp ON lp.user_id = v.user_id
        WHERE v.branch IS NOT NULL
          AND datetime(v.visited_at) >= ? AND datetime(v.visited_at) < ?
      `).run(today, start, end).changes;
      reps = db.prepare(`
        UPDATE lead_visits SET sales_rep_set_at = datetime(visited_at)
        WHERE sales_rep IS NOT NULL AND sales_rep_set_at IS NULL
          AND datetime(visited_at) >= ? AND datetime(visited_at) < ?
      `).run(start, end).changes;
      db.prepare(`
        INSERT INTO settings (key, value, updated_at)
        VALUES ('visit_checkins_backfill_v1', ?, datetime('now'))
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
      `).run(today);
    })();
    console.log(`✅ Migration: visit_checkins back-filled for ${today} — checkins:${checkins} reps:${reps}`);
  } catch (e) {
    console.error('[migration] visit_checkins backfill failed:', e.message);
  }
})();

// ── Start Server ──────────────────────────────────────────────────────────
// Phase 0 boot steps (never fail the boot):
//   • where the JWT signing key comes from — a boolean, never the value;
//   • phase 0 r4: the old demo sandbox DB is deleted if present (removed);
//   • the daily backup schedule (04:00 Cairo; services/backup.js).
//   • phase 0 r3: the DB-stored key is replaced ONCE (middleware/auth.js
//     rotateJwtSecretOnce) — every older session logs in again;
try { if (rotateJwtSecretOnce()) console.log('🔐 JWT secret rotated once (phase 0 r3) — every session from before logs in again'); }
catch (e) { console.error('[auth] JWT secret rotation failed:', e.message); }
console.log(`🔐 JWT_SECRET from env: ${process.env.JWT_SECRET ? 'yes' : 'NO — using the DB-stored secret (set JWT_SECRET in Railway Variables)'}`);
try { if (removeDemoDbAtBoot()) console.log('🗑️  Old demo sandbox DB deleted at boot (the sandbox is removed, 2026-11-22)'); }
catch (e) { console.error('[demo] boot removal failed:', e.message); }
backup.startSchedule({ getLiveDb, dbPath: DB_PATH });
// «قسم الأسعار»: the last good catalogue survives a restart (one row on the
// LIVE DB, grand_catalog_cache — server-side only; services/grandCatalog.js).
try {
  const cdb = getLiveDb();
  grandCatalog.configureStore({
    load: () => cdb.prepare(`SELECT body_json, etag, scope, version, fetched_at, checked_at, secret_fp FROM grand_catalog_cache WHERE id = 1`).get() || null,
    save: (c) => cdb.prepare(`INSERT INTO grand_catalog_cache (id, body_json, etag, scope, version, fetched_at, checked_at, secret_fp, saved_at)
                              VALUES (1, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                              ON CONFLICT(id) DO UPDATE SET body_json = excluded.body_json, etag = excluded.etag, scope = excluded.scope,
                                version = excluded.version, fetched_at = excluded.fetched_at, checked_at = excluded.checked_at,
                                secret_fp = excluded.secret_fp, saved_at = excluded.saved_at`)
      .run(c.body_json, c.etag || null, c.scope, c.version || null, c.fetched_at, c.checked_at, c.secret_fp || null),
    touch: (checkedAt) => cdb.prepare(`UPDATE grand_catalog_cache SET checked_at = ? WHERE id = 1`).run(checkedAt),
  });
} catch (e) { console.error('[grand-catalog] restart copy not configured:', e && e.message); }
// The estimate backfill: at boot (after the restart copy is loaded) and every 10 min, on the LIVE DB.
{
  const runBackfill = () => { try { backfillPurchaseEstimates(getLiveDb()).catch(() => {}); } catch (e) { console.error('[estimate-backfill] not run:', e && e.message); } };
  setTimeout(runBackfill, 2000).unref();
  setInterval(runBackfill, PURCHASE_BACKFILL_MS).unref();
}

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
