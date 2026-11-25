// services/grandCatalog.js — the CRM's client for the prices system (grand-system).
//
// Owner, 2026-11-22 («قسم الأسعار»): the prices system is the ONE source of
// products, pieces, prices, photos and his sales notes; the CRM reads them from
// it. Contract: grand-system docs/crm-catalog.md.
//
//   GET  <GRAND_SYSTEM_URL>/api/crm/catalog   — the catalogue (public scope with
//        no header; staff scope with `Authorization: Bearer <CRM_CATALOG_SECRET>`:
//        hidden models too + his sales note on each model)
//   POST <GRAND_SYSTEM_URL>/api/crm/quote     — today's LIST prices of a sale's
//        lines (staff scope only): the CRM stores it as an APPROXIMATE estimate,
//        shown to the admin only
//   GET  <GRAND_SYSTEM_URL>/catalogue.pdf     — the nightly catalogue PDF: 302 to
//        the current file (503 before the first one). Public. «اطبع الكتالوج».
//
// Env (read at call time, so a Railway variable change needs no code change):
//   GRAND_SYSTEM_URL    default https://grand-system-production.up.railway.app
//   CRM_CATALOG_SECRET  optional; when set, the staff scope is asked first (a
//                       refused Bearer — 401 / 503 not_configured — falls back to
//                       the public scope, so prices still show without notes)
//
// Caching: one copy in memory. A copy younger than 60 s is served as it is;
// an older one is re-checked with If-None-Match (304 = still today's). At most
// one refresh attempt per 60 s (10 s while there is no copy at all), one at a
// time. If grand-system cannot be reached the last good copy is served with its
// age (`stale: true`). Nothing here throws to a caller and nothing is logged
// with the secret.
//
// The last good copy also survives a restart (review 2026-11-22): server.js
// gives configureStore() a load/save pair on the live SQLite DB (the one-row
// table grand_catalog_cache — server-side only: not on the sqlGuard allowlist,
// in no CSV / export, read by nothing but this module). Every 200 saves it; a
// boot loads it as a STALE copy, so a CRM restart while grand-system is down
// still shows prices and still takes sales.
//
// A sale never waits on grand-system: getCatalogNow() serves the copy there is
// and refreshes in the background when it is older than the refresh window
// (it waits only when there is no copy at all).
//
// A staff copy is shown as staff only while the CURRENT secret is known to be
// accepted (review 2026-11-22 r2): the copy carries `staffOk`, true after a
// staff 200 / 304 with this secret, and the saved row carries a fingerprint
// of the secret that fetched it (secret_fp — a hash, never the secret). When
// the staff scope is refused (a wrong / rotated secret) and no fresh public
// copy came, or a boot loads a staff row whose fingerprint is not the current
// secret's, the copy is served as the PUBLIC view: no sales_note, hidden
// models filtered (publicOf()).
'use strict';

const crypto = require('crypto');

const DEFAULT_URL   = 'https://grand-system-production.up.railway.app';
// The smoke (scripts/smoke-prices.js) shortens the two intervals; bounded so a
// stray variable can't make the CRM hammer the prices system.
const envMs = (name, def, min, max) => {
  const n = Number(process.env[name]);
  return Number.isFinite(n) && n >= min && n <= max ? n : def;
};
const REFRESH_MS    = envMs('GRAND_CATALOG_REFRESH_MS', 60 * 1000, 1000, 10 * 60 * 1000);
const RETRY_EMPTY_MS = Math.min(10 * 1000, REFRESH_MS);
const TIMEOUT_MS    = 8000;
const PDF_CHECK_MS  = envMs('GRAND_CATALOG_PDF_CHECK_MS', 10 * 60 * 1000, 1000, 60 * 60 * 1000);
const PDF_TIMEOUT_MS = 4000;
const MAX_LINES     = 50;   // a sale's lines (the quote takes 200; a contract never needs that many)
const MAX_WITH      = 20;   // the contract's bound on a set line's «with»

const GID_PRODUCT = /^gid:\/\/shopify\/Product\/\d{1,20}$/;
const GID_VARIANT = /^gid:\/\/shopify\/ProductVariant\/\d{1,20}$/;

function baseUrl() {
  const raw = String(process.env.GRAND_SYSTEM_URL || '').trim().replace(/\/+$/, '');
  if (raw && /^https?:\/\/[^\s/]+(\/[^\s]*)?$/i.test(raw)) return raw;
  return DEFAULT_URL;
}
function secret() {
  const s = String(process.env.CRM_CATALOG_SECRET || '').trim();
  return s || null;
}
const catalogueUrl = () => `${baseUrl()}/catalogue.pdf`;
// Which secret fetched a saved staff copy: a one-way hash (16 hex), never the value.
const secretFp = (sec) => (sec ? crypto.createHash('sha256').update(`grand-crm/catalog-copy/${sec}`).digest('hex').slice(0, 16) : null);

const state = {
  copy: null,            // { body, etag, version, scope, fetchedAt, checkedAt }
  lastAttemptAt: 0,
  lastError: null,       // a short code: unreachable | timeout | not_ready | too_many | bad_body | http_<n>
  lastErrorAt: 0,
  staffRefused: null,    // null | 'unauthorized' | 'not_configured' — the staff scope's last refusal
  inflight: null,
  pdf: { status: 'unknown', checkedAt: 0, inflight: null },
  store: null,           // { load(), save(row), touch(checkedAt) } — the restart copy (server.js)
};

const isObj = (v) => v != null && typeof v === 'object' && !Array.isArray(v);
const str = (v) => (typeof v === 'string' ? v : null);
const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const bool = (v) => (typeof v === 'boolean' ? v : null);

function validCatalog(b) {
  return isObj(b) && typeof b.version === 'string' && b.version.length > 0 && b.version.length < 200
    && Array.isArray(b.models) && Array.isArray(b.categories);
}

async function timedFetch(url, init, ms) {
  return fetch(url, { ...init, signal: AbortSignal.timeout(ms) });
}

// One catalogue request in one scope → { kind: 'ok'|'not_modified'|'refused'|'error', ... }
async function fetchCatalog(sec) {
  const scope = sec ? 'staff' : 'public';
  const headers = { accept: 'application/json' };
  if (sec) headers.authorization = `Bearer ${sec}`;
  const c = state.copy;
  if (c && c.scope === scope && c.etag) headers['if-none-match'] = c.etag;
  let res;
  try {
    res = await timedFetch(`${baseUrl()}/api/crm/catalog`, { method: 'GET', headers }, TIMEOUT_MS);
  } catch (e) {
    return { kind: 'error', code: e && (e.name === 'TimeoutError' || e.name === 'AbortError') ? 'timeout' : 'unreachable' };
  }
  if (res.status === 304) {
    if (c && c.scope === scope) return { kind: 'not_modified' };
    return { kind: 'error', code: 'http_304' };
  }
  let body = null;
  try { body = await res.json(); } catch (_) { body = null; }
  if (res.status === 200) {
    if (!validCatalog(body)) return { kind: 'error', code: 'bad_body' };
    const etag = res.headers.get('etag') || `"${body.version}"`;
    return { kind: 'ok', body, etag, scope: body.scope === 'staff' ? 'staff' : 'public' };
  }
  const code = isObj(body) && typeof body.error === 'string' ? body.error : null;
  if (sec && (res.status === 401 || (res.status === 503 && code === 'not_configured'))) {
    return { kind: 'refused', code: res.status === 401 ? 'unauthorized' : 'not_configured' };
  }
  if (res.status === 503 && code === 'not_ready') return { kind: 'error', code: 'not_ready' };
  if (res.status === 429) return { kind: 'error', code: 'too_many' };
  return { kind: 'error', code: `http_${res.status}` };
}

async function refresh() {
  state.lastAttemptAt = Date.now();
  const sec = secret();
  let r = await fetchCatalog(sec);
  if (sec) {
    if (r.kind === 'refused') {
      state.staffRefused = r.code;
      console.warn(`[grand-catalog] staff scope refused (${r.code}) — using the public scope (no sales notes)`);
      r = await fetchCatalog(null);
    } else if (r.kind === 'ok' || r.kind === 'not_modified') {
      state.staffRefused = null;
    }
  } else {
    state.staffRefused = null;
  }
  const now = Date.now();
  if (r.kind === 'ok') {
    // a staff 200 can only have come with the current secret
    state.copy = { body: r.body, etag: r.etag, version: r.body.version, scope: r.scope, fetchedAt: now, checkedAt: now, fromDisk: false,
      staffOk: r.scope === 'staff', fp: r.scope === 'staff' ? secretFp(sec) : null };
    state.lastError = null;
    persist(state.copy);
  } else if (r.kind === 'not_modified') {
    const c = state.copy;
    const wasTrusted = c.staffOk === true;
    c.checkedAt = now;
    c.fromDisk = false;
    // a staff 304 answers the If-None-Match of the staff copy: this secret is accepted
    if (c.scope === 'staff') { c.staffOk = true; c.fp = secretFp(sec); }
    state.lastError = null;
    if (c.scope === 'staff' && !wasTrusted) persist(c);          // the row's fingerprint becomes this secret's
    else if (state.store && typeof state.store.touch === 'function') {
      try { state.store.touch(now); } catch (e) { console.warn(`[grand-catalog] could not stamp the saved copy (${e && e.code || 'error'})`); }
    }
  } else {
    state.lastError = r.code || 'unreachable';
    state.lastErrorAt = now;
    console.warn(`[grand-catalog] refresh failed (${state.lastError})${state.copy ? ' — serving the last good copy' : ''}`);
  }
}

// ── The restart copy ────────────────────────────────────────────────────────
function persist(c) {
  if (!state.store || typeof state.store.save !== 'function') return;
  try {
    state.store.save({ body_json: JSON.stringify(c.body), etag: c.etag, scope: c.scope, version: c.version,
      fetched_at: c.fetchedAt, checked_at: c.checkedAt, secret_fp: c.scope === 'staff' ? (c.fp || null) : null });
  } catch (e) {
    console.warn(`[grand-catalog] could not save the last good copy (${e && e.code || 'error'})`);
  }
}
/**
 * server.js at boot: store = { load() → row|null, save(row), touch(checkedAtMs) }.
 * The saved copy is loaded as a STALE copy (until grand-system confirms it).
 * A staff-scope copy (his sales notes, hidden models) is loaded only while
 * CRM_CATALOG_SECRET is set, and shown as staff only when its fingerprint is
 * the current secret's (accepted once already); otherwise it is shown as the
 * public view until grand-system accepts this secret. → true when a copy was
 * loaded. Never throws.
 */
function configureStore(store) {
  state.store = store || null;
  if (!store || typeof store.load !== 'function' || state.copy) return false;
  try {
    const row = store.load();
    if (!row || typeof row.body_json !== 'string') return false;
    const body = JSON.parse(row.body_json);
    if (!validCatalog(body)) return false;
    const scope = row.scope === 'staff' ? 'staff' : 'public';
    if (scope === 'staff' && !secret()) return false;
    const fetchedAt = Number(row.fetched_at) || 0;
    const checkedAt = Number(row.checked_at) || fetchedAt;
    if (!fetchedAt) return false;
    const fp = typeof row.secret_fp === 'string' && row.secret_fp ? row.secret_fp : null;
    const staffOk = scope === 'staff' && fp !== null && fp === secretFp(secret());
    state.copy = { body, etag: typeof row.etag === 'string' && row.etag ? row.etag : `"${body.version}"`, version: body.version,
      scope, fetchedAt, checkedAt: Math.min(checkedAt, Date.now()), fromDisk: true, staffOk, fp };
    console.log(`[grand-catalog] last good copy loaded from the DB (${scope}${scope === 'staff' && !staffOk ? ' — shown as public until the prices system accepts this secret' : ''}, saved ${new Date(fetchedAt).toISOString()}) — stale until the prices system answers`);
    return true;
  } catch (e) {
    console.warn(`[grand-catalog] the saved copy could not be read (${e && e.code || e && e.name || 'error'}) — starting without it`);
    return false;
  }
}

// The public view of a staff body: hidden models out, no sales notes.
function publicOf(body) {
  return { ...body, scope: 'public',
    models: body.models.filter(m => isObj(m) && m.is_public !== false)
      .map(({ sales_note, ...m }) => ({ ...m, pieces: (m.pieces || []).filter(p => isObj(p) && p.available !== false) })) };
}
// Is the copy shown as staff? Only with a secret set, the current secret
// accepted (staffOk) and not refused since.
const staffShown = (c) => c.scope === 'staff' && c.staffOk === true && !!secret() && !state.staffRefused;
function shownBody(c) {
  if (c.scope !== 'staff' || staffShown(c)) return c.body;
  if (!c.publicBody) c.publicBody = publicOf(c.body);     // derived once per copy
  return c.publicBody;
}

function view() {
  const c = state.copy;
  const now = Date.now();
  return {
    catalog:     c ? shownBody(c) : null,
    scope:       c ? (c.scope === 'staff' && !staffShown(c) ? 'public' : c.scope) : null,
    version:     c ? c.version : null,
    fetched_at:  c ? new Date(c.fetchedAt).toISOString() : null,
    checked_at:  c ? new Date(c.checkedAt).toISOString() : null,
    age_seconds: c ? Math.max(0, Math.round((now - c.checkedAt) / 1000)) : null,
    stale:       !!c && (c.fromDisk === true || state.lastErrorAt > c.checkedAt),
    error:       state.lastError,
    staff_configured: !!secret(),
    staff_refused: state.staffRefused,
  };
}

/** The catalogue (cached). Never throws: { catalog: null, error } when there never was a copy. */
async function getCatalog() {
  try {
    const now = Date.now();
    const c = state.copy;
    if (c && !c.fromDisk && now - c.checkedAt < REFRESH_MS && !(secret() && c.scope === 'public' && !state.staffRefused)) return view();
    const gap = c ? REFRESH_MS : RETRY_EMPTY_MS;
    if (now - state.lastAttemptAt < gap && !state.inflight) return view();
    if (!state.inflight) state.inflight = refresh().catch(() => {}).finally(() => { state.inflight = null; });
    await state.inflight;
  } catch (_) { /* view() below */ }
  return view();
}

/**
 * For a sale (POST /api/purchases, /api/reception/sales, PUT /api/contracts):
 * never waits on grand-system while there is a copy — serves it and, when it
 * is older than the refresh window, refreshes in the background. With no copy
 * at all it waits like getCatalog(). Never throws.
 */
async function getCatalogNow() {
  try {
    const c = state.copy;
    if (!c) return getCatalog();
    const now = Date.now();
    const due = c.fromDisk || now - c.checkedAt >= REFRESH_MS || (secret() && c.scope === 'public' && !state.staffRefused);
    if (due && now - state.lastAttemptAt >= REFRESH_MS && !state.inflight) {
      state.inflight = refresh().catch(() => {}).finally(() => { state.inflight = null; });
    }
  } catch (_) { /* view() below */ }
  return view();
}

/** «اطبع الكتالوج»: is there a published catalogue PDF? 'ready' | 'preparing' | 'missing' | 'unknown'. Never throws. */
async function catalogueStatus() {
  const p = state.pdf;
  if (Date.now() - p.checkedAt < PDF_CHECK_MS) return { url: catalogueUrl(), status: p.status, checked_at: p.checkedAt ? new Date(p.checkedAt).toISOString() : null };
  if (!p.inflight) {
    p.inflight = (async () => {
      let status = 'unknown';
      try {
        const res = await timedFetch(catalogueUrl(), { method: 'GET', redirect: 'manual' }, PDF_TIMEOUT_MS);
        if ((res.status >= 300 && res.status < 400) || res.type === 'opaqueredirect' || res.status === 200) status = 'ready';
        else if (res.status === 503) status = 'preparing';
        else if (res.status === 404) status = 'missing';
        try { if (res.body && typeof res.body.cancel === 'function') await res.body.cancel(); } catch (_) {}
      } catch (_) { status = 'unknown'; }
      p.status = status;
      p.checkedAt = Date.now();
    })().finally(() => { p.inflight = null; });
  }
  try { await p.inflight; } catch (_) {}
  return { url: catalogueUrl(), status: p.status, checked_at: p.checkedAt ? new Date(p.checkedAt).toISOString() : null };
}

// ── A sale's lines ──────────────────────────────────────────────────────────
// What staff send (POST /api/purchases, /api/reception/sales, PUT /api/contracts/:id):
//   items: [ { model_id, with?: [variant_id…], qty? }   ← a room / set (optionally with changed pieces)
//          | { variant_id, qty? } ]                     ← a single piece (or a set row by its variant)
// → { lines } (validated against the cached catalogue, titles from IT — never the
//   client's words) | { code, error } (Arabic).
function indexCatalog(cat) {
  const byModel = new Map();
  const byVariant = new Map();
  for (const m of (cat && Array.isArray(cat.models) ? cat.models : [])) {
    if (!isObj(m) || typeof m.id !== 'string') continue;
    byModel.set(m.id, m);
    for (const r of (Array.isArray(m.set) ? m.set : [])) if (isObj(r) && typeof r.variant_id === 'string') byVariant.set(r.variant_id, { kind: 'set', model: m, row: r });
    for (const p of (Array.isArray(m.pieces) ? m.pieces : [])) if (isObj(p) && typeof p.variant_id === 'string') byVariant.set(p.variant_id, { kind: 'piece', model: m, piece: p });
  }
  return { byModel, byVariant };
}

const BAD = (code, error) => ({ code, error });

// A line's category, written on it at sale time (the analytics' «الأكثر مبيعاً»
// per category): the model's category code + its Arabic name (the model's own,
// else the catalogue's categories list).
function categoryNames(cat) {
  const out = new Map();
  for (const c of (cat && Array.isArray(cat.categories) ? cat.categories : [])) {
    if (isObj(c) && typeof c.code === 'string' && typeof c.name_ar === 'string' && c.name_ar.trim()) out.set(c.code, c.name_ar.trim());
  }
  return out;
}
function categoryOf(m, names) {
  const code = typeof m.category === 'string' && m.category.trim() ? m.category.trim().slice(0, 100) : null;
  const own = typeof m.category_ar === 'string' && m.category_ar.trim() ? m.category_ar.trim() : null;
  const ar = own || (code && names.get(code)) || null;
  return { category: code, category_ar: ar ? ar.slice(0, 200) : null };
}

// ── «مخصوص» (2026-11-26): a piece in the showroom that is in no catalogue ────
// Owner: «في منتجات بتبقي موجودة احيانا في المعرض وغير موجودة في الكتالوج او
// التسعير … عايزين يبقي في كاتيجوري جديد اسمه مخصوص … بس طبعا مينزلش في
// الكتالوج او التسعير». Staff TYPE it: { kind: 'custom', name, piece?, price?, qty? }.
// It lives on the contract only (purchase_lines kind = 'custom', no model /
// variant id, no category): never sent to the prices system (quoteLinesOf skips
// it), never a products row, never in the best sellers (server.js /api/analytics
// counts it apart as `customSold`). Its typed price (optional, whole EGP) is the
// estimate's number for that line; with no price the estimate is not complete.
const CUSTOM_KIND       = 'custom';
const MAX_CUSTOM_LINES  = 20;
const CUSTOM_NAME_MAX   = 80;
const CUSTOM_PIECE_MAX  = 40;
// A typed piece price is the first staff-typed number that reaches Meta (as
// the estimate): furniture-scale bounds, so a slipped key («45000000» for a
// 45,000 sofa, «5» for 5,000) is refused out loud instead of stored and sent
// (review r1). 0 stays allowed (a piece given free). The frontend's
// parsePiecePrice (frontend/src/utils/catalog.js) keeps the same numbers.
const CUSTOM_PRICE_MAX  = 1000000;     // one piece
const CUSTOM_PRICE_MIN  = 50;          // 1–49 = a typo; 0 = free
const CUSTOM_TOTAL_MAX  = 2000000;     // every custom line's price × qty on one contract
const isCustom = (l) => !!l && l.kind === CUSTOM_KIND;
const CUSTOM_UNCHECKED = 'custom_price_unchecked';
// Typed text → one line of plain text: every whitespace run (new lines, tabs)
// is one space; other control / direction-override characters go.
function cleanTyped(v) {
  if (typeof v !== 'string') return null;
  return v.replace(/[\u0000-\u0008\u000e-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, '')
    .replace(/\s+/g, ' ').trim();
}
// The typed piece price: empty → null; whole EGP (Arabic digits, «ج.م» /
// «جنيه» accepted; a separator only between real groups of three: «4,500»,
// «٤٬٥٠٠», «1,250,000» — «4,5» or «4 5» is refused, never read as 45) → the
// number; anything else → undefined (refused). Range: 0, or CUSTOM_PRICE_MIN…
// CUSTOM_PRICE_MAX (out of range → { range: true }, its own message).
const PRICE_GROUPED = /^\d{1,3}([,،٬' ])\d{3}(?:\1\d{3})*$/;
const priceInRange = (n) => n === 0 || (n >= CUSTOM_PRICE_MIN && n <= CUSTOM_PRICE_MAX);
function customPrice(v) {
  if (v == null || v === '') return null;
  if (typeof v === 'number') {
    if (!Number.isInteger(v) || v < 0) return undefined;
    return priceInRange(v) ? v : { range: true };
  }
  if (typeof v !== 'string') return undefined;
  const s = v.replace(/[٠-٩]/g, (d) => String(d.charCodeAt(0) - 0x0660)).replace(/[۰-۹]/g, (d) => String(d.charCodeAt(0) - 0x06f0))
    .replace(/ج\.?م\.?|جنيه/g, '').replace(/\s+/g, ' ').trim();
  if (s === '') return null;
  if (!/^\d{1,9}$/.test(s) && !PRICE_GROUPED.test(s)) return undefined;
  const n = Number(s.replace(/[,،٬' ]/g, ''));
  return priceInRange(n) ? n : { range: true };
}
const fmtEgp = (n) => new Intl.NumberFormat('en-US').format(n);
function normalizeCustom(it, qty) {
  for (const k of ['model_id', 'variant_id', 'with']) {
    if (it[k] != null) return BAD('bad_custom', 'القطعة المخصوصة مالهاش موديل من الكتالوج — اكتبها تاني');
  }
  if (it.name != null && typeof it.name !== 'string') return BAD('custom_name_required', 'اكتب اسم القطعة المخصوصة');
  const name = cleanTyped(it.name) || '';
  if (!name) return BAD('custom_name_required', 'اكتب اسم القطعة المخصوصة');
  if ([...name].length > CUSTOM_NAME_MAX) return BAD('custom_name_too_long', `اسم القطعة المخصوصة طويل — ${CUSTOM_NAME_MAX} حرف بالكتير`);
  if (it.piece != null && typeof it.piece !== 'string') return BAD('bad_custom_piece', 'نوع القطعة لازم يكون كلام');
  const piece = cleanTyped(it.piece) || null;
  if (piece && [...piece].length > CUSTOM_PIECE_MAX) return BAD('custom_piece_too_long', `نوع القطعة طويل — ${CUSTOM_PIECE_MAX} حرف بالكتير`);
  const price = customPrice(it.price);
  if (price === undefined) return BAD('bad_custom_price', 'سعر القطعة المخصوصة أرقام بس من غير كسور (مثلاً 4500) — أو سيبه فاضي');
  if (price && price.range) {
    return BAD('custom_price_range', `سعر القطعة المخصوصة لازم يبقى من ${fmtEgp(CUSTOM_PRICE_MIN)} لـ ${fmtEgp(CUSTOM_PRICE_MAX)} جنيه — راجع السعر (لو القطعة هدية اكتب 0، ولو مش عارفه سيبه فاضي)`);
  }
  return { line: { kind: CUSTOM_KIND, model_id: null, variant_id: null, with: [], with_titles: [], qty,
    title: name, model_title: null, category: null, category_ar: null, custom_piece: piece, custom_price: price } };
}

function normalizeItems(raw, cat) {
  if (!Array.isArray(raw)) return { lines: [] };
  if (raw.length > MAX_LINES) return BAD('too_many_items', `العقد فيه أكتر من ${MAX_LINES} سطر — قسّمه على عقدين`);
  const customCount = raw.filter(it => isObj(it) && it.kind === CUSTOM_KIND).length;
  if (customCount > MAX_CUSTOM_LINES) return BAD('too_many_custom', `العقد فيه أكتر من ${MAX_CUSTOM_LINES} قطعة مخصوصة — جمّعهم أو قسّم العقد`);
  // A contract of custom pieces only needs no catalogue (the prices system may be down).
  if (!cat && customCount < raw.length) return BAD('catalog_unavailable', 'الأسعار مش متاحة دلوقتي — جرّب كمان شوية');
  const { byModel, byVariant } = cat ? indexCatalog(cat) : { byModel: new Map(), byVariant: new Map() };
  const catNames = categoryNames(cat);
  const lines = [];
  let customTotal = 0;
  for (const it of raw) {
    if (!isObj(it)) return BAD('bad_item', 'فيه منتج مش مفهوم — اختاره تاني من القايمة');
    let qty = it.qty == null || it.qty === '' ? 1 : Number(it.qty);
    if (!Number.isInteger(qty) || qty < 1 || qty > 99) return BAD('bad_qty', 'العدد لازم يكون رقم من 1 لـ 99');
    if (it.kind === CUSTOM_KIND) {
      const c = normalizeCustom(it, qty);
      if (c.code) return c;
      lines.push(c.line);
      customTotal += (c.line.custom_price || 0) * qty;
      if (customTotal > CUSTOM_TOTAL_MAX) {
        return BAD('custom_total_too_big', `مجموع أسعار القطع المخصوصة أكتر من ${fmtEgp(CUSTOM_TOTAL_MAX)} جنيه — راجع الأسعار والعدد`);
      }
      continue;
    }
    if (it.kind != null) return BAD('bad_item', 'فيه منتج مش مفهوم — اختاره تاني من القايمة');
    const modelId = str(it.model_id);
    const variantId = str(it.variant_id);
    if ((modelId ? 1 : 0) + (variantId ? 1 : 0) !== 1) return BAD('bad_item', 'فيه منتج مش مفهوم — اختاره تاني من القايمة');
    if (modelId) {
      if (!GID_PRODUCT.test(modelId)) return BAD('bad_item', 'فيه منتج مش مفهوم — اختاره تاني من القايمة');
      const m = byModel.get(modelId);
      if (!m) return BAD('unknown_catalog_item', 'فيه منتج مش موجود في الأسعار النهارده — حدّث الصفحة واختار تاني');
      const withRaw = it.with == null ? [] : it.with;
      if (!Array.isArray(withRaw) || withRaw.length > MAX_WITH) return BAD('bad_with', 'اختيار القطع المتغيّرة مش مفهوم — اختار تاني');
      const withIds = [];
      const seenProducts = new Set();
      const withTitles = [];
      for (const w of withRaw) {
        if (typeof w !== 'string' || !GID_VARIANT.test(w) || withIds.includes(w)) return BAD('bad_with', 'اختيار القطع المتغيّرة مش مفهوم — اختار تاني');
        const p = (Array.isArray(m.pieces) ? m.pieces : []).find(x => x && x.variant_id === w);
        if (!p) return BAD('bad_with', `فيه قطعة متغيّرة مش من «${m.title}» — اختار تاني`);
        if (seenProducts.has(p.product_id)) return BAD('bad_with', `اختار نوع واحد بس لكل قطعة في «${m.title}»`);
        seenProducts.add(p.product_id);
        // the option the set already counts adds nothing: not a change
        if (p.counted_in_set === true) continue;
        withIds.push(w);
        withTitles.push(String(p.title || ''));
      }
      lines.push({ kind: 'set', model_id: modelId, variant_id: null, with: withIds, with_titles: withTitles, qty,
        title: String(m.title || ''), model_title: String(m.title || ''), ...categoryOf(m, catNames) });
    } else {
      if (!GID_VARIANT.test(variantId)) return BAD('bad_item', 'فيه منتج مش مفهوم — اختاره تاني من القايمة');
      const hit = byVariant.get(variantId);
      if (!hit) return BAD('unknown_catalog_item', 'فيه منتج مش موجود في الأسعار النهارده — حدّث الصفحة واختار تاني');
      lines.push({ kind: hit.kind, model_id: hit.model.id, variant_id: variantId, with: [], with_titles: [], qty,
        title: String(hit.kind === 'set' ? (hit.row.title || hit.model.title) : (hit.piece.title || '')),
        model_title: String(hit.model.title || ''), ...categoryOf(hit.model, catNames) });
    }
  }
  return { lines };
}

// The quote's request lines from stored lines.
// A custom line («مخصوص») is never part of it: it is not the prices system's.
function quoteLinesOf(lines) {
  return lines.filter(l => !isCustom(l)).map(l => (l.kind === 'set' && !l.variant_id
    ? { model_id: l.model_id, qty: l.qty, ...(l.with && l.with.length ? { with: l.with } : {}) }
    : { variant_id: l.variant_id, qty: l.qty }));
}

// ── The estimate from the cached catalogue (when the quote API is unavailable) ──
// A port of grand-system src/domain/crmCatalog.ts crmQuote (same rules: a set at
// its set price; «with» adds (option − the counted option) × quantity_in_set; an
// unknown / ambiguous line or an upgrade that can't be priced → not complete).
const cents = (egp) => Math.round(Number(egp) * 100);
function quoteFromCatalog(cat, reqLines) {
  const { byModel, byVariant } = indexCatalog(cat);
  let totalCents = 0;
  let complete = true;
  const lines = [];
  const warnings = [];
  const setModels = new Set();
  const pieceLines = [];
  reqLines.forEach((l, index) => {
    const line = { index, unit_price: null, line_total: null, warnings: [] };
    lines.push(line);
    const warn = (code) => { if (!line.warnings.includes(code)) line.warnings.push(code); warnings.push({ index, code }); };
    let priced = null;
    if (l.model_id) {
      const m = byModel.get(l.model_id);
      if (m && Array.isArray(m.set) && m.set.length > 1) { complete = false; return warn('ambiguous_model'); }
      const row = m && Array.isArray(m.set) ? m.set[0] : null;
      if (m && row && num(row.price) != null && row.price > 0) priced = { kind: 'set', model: m, price: row.price, isPublic: m.is_public !== false };
    } else if (l.variant_id) {
      const hit = byVariant.get(l.variant_id);
      if (hit && hit.kind === 'set' && num(hit.row.price) > 0) priced = { kind: 'set', model: hit.model, price: hit.row.price, isPublic: hit.model.is_public !== false };
      if (hit && hit.kind === 'piece' && num(hit.piece.price) > 0) priced = { kind: 'piece', model: hit.model, price: hit.piece.price, isPublic: hit.piece.available !== false };
    }
    if (!priced) { complete = false; return warn('unknown'); }
    let unit = cents(priced.price);
    if (priced.kind === 'set' && l.with && l.with.length) {
      let add = 0; let unknown = false; const taken = new Set();
      const pieces = Array.isArray(priced.model.pieces) ? priced.model.pieces : [];
      for (const id of l.with) {
        const p = pieces.find(x => x && x.variant_id === id);
        if (!p || taken.has(p.product_id)) { unknown = true; continue; }
        taken.add(p.product_id);
        const base = pieces.filter(x => x && x.product_id === p.product_id && x.counted_in_set === true);
        if (base.length !== 1 || num(p.price) == null || num(base[0].price) == null) { unknown = true; continue; }
        add += (cents(p.price) - cents(base[0].price)) * (Number(p.quantity_in_set) || 1);
      }
      if (unit + add > 0) unit += add; else unknown = true;
      if (unknown) { complete = false; warn('upgrade_unknown'); }
    }
    const lineCents = unit * l.qty;
    totalCents += lineCents;
    line.unit_price = unit / 100;
    line.line_total = lineCents / 100;
    if (!priced.isPublic) warn('hidden');
    if (priced.kind === 'set') setModels.add(priced.model.id); else pieceLines.push({ line, model: priced.model, index });
  });
  for (const { model, index } of pieceLines) if (setModels.has(model.id)) { lines[index].warnings.push('piece_of_set'); warnings.push({ index, code: 'piece_of_set' }); }
  return { version: cat.version || null, total: totalCents / 100, complete, lines, warnings };
}

async function remoteQuote(reqLines, version) {
  const sec = secret();
  if (!sec) return { ok: false, code: 'no_secret' };
  let res;
  try {
    res = await timedFetch(`${baseUrl()}/api/crm/quote`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json', authorization: `Bearer ${sec}` },
      body: JSON.stringify({ ...(version ? { version } : {}), lines: reqLines }),
    }, TIMEOUT_MS);
  } catch (e) {
    return { ok: false, code: e && (e.name === 'TimeoutError' || e.name === 'AbortError') ? 'timeout' : 'unreachable' };
  }
  let body = null;
  try { body = await res.json(); } catch (_) { body = null; }
  if (res.status !== 200 || !isObj(body) || num(body.total) == null || typeof body.complete !== 'boolean' || !Array.isArray(body.lines)) {
    return { ok: false, code: res.status === 200 ? 'bad_body' : `http_${res.status}` };
  }
  return { ok: true, body };
}

/**
 * Today's LIST-price estimate of stored lines → { source, total, complete, version, lines, warnings }.
 *   source 'quote'          — POST /api/crm/quote (staff scope)
 *   source 'catalog_cache'  — computed here from the cached catalogue (the quote unavailable)
 *   source 'none'           — no catalogue at all: total null, not complete
 * total is whole EGP (rounded). Never throws.
 */
async function estimate(lines) {
  try {
    if (!Array.isArray(lines) || !lines.length) return { source: 'none', total: null, complete: false, version: null, lines: [], warnings: [] };
    const catIdx = [];
    lines.forEach((l, i) => { if (!isCustom(l)) catIdx.push(i); });
    const custom = lines.map((l, i) => ({ l, i })).filter(x => isCustom(x.l));
    if (!custom.length) return await estimateCatalog(lines);
    // «مخصوص» (2026-11-26): the custom lines are priced by what staff typed
    // (price × qty); the rest by the prices system as always (only those lines
    // are sent). Complete only when every line has a number. The catalogue part
    // not priceable at all (source 'none') → no total, as before.
    // A typed number past the bounds (a contract saved before them, review r1)
    // counts as NO price: never in the total (so never Meta's value, the sales
    // value or the median), the estimate never complete, warning CUSTOM_UNCHECKED.
    const typedOf = (l) => {
      // custom_price on a line just validated, price on a stored line (readPurchaseLines)
      const typed = l.custom_price !== undefined ? l.custom_price : l.price;
      return Number.isInteger(typed) && typed >= 0 ? typed : null;
    };
    const overTotal = custom.reduce((s, { l }) => s + (typedOf(l) || 0) * (Number(l.qty) || 1), 0) > CUSTOM_TOTAL_MAX;
    const cLines = custom.map(({ l, i }) => {
      const typed = typedOf(l);
      const unchecked = typed != null && (overTotal || !priceInRange(typed));
      const unit = unchecked ? null : typed;
      return { index: i, unit_price: unit, line_total: unit == null ? null : unit * (Number(l.qty) || 1),
        warnings: [unchecked ? CUSTOM_UNCHECKED : unit == null ? 'custom_no_price' : 'custom'] };
    });
    const cTotal = cLines.reduce((s, x) => s + (x.line_total || 0), 0);
    const cComplete = cLines.every(x => x.unit_price != null);
    const cWarn = [...new Set(cLines.flatMap(x => x.warnings).filter(w => w !== 'custom'))];
    if (!catIdx.length) {
      return { source: 'custom', total: cLines.some(x => x.unit_price != null) ? Math.round(cTotal) : null, complete: cComplete,
        version: null, lines: cLines, warnings: cWarn };
    }
    const base = await estimateCatalog(lines.filter(l => !isCustom(l)));
    if (base.source === 'none' || base.total == null) {
      return { ...base, total: null, complete: false, lines: [], warnings: [...(base.warnings || []), ...cWarn] };
    }
    const merged = [
      ...base.lines.map((x, j) => ({ ...x, index: catIdx[x.index != null ? x.index : j] ?? catIdx[j] })),
      ...cLines,
    ].sort((a, b) => a.index - b.index);
    return { ...base, total: Math.round(base.total + cTotal), complete: base.complete === true && cComplete,
      lines: merged, warnings: [...(base.warnings || []), ...cWarn] };
  } catch (e) {
    console.error('[grand-catalog] estimate failed:', e && e.message);
    return { source: 'none', total: null, complete: false, version: null, lines: [], warnings: [] };
  }
}
// The prices system's estimate of catalogue lines only.
async function estimateCatalog(lines) {
  try {
    const reqLines = quoteLinesOf(lines);
    const v = await getCatalog();
    const q = await remoteQuote(reqLines, v.version);
    if (q.ok) {
      return {
        source: 'quote',
        total: Math.round(q.body.total),
        complete: q.body.complete === true,
        version: str(q.body.version),
        lines: q.body.lines.map((l, i) => ({ index: i, unit_price: num(l && l.unit_price), line_total: num(l && l.line_total),
          warnings: Array.isArray(l && l.warnings) ? l.warnings.filter(w => typeof w === 'string').slice(0, 10) : [] })),
        warnings: Array.isArray(q.body.warnings) ? q.body.warnings.map(w => (isObj(w) ? str(w.code) : null)).filter(Boolean).slice(0, 50) : [],
      };
    }
    if (v.catalog) {
      const local = quoteFromCatalog(v.catalog, reqLines);
      return { source: 'catalog_cache', total: Math.round(local.total), complete: local.complete, version: local.version,
        lines: local.lines, warnings: local.warnings.map(w => w.code), quote_error: q.code };
    }
    return { source: 'none', total: null, complete: false, version: null, lines: [], warnings: [], quote_error: q.code };
  } catch (e) {
    console.error('[grand-catalog] estimate failed:', e && e.message);
    return { source: 'none', total: null, complete: false, version: null, lines: [], warnings: [] };
  }
}

// ── What the portal shows ───────────────────────────────────────────────────
function cleanPiece(p, withPrice) {
  const o = {
    product_id: str(p.product_id), variant_id: str(p.variant_id), title: str(p.title) || '',
    piece_kind: str(p.piece_kind), quantity_in_set: num(p.quantity_in_set) || 1,
    available: bool(p.available) !== false, image_url: str(p.image_url), counted_in_set: bool(p.counted_in_set),
  };
  if (withPrice) o.price = num(p.price);
  return o;
}
function cleanModel(m, { withPrice, withNote }) {
  const o = {
    id: str(m.id), handle: str(m.handle), title: str(m.title) || '', category: str(m.category), category_ar: str(m.category_ar),
    kind: str(m.kind), is_public: bool(m.is_public) !== false, in_offer: bool(m.in_offer) === true, badge: str(m.badge),
    image_url: str(m.image_url), url: str(m.url),
    pieces: (Array.isArray(m.pieces) ? m.pieces : []).filter(isObj).map(p => cleanPiece(p, withPrice)),
  };
  if (withPrice) {
    o.set_price = num(m.set_price);
    o.set = (Array.isArray(m.set) ? m.set : []).filter(isObj).map(r => ({ variant_id: str(r.variant_id), title: str(r.title) || '', price: num(r.price), available: bool(r.available) !== false }));
  } else {
    o.set_count = Array.isArray(m.set) ? m.set.length : 0;
  }
  if (withNote) {
    const n = isObj(m.sales_note) && typeof m.sales_note.text === 'string' && m.sales_note.text.trim()
      ? { text: m.sales_note.text, updated_at: str(m.sales_note.updated_at) } : null;
    o.sales_note = n;
  }
  return o;
}
function cleanCategories(cat) {
  const counts = {};
  for (const m of cat.models) if (isObj(m) && typeof m.category === 'string') counts[m.category] = (counts[m.category] || 0) + 1;
  return cat.categories.filter(isObj).map(c => ({ code: str(c.code), name_ar: str(c.name_ar), count: counts[c.code] || 0 }))
    .filter(c => c.code && c.count > 0);
}

/** GET /api/prices body (prices + notes) or the picker's (no prices, no notes). */
function pricesView(v, { picker = false } = {}) {
  const cat = v.catalog;
  const withNote = !picker && v.scope === 'staff';
  return {
    scope: v.scope,
    notes_available: withNote,
    version: v.version,
    generated_at: cat ? str(cat.generated_at) : null,
    fetched_at: v.fetched_at,
    checked_at: v.checked_at,
    age_seconds: v.age_seconds,
    stale: v.stale,
    currency: 'EGP',
    categories: cleanCategories(cat),
    models: cat.models.filter(isObj).filter(m => typeof m.id === 'string').map(m => cleanModel(m, { withPrice: !picker, withNote })),
  };
}

function snapshot() {
  const v = view();
  return {
    url_set: !!process.env.GRAND_SYSTEM_URL, secret_set: !!secret(), scope: v.scope, version: v.version,
    checked_at: v.checked_at, stale: v.stale, error: v.error, staff_refused: v.staff_refused,
    catalogue_pdf: state.pdf.status,
  };
}

// Tests only: forget the copy.
function _reset() {
  state.copy = null; state.lastAttemptAt = 0; state.lastError = null; state.lastErrorAt = 0; state.staffRefused = null; state.store = null;
  state.pdf = { status: 'unknown', checkedAt: 0, inflight: null };
}

module.exports = {
  getCatalog, getCatalogNow, configureStore, catalogueStatus, normalizeItems, quoteLinesOf, quoteFromCatalog, estimate, pricesView, snapshot,
  baseUrl, catalogueUrl, _reset, MAX_LINES, isCustom, CUSTOM_KIND, MAX_CUSTOM_LINES, CUSTOM_NAME_MAX, CUSTOM_PIECE_MAX,
  CUSTOM_PRICE_MIN, CUSTOM_PRICE_MAX, CUSTOM_TOTAL_MAX, CUSTOM_UNCHECKED,
};
