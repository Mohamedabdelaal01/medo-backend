// services/healthCounters.js — in-memory counters shown on GET /health (C1.12).
//
// Counts only, since boot: no user ids, no names, no phones, no keys. They make
// the bot↔CRM work checkable from outside with a plain GET /health:
//   test_events    — test-mode intake requests by known event_type (else "other"), with how
//                    many carried a phone (present/absent only, never the value);
//   manychat_api   — real ManyChat API calls (getInfo / setCustomField / addTag /
//                    sendFlow): ok, and failed by HTTP status or error code
//                    (getInfo: ok only with a readable timestamp, else no_value);
//   window_skips   — sends the 24 h window guard stopped, by site and reason;
//   lead_rule      — CAPI Leads not fired because the phone already sits on
//                    another profile (C1.6);
//   branch_repeats — branch_selected repeats inside 6 h (R1) answered as skips.
// Reset on every restart (a Railway redeploy) — they are a since-boot view.

const API_NAMES = ['getInfo', 'setCustomField', 'addTag', 'sendFlow'];
// test_events keys are capped (review r2): /api/events is public, so an
// unknown event_type goes into "other" and can't grow memory or /health.
const KNOWN_EVENT_TYPES = new Set([
  'entry_offer', 'entry_catalog', 'entry_location', 'category_request', 'product_details',
  'location_request', 'contact_request', 'branch_selected', 'map_click', 'visit_planned', 'visit_confirmed',
]);
const SITES     = ['visit', 'purchase', 'rep', 'reminder'];

const state = {
  since: new Date().toISOString(),
  test_events: {},                       // type → { n, phone_present }
  manychat_api: Object.fromEntries(API_NAMES.map(n => [n, { ok: 0, failed: {} }])),
  window_skips: Object.fromEntries(SITES.map(s => [s, {}])),   // site → reason → n
  lead_rule: { skipped_other_profile: 0 },
  branch_repeats: 0,
};

function countTestEvent(type, phonePresent) {
  const key = KNOWN_EVENT_TYPES.has(type) ? type : 'other';
  const row = state.test_events[key] || (state.test_events[key] = { n: 0, phone_present: 0 });
  row.n++;
  if (phonePresent) row.phone_present++;
}

// name: one of API_NAMES (others are ignored — removeTag / sendContent are not
// part of the guard's proof). error: 'http_401', 'timeout', 'missing_api_key', …
function countManyChatApi(name, ok, error) {
  const row = state.manychat_api[name];
  if (!row) return;
  if (ok) { row.ok++; return; }
  const key = String(error || 'request_failed').slice(0, 40);
  row.failed[key] = (row.failed[key] || 0) + 1;
}

function countWindowSkip(site, reason) {
  const bySite = state.window_skips[site] || (state.window_skips[site] = {});
  bySite[reason] = (bySite[reason] || 0) + 1;
}

function countLeadSkipped() { state.lead_rule.skipped_other_profile++; }
function countBranchRepeat() { state.branch_repeats++; }

function snapshot() {
  return JSON.parse(JSON.stringify(state));
}

module.exports = {
  countTestEvent, countManyChatApi, countWindowSkip, countLeadSkipped, countBranchRepeat, snapshot,
};
