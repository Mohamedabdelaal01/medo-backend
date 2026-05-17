// scoring.js — Lead Scoring Engine
// Translates ManyChat events into scores and lead classifications

// ── Score Map ─────────────────────────────────────────────────────────────
// How many points each event_type is worth
const SCORE_MAP = {
  entry_offer:      5,
  entry_catalog:    5,
  category_request: 10,   // picked a specific category (غرف النوم / السفرة …)
  entry_location:   10,
  product_details:  20,
  location_request: 40,
  contact_request:  15,
  branch_selected:  30,
  visit_confirmed:  100,

  // Bonus events (applied contextually in server.js)
  map_click:           25,
};

// Event types that are scored ONCE per distinct value per user.
// A 2nd click on the SAME product / SAME category earns 0 points
// (the event is still recorded for analytics, just with score_delta = 0).
// A click on a DIFFERENT product/category still earns full points.
const DEDUP_SCORED_EVENTS = ['product_details', 'category_request'];

// ── Lead Classification Thresholds ────────────────────────────────────────
// 5-state system:
//   cold      0–30   — browsed but low intent
//   warm      31–74  — showing interest
//   hot       75+    — strong intent (location request, repeat views)
//   visited          — physically arrived at showroom (set by visit_confirmed event or /visits/confirm)
//   purchased        — completed offline purchase (set by POST /purchases)
// Legacy 'converted' state kept for backward compat with existing DB rows.
const THRESHOLDS = {
  cold: 0,
  warm: 31,
  hot:  75,
};

/**
 * Get score delta for a given event_type
 * @param {string} eventType
 * @returns {number} points to add
 */
function getScoreDelta(eventType) {
  return SCORE_MAP[eventType] || 0;
}

/**
 * Classify a lead based on total score and flags.
 * 'purchased' is NEVER returned here — it is set directly by the purchases route.
 * @param {number}  totalScore
 * @param {boolean} visitConfirmed
 * @param {boolean} locationRequested
 * @param {string}  currentClass  — pass existing class so purchased leads are never downgraded
 * @returns {string} 'cold' | 'warm' | 'hot' | 'visited' | 'purchased' (preserved)
 */
function classifyLead(totalScore, visitConfirmed = false, locationRequested = false, currentClass = '') {
  // Purchased is terminal — never downgrade a buyer
  if (currentClass === 'purchased') return 'purchased';

  // Visit confirmed → visited (was 'converted' in v1; legacy rows still read as converted)
  if (visitConfirmed) return 'visited';

  // Location requested means at minimum HOT — strongest intent signal short of visit
  if (locationRequested && totalScore >= 40) return 'hot';

  if (totalScore >= THRESHOLDS.hot)  return 'hot';
  if (totalScore >= THRESHOLDS.warm) return 'warm';
  return 'cold';
}

/**
 * Full scoring result for a new event
 * @param {object}  profile       - current lead profile from DB
 * @param {string}  eventType     - incoming event
 * @param {string}  eventValue    - incoming event value
 * @param {boolean} alreadyScored - true when this exact product/category was
 *                                  already scored for this user before
 *                                  (caller resolves this via a DB lookup).
 * @returns {object} { scoreDelta, newTotalScore, newLeadClass }
 */
function processScore(profile, eventType, eventValue, alreadyScored = false) {
  let scoreDelta = getScoreDelta(eventType);

  // Per-value dedup: a repeated view of the SAME product or the SAME category
  // earns zero. Distinct products/categories are unaffected.
  if (alreadyScored && DEDUP_SCORED_EVENTS.includes(eventType)) {
    scoreDelta = 0;
  }

  // Bonus: map click inside branch detail (independent signal — kept)
  if (scoreDelta > 0 && eventValue && eventValue.includes('map_click')) {
    scoreDelta += SCORE_MAP.map_click;
  }

  const newTotalScore = (profile.total_score || 0) + scoreDelta;

  const visitConfirmed  = eventType === 'visit_confirmed' || profile.visit_confirmed === 1;

  // Must match the isLocationEvent list in server.js exactly.
  // entry_location was missing here, causing an inconsistency:
  // server.js wrote location_requested=1 to DB for entry_location,
  // but this function did not treat it as a location event during classification.
  const locationRequested = eventType === 'location_request'
    || eventType === 'branch_selected'
    || eventType === 'entry_location'
    || profile.location_requested === 1;

  const newLeadClass = classifyLead(
    newTotalScore,
    visitConfirmed,
    locationRequested,
    profile.lead_class || ''   // preserve 'purchased' / 'visited' from DB
  );

  return {
    scoreDelta,
    newTotalScore,
    newLeadClass,
  };
}

module.exports = { getScoreDelta, classifyLead, processScore, SCORE_MAP, THRESHOLDS, DEDUP_SCORED_EVENTS };
