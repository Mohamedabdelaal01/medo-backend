// scoring.js — Lead Scoring Engine
// Translates ManyChat events into scores and lead classifications

// ── Score Map (defaults) ─────────────────────────────────────────────────
// How many points each event_type is worth. Admin-overridable via the
// 'scoring_rules' setting (see getScoringConfig) — these are the fallback
// used until a config is configured or if the stored config is invalid.
const DEFAULT_SCORE_MAP = {
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
// Not admin-configurable — this is a data-integrity rule, not a business knob.
const DEDUP_SCORED_EVENTS = ['product_details', 'category_request'];

// ── Lead Classification Thresholds (defaults) ─────────────────────────────
// 5-state system:
//   cold      0–30   — browsed but low intent
//   warm      31–74  — showing interest
//   hot       75+    — strong intent (location request, repeat views)
//   visited          — physically arrived at showroom (set by visit_confirmed event or /visits/confirm)
//   purchased        — completed offline purchase (set by POST /purchases)
// Legacy 'converted' state kept for backward compat with existing DB rows.
// Admin-overridable via 'scoring_hot_threshold'/'scoring_warm_threshold' settings.
const DEFAULT_THRESHOLDS = {
  cold: 0,
  warm: 31,
  hot:  75,
};

// Backward-compatible aliases — some call sites may still import these names.
const SCORE_MAP  = DEFAULT_SCORE_MAP;
const THRESHOLDS = DEFAULT_THRESHOLDS;

/**
 * Read the admin-configurable scoring config from settings. Never throws —
 * any missing/corrupt/inconsistent stored config falls back to the hardcoded
 * defaults above (with a warning), so a bad settings row can never break
 * event ingestion.
 * @param {object} db - a better-sqlite3 handle (caller resolves live/demo)
 * @returns {{scoreMap:object, thresholds:{warm:number,hot:number}, decay:{enabled:boolean,graceDays:number,pointsPerDay:number}}}
 */
function getScoringConfig(db) {
  let scoreMap = DEFAULT_SCORE_MAP;
  let thresholds = { warm: DEFAULT_THRESHOLDS.warm, hot: DEFAULT_THRESHOLDS.hot };
  let decay = { enabled: false, graceDays: 30, pointsPerDay: 2 };

  try {
    const rows = db.prepare(`
      SELECT key, value FROM settings
      WHERE key IN ('scoring_rules','scoring_hot_threshold','scoring_warm_threshold',
                     'lead_expiry_days','scoring_decay_enabled','scoring_decay_points_per_day')
    `).all();
    const m = Object.fromEntries(rows.map(r => [r.key, r.value]));

    if (m.scoring_rules) {
      const rules = JSON.parse(m.scoring_rules);
      if (Array.isArray(rules)) {
        const map = {};
        for (const r of rules) {
          if (r && typeof r.event_type === 'string' && r.event_type && r.active !== false) {
            const pts = parseInt(r.points, 10);
            if (Number.isFinite(pts)) map[r.event_type] = pts;
          }
        }
        if (Object.keys(map).length) scoreMap = map;
      }
    }

    const hot  = parseInt(m.scoring_hot_threshold, 10);
    const warm = parseInt(m.scoring_warm_threshold, 10);
    if (Number.isFinite(hot) && Number.isFinite(warm) && warm < hot) {
      thresholds = { warm, hot };
    }

    decay.enabled      = m.scoring_decay_enabled === 'true';
    const grace = parseInt(m.lead_expiry_days, 10);
    if (Number.isFinite(grace) && grace > 0) decay.graceDays = grace;
    const rate = parseInt(m.scoring_decay_points_per_day, 10);
    if (Number.isFinite(rate) && rate >= 0) decay.pointsPerDay = rate;
  } catch (e) {
    console.warn(`[scoring] invalid scoring config, using defaults: ${e.message}`);
    scoreMap = DEFAULT_SCORE_MAP;
    thresholds = { warm: DEFAULT_THRESHOLDS.warm, hot: DEFAULT_THRESHOLDS.hot };
  }

  return { scoreMap, thresholds, decay };
}

/**
 * Get score delta for a given event_type
 * @param {string} eventType
 * @param {object} [scoreMap] - defaults to DEFAULT_SCORE_MAP
 * @returns {number} points to add
 */
function getScoreDelta(eventType, scoreMap = DEFAULT_SCORE_MAP) {
  return scoreMap[eventType] || 0;
}

/**
 * A dormant lead's effective score for classification purposes. Never
 * mutates or replaces the stored total_score — decay is purely analytic,
 * recomputed from (total_score, last_activity) whenever needed, so a lead
 * that re-engages is instantly re-evaluated from its full raw score.
 * @param {number} totalScore
 * @param {string|null} lastActivity - SQLite datetime string ('YYYY-MM-DD HH:MM:SS', UTC) or ISO
 * @param {{enabled:boolean,graceDays:number,pointsPerDay:number}} decay
 * @param {number} [nowMs]
 * @returns {number}
 */
function computeDecayedScore(totalScore, lastActivity, decay, nowMs = Date.now()) {
  if (!decay?.enabled || !lastActivity) return totalScore;
  const iso = String(lastActivity).includes('T')
    ? lastActivity
    : lastActivity.replace(' ', 'T') + 'Z';
  const lastMs = Date.parse(iso);
  if (!Number.isFinite(lastMs)) return totalScore;
  const idleDays = (nowMs - lastMs) / 86400000;
  const overGrace = Math.max(0, idleDays - decay.graceDays);
  return Math.max(0, totalScore - overGrace * decay.pointsPerDay);
}

/**
 * Classify a lead based strictly on earned total score and flags.
 * 'purchased' is NEVER returned here — it is set directly by the purchases route.
 *
 * A lead's tier is dictated ONLY by score — requesting a branch location is a
 * real high-intent signal but does NOT upgrade the tier by itself (it used to,
 * via a score>=40 override; that mixed a 40-point window-shopper with a
 * genuinely 75+ engaged lead under the same "hot" label, diluting sales
 * reps' focus — measured at ~1.2% real conversion for that inflated bucket).
 * location_requested is still recorded on the lead and should be shown as a
 * separate UI flag (📍) so reps see the signal without it distorting the tier.
 *
 * @param {number}  totalScore
 * @param {boolean} visitConfirmed
 * @param {string}  currentClass  — pass existing class so purchased leads are never downgraded
 * @param {{warm:number,hot:number}} [thresholds] - defaults to DEFAULT_THRESHOLDS
 * @returns {string} 'cold' | 'warm' | 'hot' | 'visited' | 'purchased' (preserved)
 */
function classifyLead(totalScore, visitConfirmed = false, currentClass = '', thresholds = DEFAULT_THRESHOLDS) {
  // Purchased is terminal — never downgrade a buyer
  if (currentClass === 'purchased') return 'purchased';

  // Visit confirmed → visited (was 'converted' in v1; legacy rows still read as converted)
  if (visitConfirmed) return 'visited';

  if (totalScore >= thresholds.hot)  return 'hot';
  if (totalScore >= thresholds.warm) return 'warm';
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
 * @param {{scoreMap:object,thresholds:object}} [config] - from getScoringConfig; defaults used if omitted
 * @returns {object} { scoreDelta, newTotalScore, newLeadClass }
 */
function processScore(profile, eventType, eventValue, alreadyScored = false, config = null) {
  const scoreMap   = config?.scoreMap   || DEFAULT_SCORE_MAP;
  const thresholds = config?.thresholds || DEFAULT_THRESHOLDS;

  let scoreDelta = getScoreDelta(eventType, scoreMap);

  // Per-value dedup: a repeated view of the SAME product or the SAME category
  // earns zero. Distinct products/categories are unaffected.
  if (alreadyScored && DEDUP_SCORED_EVENTS.includes(eventType)) {
    scoreDelta = 0;
  }

  // Bonus: map click inside branch detail (independent signal — kept)
  if (scoreDelta > 0 && eventValue && eventValue.includes('map_click')) {
    scoreDelta += (scoreMap.map_click ?? DEFAULT_SCORE_MAP.map_click);
  }

  const newTotalScore = (profile.total_score || 0) + scoreDelta;

  const visitConfirmed  = eventType === 'visit_confirmed' || profile.visit_confirmed === 1;

  const newLeadClass = classifyLead(
    newTotalScore,
    visitConfirmed,
    profile.lead_class || '',   // preserve 'purchased' / 'visited' from DB
    thresholds
  );

  return {
    scoreDelta,
    newTotalScore,
    newLeadClass,
  };
}

module.exports = {
  getScoreDelta, classifyLead, processScore, getScoringConfig, computeDecayedScore,
  SCORE_MAP, THRESHOLDS, DEDUP_SCORED_EVENTS, DEFAULT_SCORE_MAP, DEFAULT_THRESHOLDS,
};
