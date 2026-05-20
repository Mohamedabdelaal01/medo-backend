// services/prediction.js — Weekly visit forecast based on branch_selected
//
// A customer who picked a branch (branch_selected) shows clear intent to
// visit. Their *actual* probability of showing up depends on whether they
// also gave us a phone number:
//   • With phone   → ~80% (we can call/remind, and they're committed enough
//                   to share a number)
//   • Without phone → ~35% (raw drop-off rate without follow-up channel)
//
// Both weights are stored in `settings` (admin-editable):
//   forecast_with_phone_weight     (default 80)
//   forecast_without_phone_weight  (default 35)
//
// Forecast = average daily *weighted expected visits* over the last 7 days,
// extrapolated 7 days ahead.

const { getDb } = require('../db');

function pad(n) { return n < 10 ? '0' + n : '' + n; }
function dayKey(d) {
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
}

function lastNDays(n, now = new Date()) {
  const out = [];
  const today = new Date(now);
  today.setUTCHours(0, 0, 0, 0);
  for (let i = n - 1; i >= 0; i--) {
    const d = new Date(today);
    d.setUTCDate(today.getUTCDate() - i);
    out.push(dayKey(d));
  }
  return out;
}

function average(arr) {
  if (!arr.length) return 0;
  return arr.reduce((s, n) => s + n, 0) / arr.length;
}

function variance(arr, mean) {
  if (arr.length < 2) return 0;
  return arr.reduce((s, n) => s + (n - mean) ** 2, 0) / (arr.length - 1);
}

function getForecastWeights() {
  const db = getDb();
  const rows = db.prepare(`SELECT key, value FROM settings WHERE key IN
    ('forecast_with_phone_weight','forecast_without_phone_weight')`).all();
  const m = Object.fromEntries(rows.map(r => [r.key, parseFloat(r.value)]));
  const withPct    = Number.isFinite(m.forecast_with_phone_weight)    ? m.forecast_with_phone_weight    : 80;
  const withoutPct = Number.isFinite(m.forecast_without_phone_weight) ? m.forecast_without_phone_weight : 35;
  return { withPct, withoutPct };
}

// Two-bucket daily series of intent signals:
//   • with_phone    — customers who reached `branch_selected` (highest intent
//                     in the funnel; in this flow they always have a phone).
//   • without_phone — customers who triggered `location_request` BUT never
//                     left a phone. The flow still sends them the branch
//                     address after a 2-minute timeout, so they're potential
//                     visitors at a lower probability (~35%).
//
// Branch-selectors are excluded from the without_phone bucket on the same day
// to keep the two cohorts disjoint (no double counting).
function getDailySeries(days = 14) {
  const db = getDb();

  // High-intent: branch_selected users (all have phone in this flow)
  const branchRows = db.prepare(`
    SELECT user_id, substr(created_at, 1, 10) AS day
    FROM events
    WHERE event_type = 'branch_selected'
      AND created_at >= datetime('now', ?)
  `).all(`-${days} days`);

  // Low-intent: location_request users with NO phone ever recorded.
  // These got the address auto-sent after the phone-prompt timeout.
  const locRows = db.prepare(`
    SELECT user_id, substr(created_at, 1, 10) AS day
    FROM events e
    WHERE e.event_type = 'location_request'
      AND e.created_at >= datetime('now', ?)
      AND NOT EXISTS (SELECT 1 FROM lead_phones p WHERE p.user_id = e.user_id)
  `).all(`-${days} days`);

  const buckets = new Map(); // day → { withPhone:Set, withoutPhone:Set }
  for (const day of lastNDays(days)) {
    buckets.set(day, { withPhone: new Set(), withoutPhone: new Set() });
  }
  for (const r of branchRows) {
    const b = buckets.get(r.day);
    if (b) b.withPhone.add(r.user_id);
  }
  for (const r of locRows) {
    const b = buckets.get(r.day);
    // A user who reached branch_selected the same day shouldn't be double-
    // counted in the lower bucket (defensive — in practice branch_selected
    // users have phone so they wouldn't pass the NOT EXISTS filter).
    if (b && !b.withPhone.has(r.user_id)) b.withoutPhone.add(r.user_id);
  }

  const { withPct, withoutPct } = getForecastWeights();
  return [...buckets.entries()].map(([date, b]) => {
    const withN    = b.withPhone.size;
    const withoutN = b.withoutPhone.size;
    const expected = (withN * withPct + withoutN * withoutPct) / 100;
    return {
      date,
      with_phone:    withN,
      without_phone: withoutN,
      // chart still reads `count` — keep it as the weighted expected number
      // (rounded for display) so the line shows the same KPI as the headline.
      count:         Math.round(expected),
      expected_raw:  Number(expected.toFixed(2)),
    };
  });
}

function predict() {
  const series = getDailySeries(14);
  const expected = series.map(d => d.expected_raw);
  const recent = expected.slice(7);
  const prior  = expected.slice(0, 7);
  const recentAvg = average(recent);
  const priorAvg  = average(prior);
  const trend     = priorAvg > 0 ? recentAvg / priorAvg : 1;
  const expectedTotal = Math.round(recentAvg * 7 * (trend > 0 ? trend : 1));

  // Confidence: based on raw branch_selected sample size + variance.
  const totalSamples = series.reduce((s, d) => s + d.with_phone + d.without_phone, 0);
  const sd = Math.sqrt(variance(recent, recentAvg));
  let confidence = 'low';
  if (totalSamples >= 14 && sd < recentAvg * 0.6) confidence = 'high';
  else if (totalSamples >= 7) confidence = 'medium';

  // Per-branch ACTUAL confirmed arrivals over the last 7 days
  const db = getDb();
  const topBranches = db.prepare(`
    SELECT branch, COUNT(DISTINCT user_id) AS visits
    FROM lead_visits
    WHERE visited_at >= datetime('now', '-7 days')
      AND branch IS NOT NULL
    GROUP BY branch
    ORDER BY visits DESC
    LIMIT 5
  `).all();

  // Last-7-days totals split by phone status (for transparency in the UI)
  const recentSeries = series.slice(7);
  const withPhone7    = recentSeries.reduce((s, d) => s + d.with_phone, 0);
  const withoutPhone7 = recentSeries.reduce((s, d) => s + d.without_phone, 0);

  const { withPct, withoutPct } = getForecastWeights();

  return {
    expected_visits:     expectedTotal,
    confidence,
    trend:               Number(trend.toFixed(2)),
    recent_avg_per_day:  Number(recentAvg.toFixed(2)),
    daily_series:        series,
    top_branches:        topBranches,
    // Breakdown for the UI
    last7_with_phone:    withPhone7,
    last7_without_phone: withoutPhone7,
    weights: {
      with_phone:    withPct,
      without_phone: withoutPct,
    },
  };
}

module.exports = { predict, getDailySeries };
