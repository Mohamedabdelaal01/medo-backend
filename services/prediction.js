// services/prediction.js — Weekly visit forecast
// A "potential visit" = a customer who showed they want to come to a branch:
// picked a branch (branch_selected, usually with phone), asked for the
// location, or already confirmed. Counts DISTINCT customers per day over the
// last 14 days and projects the next 7.

const { getDb } = require('../db');

// branch_selected is the strongest pre-visit signal in this funnel
// (customer chose a branch + left their phone) — count it even if they
// never tapped the map link.
const VISIT_EVENTS = ['branch_selected', 'location_request', 'visit_confirmed'];

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

function getDailySeries(days = 14) {
  const db = getDb();
  const placeholders = VISIT_EVENTS.map(() => '?').join(',');
  const rows = db.prepare(`
    SELECT user_id, created_at FROM events
    WHERE event_type IN (${placeholders})
      AND created_at >= datetime('now', '-${days} days')
  `).all(...VISIT_EVENTS);

  // Count DISTINCT customers per day — a customer comparing two branches
  // is one potential visitor, not two.
  const seen = new Map(); // day → Set(user_id)
  for (const day of lastNDays(days)) seen.set(day, new Set());
  for (const row of rows) {
    const day = row.created_at.slice(0, 10); // "YYYY-MM-DD"
    if (seen.has(day)) seen.get(day).add(row.user_id);
  }
  return [...seen.entries()].map(([date, set]) => ({ date, count: set.size }));
}

function predict() {
  const series = getDailySeries(14);
  const counts = series.map((d) => d.count);
  const recent = counts.slice(7);
  const prior = counts.slice(0, 7);
  const recentAvg = average(recent);
  const priorAvg = average(prior);
  const trend = priorAvg > 0 ? recentAvg / priorAvg : 1;
  const expected = Math.round(recentAvg * 7 * (trend > 0 ? trend : 1));

  const totalSamples = counts.reduce((s, n) => s + n, 0);
  const sd = Math.sqrt(variance(recent, recentAvg));
  let confidence = 'low';
  if (totalSamples >= 14 && sd < recentAvg * 0.6) confidence = 'high';
  else if (totalSamples >= 7) confidence = 'medium';

  // Per-branch ACTUAL confirmed arrivals over the last 7 days — read from
  // lead_visits (reception confirmations live here, not in the events table).
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

  return {
    expected_visits: expected,
    confidence,
    trend: Number(trend.toFixed(2)),
    recent_avg_per_day: Number(recentAvg.toFixed(2)),
    daily_series: series,
    top_branches: topBranches,
  };
}

module.exports = { predict, getDailySeries };
