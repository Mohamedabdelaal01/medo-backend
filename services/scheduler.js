// services/scheduler.js — Smart Follow-Up Scheduler
// Hard rule: every lead can receive a maximum of 2 outbound flows per ISO week.
// Reset happens lazily on the next call after week_anchor < this week's Monday.

const { getDb } = require('../db');

// Reads weekly_message_limit from DB at call-time so Settings page changes
// take effect immediately without a server restart.
function getWeeklyLimit() {
  try {
    const db  = getDb();
    const row = db.prepare(`SELECT value FROM settings WHERE key = 'weekly_message_limit'`).get();
    const val = parseInt(row?.value, 10);
    return Number.isFinite(val) && val > 0 ? val : 2; // safe fallback = 2
  } catch {
    return 2;
  }
}

function pad(n) { return n < 10 ? '0' + n : '' + n; }

// ISO week anchor — Monday of the current week (UTC), as 'YYYY-MM-DD'.
function isoMondayAnchor(date = new Date()) {
  const d = new Date(date);
  const day = d.getUTCDay();              // 0=Sun .. 6=Sat
  const diffToMonday = (day + 6) % 7;     // 0 if Mon, 1 if Tue, ... 6 if Sun
  d.setUTCDate(d.getUTCDate() - diffToMonday);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
}

function getState(userId) {
  const db = getDb();
  return db.prepare(`SELECT * FROM follow_up_state WHERE user_id = ?`).get(userId);
}

// Returns the state row, rotating the weekly counter if a new week has started.
// Always returns a row (creates one with defaults if missing).
function getStateRotated(userId, now = new Date()) {
  const db = getDb();
  const anchor = isoMondayAnchor(now);
  let state = getState(userId);

  if (!state) {
    db.prepare(`
      INSERT INTO follow_up_state (user_id, sends_this_week, week_anchor)
      VALUES (?, 0, ?)
    `).run(userId, anchor);
    return { user_id: userId, sends_this_week: 0, week_anchor: anchor, last_sent_at: null };
  }

  if (state.week_anchor !== anchor) {
    db.prepare(`
      UPDATE follow_up_state
      SET sends_this_week = 0, week_anchor = ?
      WHERE user_id = ?
    `).run(anchor, userId);
    state = { ...state, sends_this_week: 0, week_anchor: anchor };
  }

  return state;
}

function canSend(userId, { force = false } = {}) {
  const state       = getStateRotated(userId);
  const weeklyLimit = getWeeklyLimit();
  if (force) return { ok: true, state };
  if (state.sends_this_week >= weeklyLimit) {
    return {
      ok: false,
      reason: `Weekly send limit reached (${weeklyLimit})`,
      state,
    };
  }
  return { ok: true, state };
}

function recordSend(userId) {
  const db = getDb();
  const anchor = isoMondayAnchor();
  // UPSERT in one statement so concurrent calls do not lose the increment.
  db.prepare(`
    INSERT INTO follow_up_state (user_id, sends_this_week, week_anchor, last_sent_at)
    VALUES (?, 1, ?, datetime('now'))
    ON CONFLICT(user_id) DO UPDATE SET
      sends_this_week = sends_this_week + 1,
      last_sent_at    = datetime('now'),
      week_anchor     = excluded.week_anchor
  `).run(userId, anchor);
  return getState(userId);
}

module.exports = { canSend, recordSend, getStateRotated, isoMondayAnchor, getWeeklyLimit };
