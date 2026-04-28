// services/nextAction.js — Server-side picker for which ManyChat flow to fire.
// Mirrors the Arabic-language client engine in frontend/src/utils/leadIntelligence.js
// but only returns the action_type + flow_id needed by /api/trigger-message.
//
// Frontend already shows the human-readable suggestion to the rep; this module's
// job is to map the suggestion to a concrete flow_id when the rep clicks Send
// without specifying one.

const { getDb } = require('../db');

// Reads flow IDs from DB settings at call-time (not module load-time),
// so any change via the Settings page takes effect immediately — no restart needed.
function getFlowIds() {
  const db = getDb();
  const rows = db.prepare(
    `SELECT key, value FROM settings WHERE key IN (
      'manychat_flow_immediate',
      'manychat_flow_branch_info',
      'manychat_flow_offer',
      'manychat_flow_reengage'
    )`
  ).all();
  const map = Object.fromEntries(rows.map(r => [r.key, r.value || null]));
  return {
    send_immediate:   map['manychat_flow_immediate']   || null,
    send_branch_info: map['manychat_flow_branch_info'] || null,
    send_offer:       map['manychat_flow_offer']       || null,
    re_engage:        map['manychat_flow_reengage']    || null,
  };
}

const RECENT_HOURS = 48;

function hoursSince(sqliteIso) {
  if (!sqliteIso) return Infinity;
  const t = new Date(sqliteIso.replace(' ', 'T') + 'Z').getTime();
  return (Date.now() - t) / 3_600_000;
}

function recentEvent(userId, eventType, hours = RECENT_HOURS) {
  const db = getDb();
  return db.prepare(`
    SELECT * FROM events
    WHERE user_id = ? AND event_type = ?
      AND created_at >= datetime('now', '-${hours} hours')
    ORDER BY created_at DESC LIMIT 1
  `).get(userId, eventType);
}

function decide(profile) {
  if (!profile) return { action_type: 'none', flow_id: null };
  const FLOW_IDS = getFlowIds();

  // visit_confirmed → send branch info / appointment confirmation
  if (profile.visit_confirmed === 1) {
    return { action_type: 'send_branch_info', flow_id: FLOW_IDS.send_branch_info };
  }

  // Hot lead with recent activity → send_immediate
  if (profile.lead_class === 'hot' && hoursSince(profile.last_activity) <= 6) {
    return { action_type: 'send_immediate', flow_id: FLOW_IDS.send_immediate };
  }

  // Recent location_request → branch info
  if (profile.location_requested === 1) {
    const loc = recentEvent(profile.user_id, 'location_request');
    if (loc) return { action_type: 'send_branch_info', flow_id: FLOW_IDS.send_branch_info };
  }

  // Recent product_details → offer
  const prod = recentEvent(profile.user_id, 'product_details');
  if (prod) return { action_type: 'send_offer', flow_id: FLOW_IDS.send_offer };

  // Inactive ≥ 3 days but was warm/hot → re_engage
  const inactiveHours = hoursSince(profile.last_activity);
  if (inactiveHours >= 72 && (profile.lead_class === 'warm' || profile.lead_class === 'hot')) {
    return { action_type: 're_engage', flow_id: FLOW_IDS.re_engage };
  }

  return { action_type: 'none', flow_id: null };
}

function flowIdFor(actionType) {
  return getFlowIds()[actionType] || null;
}

module.exports = { decide, flowIdFor, getFlowIds };
