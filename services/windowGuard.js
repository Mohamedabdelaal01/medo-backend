// services/windowGuard.js — Meta's 24 h messaging window, in front of every
// CRM → ManyChat sendFlow (C1.9). Fail closed: a send goes out only when
// ManyChat itself says the customer wrote within the last 23 hours.
//
// Four reasons, never mixed:
//   no_manychat_id — the user_id is not a ManyChat contact id (reception's
//                    walkin_… profiles, anything that is not all digits).
//                    Checked FIRST: no getInfo, no sendFlow, so a walk-in sale
//                    never moves the manychat_api counters.
//   outside_24h    — getInfo answered, and the newer of last_interaction /
//                    ig_last_interaction is ≥ 23 h old.
//   window_unknown — getInfo failed, timed out, the key is missing, or no
//                    readable value came back (a value without a UTC offset
//                    counts as unreadable — never assumed UTC).
//   local_stale    — the reminder job ONLY: the lead's newest chat event is
//                    older than 23 h (or there is none) → skipped before any
//                    API call. The 3 user-driven sites (visit, purchase, rep)
//                    never use events: a customer chatting with staff in the
//                    ManyChat inbox has no CRM event and is still in window.
// A skip is logged with the site and the reason only — no id, no phone.

const { getManyChatClient } = require('../manychat/client');
const counters = require('./healthCounters');
const { parseWithOffset } = require('../manychat/time');

const WINDOW_HOURS = 23;
const WINDOW_MS = WINDOW_HOURS * 3600 * 1000;

function isManyChatId(userId) {
  if (typeof userId !== 'string') return false;
  if (userId.startsWith('walkin_')) return false;
  return /^\d+$/.test(userId);
}

// The newest CRM event that came from the chat (/api/events stores its body in
// raw_payload; reception / system inserts don't) — the reminder's pre-filter.
function newestChatEventMs(db, userId) {
  const row = db.prepare(`
    SELECT MAX(created_at) AS t FROM events WHERE user_id = ? AND raw_payload IS NOT NULL
  `).get(userId);
  if (!row || !row.t) return null;
  const v = String(row.t);
  const ms = Date.parse(/Z$|[+-]\d\d:\d\d$/.test(v) ? v : v.replace(' ', 'T') + 'Z');
  return Number.isFinite(ms) ? ms : null;
}

/**
 * @returns {Promise<{ok:true}|{ok:false, reason:string}>}
 */
async function checkWindow(db, userId, site, { client = getManyChatClient(), nowMs = Date.now() } = {}) {
  if (!isManyChatId(userId)) return { ok: false, reason: 'no_manychat_id' };

  if (site === 'reminder') {
    const last = newestChatEventMs(db, userId);
    if (last == null || nowMs - last >= WINDOW_MS) return { ok: false, reason: 'local_stale' };
  }

  let info;
  try {
    info = typeof client.getInfo === 'function'
      ? await client.getInfo({ user_id: userId })
      : { ok: false, error: 'no_getinfo' };
  } catch (_) {
    info = { ok: false, error: 'request_failed' };
  }
  if (!info || !info.ok) return { ok: false, reason: 'window_unknown' };

  const times = [parseWithOffset(info.last_interaction), parseWithOffset(info.ig_last_interaction)]
    .filter(t => t != null);
  if (!times.length) return { ok: false, reason: 'window_unknown' };
  const newest = Math.max(...times);
  if (nowMs - newest >= WINDOW_MS) return { ok: false, reason: 'outside_24h' };
  return { ok: true };
}

/**
 * The only way the CRM sends a ManyChat flow. Never throws.
 * @returns {Promise<{sent:boolean, reason?:string, error?:string}>}
 */
async function guardedSendFlow(db, { user_id, flow_id, site }) {
  try {
    const client = getManyChatClient();
    const gate = await checkWindow(db, user_id, site, { client });
    if (!gate.ok) {
      counters.countWindowSkip(site, gate.reason);
      console.log(`[window] ${site} send skipped — ${gate.reason}`);
      return { sent: false, reason: gate.reason };
    }
    const r = await client.sendFlow({ user_id, flow_id });
    if (!r || !r.ok) {
      console.warn(`[window] ${site} send failed — ${(r && r.error) || 'unknown'}`);
      return { sent: false, error: (r && r.error) || 'send_failed' };
    }
    return { sent: true };
  } catch (e) {
    console.error(`[window] ${site} send error — ${e && e.message}`);
    return { sent: false, error: 'send_error' };
  }
}

// What a rep / reception sees for each reason (SendFlowButton shows the same).
const SKIP_MESSAGES_AR = {
  no_manychat_id: 'مش هيتبعت: العميل ده زيارة مباشرة، مالوش شات',
  outside_24h:    'مش هيتبعت: العميل مكلمناش من أكتر من 24 ساعة',
  window_unknown: 'مش هيتبعت: مش قادرين نتأكد من ManyChat دلوقتي — جرّب تاني بعد شوية',
};

module.exports = {
  WINDOW_HOURS, isManyChatId, parseWithOffset, checkWindow, guardedSendFlow, SKIP_MESSAGES_AR,
};
