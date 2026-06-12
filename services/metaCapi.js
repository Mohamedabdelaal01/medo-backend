/**
 * Meta (Facebook) Conversions API service.
 *
 * Sends offline CRM signals (Lead / Purchase) back to Meta so the ad account
 * can build high-quality Custom & Lookalike Audiences from customers who left
 * phone numbers via ManyChat — closing the offline attribution loop.
 *
 * SAFETY CONTRACT (the most important thing in this file):
 *   sendMetaEvent is STRICTLY fire-and-forget. It never throws, never rejects,
 *   never blocks. If the token is bad / Meta is down / there's no network, it
 *   logs one line and the CRM flow continues untouched. Callers must NOT await
 *   it on the request path.
 *
 * Config (read at call time so a restart isn't needed between edits):
 *   META_PIXEL_ID      — the Pixel / Dataset id
 *   META_ACCESS_TOKEN  — a system-user token with ads_management
 *   META_TEST_EVENT_CODE (optional) — routes events to Test Events while wiring
 */
const crypto = require('crypto');

const GRAPH_VERSION = 'v19.0';
const EGYPT_CC = '20';

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

/**
 * Normalize + hash a phone for Meta `ph`. Meta requires: digits only, WITH
 * country code, no leading zeros, no symbols — then SHA-256.
 *   "010 1234-5678"   → "201012345678" → sha256
 *   "+20 101 2345678" → "201012345678" → sha256
 * Returns null when the input can't yield a plausible number.
 */
function hashPhone(raw) {
  if (raw == null) return null;
  let d = String(raw).replace(/\D/g, '');     // digits only
  if (!d) return null;
  d = d.replace(/^0+(?=20)/, '');             // "0020…" → "20…"
  if (d.startsWith(EGYPT_CC) && d.length >= 12) {
    // already has the country code (e.g. 201012345678)
  } else {
    d = d.replace(/^0+/, '');                 // drop local leading zero(s)
    d = EGYPT_CC + d;                         // prepend Egypt country code
  }
  if (d.length < 11 || d.length > 15) return null; // not a plausible E.164
  return sha256(d);
}

/** Normalize + hash a name-ish field (Meta: lowercase, trimmed, then SHA-256). */
function hashText(raw) {
  if (raw == null) return null;
  const v = String(raw).trim().toLowerCase();
  return v ? sha256(v) : null;
}

/**
 * Fire one event to Meta CAPI. Fire-and-forget — see the safety contract.
 *
 * @param {string} eventName        e.g. 'Lead' | 'Purchase'
 * @param {object} userData         { phone?, firstName?, externalId? } — RAW values; hashed here
 * @param {string} [eventId]        stable id for Meta-side deduplication
 * @param {object} [custom]         optional custom_data (e.g. { currency, value })
 */
function sendMetaEvent(eventName, userData = {}, eventId = undefined, custom = undefined) {
  try {
    const pixelId = process.env.META_PIXEL_ID;
    const token   = process.env.META_ACCESS_TOKEN;
    if (!pixelId || !token) return; // not configured — silently skip

    const user_data = {};
    const ph = hashPhone(userData.phone);
    if (ph) user_data.ph = [ph];
    const fn = hashText(userData.firstName);
    if (fn) user_data.fn = [fn];
    if (userData.externalId) user_data.external_id = [sha256(String(userData.externalId))];

    // Meta requires at least one identifier — without one the event is useless.
    if (!user_data.ph && !user_data.external_id) return;

    const body = {
      data: [{
        event_name: eventName,
        event_time: Math.floor(Date.now() / 1000),
        action_source: 'chat', // leads arrive via ManyChat conversations
        ...(eventId ? { event_id: String(eventId) } : {}),
        user_data,
        ...(custom ? { custom_data: custom } : {}),
      }],
      ...(process.env.META_TEST_EVENT_CODE
        ? { test_event_code: process.env.META_TEST_EVENT_CODE } : {}),
    };

    const url = `https://graph.facebook.com/${GRAPH_VERSION}/${pixelId}/events?access_token=${encodeURIComponent(token)}`;

    // Background send — deliberately NOT returned/awaited by callers.
    fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(8000), // never hang a socket forever
    })
      .then(async (res) => {
        if (!res.ok) {
          const text = await res.text().catch(() => '');
          console.error(`[meta-capi] ${eventName} rejected (HTTP ${res.status}): ${text.slice(0, 300)}`);
        } else {
          console.log(`[meta-capi] ${eventName} sent ✓${eventId ? ` (event_id=${eventId})` : ''}`);
        }
      })
      .catch((err) => {
        console.error(`[meta-capi] ${eventName} failed: ${err.message}`);
      });
  } catch (err) {
    // Absolute last line of defense — a CAPI bug must never touch the CRM flow.
    console.error(`[meta-capi] ${eventName} error: ${err.message}`);
  }
}

module.exports = { sendMetaEvent, hashPhone };
