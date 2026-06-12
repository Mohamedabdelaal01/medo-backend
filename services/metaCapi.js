/**
 * Meta (Facebook) Conversions API service — CRM (Conversion Leads) integration.
 *
 * Sends offline CRM signals (Lead / Purchase / stage changes) back to Meta so
 * the ad account can build high-quality Custom & Lookalike Audiences from
 * customers who left phone numbers via ManyChat — closing the offline loop.
 *
 * Follows Meta's official CRM integration spec (v25.0):
 *   - action_source MUST be "system_generated"
 *   - custom_data MUST carry { event_source: "crm", lead_event_source: <CRM name> }
 *   - event_time in UNIX SECONDS
 *   - user_data.ph MUST be an array of SHA-256 hashes (digits-only, with country
 *     code, no leading zeros); more identifiers (fn, external_id) improve matching.
 *
 * SAFETY CONTRACT (the most important thing in this file):
 *   sendMetaEvent is STRICTLY fire-and-forget. It never throws, never rejects,
 *   never blocks. If the token is bad / Meta is down / there's no network, it
 *   logs one line and the CRM flow continues untouched. Callers must NOT await
 *   it on the request path.
 *
 * Config (read at call time):
 *   META_PIXEL_ID        — the Dataset (formerly Pixel) id
 *   META_ACCESS_TOKEN    — a system-user token for the dataset
 *   META_TEST_EVENT_CODE (optional) — routes events to Test Events while wiring
 */
const crypto = require('crypto');

const API_VERSION = 'v25.0';
const LEAD_EVENT_SOURCE = 'Grand Furniture CRM';
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
 * Fire one CRM event to Meta CAPI. Fire-and-forget — see the safety contract.
 *
 * @param {string} eventName   critical CRM stage, e.g. 'Lead' | 'Purchase'
 * @param {object} userData    { phone?, firstName?, externalId?, leadId? } — RAW values; hashed here
 * @param {string} [eventId]   stable id for Meta-side deduplication
 * @param {object} [custom]    extra custom_data merged over the required CRM
 *                             fields (e.g. { currency: 'EGP', value: 0 })
 */
function sendMetaEvent(eventName, userData = {}, eventId = undefined, custom = undefined) {
  try {
    if (!process.env.META_PIXEL_ID || !process.env.META_ACCESS_TOKEN) return; // not configured — skip

    // ── user_data: as many matchable identifiers as we have ──────────────────
    const user_data = {};
    const ph = hashPhone(userData.phone);
    if (ph) user_data.ph = [ph];                       // MUST be an array of SHA-256
    const fn = hashText(userData.firstName);
    if (fn) user_data.fn = [fn];
    if (userData.externalId) user_data.external_id = [sha256(String(userData.externalId))];
    // Meta-generated lead id (15-17 digits) when the lead came from a Lead Ad —
    // highest-priority matcher, sent UNHASHED per spec.
    if (userData.leadId && /^\d{15,17}$/.test(String(userData.leadId))) {
      user_data.lead_id = Number(userData.leadId);
    }

    // At least one identifier or the event can't be matched to anyone.
    if (!user_data.ph && !user_data.external_id && !user_data.lead_id) return;

    // ── exact Meta CRM payload schema ─────────────────────────────────────────
    const payload = {
      data: [
        {
          action_source: 'system_generated',           // REQUIRED for CRM events
          custom_data: {
            event_source: 'crm',                       // REQUIRED, always "crm"
            lead_event_source: LEAD_EVENT_SOURCE,      // REQUIRED: this CRM's name
            ...(custom || {}),
          },
          event_name: eventName,
          event_time: Math.floor(Date.now() / 1000),   // UNIX seconds
          ...(eventId ? { event_id: String(eventId) } : {}),
          user_data,
        },
      ],
      ...(process.env.META_TEST_EVENT_CODE
        ? { test_event_code: process.env.META_TEST_EVENT_CODE } : {}),
    };

    const url = `https://graph.facebook.com/v25.0/${process.env.META_PIXEL_ID}/events?access_token=${process.env.META_ACCESS_TOKEN}`;

    // Background send — deliberately NOT returned/awaited by callers.
    fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
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

/**
 * Pixel warm-up: bulk-sync historical CRM leads to the Meta dataset.
 *
 * Sends every lead as a "Lead" event in batches of 500 (Meta caps `data` at
 * 1000), SEQUENTIALLY to stay friendly with rate limits. event_time is NOW for
 * every lead — Meta rejects events older than 7 days, and for audience building
 * (the whole point of the warm-up) the match matters, not the date.
 *
 * event_id reuses the live trigger's format (lead_{user_id}_{phone}) so leads
 * that already fired a real-time Lead event are DEDUPLICATED by Meta, not
 * double-counted.
 *
 * Unlike sendMetaEvent this IS awaitable (it's an explicit admin action with a
 * progress UI) — but it still never throws: every failure is captured in the
 * returned summary.
 *
 * @param {Array<{user_id:string, phone:string, first_name?:string}>} leads
 * @returns {Promise<{configured:boolean,total:number,eligible:number,sent:number,batches:number,failed_batches:number,errors:string[]}>}
 */
async function bulkSyncHistoricalLeads(leads = []) {
  const summary = {
    configured: !!(process.env.META_PIXEL_ID && process.env.META_ACCESS_TOKEN),
    total: leads.length, eligible: 0, sent: 0, batches: 0, failed_batches: 0, errors: [],
  };
  try {
    if (!summary.configured) return summary;

    // Build events, dropping leads whose phone can't be hashed to a valid number.
    const events = [];
    for (const lead of leads) {
      const ph = hashPhone(lead.phone);
      if (!ph) continue;
      const user_data = { ph: [ph] };
      const fn = hashText(lead.first_name);
      if (fn) user_data.fn = [fn];
      if (lead.user_id) user_data.external_id = [sha256(String(lead.user_id))];
      events.push({
        action_source: 'system_generated',
        custom_data: { event_source: 'crm', lead_event_source: LEAD_EVENT_SOURCE },
        event_name: 'Lead',
        event_time: Math.floor(Date.now() / 1000),
        event_id: `lead_${lead.user_id}_${lead.phone}`,
        user_data,
      });
    }
    summary.eligible = events.length;
    if (!events.length) return summary;

    // Chunk into batches of 500 and send sequentially.
    const BATCH = 500;
    const url = `https://graph.facebook.com/v25.0/${process.env.META_PIXEL_ID}/events?access_token=${process.env.META_ACCESS_TOKEN}`;
    const chunks = [];
    for (let i = 0; i < events.length; i += BATCH) chunks.push(events.slice(i, i + BATCH));

    for (const chunk of chunks) {
      summary.batches++;
      try {
        const body = {
          data: chunk,
          ...(process.env.META_TEST_EVENT_CODE
            ? { test_event_code: process.env.META_TEST_EVENT_CODE } : {}),
        };
        const res = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(30000),
        });
        if (res.ok) {
          const json = await res.json().catch(() => ({}));
          summary.sent += json.events_received ?? chunk.length;
          console.log(`[meta-capi] warm-up batch ${summary.batches}/${chunks.length}: ${json.events_received ?? chunk.length} received ✓`);
        } else {
          const text = await res.text().catch(() => '');
          summary.failed_batches++;
          summary.errors.push(`batch ${summary.batches}: HTTP ${res.status} ${text.slice(0, 200)}`);
          console.error(`[meta-capi] warm-up batch ${summary.batches} rejected (HTTP ${res.status}): ${text.slice(0, 200)}`);
        }
      } catch (err) {
        summary.failed_batches++;
        summary.errors.push(`batch ${summary.batches}: ${err.message}`);
        console.error(`[meta-capi] warm-up batch ${summary.batches} failed: ${err.message}`);
      }
    }
  } catch (err) {
    summary.errors.push(err.message);
    console.error(`[meta-capi] warm-up error: ${err.message}`);
  }
  return summary;
}

module.exports = { sendMetaEvent, bulkSyncHistoricalLeads, hashPhone, API_VERSION };
