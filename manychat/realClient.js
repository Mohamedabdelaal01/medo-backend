// backend/manychat/realClient.js
const { getDb } = require('../db');
const counters = require('../services/healthCounters');
const { parseWithOffset } = require('./time');
const { blockInDemo } = require('../services/outbound');

// getInfo must answer well inside the portal's 10 s request timeout, with
// sendFlow after it (review r2).
const GETINFO_TIMEOUT_MS = 4000;

// endpoint → the /health counter name (C1.12). Others are not counted.
const COUNTED = {
  '/sending/sendFlow': 'sendFlow',
  '/subscriber/setCustomFieldByName': 'setCustomField',
  '/subscriber/addTagByName': 'addTag',
  // getInfo is counted by realClient.getInfo itself: ok only for a valid
  // payload (status success + a readable timestamp), else failed.no_value.
};
function count(endpoint, result) {
  const name = COUNTED[endpoint];
  if (name) counters.countManyChatApi(name, result.ok, result.error);
  return result;
}

function getApiKey() {
  const db = getDb();
  const row = db.prepare(`SELECT value FROM settings WHERE key = 'manychat_api_key'`).get();
  return row ? row.value : null;
}

// Always resolves to { ok, data, error } — never throws, never hangs.
async function apiCall(endpoint, payload) {
  return count(endpoint, await apiPost(endpoint, payload));
}
async function apiPost(endpoint, payload) {
  // Phase 0 backstop: getManyChatClient() already hands a demo session the
  // demo client; this refuses even if the real client is reached directly.
  if (blockInDemo('manychat.post')) return { ok: false, data: null, error: 'demo' };
  const apiKey = getApiKey();
  if (!apiKey) {
    console.warn(`[ManyChat] ⚠️ Missing API Key — skipping ${endpoint} (no message sent)`);
    return { ok: false, data: null, error: 'missing_api_key' };
  }

  // 10s timeout so a stalled ManyChat call can't hang the whole request.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);

  try {
    const response = await fetch(`https://api.manychat.com/fb${endpoint}`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    // Body may not be JSON (HTML error page, empty 502, etc.) — guard it.
    let data = null;
    const raw = await response.text();
    if (raw) {
      try { data = JSON.parse(raw); }
      catch { data = { raw }; }
    }

    if (!response.ok) {
      // JSON.stringify so nested validation detail (e.g. details.messages) is
      // printed in full on one line — Node's console truncates objects to [Object].
      let detail;
      try { detail = JSON.stringify(data); } catch { detail = String(data); }
      console.error(`[ManyChat] ❌ ${endpoint} → HTTP ${response.status}: ${detail}`);
      return { ok: false, data, error: `http_${response.status}` };
    }
    return { ok: true, data, error: null };
  } catch (error) {
    const isAbort = error && error.name === 'AbortError';
    console.error(`[ManyChat] ❌ ${endpoint} →`, isAbort ? 'timeout' : error.message);
    return { ok: false, data: null, error: isAbort ? 'timeout' : (error.message || 'request_failed') };
  } finally {
    clearTimeout(timer);
  }
}

// GET twin of apiCall (C1.9): ManyChat's Page API reads (subscriber/getInfo)
// are GETs with the parameters in the query string — no body, no
// Content-Type. Same 10 s timeout, same never-throws { ok, data, error } shape,
// same «Missing API Key» short-cut. The answer of getInfo is a customer's
// profile, so it is NEVER logged — failures log the endpoint and status only.
async function apiGet(endpoint, query, timeoutMs = 10000) {
  return count(endpoint, await apiGetRaw(endpoint, query, timeoutMs));
}
async function apiGetRaw(endpoint, query, timeoutMs = 10000) {
  if (blockInDemo('manychat.get')) return { ok: false, data: null, error: 'demo' };
  const apiKey = getApiKey();
  if (!apiKey) {
    console.warn(`[ManyChat] ⚠️ Missing API Key — skipping ${endpoint}`);
    return { ok: false, data: null, error: 'missing_api_key' };
  }
  const qs = Object.entries(query || {})
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`https://api.manychat.com/fb${endpoint}${qs ? '?' + qs : ''}`, {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${apiKey}` },
      signal: controller.signal,
    });
    let data = null;
    const raw = await response.text();
    if (raw) {
      try { data = JSON.parse(raw); }
      catch { data = null; }
    }
    if (!response.ok) {
      console.error(`[ManyChat] ❌ GET ${endpoint} → HTTP ${response.status}`);
      return { ok: false, data: null, error: `http_${response.status}` };
    }
    return { ok: true, data, error: null };
  } catch (error) {
    const isAbort = error && error.name === 'AbortError';
    console.error(`[ManyChat] ❌ GET ${endpoint} →`, isAbort ? 'timeout' : 'request_failed');
    return { ok: false, data: null, error: isAbort ? 'timeout' : 'request_failed' };
  } finally {
    clearTimeout(timer);
  }
}

const realClient = {
  mode: 'real',
  // { ok, last_interaction, ig_last_interaction, error } — the raw strings;
  // windowGuard parses them (with their offset only).
  async getInfo({ user_id }) {
    const fail = (error) => {
      counters.countManyChatApi('getInfo', false, error);
      return { ok: false, last_interaction: null, ig_last_interaction: null, error };
    };
    const r = await apiGet('/subscriber/getInfo', { subscriber_id: user_id }, GETINFO_TIMEOUT_MS);
    if (!r.ok) return fail(r.error);
    const d = r.data;
    if (!d || d.status !== 'success' || !d.data || typeof d.data !== 'object') return fail('no_value');
    const li  = typeof d.data.last_interaction === 'string' ? d.data.last_interaction : null;
    const ili = typeof d.data.ig_last_interaction === 'string' ? d.data.ig_last_interaction : null;
    if (parseWithOffset(li) == null && parseWithOffset(ili) == null) return fail('no_value');
    counters.countManyChatApi('getInfo', true);
    return { ok: true, last_interaction: li, ig_last_interaction: ili, error: null };
  },
  async sendFlow({ user_id, flow_id }) {
    if (!flow_id) return { ok: false, error: 'No flow_id provided' };
    return apiCall('/sending/sendFlow', {
      subscriber_id: user_id,
      flow_ns: flow_id
    });
  },
  async sendMessage({ user_id, text }) {
    // Basic text message for fallback
    return apiCall('/sending/sendContent', {
      subscriber_id: user_id,
      data: {
        version: "v2",
        content: {
          messages: [{ type: "text", text: text }]
        }
      },
      message_tag: "ACCOUNT_UPDATE"
    });
  },
  async setCustomField({ user_id, field, value }) {
    return apiCall('/subscriber/setCustomFieldByName', {
      subscriber_id: user_id,
      field_name: field,
      field_value: value
    });
  },
  async addTag({ user_id, tag }) {
    return apiCall('/subscriber/addTagByName', {
      subscriber_id: user_id,
      tag_name: tag
    });
  },
  async removeTag({ user_id, tag }) {
    return apiCall('/subscriber/removeTagByName', {
      subscriber_id: user_id,
      tag_name: tag
    });
  },
};

realClient._apiGet = apiGet; // for the smoke's unit test
module.exports = realClient;
