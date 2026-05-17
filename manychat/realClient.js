// backend/manychat/realClient.js
const { getDb } = require('../db');

function getApiKey() {
  const db = getDb();
  const row = db.prepare(`SELECT value FROM settings WHERE key = 'manychat_api_key'`).get();
  return row ? row.value : null;
}

// Always resolves to { ok, data, error } — never throws, never hangs.
async function apiCall(endpoint, payload) {
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
      console.error(`[ManyChat] ❌ ${endpoint} → HTTP ${response.status}:`, data);
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

const realClient = {
  mode: 'real',
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

module.exports = realClient;
