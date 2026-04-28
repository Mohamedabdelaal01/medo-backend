// backend/manychat/realClient.js
const { getDb } = require('../db');

function getApiKey() {
  const db = getDb();
  const row = db.prepare(`SELECT value FROM settings WHERE key = 'manychat_api_key'`).get();
  return row ? row.value : null;
}

async function apiCall(endpoint, payload) {
  const apiKey = getApiKey();
  if (!apiKey) {
    console.log(`[ManyChat REAL] Missing API Key, skipping ${endpoint}`);
    return { ok: false, error: 'Missing API Key' };
  }

  try {
    const response = await fetch(`https://api.manychat.com/fb${endpoint}`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });
    
    const data = await response.json();
    if (!response.ok) {
        console.error(`[ManyChat REAL] Error calling ${endpoint}:`, data);
    }
    return { ok: response.ok, data };
  } catch (error) {
    console.error(`[ManyChat REAL] Error calling ${endpoint}:`, error);
    return { ok: false, error: error.message };
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
