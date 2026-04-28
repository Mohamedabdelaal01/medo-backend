// services/tagging.js — Sync lead_class to ManyChat custom field + tag.
// Best-effort — wrapped in try/catch by the caller so a tagging failure
// never breaks webhook ingest or send flow.

const { getManyChatClient } = require('../manychat/client');

async function syncLeadClass({ user_id, lead_class, total_score }) {
  if (!user_id || !lead_class) return;
  const client = getManyChatClient();
  await client.setCustomField({ user_id, field: 'crm_lead_class', value: lead_class });
  if (typeof total_score === 'number') {
    await client.setCustomField({ user_id, field: 'crm_total_score', value: total_score });
  }
  await client.addTag({ user_id, tag: lead_class });
}

module.exports = { syncLeadClass };
