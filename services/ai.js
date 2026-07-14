// services/ai.js — GLM (z.ai) client for the CRM's AI features.
//
// SAFETY CONTRACT (mirrors metaCapi.js):
//   - callAi() NEVER throws — it resolves { ok, text | error } always.
//   - Hard timeout so a slow provider can never hang a request.
//   - All config lives in `settings` (admin-editable, no redeploy needed):
//       zai_api_key   — required; empty = AI features respond "مش متظبط"
//       zai_model     — default 'glm-4.6' (change to any z.ai model id)
//       zai_base_url  — default z.ai OpenAI-compatible chat endpoint
//
// GLM's API is OpenAI-compatible (messages / choices), so swapping providers
// later means changing two settings, not code.

const { getDb } = require('../db');

const DEFAULT_BASE_URL = 'https://api.z.ai/api/paas/v4/chat/completions';
const DEFAULT_MODEL    = 'glm-4.6';
const TIMEOUT_MS       = 25000;

function getAiConfig() {
  let key = null, model = DEFAULT_MODEL, baseUrl = DEFAULT_BASE_URL;
  try {
    const rows = getDb().prepare(
      `SELECT key, value FROM settings WHERE key IN ('zai_api_key','zai_model','zai_base_url')`
    ).all();
    const m = Object.fromEntries(rows.map(r => [r.key, (r.value || '').trim()]));
    key     = m.zai_api_key   || null;
    model   = m.zai_model     || DEFAULT_MODEL;
    baseUrl = m.zai_base_url  || DEFAULT_BASE_URL;
  } catch (_) { /* settings unreadable → treated as unconfigured */ }
  return { key, model, baseUrl, configured: !!key };
}

/**
 * One chat completion. Never throws.
 * @param {Array<{role:string,content:string}>} messages
 * @param {object} [opts]  { maxTokens?, temperature? }
 * @returns {Promise<{ok:true,text:string,model:string}|{ok:false,error:string,unconfigured?:true}>}
 */
async function callAi(messages, opts = {}) {
  const { key, model, baseUrl, configured } = getAiConfig();
  if (!configured) {
    return { ok: false, unconfigured: true,
      error: 'الذكاء الاصطناعي مش متظبط — حط مفتاح z.ai في الإعدادات → API' };
  }
  try {
    const res = await fetch(baseUrl, {
      method: 'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${key}`,
      },
      body: JSON.stringify({
        model,
        messages,
        temperature: opts.temperature ?? 0.4,
        max_tokens:  opts.maxTokens ?? 500,
      }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      console.error(`[ai] HTTP ${res.status}: ${text.slice(0, 300)}`);
      return { ok: false, error: `مزوّد الذكاء الاصطناعي رفض الطلب (HTTP ${res.status}) — راجع المفتاح واسم الموديل في الإعدادات` };
    }
    const json = await res.json().catch(() => null);
    const text = json?.choices?.[0]?.message?.content;
    if (!text || typeof text !== 'string') {
      return { ok: false, error: 'رد غير متوقع من مزوّد الذكاء الاصطناعي' };
    }
    return { ok: true, text: text.trim(), model };
  } catch (err) {
    const msg = err?.name === 'TimeoutError'
      ? 'مزوّد الذكاء الاصطناعي بطيء جداً — حاول تاني'
      : `تعذّر الاتصال بمزوّد الذكاء الاصطناعي: ${err.message}`;
    console.error(`[ai] ${err.message}`);
    return { ok: false, error: msg };
  }
}

/** Pull the first JSON object out of a model reply (handles ```json fences and
 *  surrounding chatter). Returns null when nothing parseable is found. */
function extractJson(text) {
  if (!text) return null;
  const cleaned = text.replace(/```(?:json)?/gi, '');
  const start = cleaned.indexOf('{');
  const end   = cleaned.lastIndexOf('}');
  if (start === -1 || end <= start) return null;
  try { return JSON.parse(cleaned.slice(start, end + 1)); } catch (_) { return null; }
}

module.exports = { callAi, getAiConfig, extractJson };
