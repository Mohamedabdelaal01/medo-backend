// services/ai.js — GLM (z.ai) client for the CRM's AI features.
//
// SAFETY CONTRACT (mirrors metaCapi.js):
//   - callAi() NEVER throws — it resolves { ok, text | error } always.
//   - Hard timeout so a slow provider can never hang a request.
//   - All config lives in `settings` (admin-editable, no redeploy needed):
//       zai_api_key   — required; empty = AI features respond "مش متظبط"
//       zai_model     — default 'glm-4.7-flash' (free tier; change to any z.ai model id)
//       zai_base_url  — default z.ai OpenAI-compatible chat endpoint
//
// GLM's API is OpenAI-compatible (messages / choices), so swapping providers
// later means changing two settings, not code.

const { getDb } = require('../db');

const DEFAULT_BASE_URL = 'https://api.z.ai/api/paas/v4/chat/completions';
const DEFAULT_MODEL    = 'glm-4.7-flash'; // free tier on z.ai
const TIMEOUT_MS       = 45000; // thinking is enabled by default — verified up to ~17s for a short reply

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
 * @param {Array<object>} messages
 * @param {object} [opts]  { maxTokens?, temperature?, thinking?, tools?, toolChoice?, timeoutMs? }
 *   thinking defaults to ON (glm-4.7-flash is free — the user wants full
 *   reasoning always; empirically verified 2000 max_tokens comfortably covers
 *   reasoning + a real answer for our prompt sizes, ~17s typical latency).
 *   Pass tools (OpenAI-style function definitions) to enable tool-calling —
 *   the reply may come back as toolCalls instead of / alongside text.
 * @returns {Promise<{ok:true,text:string,toolCalls:Array|null,model:string}|{ok:false,error:string,unconfigured?:true}>}
 */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function callAi(messages, opts = {}) {
  const { key, model, baseUrl, configured } = getAiConfig();
  if (!configured) {
    return { ok: false, unconfigured: true,
      error: 'الذكاء الاصطناعي مش متظبط — حط مفتاح z.ai في الإعدادات → API' };
  }
  const body = {
    model,
    messages,
    temperature: opts.temperature ?? 0.4,
    max_tokens:  opts.maxTokens ?? 2000,
    thinking: { type: opts.thinking === false ? 'disabled' : 'enabled' },
  };
  if (opts.tools) {
    body.tools = opts.tools;
    body.tool_choice = opts.toolChoice ?? 'auto';
  }

  // The free tier rate-limits (429) and occasionally 500s under bursty load —
  // both transient, so retry those a couple of times with backoff. A client
  // timeout is NOT retried: a slow/hung request is likely to hang again, and
  // doubling the wait doesn't help the caller.
  const maxAttempts = opts.retries ?? 3;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const res = await fetch(baseUrl, {
        method: 'POST',
        headers: {
          'Content-Type':  'application/json',
          'Authorization': `Bearer ${key}`,
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(opts.timeoutMs ?? TIMEOUT_MS),
      });
      if (!res.ok) {
        const text = await res.text().catch(() => '');
        console.error(`[ai] HTTP ${res.status} (attempt ${attempt}/${maxAttempts}): ${text.slice(0, 300)}`);
        if ((res.status === 429 || res.status >= 500) && attempt < maxAttempts) {
          await sleep(attempt * 4000);
          continue;
        }
        return { ok: false, error: `مزوّد الذكاء الاصطناعي رفض الطلب (HTTP ${res.status}) — راجع المفتاح واسم الموديل في الإعدادات` };
      }
      const json    = await res.json().catch(() => null);
      const msg     = json?.choices?.[0]?.message;
      const toolCalls = msg?.tool_calls?.length ? msg.tool_calls : null;
      const text    = msg?.content;
      // When the model requests a tool call, `content` is legitimately empty —
      // only treat empty content as an error when there's no tool call either.
      if (!toolCalls && (!text || typeof text !== 'string')) {
        return { ok: false, error: 'رد غير متوقع من مزوّد الذكاء الاصطناعي' };
      }
      return { ok: true, text: (text || '').trim(), toolCalls, model };
    } catch (err) {
      const msg = err?.name === 'TimeoutError'
        ? 'مزوّد الذكاء الاصطناعي بطيء جداً — حاول تاني'
        : `تعذّر الاتصال بمزوّد الذكاء الاصطناعي: ${err.message}`;
      console.error(`[ai] ${err.message}`);
      return { ok: false, error: msg };
    }
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
