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
const { createPhoneMasker } = require('./phoneMask');
const { blockInDemo } = require('./outbound');

const DEFAULT_BASE_URL = 'https://api.z.ai/api/paas/v4/chat/completions';
const DEFAULT_MODEL    = 'glm-4.7-flash'; // free tier on z.ai
const TIMEOUT_MS       = 45000; // thinking is enabled by default — verified up to ~17s for a short reply

// zai_base_url may only point at z.ai's or BigModel's (Zhipu's) own API: the
// prompt (lead names, typed messages — phones masked) and the z.ai key are
// sent there, so an admin typo or a planted value must not redirect them
// (phase 0 r2). Matched on the parsed URL's origin: https, that exact host,
// default port, no user:password.
const ALLOWED_AI_ORIGINS = ['https://api.z.ai', 'https://open.bigmodel.cn'];
function isAllowedAiBaseUrl(raw) {
  let u;
  try { u = new URL(String(raw || '').trim()); } catch (_) { return false; }
  if (u.username || u.password) return false;
  return ALLOWED_AI_ORIGINS.includes(u.origin);
}

function getAiConfig() {
  let key = null, model = DEFAULT_MODEL, baseUrl = DEFAULT_BASE_URL;
  try {
    const rows = getDb().prepare(
      `SELECT key, value FROM settings WHERE key IN ('zai_api_key','zai_model','zai_base_url')`
    ).all();
    const m = Object.fromEntries(rows.map(r => [r.key, (r.value || '').trim()]));
    key     = m.zai_api_key   || null;
    model   = m.zai_model     || DEFAULT_MODEL;
    baseUrl = m.zai_base_url && isAllowedAiBaseUrl(m.zai_base_url) ? m.zai_base_url : DEFAULT_BASE_URL;
    if (m.zai_base_url && baseUrl === DEFAULT_BASE_URL && m.zai_base_url !== DEFAULT_BASE_URL) {
      console.warn('[ai] zai_base_url is not z.ai / bigmodel.cn — using the default');
    }
  } catch (_) { /* settings unreadable → treated as unconfigured */ }
  return { key, model, baseUrl, configured: !!key };
}

/**
 * One chat completion. Never throws.
 * @param {Array<object>} messages
 * @param {object} [opts]  { maxTokens?, temperature?, thinking?, tools?, toolChoice?, timeoutMs?, masker? }
 *   PHONES NEVER LEAVE (C1.11): every message is sent as a masked COPY (the
 *   caller's array is not changed) — phones become ⟨phone:N…XY⟩ tokens.
 *   With opts.masker (the admin chat: one masker per HTTP request, all its
 *   tool rounds) text/toolCalls come back exactly as the model wrote them
 *   (tokens) and the CALLER unmasks. Without one, callAi makes a per-call
 *   masker and returns text already unmasked through it.
 *   thinking defaults to ON (glm-4.7-flash is free — the user wants full
 *   reasoning always; empirically verified 2000 max_tokens comfortably covers
 *   reasoning + a real answer for our prompt sizes, ~17s typical latency).
 *   Pass tools (OpenAI-style function definitions) to enable tool-calling —
 *   the reply may come back as toolCalls instead of / alongside text.
 * @returns {Promise<{ok:true,text:string,toolCalls:Array|null,model:string}|{ok:false,error:string,unconfigured?:true}>}
 */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function callAi(messages, opts = {}) {
  // Phase 0: a demo_ session never reaches the AI provider (its DB is a clone
  // of production — names and typed messages would leave with the prompt).
  if (blockInDemo('ai')) {
    return { ok: false, unconfigured: true, error: 'وضع التدريب: الذكاء الاصطناعي مقفول هنا' };
  }
  const { key, model, baseUrl, configured } = getAiConfig();
  if (!configured) {
    return { ok: false, unconfigured: true,
      error: 'الذكاء الاصطناعي مش متظبط — حط مفتاح z.ai في الإعدادات → API' };
  }
  const ownMasker = !opts.masker;
  const masker = opts.masker || createPhoneMasker();
  const before = masker.count();
  const safeMessages = masker.maskMessages(messages);
  const maskedNow = masker.count() - before;
  if (maskedNow > 0) console.log(`[ai] masked: ${maskedNow}`);
  const body = {
    model,
    messages: safeMessages,
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
        // Phase 0 r3: never follow a redirect — the key and the prompt go to
        // the allow-listed host only, not wherever it points us.
        redirect: 'error',
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
      const outText = (text || '').trim();
      return { ok: true, text: ownMasker ? masker.unmaskText(outText) : outText, toolCalls, model };
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

module.exports = { callAi, getAiConfig, extractJson, isAllowedAiBaseUrl, ALLOWED_AI_ORIGINS };
