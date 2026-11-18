// services/phoneMask.js — phone masking for every z.ai call (C1.11). Pure, no I/O.
//
// createPhoneMasker() → { maskText, maskMessages, unmaskText, unmaskSql, count }
//
// A masker swaps each phone it sees for a token ⟨phone:N…XY⟩ (N = its number in
// THIS masker, XY = the phone's last 2 digits) and keeps the phone ↔ token map
// in memory for its own life only — never logged, never stored. The same phone
// always gets the same token inside one masker; a new masker numbers from 1.
// The admin AI chat owns ONE masker per HTTP request (all its tool rounds); a
// single callAi() without one makes its own.
//
// What counts as a phone — SHAPES only, so ids survive:
//   • Egyptian mobiles 01[0125] + 8 digits;
//   • the same with the country code (+20 / 0020 / 20) and no leading 0;
//   • landlines 0[2-9] + 7–8 digits (Cairo 02 + 8);
//   • a bare 10-digit 1[0125] + 8 (a mobile typed without its 0) ONLY in typed
//     text (last_input_text, notes, call summaries) and phone-named columns —
//     elsewhere a 10-digit ManyChat contact id can look the same.
// Digits may be Western, Arabic-Indic (٠–٩) or Persian (۰–۹). Between two
// digits up to 3 separator characters are allowed: spaces (incl. NBSP and the
// other Unicode spaces), zero-width characters / direction marks, - . / ( )
// and the Arabic comma «،» — so «(010) 1234 5678», «010 - 1234 - 5678» and
// «(+20) 1012345678» match. A newline or a Latin comma is not a separator.
// A match never touches another digit or a Latin letter on either side (a
// 9-digit contact id, a 17-digit PSID, an 18-digit ad id or a dataset id
// never matches).
'use strict';

const AR = '٠-٩';
const FA = '۰-۹';
const ANY_DIGIT = `[0-9${AR}${FA}]`;
// A class for the given Western digits plus their Arabic-Indic / Persian twins.
function D(digits) {
  let out = '';
  for (const ch of digits) {
    const n = ch.charCodeAt(0) - 48;
    out += ch + String.fromCharCode(0x0660 + n) + String.fromCharCode(0x06F0 + n);
  }
  return `[${out}]`;
}
function R(lo, hi) { // a digit range, e.g. R(2, 9) → [2-9٢-٩۲-۹]
  return `[${lo}-${hi}${String.fromCharCode(0x0660 + lo)}-${String.fromCharCode(0x0660 + hi)}` +
         `${String.fromCharCode(0x06F0 + lo)}-${String.fromCharCode(0x06F0 + hi)}]`;
}
// up to 3 separators between digits (review r2)
const SEP_CHARS = ' \\t\\u00A0\\u1680\\u2000-\\u200F\\u2028\\u2029\\u202A-\\u202F\\u205F\\u2060\\u3000\\uFEFF\\-./()\\u060C';
const S  = `[${SEP_CHARS}]{0,3}`;
const NB = `(?<![0-9${AR}${FA}A-Za-z])`;       // not touching a digit / Latin letter before
const NA = `(?![0-9${AR}${FA}A-Za-z])`;        // … or after
const REST8 = `(?:${S}${ANY_DIGIT}){8}`;

const P_INTL   = `(?:\\+${S}|${D('0')}${S}${D('0')}${S})?${S}${D('2')}${S}${D('0')}${S}${D('1')}${S}${D('0125')}${REST8}`;
const P_MOBILE = `${D('0')}${S}${D('1')}${S}${D('0125')}${REST8}`;
const P_LAND   = `${D('0')}${S}${R(2, 9)}(?:${S}${ANY_DIGIT}){7,8}`;
const P_BARE   = `${D('1')}${S}${D('0125')}${REST8}`;

const RE_SHAPE = new RegExp(`${NB}(?:${P_INTL}|${P_MOBILE}|${P_LAND})${NA}`, 'g');
const RE_SHAPE_TYPED = new RegExp(`${NB}(?:${P_INTL}|${P_MOBILE}|${P_LAND}|${P_BARE})${NA}`, 'g');
const RE_TOKEN = /[⟨<]phone:(\d+)(?:…|\.\.\.)(\d{2})[⟩>]/g;

function westernDigits(s) {
  return String(s).replace(/[٠-٩]/g, c => String(c.charCodeAt(0) - 0x0660))
                  .replace(/[۰-۹]/g, c => String(c.charCodeAt(0) - 0x06F0));
}
// The canonical local form — the same rules as server.js normalizePhone, after
// turning Arabic-Indic / Persian digits into Western ones.
function canonPhone(raw) {
  let d = westernDigits(raw).replace(/\D/g, '');
  if (!d) return null;
  d = d.replace(/^00/, '');
  if (d.startsWith('20') && d.length >= 11) d = d.slice(2);
  if (d.length === 10 && d[0] !== '0') d = '0' + d;
  return d;
}
// A whole cell of a phone-named column is a phone when it normalizes to a
// mobile (01 + 9 digits) or a landline shape.
function isWholePhone(value) {
  if (typeof value !== 'string' || !value.trim()) return false;
  const c = canonPhone(value);
  return !!c && (/^01\d{9}$/.test(c) || /^0[2-9]\d{7,8}$/.test(c));
}

const ID_COL     = (c) => c === 'id' || c === 'user_id' || c.endsWith('_id');
const PHONE_COL  = (c) => c.includes('phone');
const TYPED_COL  = (c) => c === 'last_input_text' || c === 'call_summary' || /(^|_)notes?$/.test(c) ||
                          c.endsWith('_note') || c.endsWith('_summary');
const JSON_COL   = (c) => c === 'raw_payload' || c === 'extra_fields';

function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

function createPhoneMasker() {
  const byCanon = new Map(); // canon → entry
  const byN = new Map();     // n → entry
  let replaced = 0;

  function entryFor(raw, { fromCell = false } = {}) {
    const canon = canonPhone(raw);
    if (!canon) return null;
    let e = byCanon.get(canon);
    if (!e) {
      const n = byN.size + 1;
      e = { n, canon, last2: canon.slice(-2), stored: canon, fromCell: false, forms: new Set([canon]) };
      byCanon.set(canon, e); byN.set(n, e);
    }
    if (fromCell && !e.fromCell) { e.stored = String(raw); e.fromCell = true; }
    e.forms.add(String(raw));
    return e;
  }
  const tokenOf = (e) => `⟨phone:${e.n}…${e.last2}⟩`;

  // Shape pass, then the known-phone pass.
  function maskText(text, { typed = false } = {}) {
    if (typeof text !== 'string' || !text) return text;
    const re = typed ? RE_SHAPE_TYPED : RE_SHAPE;
    let out = text.replace(re, (m) => {
      const e = entryFor(m);
      if (!e) return m;
      replaced++;
      return tokenOf(e);
    });
    return knownPass(out);
  }

  // A phone already in the map, in any form it was seen in, wherever it still
  // appears — only forms of 9+ digits, never touching another digit.
  function knownPass(text) {
    if (typeof text !== 'string' || !text || !byCanon.size) return text;
    let out = text;
    for (const e of byCanon.values()) {
      for (const form of e.forms) {
        if (westernDigits(form).replace(/\D/g, '').length < 9) continue;
        const re = new RegExp(`(?<![0-9${AR}${FA}])${escapeRe(form)}(?![0-9${AR}${FA}])`, 'g');
        out = out.replace(re, () => { replaced++; return tokenOf(e); });
      }
    }
    return out;
  }

  function maskCell(col, value) {
    const c = String(col || '').toLowerCase();
    if (ID_COL(c)) return value;
    // A NUMBER under a phone-named column is a phone only when its digits are
    // one (review r2) — counts like phone_count 42 / users_with_phone stay.
    if (typeof value === 'number' && PHONE_COL(c) && Number.isInteger(value) && isWholePhone(String(value))) {
      const e = entryFor(String(value)); replaced++; return tokenOf(e);
    }
    if (typeof value !== 'string') return value;   // other numbers, booleans, NULL: never masked
    if (PHONE_COL(c)) {
      if (isWholePhone(value)) { const e = entryFor(value, { fromCell: true }); replaced++; return tokenOf(e); }
      return maskText(value, { typed: true });
    }
    if (JSON_COL(c)) {
      let parsed;
      try { parsed = JSON.parse(value); } catch (_) { parsed = undefined; }
      if (parsed && typeof parsed === 'object') return JSON.stringify(maskJson(parsed));
      return maskText(value);
    }
    if (TYPED_COL(c)) return maskText(value, { typed: true });
    return maskText(value);
  }

  function maskJson(v, key = '') {
    if (Array.isArray(v)) return v.map(x => maskJson(x, key));
    if (v && typeof v === 'object') {
      const o = {};
      for (const [k, x] of Object.entries(v)) {
        o[k] = (x && typeof x === 'object') ? maskJson(x, k) : maskCell(k, x);
      }
      return o;
    }
    return maskCell(key, v);
  }

  // A role:'tool' message: its JSON's rows masked by column, everything else by
  // shape; not JSON → text. The known-phone pass runs per string cell (inside
  // maskText), never over id columns — a 10-digit user_id that has the same
  // digits as a phone typed without its 0 stays as it is.
  function maskToolContent(content) {
    if (typeof content !== 'string') return content;
    let parsed;
    try { parsed = JSON.parse(content); } catch (_) { return maskText(content); }
    if (!parsed || typeof parsed !== 'object') return maskText(content);
    const out = Array.isArray(parsed) ? parsed.map(r => maskRow(r)) : {};
    if (!Array.isArray(parsed)) {
      for (const [k, v] of Object.entries(parsed)) {
        if (k === 'rows' && Array.isArray(v)) out.rows = v.map(r => maskRow(r));
        else if (typeof v === 'string') out[k] = maskText(v);
        else if (v && typeof v === 'object') out[k] = maskJson(v, k);
        else out[k] = v;
      }
    }
    return JSON.stringify(out);
  }
  function maskRow(r) {
    if (!r || typeof r !== 'object' || Array.isArray(r)) return maskJson(r);
    const o = {};
    for (const [k, v] of Object.entries(r)) o[k] = (v && typeof v === 'object') ? maskJson(v, k) : maskCell(k, v);
    return o;
  }

  // A masked COPY — the caller's array and objects are not changed.
  function maskMessages(messages) {
    if (!Array.isArray(messages)) return messages;
    return messages.map((m) => {
      if (!m || typeof m !== 'object') return m;
      const c = { ...m };
      if (m.role === 'tool') c.content = maskToolContent(m.content);
      else if (typeof m.content === 'string') c.content = maskText(m.content, { typed: m.role === 'user' });
      if (Array.isArray(m.tool_calls)) {
        c.tool_calls = m.tool_calls.map((t) => {
          if (!t || !t.function || typeof t.function.arguments !== 'string') return t;
          return { ...t, function: { ...t.function, arguments: maskText(t.function.arguments) } };
        });
      }
      return c;
    });
  }

  // Tokens back to phones (the stored form). An unknown token stays as it is.
  function unmaskText(text) {
    if (typeof text !== 'string' || !text) return text;
    return text.replace(RE_TOKEN, (m, n, xy) => {
      const e = byN.get(Number(n));
      return e && e.last2 === xy ? e.stored : m;
    });
  }

  // The model's SQL: every token must be one this masker gave out (N known AND
  // XY matching) — otherwise the SQL is not run. A token becomes the CANONICAL
  // form (01XXXXXXXXX / 0XXXXXXXXX) — what normalizePhone writes in the tables —
  // never the raw form it was first seen in (review r2).
  function unmaskSql(sql) {
    if (typeof sql !== 'string') return { ok: true, sql };
    let bad = false;
    const out = sql.replace(RE_TOKEN, (m, n, xy) => {
      const e = byN.get(Number(n));
      if (!e || e.last2 !== xy) { bad = true; return m; }
      return e.canon;
    });
    return bad ? { ok: false, sql: null, error: 'unknown_phone_token' } : { ok: true, sql: out };
  }

  return { maskText, maskMessages, unmaskText, unmaskSql, count: () => replaced };
}

module.exports = { createPhoneMasker, canonPhone };
