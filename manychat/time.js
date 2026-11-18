// manychat/time.js — ManyChat timestamps → ms. Pure.
// Only a value that carries its own offset (Z or ±HH:MM) is readable; a value
// with no offset, or one Date.parse can't read, is missing (never assumed UTC).
function parseWithOffset(v) {
  if (typeof v !== 'string') return null;
  const s = v.trim();
  if (!/(Z|[+-]\d\d:?\d\d)$/i.test(s)) return null;
  const ms = Date.parse(s);
  return Number.isFinite(ms) ? ms : null;
}
module.exports = { parseWithOffset };
