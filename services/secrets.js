// services/secrets.js — which `settings` rows are secrets, and how they are
// shown (phase 0, 2026-11-22).
//
// A secret row's value never leaves the server: GET /api/settings answers a
// mask instead, PUT /api/settings/:key ignores a mask sent back unchanged, the
// demo DB holds none (scrubSettingsSecrets), and the SQL readers can't open
// the settings table at all (services/sqlGuard.js).
//
// Pure module: no DB handle of its own, no network.

// Every key that holds a credential today, plus any future key that looks
// like one (…_key, …secret…, …token…, …password…). Matching by pattern keeps
// a key added later safe by default.
const SECRET_KEYS = new Set([
  'manychat_api_key', 'openai_api_key', 'zai_api_key',
  'webhook_secret', 'jwt_secret', 'meta_capi_token', 'meta_access_token',
]);
const SECRET_RE = /(_key$|secret|token|password|passwd)/i;

function isSecretSettingKey(key) {
  const k = String(key || '');
  return SECRET_KEYS.has(k) || SECRET_RE.test(k);
}

// Never returned by any route, not even masked (the session signing key when
// JWT_SECRET is not set in the environment).
const NEVER_LISTED = new Set(['jwt_secret']);

// The mask the portal's key fields receive for a key that is set. It starts
// with a character no real key contains, so a mask sent back unchanged (the
// admin pressed save without typing) is recognised and ignored.
const MASK = '••••••••';
function maskSecret(value) {
  const v = value == null ? '' : String(value);
  if (!v.trim()) return '';
  // The last 4 only for long values (a real API key), so the owner can tell
  // which key is in; short values show the mask alone.
  return v.length >= 16 ? `${MASK}${v.slice(-4)}` : MASK;
}
function isMask(value) {
  return typeof value === 'string' && value.startsWith('••••');
}

// GET /api/settings body: every row, secrets masked, jwt_secret left out.
function settingsForClient(rows) {
  const out = {};
  for (const r of rows || []) {
    if (NEVER_LISTED.has(r.key)) continue;
    out[r.key] = isSecretSettingKey(r.key) ? maskSecret(r.value) : r.value;
  }
  return out;
}

// Blanks every secret row in a DB handle (the demo clone). Returns how many
// rows held a value. The rows stay (empty), so code that reads them sees
// "not configured" — never a live credential.
function scrubSettingsSecrets(db) {
  const rows = db.prepare(`SELECT key, value FROM settings`).all();
  const upd = db.prepare(`UPDATE settings SET value = '', updated_at = datetime('now') WHERE key = ?`);
  let n = 0;
  db.transaction(() => {
    for (const r of rows) {
      if (!isSecretSettingKey(r.key)) continue;
      if (r.value != null && String(r.value) !== '') { upd.run(r.key); n++; }
    }
  })();
  return n;
}

module.exports = { isSecretSettingKey, maskSecret, isMask, settingsForClient, scrubSettingsSecrets, MASK, NEVER_LISTED };
