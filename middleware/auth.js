// middleware/auth.js — JWT authentication middleware

const jwt    = require('jsonwebtoken');
const crypto = require('crypto');
const { getLiveDb, getDemoDb, runWithDbContext } = require('../db');

// ── Secret resolution (free, no env var required) ──────────────────────────
// Priority: process.env.JWT_SECRET  →  persistent random secret in DB settings.
// The DB-stored secret is generated once and survives as long as the DB does,
// so tokens stay valid without any hardcoded fallback. Always the LIVE DB's
// row (the demo clone's copy is blanked), whatever context the caller is in.
let _cachedSecret = null;

function getJwtSecret() {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
  if (_cachedSecret) return _cachedSecret;

  const db  = getLiveDb();
  const row = db.prepare(`SELECT value FROM settings WHERE key = 'jwt_secret'`).get();
  if (row && row.value) {
    _cachedSecret = row.value;
    return _cachedSecret;
  }

  const generated = crypto.randomBytes(48).toString('hex');
  db.prepare(`
    INSERT INTO settings (key, value, updated_at)
    VALUES ('jwt_secret', ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `).run(generated);
  _cachedSecret = generated;
  console.log('🔐 Generated persistent JWT secret (stored in settings)');
  return _cachedSecret;
}

// ── Which DB a session belongs to (phase 0 r2, 2026-11-22) ─────────────────
// r4 (2026-11-22): the demo sandbox is REMOVED (owner) — only ctx 'live' is
// signed or accepted now; the history below explains why the claim exists.
// The context is a SIGNED claim, set by the DB that checked the password at
// login: ctx 'live' | 'demo'. It used to be read from the token's name
// (demo_… → sandbox), and a sandbox admin could give a cloned live account a
// demo_ email, log in through the sandbox and hold a token the server took as
// live. Now:
//   • a demo token is signed with a key derived from the secret
//     (HMAC(secret, 'demo')): it never verifies as live, a live token never
//     verifies as demo;
//   • requireAuth routes on the verified claim only — never on a name;
//   • r3: a token with no ctx claim (made before r2 — possibly through the old
//     demo hole, which signed sandbox logins with the live key) is 401, always.
function demoJwtKey() {
  return crypto.createHmac('sha256', getJwtSecret()).update('demo').digest('hex');
}
const TOKEN_TTL = '7d';
const ALGS = ['HS256'];

// The ONLY way a session token is made. ctx = the DB that authenticated it.
// payload.tv = the account's users.token_version (phase 0 r4).
function signSessionToken(payload, ctx) {
  if (ctx !== 'live') throw new Error('signSessionToken: only live sessions (the demo sandbox is removed)');
  const key = ctx === 'demo' ? demoJwtKey() : getJwtSecret();
  return jwt.sign({ ...payload, ctx }, key, { expiresIn: TOKEN_TTL, algorithm: 'HS256' });
}

// → { user, ctx } or null. Only a signed ctx claim counts (phase 0 r3): a
// token without one is refused — the client logs out and the next login signs
// a claim. Phase 0 r4: the demo sandbox is removed (owner, 2026-11-22), so a
// ctx 'demo' token — under either key — is refused too: no request ever runs
// in the demo context again.
function verifySessionToken(token) {
  try {
    const p = jwt.verify(token, getJwtSecret(), { algorithms: ALGS });
    if (p && p.ctx === 'live') return { user: p, ctx: 'live' };
    return null;   // the live key never signs a demo claim, and no-claim tokens are dead
  } catch (_) { /* not a live token */ }
  return null;     // a demo-key token (the old sandbox) is dead
}

// ── One-time key rotation (phase 0 r3, 2026-11-22) ──────────────────────────
// Before r2 a sandbox login was signed with the LIVE key, so a token minted
// through the old demo hole may still be out there. When the key lives in the
// DB (JWT_SECRET not set in the environment), the first boot of this version
// replaces it with a fresh random one and records settings
// jwt_rotated_phase0 = '1', so it happens ONCE: every session from before is
// dead (one login each), later boots keep the key. The value is never logged
// or returned. With JWT_SECRET in the environment nothing here runs (the
// no-claim tokens are refused by verifySessionToken anyway).
const ROTATED_FLAG = 'jwt_rotated_phase0';
function rotateJwtSecretOnce() {
  if (process.env.JWT_SECRET) return false;
  const db = getLiveDb();
  const done = db.prepare(`SELECT value FROM settings WHERE key = ?`).get(ROTATED_FLAG);
  if (done && done.value === '1') return false;
  const fresh = crypto.randomBytes(48).toString('hex');
  const up = db.prepare(`
    INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
  `);
  db.transaction(() => { up.run('jwt_secret', fresh); up.run(ROTATED_FLAG, '1'); })();
  _cachedSecret = fresh;
  return true;
}
// /health: has the one-time rotation happened on this DB? (a boolean)
function jwtRotated() {
  try {
    const row = getLiveDb().prepare(`SELECT value FROM settings WHERE key = ?`).get(ROTATED_FLAG);
    return !!(row && row.value === '1');
  } catch (_) { return false; }
}

/**
 * requireAuth — verifies Bearer token in Authorization header.
 * Attaches decoded payload to req.user on success.
 */
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const v = verifySessionToken(token);
  if (!v || v.user == null || v.user.id == null) {
    return res.status(401).json({ error: 'Token expired or invalid' });
  }
  req.user = v.user;
  const isDemo = v.ctx === 'demo';

  // The rest of this request runs on the DB the verified claim names.
  return runWithDbContext(isDemo, () => {
    // Honor account suspension IMMEDIATELY — even with a still-valid 7-day JWT.
    // The token is signed at login, so an admin who freezes an account can't wait
    // for it to expire; we re-check the live `active` flag on every request and
    // reject (401, so the client logs the user straight out) the moment it's 0.
    let row;
    try {
      const db = isDemo ? getDemoDb() : getLiveDb();
      row = db.prepare('SELECT id, active, name, role, branch, token_version, demo_account FROM users WHERE id = ?').get(req.user.id);
    } catch (_) {
      // A lookup failure must never lock everyone out — fail open on errors
      // only, and only for a token that carries the signed live claim. A
      // sandbox one must prove its row: 401.
      if (!isDemo) return next();
      return res.status(401).json({ error: 'بيانات الحساب اتغيّرت — سجّل دخول تاني' });
    }
    if (row && row.active === 0) {
      return res.status(401).json({ error: 'الحساب موقوف — تواصل مع مدير النظام', suspended: true });
    }
    // Same for a renamed or deleted account: writes stamp rows with req.user.name,
    // and a rename / delete frees that name for another account at once — a stale
    // token must not keep acting under it for 7 days. 401 → the client logs out,
    // and the next login signs the current name.
    if (!row || row.name !== req.user.name) {
      return res.status(401).json({ error: 'بيانات الحساب اتغيّرت — سجّل دخول تاني' });
    }
    // Phase 0 r4: the session follows the user row. Every route reads the
    // role and branch from the token (req.user), so a demoted / moved account
    // must not keep its old powers for 7 days: a token whose role or branch
    // differs from the row, or whose tv (users.token_version — bumped by a
    // trigger on any password / role / branch / active change, db.js) is older
    // than the row's, is 401 → the next login signs the current values. A
    // token without tv counts as 0 (nobody is logged out by this alone).
    const tokTv = Number.isInteger(req.user.tv) ? req.user.tv : 0;
    if (row.role !== req.user.role
        || (row.branch || null) !== (req.user.branch || null)
        || (row.token_version ?? 0) !== tokTv) {
      return res.status(401).json({ error: 'بيانات الحساب اتغيّرت — سجّل دخول تاني' });
    }
    // A sandbox session belongs to a training account made by «generate demo
    // accounts» only — never to a cloned copy of a live account.
    if (isDemo && row.demo_account !== 1) {
      return res.status(401).json({ error: 'بيانات الحساب اتغيّرت — سجّل دخول تاني' });
    }
    return next();
  });
}

/**
 * requireRole(role) — must be used after requireAuth.
 * Returns 403 if the authenticated user does not have the expected role.
 */
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}

/**
 * authorizeRoles(...roles) — variadic version of requireRole.
 * Accepts one or more allowed roles. Must be used after requireAuth.
 * Returns 403 if the user's role is not in the allowed list.
 *
 * Usage: app.get('/route', requireAuth, authorizeRoles('admin', 'manager'), handler)
 */
function authorizeRoles(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden — insufficient role' });
    }
    next();
  };
}

module.exports = { requireAuth, requireRole, authorizeRoles, getJwtSecret, signSessionToken, verifySessionToken,
                   rotateJwtSecretOnce, jwtRotated, ROTATED_FLAG };
