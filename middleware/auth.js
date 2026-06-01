// middleware/auth.js — JWT authentication middleware

const jwt    = require('jsonwebtoken');
const crypto = require('crypto');
const { getDb, runWithDbContext } = require('../db');

// ── Secret resolution (free, no env var required) ──────────────────────────
// Priority: process.env.JWT_SECRET  →  persistent random secret in DB settings.
// The DB-stored secret is generated once and survives as long as the DB does,
// so tokens stay valid without any hardcoded fallback.
let _cachedSecret = null;

function getJwtSecret() {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
  if (_cachedSecret) return _cachedSecret;

  const db  = getDb();
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

  try {
    req.user = jwt.verify(token, getJwtSecret());
  } catch {
    return res.status(401).json({ error: 'Token expired or invalid' });
  }

  // Route the rest of this request to the sandbox DB for demo_ training
  // accounts; everything else stays on production.
  const isDemo = typeof req.user?.name === 'string' && req.user.name.startsWith('demo_');
  return runWithDbContext(isDemo, () => {
    // Honor account suspension IMMEDIATELY — even with a still-valid 7-day JWT.
    // The token is signed at login, so an admin who freezes an account can't wait
    // for it to expire; we re-check the live `active` flag on every request and
    // reject (401, so the client logs the user straight out) the moment it's 0.
    try {
      const db  = getDb();
      const row = req.user?.id != null
        ? db.prepare('SELECT active FROM users WHERE id = ?').get(req.user.id)
        : db.prepare('SELECT active FROM users WHERE name = ?').get(req.user?.name);
      if (row && row.active === 0) {
        return res.status(401).json({ error: 'الحساب موقوف — تواصل مع مدير النظام', suspended: true });
      }
    } catch (_) {
      // A lookup failure must never lock everyone out — fail open on errors only.
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

module.exports = { requireAuth, requireRole, authorizeRoles, getJwtSecret };
