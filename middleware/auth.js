// middleware/auth.js — JWT authentication middleware

const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'gf-dev-secret-2025';

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
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Token expired or invalid' });
  }
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

module.exports = { requireAuth, requireRole, authorizeRoles, JWT_SECRET };
