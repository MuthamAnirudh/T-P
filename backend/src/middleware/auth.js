const { verifyAccessToken } = require('../auth');

function getBearerToken(req) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');
  if (scheme === 'Bearer' && token) return token;
  return null;
}

// Rejects the request with 401 if there's no valid access token.
function requireAuth(req, res, next) {
  const token = getBearerToken(req);
  if (!token) return res.status(401).json({ error: 'Not authenticated. Log in and try again.' });
  try {
    req.user = verifyAccessToken(token);
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Session expired. Please log in again.', code: 'TOKEN_EXPIRED' });
  }
}

// Attaches req.user if a valid token is present, but never blocks the request — used for
// endpoints that behave slightly differently for logged-in users (e.g. peer benchmarking
// can optionally exclude the requester's own past attempts) without requiring an account.
function optionalAuth(req, res, next) {
  const token = getBearerToken(req);
  if (token) {
    try {
      req.user = verifyAccessToken(token);
    } catch (_) {
      /* ignore — treated as anonymous */
    }
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'ADMIN') {
    return res.status(403).json({ error: 'Admin access required.' });
  }
  next();
}

module.exports = { requireAuth, optionalAuth, requireAdmin };
