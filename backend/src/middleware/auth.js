import { verifyUserToken } from '../services/supabaseClient.js';

/**
 * Extract the Bearer token from the Authorization header
 */
function extractBearerToken(req) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || typeof authHeader !== 'string') {
    return null;
  }

  const parts = authHeader.trim().split(' ');
  if (parts.length === 2 && parts[0].toLowerCase() === 'bearer') {
    return parts[1];
  }

  return null;
}

/**
 * Middleware: Requires a valid Supabase JWT token.
 * Extracts user_id server-side from verified token.
 * Returns 401 if missing or invalid.
 */
export async function requireAuth(req, res, next) {
  const token = extractBearerToken(req);

  if (!token) {
    return res.status(401).json({
      error: 'Authentication required. Missing Bearer token in Authorization header.',
      code: 'AUTH_REQUIRED'
    });
  }

  try {
    const user = await verifyUserToken(token);
    if (!user || !user.id) {
      return res.status(401).json({
        error: 'Invalid authentication credentials.',
        code: 'INVALID_TOKEN'
      });
    }

    // Attach verified user to request
    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({
      error: err.message || 'Authentication failed or token has expired.',
      code: 'AUTH_FAILED'
    });
  }
}

/**
 * Middleware: Optional authentication.
 * If token is present, verifies and attaches req.user.
 * If token is absent, sets req.user = null and continues without error.
 */
export async function optionalAuth(req, res, next) {
  const token = extractBearerToken(req);

  if (!token) {
    req.user = null;
    return next();
  }

  try {
    const user = await verifyUserToken(token);
    req.user = user;
    next();
  } catch (err) {
    // If a token was provided but failed verification, return 401
    return res.status(401).json({
      error: 'Provided authentication token is invalid or expired.',
      code: 'INVALID_TOKEN'
    });
  }
}
