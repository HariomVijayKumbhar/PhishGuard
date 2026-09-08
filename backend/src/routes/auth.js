import express from 'express';
import rateLimit from 'express-rate-limit';
import { signUpUser, signInUser } from '../services/supabaseClient.js';
import { requireAuth } from '../middleware/auth.js';

const router = express.Router();

// Rate limiter for authentication routes (Brute force protection)
const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30, // Limit each IP to 30 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many authentication attempts from this IP. Please try again after 15 minutes.',
    code: 'AUTH_RATE_LIMIT_EXCEEDED'
  }
});

router.use(authRateLimiter);

/**
 * Helper to validate email format
 */
function isValidEmail(email) {
  if (!email || typeof email !== 'string') return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

/**
 * POST /api/auth/register
 * Body: { email, password }
 */
router.post('/register', async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !isValidEmail(email)) {
    return res.status(400).json({
      error: 'Please provide a valid email address.',
      code: 'INVALID_EMAIL'
    });
  }

  if (!password || typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({
      error: 'Password must be at least 8 characters long.',
      code: 'WEAK_PASSWORD'
    });
  }

  try {
    const { user, session } = await signUpUser({ email: email.trim().toLowerCase(), password });

    return res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: {
        id: user.id,
        email: user.email,
        created_at: user.created_at
      },
      token: session?.access_token || null
    });
  } catch (err) {
    const isDuplicate = err.message?.toLowerCase().includes('already') || err.message?.toLowerCase().includes('duplicate');
    const statusCode = isDuplicate ? 409 : 400;

    return res.status(statusCode).json({
      error: err.message || 'Registration failed',
      code: isDuplicate ? 'USER_ALREADY_EXISTS' : 'REGISTRATION_FAILED'
    });
  }
});

/**
 * POST /api/auth/login
 * Body: { email, password }
 */
router.post('/login', async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({
      error: 'Email and password are required.',
      code: 'MISSING_CREDENTIALS'
    });
  }

  try {
    const { user, session } = await signInUser({ email: email.trim().toLowerCase(), password });

    return res.status(200).json({
      success: true,
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        created_at: user.created_at
      },
      token: session?.access_token || null
    });
  } catch (err) {
    return res.status(401).json({
      error: err.message || 'Invalid email or password',
      code: 'INVALID_CREDENTIALS'
    });
  }
});

/**
 * GET /api/auth/me
 * Headers: Authorization: Bearer <token>
 */
router.get('/me', requireAuth, (req, res) => {
  return res.status(200).json({
    success: true,
    user: {
      id: req.user.id,
      email: req.user.email,
      created_at: req.user.created_at
    }
  });
});

/**
 * POST /api/auth/logout
 */
router.post('/logout', (req, res) => {
  return res.status(200).json({
    success: true,
    message: 'Logged out successfully'
  });
});

export default router;
