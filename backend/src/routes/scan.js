import express from 'express';
import multer from 'multer';
import rateLimit from 'express-rate-limit';
import { parseEmailInput, EmailParseError } from '../services/emailParser.js';
import { classifyEmailWithAI, AIClassificationError } from '../services/ai/aiService.js';
import { optionalAuth, requireAuth } from '../middleware/auth.js';
import {
  saveScanRecord,
  getUserScans,
  getScanById,
  getUserMetrics,
  isSupabaseConfigured
} from '../services/supabaseClient.js';

const router = express.Router();

// Rate limiter: 50 requests per 15 minutes per IP (disabled during automated testing)
const scanRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  skip: () => process.env.NODE_ENV === 'test',
  message: {
    error: 'Rate limit exceeded: maximum 50 scan requests allowed per 15 minutes per IP address',
    code: 'RATE_LIMIT_EXCEEDED'
  }
});

// Configure Multer for streaming memory storage with a strict 5MB limit
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024 // 5 Megabytes
  },
  fileFilter: (req, file, cb) => {
    const allowedMimeTypes = [
      'message/rfc822',
      'text/plain',
      'application/octet-stream',
      'text/rfc822-headers'
    ];
    const isEmlExtension = file.originalname.toLowerCase().endsWith('.eml') ||
      file.originalname.toLowerCase().endsWith('.txt');

    if (allowedMimeTypes.includes(file.mimetype) || isEmlExtension) {
      cb(null, true);
    } else {
      const err = new Error('Only .eml or plain text email files are accepted');
      err.code = 'UNSUPPORTED_FILE_TYPE';
      cb(err, false);
    }
  }
}).single('file');

/**
 * Generate a lightweight, unique request identifier for traceable server logs
 */
function generateRequestId() {
  return `req_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 7)}`;
}

/**
 * Extract indicators list from parsed email heuristics for persistence
 */
function extractIndicators(parsedEmail) {
  const indicators = [];
  const heuristics = parsedEmail.heuristics || {};

  if (Array.isArray(heuristics.lookalike_domains)) {
    for (const item of heuristics.lookalike_domains) {
      indicators.push({
        indicator_type: 'lookalike_domain',
        detail: `Suspicious lookalike domain: "${item.original}" spoofing target "${item.brand}" (Levenshtein distance: ${item.distance})`
      });
    }
  }

  if (Array.isArray(heuristics.link_mismatches)) {
    for (const item of heuristics.link_mismatches) {
      indicators.push({
        indicator_type: 'anchor_href_mismatch',
        detail: `Display text points to "${item.anchorDomain}" but destination link redirects to "${item.hrefDomain}" (${item.href})`
      });
    }
  }

  if (Array.isArray(heuristics.ip_links)) {
    for (const item of heuristics.ip_links) {
      indicators.push({
        indicator_type: 'raw_ip_link',
        detail: `Link uses raw IP address instead of domain hostname: ${item}`
      });
    }
  }

  if (Array.isArray(heuristics.suspicious_attachments)) {
    for (const item of heuristics.suspicious_attachments) {
      indicators.push({
        indicator_type: 'dangerous_attachment',
        detail: `Potentially dangerous executable or script attachment detected: ${item.filename || item}`
      });
    }
  }

  const secHeaders = parsedEmail.securityHeaders || {};
  if (secHeaders.spf === 'fail' || secHeaders.spf === 'softfail') {
    indicators.push({
      indicator_type: 'spf_failure',
      detail: `SPF validation failed: sender IP is not authorized by sending domain policy`
    });
  }
  if (secHeaders.dmarc === 'fail') {
    indicators.push({
      indicator_type: 'dmarc_failure',
      detail: `DMARC alignment check failed`
    });
  }

  return indicators;
}

/**
 * Helper to execute AI scoring, persist if authenticated, and build response
 */
async function processParsedEmail(parsedEmail, providerPreference, user = null, allowMock = false) {
  const aiResult = await classifyEmailWithAI(parsedEmail, {
    provider: providerPreference,
    allowMock: allowMock || process.env.NODE_ENV === 'test'
  });

  let savedRecord = null;

  // Persist to database if user is authenticated and Supabase is configured
  if (user && user.id && isSupabaseConfigured()) {
    try {
      const indicators = extractIndicators(parsedEmail);
      savedRecord = await saveScanRecord({
        userId: user.id,
        subject: parsedEmail.metadata?.subject,
        sender: parsedEmail.metadata?.from,
        riskScore: aiResult.risk_score,
        verdict: aiResult.verdict,
        tacticsDetected: aiResult.tactics_detected,
        explanation: aiResult.explanation,
        safeSummary: aiResult.safe_summary,
        aiProvider: aiResult.ai_metadata?.provider || providerPreference || 'claude',
        indicators
      });
    } catch (dbErr) {
      console.error('[Supabase Save Error]', dbErr.message);
    }
  }

  return {
    scan_id: savedRecord?.id || null,
    risk_score: aiResult.risk_score,
    verdict: aiResult.verdict,
    tactics_detected: aiResult.tactics_detected,
    explanation: aiResult.explanation,
    safe_summary: aiResult.safe_summary,
    metadata: parsedEmail.metadata,
    heuristics: parsedEmail.heuristics,
    security_headers: parsedEmail.securityHeaders,
    ai_metadata: aiResult.ai_metadata
  };
}

/**
 * POST /api/scan
 * Accepts:
 *  1. Multipart/form-data with 'file' field (.eml or text)
 *  2. Application/json with { email_text: "...", provider: "claude" | "openai" | "gemini" | "auto" }
 */
router.post('/scan', scanRateLimiter, optionalAuth, (req, res) => {
  const requestId = generateRequestId();
  const contentType = req.headers['content-type'] || '';

  // Validate Content-Type
  const isMultipart = contentType.includes('multipart/form-data');
  const isJson = contentType.includes('application/json');

  if (!isMultipart && !isJson) {
    return res.status(415).json({
      error: 'Unsupported Media Type. Expected application/json or multipart/form-data',
      code: 'UNSUPPORTED_MEDIA_TYPE',
      requestId
    });
  }

  // Handle Multipart (.eml upload)
  if (isMultipart) {
    upload(req, res, async (err) => {
      if (err) {
        if (err.code === 'LIMIT_FILE_SIZE') {
          return res.status(413).json({
            error: 'File size exceeds maximum allowed limit (5MB)',
            code: 'FILE_TOO_LARGE',
            requestId
          });
        }
        if (err.code === 'UNSUPPORTED_FILE_TYPE') {
          return res.status(415).json({
            error: err.message,
            code: 'UNSUPPORTED_FILE_TYPE',
            requestId
          });
        }
        console.error(`[${requestId}] Multer error:`, err.message);
        return res.status(400).json({
          error: 'Error processing uploaded file',
          code: 'UPLOAD_ERROR',
          requestId
        });
      }

      if (!req.file || !req.file.buffer || req.file.buffer.length === 0) {
        return res.status(400).json({
          error: 'No file uploaded or file is empty',
          code: 'EMPTY_FILE',
          requestId
        });
      }

      try {
        const parsedEmail = await parseEmailInput(req.file.buffer);

        // Check if intermediate heuristics only requested
        if (req.query?.heuristics_only === 'true') {
          return res.status(200).json({
            success: true,
            requestId,
            mode: 'intermediate_heuristics',
            data: parsedEmail
          });
        }

        const provider = req.body?.provider || req.query?.provider || 'auto';
        const scanResult = await processParsedEmail(
          parsedEmail,
          provider,
          req.user,
          Boolean(req.query?.allow_mock)
        );

        return res.status(200).json({
          success: true,
          requestId,
          data: scanResult
        });
      } catch (scanErr) {
        console.error(`[${requestId}] Scan error:`, scanErr.message);
        const statusCode = scanErr.statusCode || 400;
        return res.status(statusCode).json({
          error: scanErr.message || 'Error processing email scan',
          code: scanErr.code || 'SCAN_FAILED',
          requestId
        });
      }
    });
    return;
  }

  // Handle Application/JSON (raw text scan)
  (async () => {
    try {
      const emailContent = req.body?.email_text || req.body?.raw_email;

      if (!emailContent || typeof emailContent !== 'string' || emailContent.trim().length === 0) {
        return res.status(400).json({
          error: 'Field "email_text" or "raw_email" must be a non-empty string',
          code: 'EMPTY_BODY',
          requestId
        });
      }

      // Check size of string payload (approx 5MB in UTF-8)
      if (Buffer.byteLength(emailContent, 'utf-8') > 5 * 1024 * 1024) {
        return res.status(413).json({
          error: 'Email text payload exceeds maximum allowed limit (5MB)',
          code: 'PAYLOAD_TOO_LARGE',
          requestId
        });
      }

      const parsedEmail = await parseEmailInput(emailContent);

      if (req.query?.heuristics_only === 'true') {
        return res.status(200).json({
          success: true,
          requestId,
          mode: 'intermediate_heuristics',
          data: parsedEmail
        });
      }

      const provider = req.body?.provider || req.query?.provider || 'auto';
      const scanResult = await processParsedEmail(
        parsedEmail,
        provider,
        req.user,
        Boolean(req.query?.allow_mock)
      );

      return res.status(200).json({
        success: true,
        requestId,
        data: scanResult
      });
    } catch (scanErr) {
      console.error(`[${requestId}] Scan error:`, scanErr.message);
      const statusCode = scanErr.statusCode || 400;
      return res.status(statusCode).json({
        error: scanErr.message || 'Error processing email scan',
        code: scanErr.code || 'SCAN_FAILED',
        requestId
      });
    }
  })();
});

/**
 * GET /api/scans
 * Returns historical scans for the authenticated user
 */
router.get('/scans', requireAuth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 100);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);

    const result = await getUserScans(req.user.id, { limit, offset });

    return res.status(200).json({
      success: true,
      scans: result.scans,
      total: result.total,
      limit,
      offset
    });
  } catch (err) {
    console.error('[Get Scans Error]', err.message);
    return res.status(500).json({
      error: 'Failed to retrieve scan history',
      code: 'DB_FETCH_ERROR'
    });
  }
});

/**
 * GET /api/scans/:id
 * Returns a single scan with its flagged indicators
 */
router.get('/scans/:id', requireAuth, async (req, res) => {
  try {
    const scanId = req.params.id;
    const scan = await getScanById(scanId, req.user.id);

    if (!scan) {
      return res.status(404).json({
        error: 'Scan not found or access denied',
        code: 'NOT_FOUND'
      });
    }

    return res.status(200).json({
      success: true,
      scan
    });
  } catch (err) {
    console.error('[Get Scan Detail Error]', err.message);
    return res.status(500).json({
      error: 'Failed to retrieve scan details',
      code: 'DB_FETCH_ERROR'
    });
  }
});

/**
 * GET /api/metrics
 * Returns summary statistics for the authenticated user
 */
router.get('/metrics', requireAuth, async (req, res) => {
  try {
    const metrics = await getUserMetrics(req.user.id);
    return res.status(200).json({
      success: true,
      metrics
    });
  } catch (err) {
    console.error('[Get Metrics Error]', err.message);
    return res.status(500).json({
      error: 'Failed to retrieve user metrics',
      code: 'METRICS_ERROR'
    });
  }
});

export default router;

