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
import {
  extractIOCs,
  generateSocTicketMarkdown,
  generateBlocklistRules,
  generateTeamWarningAlert
} from '../services/incidentResponseService.js';
import { inspectUrlThreatIntel } from '../services/threatIntelService.js';
import { decodeQrFromImage, analyzeQuishedUrl, QrDecodeError } from '../services/qrPhishingService.js';

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

// Configure Multer for Quishing QR image uploads with strict limits
const qrUpload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB
  },
  fileFilter: (req, file, cb) => {
    const allowed = ['image/png', 'image/jpeg', 'image/jpg', 'image/webp'];
    if (allowed.includes(file.mimetype)) {
      cb(null, true);
    } else {
      const err = new Error('Only PNG, JPEG, or WebP images are accepted for QR scanning');
      err.code = 'UNSUPPORTED_IMAGE_TYPE';
      cb(err, false);
    }
  }
}).single('image');

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

  // 1. Process all flagged heuristic indicators (lookalikes, mismatches, IP links, etc.)
  if (Array.isArray(heuristics.flaggedIndicators)) {
    for (const item of heuristics.flaggedIndicators) {
      indicators.push({
        indicator_type: item.type || item.indicator_type || 'heuristic_warning',
        detail: item.detail || `Suspicious signal detected: ${item.type || 'flagged_indicator'}`
      });
    }
  }

  // 2. Legacy fallback / Direct heuristics arrays
  if (Array.isArray(heuristics.lookalike_domains)) {
    for (const item of heuristics.lookalike_domains) {
      if (!indicators.some(i => i.indicator_type === 'lookalike_domain')) {
        indicators.push({
          indicator_type: 'lookalike_domain',
          detail: `Suspicious lookalike domain: "${item.original}" spoofing target "${item.brand}" (Levenshtein distance: ${item.distance})`
        });
      }
    }
  }

  if (Array.isArray(heuristics.link_mismatches)) {
    for (const item of heuristics.link_mismatches) {
      if (!indicators.some(i => i.indicator_type === 'anchor_href_mismatch')) {
        indicators.push({
          indicator_type: 'anchor_href_mismatch',
          detail: `Display text points to "${item.anchorDomain}" but destination link redirects to "${item.hrefDomain}" (${item.href})`
        });
      }
    }
  }

  if (Array.isArray(heuristics.ip_links)) {
    for (const item of heuristics.ip_links) {
      if (!indicators.some(i => i.indicator_type === 'raw_ip_link')) {
        indicators.push({
          indicator_type: 'raw_ip_link',
          detail: `Link uses raw IP address instead of domain hostname: ${item}`
        });
      }
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
    if (!indicators.some(i => i.indicator_type === 'spf_failure')) {
      indicators.push({
        indicator_type: 'spf_failure',
        detail: `SPF validation failed: sender IP is not authorized by sending domain policy`
      });
    }
  }
  if (secHeaders.dmarc === 'fail') {
    if (!indicators.some(i => i.indicator_type === 'dmarc_failure')) {
      indicators.push({
        indicator_type: 'dmarc_failure',
        detail: `DMARC alignment check failed`
      });
    }
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

  // Generate Defanged IOCs & Defensive Response Package
  const iocs = extractIOCs(parsedEmail, aiResult);
  const incidentKit = {
    iocs,
    socTicketMarkdown: generateSocTicketMarkdown(iocs, aiResult),
    blocklistRules: generateBlocklistRules(iocs),
    teamAlert: generateTeamWarningAlert(iocs, aiResult)
  };

  // Sandbox preview is a members-only feature — only authenticated users receive it
  const sandboxPreview = user && user.id
    ? {
        annotatedHtml: parsedEmail.content?.annotatedHtml || '',
        textSegments: parsedEmail.content?.textSegments || [],
        hasHtml: parsedEmail.content?.hasHtml || false,
        textBody: parsedEmail.content?.textBody || ''
      }
    : null;

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
    ai_metadata: aiResult.ai_metadata,
    incident_kit: incidentKit,
    ...(sandboxPreview ? { sandbox_preview: sandboxPreview } : {})
  };
}

/**
 * POST /api/scan
 * Accepts:
 *  1. Multipart/form-data with 'file' field (.eml or text)
 *  2. Application/json with { email_text: "...", provider: "claude" | "openai" | "gemini" | "groq" | "openrouter" | "auto" }
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
 * POST /api/scan/qr
 * Quishing (QR Code Phishing) Detector — decodes in-memory, never visits the URL (members-only)
 */
router.post('/scan/qr', scanRateLimiter, optionalAuth, requireFeatureAuth, (req, res) => {
  qrUpload(req, res, async (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({ error: 'Image exceeds 5MB limit', code: 'IMAGE_TOO_LARGE' });
      }
      return res.status(415).json({ error: err.message, code: err.code || 'UNSUPPORTED_IMAGE_TYPE' });
    }
    if (!req.file || !req.file.buffer?.length) {
      return res.status(400).json({ error: 'No image uploaded', code: 'EMPTY_IMAGE' });
    }

    try {
      const decoded = await decodeQrFromImage(req.file.buffer);
      const analysis = analyzeQuishedUrl(decoded.rawText);
      return res.status(200).json({ success: true, data: { ...decoded, analysis } });
    } catch (qrErr) {
      const status = qrErr.statusCode || 400;
      return res.status(status).json({ error: qrErr.message, code: qrErr.code || 'QR_DECODE_ERROR' });
    }
  });
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

/**
 * Members-only feature gate: blocks unauthenticated requests on premium
 * endpoints (Threat Intel, SOC Incident Kit). Skipped in test environment,
 * mirroring the existing scanRateLimiter test bypass.
 */
function requireFeatureAuth(req, res, next) {
  if (process.env.NODE_ENV === 'test') return next();
  if (!req.user || !req.user.id) {
    return res.status(401).json({
      error: 'This feature requires an account. Please sign in to use it.',
      code: 'AUTH_REQUIRED'
    });
  }
  next();
}

/**
 * POST /api/intel/inspect-url
 * Live URL & Domain Threat Intelligence Inspector (members-only)
 */
router.post('/intel/inspect-url', scanRateLimiter, optionalAuth, requireFeatureAuth, async (req, res) => {
  const targetUrl = req.body?.url;
  if (!targetUrl || typeof targetUrl !== 'string' || !targetUrl.trim()) {
    return res.status(400).json({
      error: 'Field "url" is required and must be a non-empty string',
      code: 'MISSING_URL'
    });
  }

  try {
    const report = await inspectUrlThreatIntel(targetUrl.trim());
    return res.status(200).json({
      success: true,
      data: report
    });
  } catch (err) {
    return res.status(400).json({
      error: err.message || 'Failed to inspect URL threat intelligence',
      code: 'INTEL_INSPECT_ERROR'
    });
  }
});

/**
 * POST /api/incident/export
 * Generates custom SOC incident reports and blocklist rules (members-only)
 */
router.post('/incident/export', optionalAuth, requireFeatureAuth, (req, res) => {
  const { parsed_email, scan_result } = req.body || {};
  if (!parsed_email && !scan_result) {
    return res.status(400).json({
      error: 'Either "parsed_email" or "scan_result" must be provided in request body',
      code: 'MISSING_DATA'
    });
  }

  const iocs = extractIOCs(parsed_email || {}, scan_result || {});
  const socTicket = generateSocTicketMarkdown(iocs, scan_result || {});
  const blocklistRules = generateBlocklistRules(iocs);
  const teamAlert = generateTeamWarningAlert(iocs, scan_result || {});

  return res.status(200).json({
    success: true,
    data: {
      iocs,
      socTicket,
      blocklistRules,
      teamAlert
    }
  });
});

export default router;


