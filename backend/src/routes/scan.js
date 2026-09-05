import express from 'express';
import multer from 'multer';
import { parseEmailInput, EmailParseError } from '../services/emailParser.js';

const router = express.Router();

// Configure Multer for streaming memory storage with a strict 5MB limit
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024 // 5 Megabytes
  },
  fileFilter: (req, file, cb) => {
    // Accept .eml, text/plain, message/rfc822, application/octet-stream
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
 * POST /api/scan
 * Accepts:
 *  1. Multipart/form-data with 'file' field (.eml or text)
 *  2. Application/json with { email_text: "..." } or { raw_email: "..." }
 * Rejects:
 *  - Any other Content-Type -> 415 Unsupported Media Type
 *  - File > 5MB -> 413 Payload Too Large (enforced at Multer layer)
 *  - Empty content -> 400 Bad Request
 *  - Malformed content -> 400 / 422
 */
router.post('/scan', (req, res) => {
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

        return res.status(200).json({
          success: true,
          requestId,
          mode: 'intermediate_heuristics',
          data: parsedEmail
        });
      } catch (parseErr) {
        console.error(`[${requestId}] Parse error:`, parseErr.message);
        const statusCode = parseErr.statusCode || 400;
        return res.status(statusCode).json({
          error: parseErr.message || 'Malformed email structure',
          code: parseErr.code || 'MALFORMED_EMAIL_STRUCTURE',
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

      return res.status(200).json({
        success: true,
        requestId,
        mode: 'intermediate_heuristics',
        data: parsedEmail
      });
    } catch (parseErr) {
      console.error(`[${requestId}] Parse error:`, parseErr.message);
      const statusCode = parseErr.statusCode || 400;
      return res.status(statusCode).json({
        error: parseErr.message || 'Malformed email input',
        code: parseErr.code || 'MALFORMED_EMAIL_STRUCTURE',
        requestId
      });
    }
  })();
});

export default router;
