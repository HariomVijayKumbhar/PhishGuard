import Jimp from 'jimp';
import jsQR from 'jsqr';
import { extractDomainInfo, checkLookalikeDomain } from '../utils/domainChecker.js';

/**
 * ─── Safety Limits (decompression-bomb / pixel-bomb protection) ─────────────
 * Everything runs strictly in-memory. Decoded URL is NEVER auto-visited.
 */
export const QR_LIMITS = {
  MAX_IMAGE_BYTES: 5 * 1024 * 1024,   // 5MB raw upload
  MAX_DECODED_PIXELS: 4096 * 4096,    // 16.7MP decompression cap
  MAX_SIDE: 4096,                     // per-dimension cap
  MAX_ATTACHMENTS_SCANNED: 3
};

const ALLOWED_IMAGE_TYPES = new Set(['image/png', 'image/jpeg', 'image/jpg', 'image/webp']);

/** URL shorteners commonly used to hide quishing destinations */
const SHORTENER_DOMAINS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'rb.gy',
  'rebrand.ly', 'shorturl.at', 'tiny.cc', 'ow.ly', 'buff.ly', 'qrco.de',
  'shorte.st', 'clck.ru', 's.id', 'lnkd.in', 'bl.ink', 'urlz.fr'
]);

/** Credential-harvest keywords weighted for mobile-only QR destinations */
const SUSPICIOUS_QR_KEYWORDS = [
  'login', 'signin', 'verify', 'verification', 'secure', 'security',
  'account', 'banking', 'update', 'password', 'credential', 'auth',
  'mfa', 'multifactor', 'authenticator', 'wallet', 'billing', 'confirm',
  'recovery', 'unlock', 'suspended', 'office', 'outlook', 'sso'
];

export class QrDecodeError extends Error {
  constructor(message, code = 'QR_DECODE_ERROR', statusCode = 400) {
    super(message);
    this.name = 'QrDecodeError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

/**
 * Decode the first QR code found in an image buffer, fully in-memory.
 * Throws QrDecodeError on bombs, unsupported types, or no QR found.
 */
export async function decodeQrFromImage(imageBuffer) {
  if (!Buffer.isBuffer(imageBuffer) || imageBuffer.length === 0) {
    throw new QrDecodeError('Empty or invalid image payload', 'EMPTY_IMAGE');
  }
  if (imageBuffer.length > QR_LIMITS.MAX_IMAGE_BYTES) {
    throw new QrDecodeError(`Image exceeds maximum allowed size (${QR_LIMITS.MAX_IMAGE_BYTES / 1024 / 1024}MB)`, 'IMAGE_TOO_LARGE', 413);
  }

  let image;
  try {
    image = await Jimp.read(imageBuffer);
  } catch (err) {
    throw new QrDecodeError('Unsupported, corrupted, or decompression-bomb image', 'IMAGE_DECODE_FAILED');
  }

  const { width, height } = image.bitmap;
  if (!width || !height || width * height > QR_LIMITS.MAX_DECODED_PIXELS) {
    throw new QrDecodeError('Decoded image exceeds pixel-bomb safety limit', 'PIXEL_BOMB_BLOCKED', 413);
  }

  // Downscale oversized-but-legal images before scanning
  if (width > QR_LIMITS.MAX_SIDE || height > QR_LIMITS.MAX_SIDE) {
    const scale = QR_LIMITS.MAX_SIDE / Math.max(width, height);
    image.resize(Math.floor(width * scale), Math.floor(height * scale));
  }

  const { data, width: w, height: h } = image.bitmap;
  const result = jsQR(data, w, h, { inversionAttempts: 'attemptBoth' });
  if (!result || !result.data) {
    throw new QrDecodeError('No QR code detected in the provided image', 'NO_QR_FOUND', 422);
  }

  return {
    rawText: result.data,
    version: result.version ?? null,
    location: result.location ? { top: result.location.topLeftCorner, bottom: result.location.bottomRightCorner } : null
  };
}

/**
 * Static, offline analysis of a decoded QR payload.
 * NEVER fetches the URL — pure lexical/domain heuristics only.
 */
export function analyzeQuishedUrl(rawText) {
  const text = String(rawText || '').trim();
  if (!text) return null;

  const isUrl = /^https?:\/\//i.test(text);
  const domainInfo = isUrl ? extractDomainInfo(text) : null;
  const hostname = domainInfo?.hostname || '';

  let threatScore = 0;
  const indicators = [];

  // 1. Lookalike / typosquat check
  const lookalike = domainInfo
    ? checkLookalikeDomain(domainInfo.registrableDomain, domainInfo.mainDomainName)
    : null;
  if (lookalike?.isLookalike) {
    threatScore += 40;
    indicators.push({
      type: 'qr_lookalike_domain',
      severity: 'HIGH',
      detail: lookalike.reason
    });
  }

  // 2. Raw IP destination
  if (domainInfo?.isIpAddress) {
    threatScore += 35;
    indicators.push({
      type: 'qr_raw_ip',
      severity: 'HIGH',
      detail: `QR code targets a raw IP address (${hostname}) — classic mobile malware/phishing vector`
    });
  }

  // 3. URL shortener — destination hidden
  const isShortener = SHORTENER_DOMAINS.has(domainInfo?.registrableDomain || '');
  if (isShortener) {
    threatScore += 30;
    indicators.push({
      type: 'qr_shortener',
      severity: 'MEDIUM',
      detail: `QR encodes a shortened URL (${hostname}) concealing its true destination`
    });
  }

  // 4. Credential-harvest keywords
  const lowerUrl = text.toLowerCase();
  const matchedKeywords = SUSPICIOUS_QR_KEYWORDS.filter(kw => lowerUrl.includes(kw));
  if (matchedKeywords.length >= 2) {
    threatScore += 25;
    indicators.push({
      type: 'qr_credential_keywords',
      severity: 'MEDIUM',
      detail: `QR destination contains sensitive authentication keywords: ${matchedKeywords.join(', ')}`
    });
  } else if (matchedKeywords.length === 1) {
    threatScore += 10;
  }

  // 5. Non-URL payloads (wifi credentials, plaintext, payment strings) — flag for review
  if (!isUrl && text.length > 0) {
    indicators.push({
      type: 'qr_non_url_payload',
      severity: 'LOW',
      detail: `QR encodes non-URL data (${text.length} chars) — verify manually before scanning with a phone`
    });
    threatScore += 5;
  }

  threatScore = Math.min(threatScore, 100);
  let verdict = 'BENIGN';
  if (threatScore >= 40) verdict = 'SUSPICIOUS';
  if (threatScore >= 70) verdict = 'MALICIOUS';

  return {
    payload: text,
    isUrl,
    domainInfo: domainInfo
      ? { hostname: domainInfo.hostname, registrableDomain: domainInfo.registrableDomain, isIpAddress: domainInfo.isIpAddress }
      : null,
    isShortener,
    matchedKeywords,
    lookalike: lookalike?.isLookalike ? { brand: lookalike.brand, targetDomain: lookalike.targetDomain, distance: lookalike.distance, reason: lookalike.reason } : null,
    threatScore,
    verdict,
    indicators
  };
}

/**
 * Defang a decoded payload for safe display (SOC convention)
 */
export function defangPayload(payload) {
  return String(payload || '')
    .replace(/^https?:\/\//i, 'hxxp[://]')
    .replace(/\./g, '[.]');
}

/**
 * Scan email image attachments (base64/buffer) for embedded QR codes.
 * Used by emailParser during a normal scan — strictly limited count + size.
 */
export async function scanAttachmentsForQr(attachments = []) {
  const images = (attachments || [])
    .filter(a => a && a.content && ALLOWED_IMAGE_TYPES.has((a.contentType || '').toLowerCase()))
    .slice(0, QR_LIMITS.MAX_ATTACHMENTS_SCANNED);

  const findings = [];

  for (const attachment of images) {
    const content = Buffer.isBuffer(attachment.content)
      ? attachment.content
      : Buffer.from(attachment.content);

    try {
      const decoded = await decodeQrFromImage(content);
      const analysis = analyzeQuishedUrl(decoded.rawText);
      findings.push({
        filename: attachment.filename || 'embedded-image',
        contentType: attachment.contentType,
        qr: { rawText: decoded.rawText, version: decoded.version },
        analysis
      });
    } catch {
      // No QR in this image (or decode failed) — not an error for the email flow
    }
  }

  return findings;
}
