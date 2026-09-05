import { simpleParser } from 'mailparser';
import * as cheerio from 'cheerio';
import sanitizeHtml from 'sanitize-html';
import { analyzeLinks } from '../utils/domainChecker.js';

export class EmailParseError extends Error {
  constructor(message, code = 'PARSE_ERROR', statusCode = 400) {
    super(message);
    this.name = 'EmailParseError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

/**
 * Sanitize email HTML safely with strict allowlist.
 * Drops scripts, iframes, event handlers, javascript: pseudo-URLs, and objects.
 */
export function sanitizeEmailHtml(rawHtml) {
  if (!rawHtml || typeof rawHtml !== 'string') return '';

  return sanitizeHtml(rawHtml, {
    allowedTags: [
      'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'p', 'a', 'ul', 'ol',
      'nl', 'li', 'b', 'i', 'strong', 'em', 'strike', 'code', 'hr', 'br', 'div',
      'table', 'thead', 'caption', 'tbody', 'tr', 'th', 'td', 'pre', 'span'
    ],
    allowedAttributes: {
      a: ['href', 'name', 'target', 'title'],
      img: [] // Strip images to prevent tracking pixels / web bugs
    },
    allowedSchemes: ['http', 'https', 'mailto'],
    disallowedTagsModes: 'discard'
  });
}

/**
 * Extract links and anchor texts from HTML and plain text
 */
export function extractLinksFromContent(htmlContent, textContent) {
  const linksMap = new Map(); // key: href -> { href, anchorText }

  // 1. Extract from HTML if present
  if (htmlContent) {
    try {
      const $ = cheerio.load(htmlContent);
      $('a').each((_, elem) => {
        const href = $(elem).attr('href');
        const anchorText = $(elem).text().trim();
        if (href && /^https?:\/\//i.test(href)) {
          const key = href.toLowerCase();
          if (!linksMap.has(key)) {
            linksMap.set(key, { href, anchorText });
          }
        }
      });
    } catch (err) {
      // Continue to text extraction if cheerio fails
    }
  }

  // 2. Extract from Plain Text via URL regex
  if (textContent) {
    const urlRegex = /(https?:\/\/[^\s<>"'{}|\\^`]+)/gi;
    let match;
    while ((match = urlRegex.exec(textContent)) !== null) {
      let rawUrl = match[1];
      // Clean trailing punctuation
      rawUrl = rawUrl.replace(/[.,;:)\]]+$/, '');
      const key = rawUrl.toLowerCase();
      if (!linksMap.has(key)) {
        linksMap.set(key, { href: rawUrl, anchorText: rawUrl });
      }
    }
  }

  return Array.from(linksMap.values());
}

/**
 * Extract authentication & security headers
 */
function extractSecurityHeaders(headerList) {
  const securityInfo = {
    spf: 'unknown',
    dkim: 'unknown',
    dmarc: 'unknown',
    returnPath: null,
    replyTo: null,
    authResults: null
  };

  if (!headerList) return securityInfo;

  for (const [key, value] of headerList) {
    const lowerKey = key.toLowerCase();
    const strVal = typeof value === 'string' ? value : JSON.stringify(value);

    if (lowerKey === 'return-path') {
      securityInfo.returnPath = strVal;
    } else if (lowerKey === 'reply-to') {
      securityInfo.replyTo = strVal;
    } else if (lowerKey === 'authentication-results' || lowerKey === 'arc-authentication-results') {
      securityInfo.authResults = strVal;
      const lowerVal = strVal.toLowerCase();
      if (lowerVal.includes('spf=pass')) securityInfo.spf = 'pass';
      else if (lowerVal.includes('spf=fail') || lowerVal.includes('spf=softfail')) securityInfo.spf = 'fail';

      if (lowerVal.includes('dkim=pass')) securityInfo.dkim = 'pass';
      else if (lowerVal.includes('dkim=fail')) securityInfo.dkim = 'fail';

      if (lowerVal.includes('dmarc=pass')) securityInfo.dmarc = 'pass';
      else if (lowerVal.includes('dmarc=fail')) securityInfo.dmarc = 'fail';
    } else if (lowerKey === 'received-spf') {
      const lowerVal = strVal.toLowerCase();
      if (lowerVal.startsWith('pass')) securityInfo.spf = 'pass';
      else if (lowerVal.startsWith('fail') || lowerVal.startsWith('softfail')) securityInfo.spf = 'fail';
    }
  }

  return securityInfo;
}

/**
 * Main parse function. Accepts a Buffer or a string (raw text or .eml).
 */
export async function parseEmailInput(inputBufferOrString) {
  if (!inputBufferOrString) {
    throw new EmailParseError('Email payload cannot be empty', 'EMPTY_BODY', 400);
  }

  let inputBuffer;
  if (Buffer.isBuffer(inputBufferOrString)) {
    inputBuffer = inputBufferOrString;
  } else if (typeof inputBufferOrString === 'string') {
    if (inputBufferOrString.trim().length === 0) {
      throw new EmailParseError('Email text content cannot be empty', 'EMPTY_BODY', 400);
    }
    inputBuffer = Buffer.from(inputBufferOrString, 'utf-8');
  } else {
    throw new EmailParseError('Invalid input format', 'INVALID_INPUT_TYPE', 400);
  }

  let parsed;
  try {
    parsed = await simpleParser(inputBuffer);
  } catch (err) {
    // Attempt fallback decode if encoding error
    try {
      const fallbackStr = inputBuffer.toString('latin1');
      parsed = await simpleParser(Buffer.from(fallbackStr, 'utf-8'));
    } catch (fallbackErr) {
      throw new EmailParseError(
        'Unable to decode email character encoding',
        'UNSUPPORTED_ENCODING',
        422
      );
    }
  }

  if (!parsed) {
    throw new EmailParseError('Malformed email structure', 'MALFORMED_EMAIL_STRUCTURE', 400);
  }

  const fromText = parsed.from?.text || parsed.headers?.get('from') || 'Unknown Sender';
  const toText = parsed.to?.text || parsed.headers?.get('to') || 'Undisclosed Recipients';
  const subject = parsed.subject || '(No Subject)';
  const date = parsed.date ? parsed.date.toISOString() : new Date().toISOString();
  const textBody = parsed.text || '';
  const rawHtml = parsed.html || '';

  // Validate that there is at least some readable text or subject
  if (!textBody.trim() && !rawHtml.trim() && !subject.trim()) {
    throw new EmailParseError('Email contains no parseable content or text body', 'EMPTY_CONTENT', 400);
  }

  // Sanitize HTML
  const sanitizedHtml = sanitizeEmailHtml(rawHtml);

  // Extract links
  const extractedLinks = extractLinksFromContent(rawHtml || sanitizedHtml, textBody);

  // Link and domain analysis
  const linkAnalysis = analyzeLinks(extractedLinks);

  // Security headers analysis
  const headerList = parsed.headerLines ? parsed.headerLines.map(h => [h.key, h.line]) : [];
  const securityHeaders = extractSecurityHeaders(headerList);

  // Heuristic indicator synthesis
  const indicators = [...linkAnalysis.indicators];

  if (securityHeaders.spf === 'fail') {
    indicators.push({
      type: 'spf_failure',
      detail: 'Sender Policy Framework (SPF) validation failed for sender domain'
    });
  }
  if (securityHeaders.dmarc === 'fail') {
    indicators.push({
      type: 'dmarc_failure',
      detail: 'DMARC alignment validation failed'
    });
  }

  return {
    metadata: {
      from: fromText,
      to: toText,
      subject,
      date,
      messageId: parsed.messageId || null
    },
    content: {
      textBody,
      sanitizedHtml,
      hasHtml: Boolean(rawHtml)
    },
    securityHeaders,
    heuristics: {
      linksCount: extractedLinks.length,
      analyzedLinks: linkAnalysis.links,
      lookalikeCount: linkAnalysis.indicators.filter(i => i.type === 'lookalike_domain').length,
      anchorMismatchCount: linkAnalysis.indicators.filter(i => i.type === 'anchor_href_mismatch').length,
      ipLinksCount: linkAnalysis.indicators.filter(i => i.type === 'ip_address_link').length,
      flaggedIndicators: indicators,
      hasImmediateRedFlags: indicators.length > 0
    }
  };
}
