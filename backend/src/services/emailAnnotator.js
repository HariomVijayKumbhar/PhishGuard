import * as cheerio from 'cheerio';

/**
 * Psychological manipulation phrase patterns grouped by category.
 * Each entry: { category, severity, patterns[] }
 */
const URGENCY_PATTERNS = [
  {
    category: 'Time Pressure',
    severity: 'high',
    patterns: [
      /within\s+\d+\s+hours?/gi,
      /expires?\s+(today|soon|now|in\s+\d+)/gi,
      /immediately/gi,
      /urgent(ly)?/gi,
      /last\s+chance/gi,
      /act\s+now/gi,
      /time\s+sensitive/gi,
      /limited\s+time/gi,
      /deadline/gi,
      /before\s+it'?s\s+too\s+late/gi,
    ]
  },
  {
    category: 'Threat / Fear',
    severity: 'high',
    patterns: [
      /account\s+(suspended|locked|disabled|terminated|compromised|blocked)/gi,
      /unauthorized\s+(access|login|sign.?in|activity)/gi,
      /suspicious\s+activity/gi,
      /security\s+(breach|alert|warning|threat|incident)/gi,
      /will\s+be\s+(terminated|deleted|suspended|closed|blocked)/gi,
      /permanent(ly)?\s+(ban|suspend|terminat|delet)/gi,
      /your\s+account\s+will/gi,
    ]
  },
  {
    category: 'Authority / Legitimacy',
    severity: 'medium',
    patterns: [
      /official\s+(notice|notification|warning|alert)/gi,
      /security\s+team/gi,
      /mandatory\s+(verif|update|action)/gi,
      /required\s+by\s+(law|regulation|policy)/gi,
      /compliance/gi,
    ]
  },
  {
    category: 'Action Demand',
    severity: 'medium',
    patterns: [
      /verify\s+(your\s+)?(account|identity|email|information|details)/gi,
      /confirm\s+(your\s+)?(account|identity|email|information|details)/gi,
      /click\s+here\s+to/gi,
      /log\s*in\s+(now|immediately|to\s+verify)/gi,
      /update\s+(your\s+)?(information|credentials|password|billing)/gi,
      /reset\s+your\s+password/gi,
      /provide\s+(your|the)\s+(details|information|credentials)/gi,
    ]
  },
  {
    category: 'Credential Harvest',
    severity: 'high',
    patterns: [
      /enter\s+(your\s+)?(password|credentials|card|ssn|social\s+security)/gi,
      /social\s+security\s+number/gi,
      /credit\s+card\s+(number|details|information)/gi,
      /bank\s+(account|details|information)/gi,
    ]
  },
  {
    category: 'Reward / Incentive',
    severity: 'low',
    patterns: [
      /you\s+have\s+(won|been\s+selected|been\s+chosen)/gi,
      /claim\s+(your\s+)?(prize|reward|gift|refund|money)/gi,
      /congratulations/gi,
      /\$\d+[\.,]\d{2}\s+refund/gi,
    ]
  }
];

/**
 * Detect urgency / psychological manipulation phrases in plain text.
 * Returns array of { phrase, category, severity, index } matches.
 */
export function detectUrgencyPhrases(text) {
  if (!text || typeof text !== 'string') return [];

  const matches = [];
  const seenPhrases = new Set();

  for (const group of URGENCY_PATTERNS) {
    for (const pattern of group.patterns) {
      // Reset lastIndex for global patterns
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(text)) !== null) {
        const phrase = match[0].trim();
        const key = phrase.toLowerCase();
        if (!seenPhrases.has(key)) {
          seenPhrases.add(key);
          matches.push({
            phrase,
            category: group.category,
            severity: group.severity,
            index: match.index
          });
        }
      }
    }
  }

  return matches;
}

/**
 * Determine threat class for a single analyzed link object
 */
function classifyLink(analyzedLink) {
  if (!analyzedLink) return 'clean';
  if (analyzedLink.lookalike) return 'lookalike';
  if (analyzedLink.mismatch) return 'mismatch';
  if (analyzedLink.isIpAddress || analyzedLink.hostname?.match(/^\d{1,3}(\.\d{1,3}){3}$/)) return 'ip';
  if (analyzedLink.isFlagged) return 'flagged';
  return 'external';
}

/**
 * Build a map of href -> analyzed link data for fast lookup
 */
function buildLinkMap(analyzedLinks = []) {
  const map = new Map();
  for (const link of analyzedLinks) {
    const key = (link.url || link.href || '').toLowerCase().trim();
    if (key) map.set(key, link);
  }
  return map;
}

/**
 * Escape HTML special characters for use in attribute values
 */
function escAttr(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/**
 * Annotate sanitized email HTML for sandboxed threat visualization.
 *
 * Transforms:
 *   - <a href="..."> → <span class="pg-link pg-threat-{type}" data-href="..." data-threat="..." data-detail="...">
 *   - Urgency phrases → <span class="pg-urgency pg-sev-{severity}" data-category="..." data-phrase="...">phrase</span>
 *
 * All real <a> tags are neutralized — NO clickable links survive.
 *
 * @param {string} sanitizedHtml - Already server-sanitized HTML (from sanitize-html)
 * @param {Array} analyzedLinks  - Array of analyzed link objects from domainChecker.analyzeLinks()
 * @returns {string} annotatedHtml safe for sandboxed rendering
 */
export function annotateSandboxHtml(sanitizedHtml, analyzedLinks = []) {
  if (!sanitizedHtml || typeof sanitizedHtml !== 'string') return '';

  const linkMap = buildLinkMap(analyzedLinks);

  // Parse with Cheerio
  const $ = cheerio.load(sanitizedHtml, {
    xmlMode: false,
    decodeEntities: false
  });

  // --- SAFETY PASS: Strip any remaining dangerous elements (belt-and-suspenders) ---
  $('script, iframe, object, embed, form, input, button, meta, link').remove();
  $('[onload], [onclick], [onerror], [onmouseover], [onfocus], [onblur], [onchange]').each((_, el) => {
    const attrs = Object.keys(el.attribs || {}).filter(a => a.startsWith('on'));
    attrs.forEach(a => $(el).removeAttr(a));
  });

  // --- LINK NEUTRALIZATION: Convert all <a> → inert <span> with data attributes ---
  $('a').each((_, el) => {
    const $el = $(el);
    const href = $el.attr('href') || '';
    const innerContent = $el.html() || $el.text() || '';

    const lookupKey = href.toLowerCase().trim();
    const linkData = linkMap.get(lookupKey);
    const threatClass = classifyLink(linkData);

    let detail = '';
    let brand = '';
    let actualDest = '';

    if (threatClass === 'lookalike' && linkData?.lookalike) {
      detail = linkData.lookalike.reason || `Lookalike domain impersonating ${linkData.lookalike.brand}`;
      brand = linkData.lookalike.brand || '';
    } else if (threatClass === 'mismatch' && linkData?.mismatch) {
      detail = linkData.mismatch.reason || 'Anchor text does not match actual destination';
      actualDest = linkData.mismatch.actualHref || '';
    } else if (threatClass === 'ip') {
      detail = `Raw IP address link — suspicious destination: ${href}`;
    } else if (href) {
      detail = `External link → ${href}`;
    }

    const spanAttrs = [
      `class="pg-link pg-threat-${escAttr(threatClass)}"`,
      `data-href="${escAttr(href)}"`,
      `data-threat="${escAttr(threatClass)}"`,
      `data-detail="${escAttr(detail)}"`,
      brand ? `data-brand="${escAttr(brand)}"` : '',
      actualDest ? `data-actual="${escAttr(actualDest)}"` : '',
      'role="button"',
      'tabindex="0"'
    ].filter(Boolean).join(' ');

    $el.replaceWith(`<span ${spanAttrs}>${innerContent}</span>`);
  });

  // Extract the processed inner HTML (body content only)
  let annotated = $('body').html() || '';

  // --- URGENCY PHRASE ANNOTATION ---
  // We annotate in plain text extracted from the HTML,
  // but inject <span> markers into the final HTML string carefully.
  for (const group of URGENCY_PATTERNS) {
    for (const pattern of group.patterns) {
      pattern.lastIndex = 0;
      annotated = annotated.replace(pattern, (match) => {
        // Don't annotate if we're inside an attribute value (basic guard)
        return `<span class="pg-urgency pg-sev-${group.severity}" data-category="${escAttr(group.category)}" data-phrase="${escAttr(match.trim())}">${match}</span>`;
      });
    }
  }

  return annotated;
}

/**
 * Generate a plain-text annotated version with urgency phrase markers.
 * Used when email has no HTML (text-only emails).
 * Returns structured segments array for frontend rendering.
 */
export function annotateTextBody(textBody, analyzedLinks = []) {
  if (!textBody || typeof textBody !== 'string') return [];

  const urlRegex = /(https?:\/\/[^\s<>"'{}|\\^`]+)/gi;
  const linkMap = buildLinkMap(analyzedLinks);

  // Find all urgency matches with positions
  const urgencyMatches = [];
  for (const group of URGENCY_PATTERNS) {
    for (const pattern of group.patterns) {
      pattern.lastIndex = 0;
      let m;
      while ((m = pattern.exec(textBody)) !== null) {
        urgencyMatches.push({
          start: m.index,
          end: m.index + m[0].length,
          phrase: m[0],
          category: group.category,
          severity: group.severity,
          type: 'urgency'
        });
      }
    }
  }

  // Find all URL matches with positions
  const urlMatches = [];
  let um;
  urlRegex.lastIndex = 0;
  while ((um = urlRegex.exec(textBody)) !== null) {
    const href = um[1].replace(/[.,;:)\]]+$/, '');
    const lookupKey = href.toLowerCase().trim();
    const linkData = linkMap.get(lookupKey);
    const threatClass = classifyLink(linkData);
    urlMatches.push({
      start: um.index,
      end: um.index + href.length,
      href,
      threatClass,
      linkData,
      type: 'url'
    });
  }

  // Merge, deduplicate, sort by start position
  const allMatches = [...urgencyMatches, ...urlMatches]
    .sort((a, b) => a.start - b.start)
    .filter((m, i, arr) => {
      // Remove overlapping ranges (keep first)
      if (i === 0) return true;
      return m.start >= arr[i - 1].end;
    });

  // Build segments array
  const segments = [];
  let cursor = 0;

  for (const match of allMatches) {
    if (match.start > cursor) {
      segments.push({ type: 'text', content: textBody.slice(cursor, match.start) });
    }

    if (match.type === 'urgency') {
      segments.push({
        type: 'urgency',
        content: match.phrase,
        category: match.category,
        severity: match.severity
      });
    } else if (match.type === 'url') {
      segments.push({
        type: 'link',
        content: match.href,
        href: match.href,
        threatClass: match.threatClass,
        linkData: match.linkData
      });
    }

    cursor = match.end;
  }

  if (cursor < textBody.length) {
    segments.push({ type: 'text', content: textBody.slice(cursor) });
  }

  return segments;
}
