import { parseDomain, fromUrl, ParseResultType } from 'parse-domain';
import { distance } from 'fastest-levenshtein';

export const PROTECTED_BRANDS = [
  { name: 'PayPal', domain: 'paypal.com' },
  { name: 'Microsoft', domain: 'microsoft.com' },
  { name: 'Google', domain: 'google.com' },
  { name: 'Apple', domain: 'apple.com' },
  { name: 'Amazon', domain: 'amazon.com' },
  { name: 'Netflix', domain: 'netflix.com' },
  { name: 'Bank of America', domain: 'bankofamerica.com' },
  { name: 'Chase', domain: 'chase.com' },
  { name: 'Wells Fargo', domain: 'wellsfargo.com' },
  { name: 'Facebook', domain: 'facebook.com' },
  { name: 'Instagram', domain: 'instagram.com' },
  { name: 'Dropbox', domain: 'dropbox.com' },
  { name: 'LinkedIn', domain: 'linkedin.com' },
  { name: 'Adobe', domain: 'adobe.com' },
  { name: 'DHL', domain: 'dhl.com' },
  { name: 'FedEx', domain: 'fedex.com' },
  { name: 'UPS', domain: 'ups.com' },
  { name: 'DocuSign', domain: 'docusign.com' }
];

/**
 * Extract normalized hostname & registrable domain from a URL or raw domain string
 */
export function extractDomainInfo(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return null;
  }

  let normalized = rawUrl.trim();
  if (!/^https?:\/\//i.test(normalized)) {
    normalized = `http://${normalized}`;
  }

  try {
    const parsedUrl = new URL(normalized);
    const hostname = parsedUrl.hostname.toLowerCase();

    // Use parse-domain to get registrable domain
    const parseResult = parseDomain(fromUrl(normalized));

    let registrableDomain = hostname;
    let mainDomainName = hostname;

    if (parseResult.type === ParseResultType.Listed) {
      const { domain, topLevelDomains } = parseResult;
      registrableDomain = `${domain}.${topLevelDomains.join('.')}`;
      mainDomainName = domain;
    } else if (parseResult.type === ParseResultType.Ip) {
      registrableDomain = hostname;
      mainDomainName = hostname;
    }

    return {
      fullUrl: rawUrl,
      hostname,
      registrableDomain,
      mainDomainName,
      isIpAddress: parseResult.type === ParseResultType.Ip
    };
  } catch (err) {
    return null;
  }
}

/**
 * Check if a candidate domain is a lookalike/typosquatting of a protected brand.
 * Condition: Levenshtein distance <= 2, distance > 0, and not an exact match.
 */
export function checkLookalikeDomain(candidateRegistrableDomain, candidateDomainName) {
  if (!candidateRegistrableDomain) return null;

  const candidateFull = candidateRegistrableDomain.toLowerCase();
  const candidateCore = (candidateDomainName || candidateFull.split('.')[0]).toLowerCase();

  for (const brand of PROTECTED_BRANDS) {
    const brandFull = brand.domain.toLowerCase();
    const brandCore = brand.domain.split('.')[0].toLowerCase();

    // Exact legitimate match -> safe, not a lookalike
    if (candidateFull === brandFull || candidateFull.endsWith(`.${brandFull}`)) {
      return {
        isLegitimateBrand: true,
        brand: brand.name,
        targetDomain: brand.domain
      };
    }

    // Levenshtein on full domain (e.g. paypa1.com vs paypal.com)
    const fullDist = distance(candidateFull, brandFull);
    // Levenshtein on core brand name (e.g. paypa1 vs paypal)
    const coreDist = distance(candidateCore, brandCore);

    // Levenshtein on hyphen-separated labels (e.g. paypa1-verify.com → label 'paypa1' vs 'paypal')
    const labelDist = (candidateCore.split('-')[0] || '').length > 0
      ? distance(candidateCore.split('-')[0], brandCore)
      : Infinity;

    const effectiveMinDist = Math.min(fullDist, coreDist, labelDist);

    if ((fullDist <= 2 && fullDist > 0) || (coreDist <= 2 && coreDist > 0 && Math.abs(candidateCore.length - brandCore.length) <= 2) || (labelDist <= 2 && labelDist > 0)) {
      return {
        isLookalike: true,
        brand: brand.name,
        targetDomain: brand.domain,
        candidateDomain: candidateFull,
        distance: effectiveMinDist,
        reason: `Domain '${candidateFull}' is visually deceptive and mimics ${brand.name} ('${brand.domain}')`
      };
    }

    // Subdomain / prefix trick check (e.g., paypal-verify.com or paypal.security-login.com)
    if (candidateCore.includes(`${brandCore}-`) || candidateCore.includes(`-${brandCore}`)) {
      return {
        isLookalike: true,
        brand: brand.name,
        targetDomain: brand.domain,
        candidateDomain: candidateFull,
        distance: 1,
        reason: `Domain '${candidateFull}' uses a hyphenated brand impersonation trick for ${brand.name}`
      };
    }
  }

  return null;
}

/**
 * Check for Anchor-Text vs Actual-Href mismatch.
 * Example: <a href="http://evil.com">https://paypal.com/login</a>
 */
export function checkAnchorHrefMismatch(anchorText, actualHref) {
  if (!anchorText || !actualHref) return null;

  const cleanAnchor = anchorText.trim();
  const cleanHref = actualHref.trim();

  // If anchor text doesn't look like a URL or domain, skip
  const isAnchorUrlLike = /^(https?:\/\/|www\.)/i.test(cleanAnchor) ||
    /^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(\/.*)?$/i.test(cleanAnchor);

  if (!isAnchorUrlLike) {
    return null;
  }

  const anchorDomainInfo = extractDomainInfo(cleanAnchor);
  const hrefDomainInfo = extractDomainInfo(cleanHref);

  if (!anchorDomainInfo || !hrefDomainInfo) {
    return null;
  }

  // If anchor text displays domain A, but href points to domain B
  if (anchorDomainInfo.registrableDomain !== hrefDomainInfo.registrableDomain) {
    return {
      isMismatch: true,
      displayedDomain: anchorDomainInfo.registrableDomain,
      actualDomain: hrefDomainInfo.registrableDomain,
      displayedText: cleanAnchor,
      actualHref: cleanHref,
      reason: `Anchor text displays '${anchorDomainInfo.registrableDomain}' but links to different domain '${hrefDomainInfo.registrableDomain}'`
    };
  }

  return null;
}

/**
 * Analyze an array of link objects: { href, anchorText }
 */
export function analyzeLinks(links = []) {
  const analyzedLinks = [];
  const lookalikeIndicators = [];
  const mismatchIndicators = [];
  const ipHostIndicators = [];

  for (const link of links) {
    const { href, anchorText } = link;
    const domainInfo = extractDomainInfo(href);

    if (!domainInfo) continue;

    const lookalikeResult = checkLookalikeDomain(
      domainInfo.registrableDomain,
      domainInfo.mainDomainName
    );

    const mismatchResult = checkAnchorHrefMismatch(anchorText, href);

    let isFlagged = false;

    if (lookalikeResult?.isLookalike) {
      isFlagged = true;
      lookalikeIndicators.push({
        type: 'lookalike_domain',
        detail: lookalikeResult.reason,
        url: href,
        targetBrand: lookalikeResult.brand
      });
    }

    if (mismatchResult?.isMismatch) {
      isFlagged = true;
      mismatchIndicators.push({
        type: 'anchor_href_mismatch',
        detail: mismatchResult.reason,
        displayed: mismatchResult.displayedText,
        actual: mismatchResult.actualHref
      });
    }

    if (domainInfo.isIpAddress) {
      isFlagged = true;
      ipHostIndicators.push({
        type: 'ip_address_link',
        detail: `Direct IP address used instead of domain name: ${domainInfo.hostname}`,
        url: href
      });
    }

    analyzedLinks.push({
      url: href,
      anchorText: anchorText || '',
      hostname: domainInfo.hostname,
      registrableDomain: domainInfo.registrableDomain,
      isFlagged,
      lookalike: lookalikeResult?.isLookalike ? lookalikeResult : null,
      mismatch: mismatchResult?.isMismatch ? mismatchResult : null
    });
  }

  return {
    links: analyzedLinks,
    indicators: [
      ...lookalikeIndicators,
      ...mismatchIndicators,
      ...ipHostIndicators
    ],
    hasSuspiciousLinks: lookalikeIndicators.length > 0 || mismatchIndicators.length > 0 || ipHostIndicators.length > 0
  };
}
