import dns from 'node:dns/promises';
import net from 'node:net';
import { extractDomainInfo } from '../utils/domainChecker.js';

/**
 * List of high-abuse TLDs commonly exploited in disposable phishing campaigns
 */
const HIGH_RISK_TLDS = new Set([
  'top', 'xyz', 'click', 'country', 'buzz', 'work', 'gq', 'cf',
  'ml', 'tk', 'ga', 'fit', 'surf', 'rest', 'icu', 'cam', 'monster',
  'stream', 'bid', 'racing', 'download', 'review', 'date', 'faith'
]);

/**
 * Phishing keyword patterns in URL paths or subdomains
 */
const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'verification', 'secure', 'security',
  'account', 'banking', 'update', 'password', 'credential', 'auth',
  'wallet', 'billing', 'confirm', 'support-desk', 'helpdesk-session'
];

/**
 * SSRF Guard: Determine if an IPv4 or IPv6 address is private, loopback, or reserved
 */
export function isPrivateOrReservedIp(ip) {
  if (!ip || typeof ip !== 'string') return false;

  // Clean IPv6-mapped IPv4 e.g. ::ffff:127.0.0.1
  const cleanIp = ip.startsWith('::ffff:') ? ip.replace('::ffff:', '') : ip;

  const version = net.isIP(cleanIp);
  if (version === 4) {
    const parts = cleanIp.split('.').map(Number);
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
      return true; // Malformed -> reject
    }

    const [a, b, c] = parts;

    // Loopback (127.0.0.0/8)
    if (a === 127) return true;
    // Private Network 10.0.0.0/8
    if (a === 10) return true;
    // Private Network 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
    if (a === 172 && b >= 16 && b <= 31) return true;
    // Private Network 192.168.0.0/16
    if (a === 192 && b === 168) return true;
    // Link-Local / Cloud Metadata (169.254.0.0/16 - e.g. AWS/GCP 169.254.169.254)
    if (a === 169 && b === 254) return true;
    // Broadcast / Local Identification (0.0.0.0/8)
    if (a === 0) return true;
    // Carrier-grade NAT (100.64.0.0/10)
    if (a === 100 && b >= 64 && b <= 127) return true;
    // Test/Documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
    if (a === 192 && b === 0 && c === 2) return true;
    if (a === 198 && b === 51 && c === 100) return true;
    if (a === 203 && b === 0 && c === 113) return true;
    // Multicast & Reserved (224.0.0.0/4 and 240.0.0.0/4)
    if (a >= 224) return true;

    return false;
  }

  if (version === 6) {
    const lower = cleanIp.toLowerCase();
    // IPv6 Loopback
    if (lower === '::1') return true;
    // Unspecified
    if (lower === '::') return true;
    // Unique Local Address (fc00::/7)
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
    // Link-Local Unicast (fe80::/10)
    if (lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) return true;

    return false;
  }

  return false;
}

/**
 * Computes Shannon entropy of a string (higher entropy = more random/DGA-like)
 */
export function calculateShannonEntropy(str) {
  if (!str || typeof str !== 'string' || str.length === 0) return 0;

  const len = str.length;
  const frequencies = new Map();

  for (const char of str) {
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }

  let entropy = 0;
  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return Number(entropy.toFixed(3));
}

/**
 * Assesses risk based on the domain's Top-Level Domain (TLD)
 */
export function evaluateTldRisk(domainInfo) {
  if (!domainInfo || !domainInfo.hostname) {
    return { level: 'unknown', reason: 'Unable to parse domain hostname' };
  }

  const parts = domainInfo.hostname.split('.');
  const tld = parts[parts.length - 1].toLowerCase();

  if (HIGH_RISK_TLDS.has(tld)) {
    return {
      level: 'high',
      tld,
      reason: `TLD ".${tld}" has elevated prevalence in malicious and disposable phishing campaigns.`
    };
  }

  return {
    level: 'low',
    tld,
    reason: `TLD ".${tld}" standard reputation.`
  };
}

/**
 * Verify DNS A records and MX mail exchanger records for a domain
 */
export async function checkDomainDnsAndMx(hostname) {
  const result = {
    resolves: false,
    ipAddresses: [],
    hasValidMx: false,
    mxRecords: [],
    warnings: []
  };

  if (!hostname || typeof hostname !== 'string') return result;

  try {
    // 1. Resolve IPv4 A-records
    const ips = await dns.resolve4(hostname).catch(() => []);
    if (ips.length > 0) {
      result.resolves = true;
      result.ipAddresses = ips;

      // Check if any resolved IP is private/reserved (DNS rebinding / SSRF attempt)
      const hasPrivateIp = ips.some(isPrivateOrReservedIp);
      if (hasPrivateIp) {
        result.warnings.push('DNS records resolve to private/reserved IP space (potential DNS rebinding)');
      }
    }
  } catch (err) {
    // Non-resolvable domain
  }

  try {
    // 2. Resolve MX records
    const mx = await dns.resolveMx(hostname).catch(() => []);
    if (mx.length > 0) {
      result.hasValidMx = true;
      result.mxRecords = mx.map(m => ({ exchange: m.exchange, priority: m.priority }));
    } else if (result.resolves) {
      result.warnings.push('Domain resolves via A-record but lacks valid MX records (uncommon for legitimate email senders)');
    }
  } catch (err) {
    // MX lookup failure
  }

  if (!result.resolves) {
    result.warnings.push('Domain does not resolve via public DNS (potentially defunct or staging phishing domain)');
  }

  return result;
}

/**
 * Safely trace redirect hops (e.g. bit.ly, tinyurl) while enforcing SSRF protection
 */
export async function traceRedirectsSafe(targetUrl, maxHops = 5) {
  const hops = [];
  let currentUrl = targetUrl;

  for (let step = 0; step < maxHops; step++) {
    let parsed;
    try {
      parsed = new URL(currentUrl);
    } catch {
      break;
    }

    if (!['http:', 'https:'].includes(parsed.protocol)) {
      hops.push({
        url: currentUrl,
        status: 400,
        error: 'Invalid or forbidden protocol'
      });
      break;
    }

    // SSRF Check: Direct hostname verification
    if (isPrivateOrReservedIp(parsed.hostname) || parsed.hostname === 'localhost') {
      throw new Error(`SSRF_BLOCKED: Access to private or loopback host "${parsed.hostname}" is forbidden`);
    }

    // SSRF Check: Resolve hostname to verify destination IP before fetching
    try {
      const resolvedIps = await dns.resolve4(parsed.hostname).catch(() => []);
      if (resolvedIps.some(isPrivateOrReservedIp)) {
        throw new Error(`SSRF_BLOCKED: Hostname "${parsed.hostname}" resolves to protected private IP range`);
      }
    } catch (dnsErr) {
      if (dnsErr.message.startsWith('SSRF_BLOCKED')) throw dnsErr;
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3500);

      // Perform HEAD request to inspect headers without downloading body
      let res = await fetch(currentUrl, {
        method: 'HEAD',
        redirect: 'manual',
        signal: controller.signal,
        headers: {
          'User-Agent': 'PhishGuard-ThreatIntel/1.0 (+https://phishguard.security)'
        }
      });
      clearTimeout(timeoutId);

      // If HEAD is rejected with 405 Method Not Allowed, fallback to GET
      if (res.status === 405) {
        const getController = new AbortController();
        const getTimeout = setTimeout(() => getController.abort(), 3500);
        res = await fetch(currentUrl, {
          method: 'GET',
          redirect: 'manual',
          signal: getController.signal,
          headers: {
            'User-Agent': 'PhishGuard-ThreatIntel/1.0 (+https://phishguard.security)'
          }
        });
        clearTimeout(getTimeout);
      }

      hops.push({
        url: currentUrl,
        status: res.status,
        destination: res.headers.get('location') || null
      });

      const location = res.headers.get('location');
      const isRedirect = [301, 302, 303, 307, 308].includes(res.status);

      if (isRedirect && location) {
        // Resolve relative redirects against current URL
        currentUrl = new URL(location, currentUrl).toString();
      } else {
        // Destination reached
        break;
      }
    } catch (err) {
      if (err.message?.startsWith('SSRF_BLOCKED')) throw err;
      hops.push({
        url: currentUrl,
        status: 0,
        error: err.name === 'AbortError' ? 'Connection timed out' : (err.message || 'Request failed')
      });
      break;
    }
  }

  return {
    initialUrl: targetUrl,
    finalUrl: currentUrl,
    hopCount: hops.length,
    hops,
    isRedirected: currentUrl !== targetUrl
  };
}

/**
 * Complete Threat Intelligence Inspector for any URL
 */
export async function inspectUrlThreatIntel(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string' || rawUrl.trim().length === 0) {
    throw new Error('Valid URL string is required for threat intelligence inspection');
  }

  const domainInfo = extractDomainInfo(rawUrl);
  if (!domainInfo) {
    throw new Error('Malformed URL: Unable to extract domain details');
  }

  // 1. Calculate Shannon Entropy on main domain name
  const entropy = calculateShannonEntropy(domainInfo.mainDomainName);
  const isHighEntropy = entropy >= 3.6 && domainInfo.mainDomainName.length >= 8;

  // 2. TLD Risk Evaluation
  const tldRisk = evaluateTldRisk(domainInfo);

  // 3. Keyword Heuristics
  const lowerUrl = rawUrl.toLowerCase();
  const matchedKeywords = SUSPICIOUS_KEYWORDS.filter(kw => lowerUrl.includes(kw));

  // 4. Trace redirects safely with SSRF protection
  let redirectInfo = {
    initialUrl: rawUrl,
    finalUrl: rawUrl,
    hopCount: 1,
    hops: [],
    isRedirected: false
  };

  try {
    redirectInfo = await traceRedirectsSafe(rawUrl);
  } catch (err) {
    if (err.message?.startsWith('SSRF_BLOCKED')) {
      return {
        url: rawUrl,
        domainInfo,
        threatScore: 95,
        verdict: 'MALICIOUS',
        ssrfBlocked: true,
        error: err.message,
        indicators: [
          {
            type: 'ssrf_vector',
            severity: 'CRITICAL',
            detail: err.message
          }
        ]
      };
    }
    // Continue with domain checks if network probe failed
    redirectInfo.error = err.message;
  }

  // 5. DNS and MX Check on the final target hostname
  const targetDomainInfo = extractDomainInfo(redirectInfo.finalUrl) || domainInfo;
  const dnsReport = await checkDomainDnsAndMx(targetDomainInfo.hostname);

  // 6. Compute Threat Intelligence Score (0 - 100)
  let threatScore = 0;
  const indicators = [];

  if (isHighEntropy) {
    threatScore += 25;
    indicators.push({
      type: 'dga_entropy',
      severity: 'MEDIUM',
      detail: `High Shannon entropy (${entropy}): domain name exhibits algorithmic randomness characteristic of DGA malware/phishing.`
    });
  }

  if (tldRisk.level === 'high') {
    threatScore += 25;
    indicators.push({
      type: 'high_risk_tld',
      severity: 'HIGH',
      detail: tldRisk.reason
    });
  }

  if (matchedKeywords.length >= 2) {
    threatScore += 25;
    indicators.push({
      type: 'suspicious_credential_keywords',
      severity: 'MEDIUM',
      detail: `URL contains sensitive authentication keywords: ${matchedKeywords.join(', ')}`
    });
  } else if (matchedKeywords.length === 1) {
    threatScore += 10;
  }

  if (!dnsReport.resolves) {
    threatScore += 30;
    indicators.push({
      type: 'unresolvable_dns',
      severity: 'HIGH',
      detail: 'Domain does not resolve to any public IPv4 address.'
    });
  }

  if (redirectInfo.isRedirected) {
    threatScore += 15;
    indicators.push({
      type: 'url_redirection',
      severity: 'LOW',
      detail: `URL redirects across ${redirectInfo.hopCount} hop(s) to destination: ${redirectInfo.finalUrl}`
    });
  }

  threatScore = Math.min(threatScore, 100);

  let verdict = 'BENIGN';
  if (threatScore >= 60) verdict = 'SUSPICIOUS';
  if (threatScore >= 80) verdict = 'MALICIOUS';

  return {
    url: rawUrl,
    domainInfo,
    threatScore,
    verdict,
    entropy: {
      score: entropy,
      isHighEntropy,
      testedString: domainInfo.mainDomainName
    },
    tldRisk,
    matchedKeywords,
    redirectInfo,
    dnsReport,
    indicators
  };
}
