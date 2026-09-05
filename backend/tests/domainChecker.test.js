import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  checkLookalikeDomain,
  checkAnchorHrefMismatch,
  extractDomainInfo,
  analyzeLinks,
  PROTECTED_BRANDS
} from '../src/utils/domainChecker.js';

describe('Domain Checker - Lookalike & Brand Impersonation', () => {
  it('should identify legitimate domains and not flag them as lookalikes', () => {
    const legitimate = [
      { domain: 'paypal.com', brand: 'PayPal' },
      { domain: 'www.paypal.com', brand: 'PayPal' },
      { domain: 'service.paypal.com', brand: 'PayPal' },
      { domain: 'google.com', brand: 'Google' },
      { domain: 'accounts.google.com', brand: 'Google' },
      { domain: 'microsoft.com', brand: 'Microsoft' },
      { domain: 'apple.com', brand: 'Apple' }
    ];

    for (const item of legitimate) {
      const info = extractDomainInfo(item.domain);
      const result = checkLookalikeDomain(info.registrableDomain, info.mainDomainName);
      assert.ok(result, `Expected a result for ${item.domain}`);
      assert.equal(result.isLegitimateBrand, true, `Expected ${item.domain} to be recognized as legitimate brand`);
      assert.equal(result.brand, item.brand);
    }
  });

  it('should flag known typosquatting and spoofed lookalike domains (distance <= 2)', () => {
    const spoofedDomains = [
      { candidate: 'paypa1.com', targetBrand: 'PayPal' },
      { candidate: 'paypaI.com', targetBrand: 'PayPal' },
      { candidate: 'paypall.com', targetBrand: 'PayPal' },
      { candidate: 'micros0ft.com', targetBrand: 'Microsoft' },
      { candidate: 'goog1e.com', targetBrand: 'Google' },
      { candidate: 'g00gle.com', targetBrand: 'Google' },
      { candidate: 'app1e.com', targetBrand: 'Apple' },
      { candidate: 'amaz0n.com', targetBrand: 'Amazon' },
      { candidate: 'netf1ix.com', targetBrand: 'Netflix' },
      { candidate: 'docus1gn.com', targetBrand: 'DocuSign' }
    ];

    for (const item of spoofedDomains) {
      const info = extractDomainInfo(item.candidate);
      assert.ok(info, `Domain info should extract for ${item.candidate}`);
      const result = checkLookalikeDomain(info.registrableDomain, info.mainDomainName);
      assert.ok(result, `Lookalike check should detect spoofed domain: ${item.candidate}`);
      assert.equal(result.isLookalike, true, `Domain ${item.candidate} must be flagged as lookalike`);
      assert.equal(result.brand, item.targetBrand, `Should identify impersonation of ${item.targetBrand}`);
      assert.ok(result.distance <= 2, `Distance should be <= 2, was ${result.distance}`);
    }
  });

  it('should flag brand impersonation with hyphenated prefix tricks', () => {
    const hyphenTricks = [
      { candidate: 'paypal-security-update.com', targetBrand: 'PayPal' },
      { candidate: 'microsoft-verify.com', targetBrand: 'Microsoft' },
      { candidate: 'apple-id-recovery.net', targetBrand: 'Apple' }
    ];

    for (const item of hyphenTricks) {
      const info = extractDomainInfo(item.candidate);
      const result = checkLookalikeDomain(info.registrableDomain, info.mainDomainName);
      assert.ok(result, `Hyphen trick should be detected for ${item.candidate}`);
      assert.equal(result.isLookalike, true);
      assert.equal(result.brand, item.targetBrand);
    }
  });

  it('should not flag unrelated benign domains', () => {
    const benignDomains = [
      'github.com',
      'stackoverflow.com',
      'wikipedia.org',
      'nytimes.com',
      'weather.com'
    ];

    for (const domain of benignDomains) {
      const info = extractDomainInfo(domain);
      const result = checkLookalikeDomain(info.registrableDomain, info.mainDomainName);
      assert.equal(result, null, `Benign domain ${domain} should not be flagged`);
    }
  });
});

describe('Domain Checker - Anchor Text vs Href Mismatches', () => {
  it('should flag when anchor text displays one domain but links to another', () => {
    const mismatch = checkAnchorHrefMismatch(
      'https://www.paypal.com/signin',
      'http://evil-phishing-site.ru/steal'
    );

    assert.ok(mismatch, 'Expected anchor mismatch to be flagged');
    assert.equal(mismatch.isMismatch, true);
    assert.equal(mismatch.displayedDomain, 'paypal.com');
    assert.equal(mismatch.actualDomain, 'evil-phishing-site.ru');
  });

  it('should not flag when anchor text is descriptive non-URL text', () => {
    const result = checkAnchorHrefMismatch('Click here to review your invoice', 'https://legitimate.com/invoice');
    assert.equal(result, null, 'Non-URL anchor text should not trigger mismatch');
  });

  it('should not flag when anchor URL matches href URL domain', () => {
    const result = checkAnchorHrefMismatch('https://legitimate.com/login', 'https://legitimate.com/login?ref=email');
    assert.equal(result, null, 'Matching domains should not trigger mismatch');
  });
});

describe('Domain Checker - Link Analyzer Suite', () => {
  it('should analyze list of links and aggregate indicators', () => {
    const rawLinks = [
      { href: 'https://paypa1.com/verify', anchorText: 'Verify Account' },
      { href: 'http://192.168.1.50/malware.exe', anchorText: 'Download attachment' },
      { href: 'https://attacker.com/login', anchorText: 'https://chase.com/login' },
      { href: 'https://google.com/search', anchorText: 'Google Search' }
    ];

    const analysis = analyzeLinks(rawLinks);

    assert.equal(analysis.hasSuspiciousLinks, true);
    assert.equal(analysis.links.length, 4);

    const indicatorTypes = analysis.indicators.map(i => i.type);
    assert.ok(indicatorTypes.includes('lookalike_domain'), 'Should include lookalike domain indicator');
    assert.ok(indicatorTypes.includes('ip_address_link'), 'Should include IP address link indicator');
    assert.ok(indicatorTypes.includes('anchor_href_mismatch'), 'Should include anchor mismatch indicator');
  });
});
