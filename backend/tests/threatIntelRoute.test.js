import { test, describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import express from 'express';
import {
  isPrivateOrReservedIp,
  calculateShannonEntropy,
  evaluateTldRisk,
  inspectUrlThreatIntel
} from '../src/services/threatIntelService.js';
import {
  defangUrl,
  defangIp,
  extractIOCs,
  generateSocTicketMarkdown,
  generateBlocklistRules,
  generateTeamWarningAlert
} from '../src/services/incidentResponseService.js';
import scanRouter from '../src/routes/scan.js';

describe('Threat Intel & SSRF Security Defense', () => {
  it('should flag private, loopback, and cloud metadata IPs as reserved (SSRF guard)', () => {
    // IPv4 private/reserved ranges
    assert.equal(isPrivateOrReservedIp('127.0.0.1'), true);
    assert.equal(isPrivateOrReservedIp('127.255.255.254'), true);
    assert.equal(isPrivateOrReservedIp('10.0.0.1'), true);
    assert.equal(isPrivateOrReservedIp('10.254.1.99'), true);
    assert.equal(isPrivateOrReservedIp('172.16.0.1'), true);
    assert.equal(isPrivateOrReservedIp('172.31.255.255'), true);
    assert.equal(isPrivateOrReservedIp('192.168.1.1'), true);
    assert.equal(isPrivateOrReservedIp('169.254.169.254'), true); // AWS/GCP Metadata
    assert.equal(isPrivateOrReservedIp('0.0.0.0'), true);
    assert.equal(isPrivateOrReservedIp('100.64.0.1'), true); // CGNAT

    // IPv6 loopback & unique local
    assert.equal(isPrivateOrReservedIp('::1'), true);
    assert.equal(isPrivateOrReservedIp('fc00::1'), true);
    assert.equal(isPrivateOrReservedIp('fe80::1'), true);

    // Public Internet IPs should NOT be blocked
    assert.equal(isPrivateOrReservedIp('8.8.8.8'), false);
    assert.equal(isPrivateOrReservedIp('1.1.1.1'), false);
    assert.equal(isPrivateOrReservedIp('93.184.216.34'), false);
  });

  it('should accurately calculate Shannon entropy on domain names', () => {
    // Normal English words have lower entropy
    const normalEntropy = calculateShannonEntropy('google');
    // High-entropy random algorithmic string (DGA)
    const randomEntropy = calculateShannonEntropy('x7k9p2m4q91z8b5a');

    assert.ok(normalEntropy < 3.0, `Expected lower entropy for normal domain, got ${normalEntropy}`);
    assert.ok(randomEntropy > 3.5, `Expected high entropy for random string, got ${randomEntropy}`);
  });

  it('should flag known high-risk TLDs', () => {
    const riskCheck = evaluateTldRisk({ hostname: 'verify-login.xyz' });
    assert.equal(riskCheck.level, 'high');

    const legitCheck = evaluateTldRisk({ hostname: 'github.com' });
    assert.equal(legitCheck.level, 'low');
  });

  it('should block SSRF attempts targeting localhost or private IPs', async () => {
    const result = await inspectUrlThreatIntel('http://127.0.0.1:8080/admin');
    assert.equal(result.ssrfBlocked, true);
    assert.equal(result.verdict, 'MALICIOUS');
    assert.ok(result.indicators.some(i => i.type === 'ssrf_vector'));
  });

  it('should inspect standard URLs and return complete telemetry', async () => {
    const result = await inspectUrlThreatIntel('https://example.com');
    assert.ok(result.domainInfo);
    assert.equal(result.domainInfo.mainDomainName, 'example');
    assert.ok(typeof result.threatScore === 'number');
    assert.ok(['BENIGN', 'SUSPICIOUS', 'MALICIOUS'].includes(result.verdict));
    assert.ok(result.dnsReport);
  });
});

describe('SOC Incident Response & Defanging Engine', () => {
  it('should correctly defang URLs and IP addresses', () => {
    const defangedHttp = defangUrl('http://paypa1-security.com/login?token=123');
    assert.equal(defangedHttp, 'hxxp[://]paypa1-security[.]com/login?token=123');

    const defangedHttps = defangUrl('https://evil.co.uk/steal');
    assert.equal(defangedHttps, 'hxxps[://]evil[.]co[.]uk/steal');

    const defangedIp = defangIp('198.51.100.24');
    assert.equal(defangedIp, '198[.]51[.]100[.]24');
  });

  it('should extract comprehensive IOCs and calculate payload SHA-256', () => {
    const mockParsed = {
      metadata: {
        from: 'Support Team <support@paypa1-security.com>',
        subject: 'Urgent: Account Locked'
      },
      content: {
        textBody: 'Please click http://paypa1-security.com to verify your credentials.'
      },
      securityHeaders: {
        spf: 'fail',
        dkim: 'none',
        dmarc: 'fail'
      },
      heuristics: {
        analyzedLinks: [
          { href: 'http://paypa1-security.com', domain: 'paypa1-security.com' }
        ],
        flaggedIndicators: [
          { type: 'lookalike_domain', detail: 'Lookalike domain spoofing PayPal' }
        ]
      }
    };

    const mockAi = {
      risk_score: 95,
      verdict: 'phishing',
      tactics_detected: ['Urgency', 'Credential harvesting'],
      explanation: 'Sender uses a lookalike domain and failed SPF.',
      safe_summary: 'Asks user to click link to unlock account.'
    };

    const iocs = extractIOCs(mockParsed, mockAi);

    assert.ok(iocs.emailSha256, 'Should generate SHA-256 hash');
    assert.equal(iocs.emailSha256.length, 64);
    assert.equal(iocs.senderEmail, 'support@paypa1-security.com');
    assert.equal(iocs.senderDomain, 'paypa1-security.com');
    assert.ok(iocs.defangedUrls.includes('hxxp[://]paypa1-security[.]com'));
    assert.ok(iocs.lookalikes.length > 0);

    // Test Markdown Ticket Generation
    const ticket = generateSocTicketMarkdown(iocs, mockAi);
    assert.ok(ticket.includes('[SEC-INCIDENT]'));
    assert.ok(ticket.includes(iocs.emailSha256));
    assert.ok(ticket.includes('Recommended SOC Mitigation'));

    // Test Blocklist Generation
    const blocklists = generateBlocklistRules(iocs);
    assert.ok(blocklists.hostsFormat.includes('0.0.0.0 paypa1-security.com'));
    assert.ok(blocklists.cloudflareCsv.includes('BLOCK'));

    // Test Team Alert
    const alert = generateTeamWarningAlert(iocs, mockAi);
    assert.ok(alert.includes('SECURITY ALERT: Suspicious Email Reported'));
    assert.ok(alert.includes('support@paypa1-security.com'));
  });
});

describe('Threat Intel & Incident Response API Endpoints', () => {
  let server;
  let baseUrl;

  before(async () => {
    const app = express();
    app.use(express.json());
    app.use('/api', scanRouter);

    await new Promise((resolve) => {
      server = app.listen(0, '127.0.0.1', () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });
  });

  after(async () => {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it('POST /api/intel/inspect-url should reject missing url with HTTP 400', async () => {
    const res = await fetch(`${baseUrl}/api/intel/inspect-url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });

    assert.equal(res.status, 400);
    const body = await res.json();
    assert.equal(body.code, 'MISSING_URL');
  });

  it('POST /api/intel/inspect-url should inspect a target URL and return report', async () => {
    const res = await fetch(`${baseUrl}/api/intel/inspect-url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'https://example.com' })
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.ok(body.data.domainInfo);
    assert.ok(typeof body.data.threatScore === 'number');
  });

  it('POST /api/incident/export should generate incident response package', async () => {
    const res = await fetch(`${baseUrl}/api/incident/export`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        parsed_email: {
          metadata: { from: 'spoof@evil-login.com', subject: 'Password Expiry' },
          content: { textBody: 'Reset now: http://evil-login.com/pwd' },
          heuristics: {
            analyzedLinks: [{ href: 'http://evil-login.com/pwd', domain: 'evil-login.com' }]
          }
        },
        scan_result: {
          risk_score: 90,
          verdict: 'MALICIOUS',
          explanation: 'Credential harvester targeting enterprise passwords.'
        }
      })
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.ok(body.data.iocs);
    assert.ok(body.data.socTicket);
    assert.ok(body.data.blocklistRules.hostsFormat);
    assert.ok(body.data.teamAlert);
  });
});
