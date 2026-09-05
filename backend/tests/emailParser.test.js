import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseEmailInput, sanitizeEmailHtml, EmailParseError } from '../src/services/emailParser.js';

describe('Email Parser Service', () => {
  const sampleEmlFixture = `From: "PayPal Security" <security@paypa1.com>
To: victim@example.com
Subject: URGENT: Your PayPal Account Has Been Suspended
Date: Wed, 05 Sep 2026 04:30:00 +0000
Message-ID: <12345678@mail.paypa1.com>
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8
Received-SPF: fail (domain of paypa1.com does not designate permitted sender)

<html>
  <body>
    <h2>Security Alert</h2>
    <p>Dear customer, please click below to restore your access:</p>
    <a href="https://paypa1.com/restore">https://www.paypal.com/signin</a>
    <script>alert('xss payload');</script>
  </body>
</html>`;

  const samplePlainText = `From: urgent-update@microsoft-verify.com
To: user@workplace.com
Subject: Critical IT Password Expiration

Your office365 login will expire in 1 hour.
Please visit http://192.168.1.100/reset immediately.
`;

  it('should parse a valid .eml fixture correctly', async () => {
    const result = await parseEmailInput(Buffer.from(sampleEmlFixture, 'utf-8'));

    assert.equal(result.metadata.subject, 'URGENT: Your PayPal Account Has Been Suspended');
    assert.ok(result.metadata.from.includes('PayPal Security'));
    assert.ok(result.heuristics.linksCount >= 1);
    assert.equal(result.heuristics.lookalikeCount, 1);
    assert.equal(result.heuristics.anchorMismatchCount, 1);
    assert.equal(result.heuristics.hasImmediateRedFlags, true);

    // Verify script tag was stripped
    assert.ok(!result.content.sanitizedHtml.includes('<script>'));
    assert.ok(!result.content.sanitizedHtml.includes('alert('));
  });

  it('should parse raw text email content correctly', async () => {
    const result = await parseEmailInput(samplePlainText);

    assert.equal(result.metadata.subject, 'Critical IT Password Expiration');
    assert.ok(result.metadata.from.includes('microsoft-verify.com'));
    assert.equal(result.heuristics.linksCount, 1);
    assert.equal(result.heuristics.ipLinksCount, 1);
    assert.equal(result.heuristics.hasImmediateRedFlags, true);
  });

  it('should reject empty body with clean 400 error', async () => {
    await assert.rejects(
      async () => parseEmailInput(''),
      (err) => {
        assert.ok(err instanceof EmailParseError);
        assert.equal(err.code, 'EMPTY_BODY');
        assert.equal(err.statusCode, 400);
        return true;
      }
    );
  });

  it('should reject whitespace-only body with clean 400 error', async () => {
    await assert.rejects(
      async () => parseEmailInput('   \n\t   '),
      (err) => {
        assert.ok(err instanceof EmailParseError);
        assert.equal(err.code, 'EMPTY_BODY');
        assert.equal(err.statusCode, 400);
        return true;
      }
    );
  });

  it('should sanitize HTML stripping scripts and malicious event handlers', () => {
    const dirtyHtml = `
      <div>
        <p>Legitimate looking text</p>
        <img src="https://tracker.com/pixel.png" onerror="alert(1)" />
        <a href="javascript:stealCookies()">Click me</a>
        <a href="https://safe.com">Safe link</a>
        <iframe src="http://evil.com"></iframe>
      </div>
    `;

    const sanitized = sanitizeEmailHtml(dirtyHtml);

    assert.ok(!sanitized.includes('<script'));
    assert.ok(!sanitized.includes('<iframe'));
    assert.ok(!sanitized.includes('onerror'));
    assert.ok(!sanitized.includes('javascript:stealCookies'));
    assert.ok(sanitized.includes('https://safe.com'));
    assert.ok(sanitized.includes('Legitimate looking text'));
  });
});
