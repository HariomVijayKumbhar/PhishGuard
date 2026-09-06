process.env.NODE_ENV = 'test';
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import app from '../src/index.js';

describe('API Route: POST /api/scan', () => {
  let server;
  let baseUrl;

  before(async () => {
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://localhost:${port}`;
        resolve();
      });
    });
  });

  after(async () => {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it('should accept valid JSON raw text scan and return complete AI classification and heuristics', async () => {
    const rawEmail = `From: support@paypa1.com
To: victim@company.com
Subject: Account Verification Needed

Please verify your billing details here: https://paypa1.com/update
`;
    const res = await fetch(`${baseUrl}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email_text: rawEmail })
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.success, true);
    assert.ok(data.requestId, 'Response must include requestId');
    assert.ok(typeof data.data.risk_score === 'number', 'Risk score must be a number');
    assert.ok(['safe', 'suspicious', 'phishing'].includes(data.data.verdict));
    assert.ok(Array.isArray(data.data.tactics_detected));
    assert.ok(typeof data.data.explanation === 'string');
    assert.ok(typeof data.data.safe_summary === 'string');
    assert.ok(data.data.heuristics.lookalikeCount >= 1, 'Should detect paypa1.com lookalike');
    assert.ok(data.data.ai_metadata, 'Response must include ai_metadata');
  });

  it('should support heuristics_only query param for intermediate output', async () => {
    const rawEmail = `From: admin@company.com\nSubject: Test\nBody`;
    const res = await fetch(`${baseUrl}/api/scan?heuristics_only=true`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email_text: rawEmail })
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.mode, 'intermediate_heuristics');
  });

  it('should reject non-JSON and non-multipart Content-Type with HTTP 415', async () => {
    const res = await fetch(`${baseUrl}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: 'Raw plain text without proper header'
    });

    assert.equal(res.status, 415);
    const data = await res.json();
    assert.equal(data.code, 'UNSUPPORTED_MEDIA_TYPE');
    assert.ok(data.requestId);
    assert.ok(!data.stack, 'Response must NEVER contain a stack trace');
  });

  it('should reject empty JSON body with HTTP 400', async () => {
    const res = await fetch(`${baseUrl}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email_text: '   ' })
    });

    assert.equal(res.status, 400);
    const data = await res.json();
    assert.equal(data.code, 'EMPTY_BODY');
    assert.ok(!data.stack, 'Response must NEVER contain a stack trace');
  });

  it('should reject oversized JSON payload (>5MB) with HTTP 413', async () => {
    // Construct ~5.2MB string
    const largeChunk = 'A'.repeat(1024 * 1024); // 1MB
    const oversizedEmail = largeChunk.repeat(6);

    const res = await fetch(`${baseUrl}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email_text: oversizedEmail })
    });

    assert.equal(res.status, 413);
    const data = await res.json();
    assert.equal(data.code, 'PAYLOAD_TOO_LARGE');
    assert.ok(!data.stack);
  });

  it('should handle multipart .eml upload correctly', async () => {
    const sampleEml = `From: security@chase-update.com
To: user@bank.com
Subject: Notice of Account Restriction

Log in to resolve: http://chase-update.com/login
`;
    const formData = new FormData();
    const blob = new Blob([sampleEml], { type: 'message/rfc822' });
    formData.append('file', blob, 'alert.eml');

    const res = await fetch(`${baseUrl}/api/scan`, {
      method: 'POST',
      body: formData
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.success, true);
    assert.equal(data.data.metadata.subject, 'Notice of Account Restriction');
    assert.ok(data.data.heuristics.hasImmediateRedFlags);
  });
});
