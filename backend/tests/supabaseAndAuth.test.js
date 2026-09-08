import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'http';
import app from '../src/index.js';
import { setSupabaseAdmin } from '../src/services/supabaseClient.js';

// Mock Supabase storage
let mockScans = [];
let mockIndicators = [];
const mockUserId = '11111111-2222-3333-4444-555555555555';
const otherUserId = '99999999-8888-7777-6666-555555555555';

function createMockSupabase() {
  return {
    auth: {
      async getUser(token) {
        if (token === 'valid-user-token') {
          return { data: { user: { id: mockUserId, email: 'user@phishguard.test' } }, error: null };
        }
        if (token === 'other-user-token') {
          return { data: { user: { id: otherUserId, email: 'other@phishguard.test' } }, error: null };
        }
        return { data: { user: null }, error: new Error('Invalid or expired token') };
      }
    },
    from(table) {
      if (table === 'scans') {
        return {
          insert(row) {
            const inserted = {
              id: `scan-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
              created_at: new Date().toISOString(),
              ...row
            };
            mockScans.push(inserted);
            return {
              select() {
                return {
                  single: async () => ({ data: inserted, error: null })
                };
              }
            };
          },
          select(fields, options = {}) {
            let filtered = [...mockScans];
            const chain = {
              eq(col, val) {
                filtered = filtered.filter(s => s[col] === val);
                return chain;
              },
              order(col, { ascending = true } = {}) {
                filtered.sort((a, b) => {
                  if (ascending) return a[col] > b[col] ? 1 : -1;
                  return a[col] < b[col] ? 1 : -1;
                });
                return chain;
              },
              range(start, end) {
                const sliced = filtered.slice(start, end + 1);
                return {
                  data: sliced,
                  count: filtered.length,
                  error: null
                };
              },
              single: async () => {
                if (filtered.length === 0) return { data: null, error: { message: 'Not found' } };
                return { data: filtered[0], error: null };
              },
              then(resolve) {
                resolve({ data: filtered, count: filtered.length, error: null });
              }
            };
            return chain;
          }
        };
      }

      if (table === 'flagged_indicators') {
        return {
          insert(rows) {
            const list = Array.isArray(rows) ? rows : [rows];
            for (const r of list) {
              mockIndicators.push({
                id: `ind-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
                created_at: new Date().toISOString(),
                ...r
              });
            }
            return Promise.resolve({ error: null });
          },
          select() {
            let filtered = [...mockIndicators];
            const chain = {
              eq(col, val) {
                filtered = filtered.filter(i => i[col] === val);
                return chain;
              },
              order() {
                return chain;
              },
              then(resolve) {
                resolve({ data: filtered, error: null });
              }
            };
            return chain;
          }
        };
      }

      throw new Error(`Unexpected table: ${table}`);
    }
  };
}

describe('Database & Auth Layer (Supabase Integration)', () => {
  let server;
  let baseUrl;

  before(async () => {
    process.env.NODE_ENV = 'test';
    setSupabaseAdmin(createMockSupabase());

    server = http.createServer(app);
    await new Promise((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });
  });

  after(async () => {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  beforeEach(() => {
    mockScans = [];
    mockIndicators = [];
  });

  it('should reject access to protected endpoints when no token is provided (401)', async () => {
    const res = await fetch(`${baseUrl}/api/scans`);
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.code, 'AUTH_REQUIRED');
  });

  it('should reject access to protected endpoints with an invalid token (401)', async () => {
    const res = await fetch(`${baseUrl}/api/scans`, {
      headers: { Authorization: 'Bearer bad-token' }
    });
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.code, 'AUTH_FAILED');
  });

  it('should allow anonymous scan and not persist without authentication', async () => {
    const res = await fetch(`${baseUrl}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email_text: 'Hello, this is a standard test email.',
        provider: 'mock'
      })
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.data.scan_id, null);
    assert.equal(mockScans.length, 0);
  });

  it('should persist scan to Supabase and return scan_id when authenticated', async () => {
    const res = await fetch(`${baseUrl}/api/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer valid-user-token'
      },
      body: JSON.stringify({
        email_text: `From: security@paypa1.com\nSubject: Account Verification Required\n\nUrgent: Click http://paypa1.com to verify your account immediately.`,
        provider: 'mock'
      })
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.ok(body.data.scan_id, 'Expected scan_id to be populated');
    assert.equal(mockScans.length, 1);
    assert.equal(mockScans[0].user_id, mockUserId);
    assert.equal(mockScans[0].verdict, 'phishing');

    // Indicators should be populated for the lookalike domain
    assert.ok(mockIndicators.length > 0);
    assert.equal(mockIndicators[0].scan_id, body.data.scan_id);
    assert.equal(mockIndicators[0].indicator_type, 'lookalike_domain');
  });

  it('should return user scan history via GET /api/scans scoped to authenticated user', async () => {
    // Insert one scan for mockUserId and one for otherUserId
    mockScans.push(
      {
        id: 'scan-1',
        user_id: mockUserId,
        subject: 'Legit Email',
        sender: 'alice@example.com',
        risk_score: 5,
        verdict: 'safe',
        created_at: new Date().toISOString()
      },
      {
        id: 'scan-2',
        user_id: otherUserId,
        subject: 'Secret Email',
        sender: 'bob@example.com',
        risk_score: 95,
        verdict: 'phishing',
        created_at: new Date().toISOString()
      }
    );

    const res = await fetch(`${baseUrl}/api/scans`, {
      headers: { Authorization: 'Bearer valid-user-token' }
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.equal(body.scans.length, 1);
    assert.equal(body.scans[0].id, 'scan-1');
    assert.equal(body.scans[0].user_id, mockUserId);
  });

  it('should return scan details and indicators via GET /api/scans/:id', async () => {
    const scanId = 'scan-detail-123';
    mockScans.push({
      id: scanId,
      user_id: mockUserId,
      subject: 'Phishing Attempt',
      sender: 'spoofer@evil.com',
      risk_score: 90,
      verdict: 'phishing',
      tactics_detected: ['urgency', 'credential_harvesting'],
      explanation: 'Detected fake login attempt.',
      safe_summary: 'An alert asking for verification.',
      created_at: new Date().toISOString()
    });

    mockIndicators.push({
      id: 'ind-1',
      scan_id: scanId,
      indicator_type: 'lookalike_domain',
      detail: 'Spoofed paypal domain detected'
    });

    const res = await fetch(`${baseUrl}/api/scans/${scanId}`, {
      headers: { Authorization: 'Bearer valid-user-token' }
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.equal(body.scan.id, scanId);
    assert.equal(body.scan.indicators.length, 1);
    assert.equal(body.scan.indicators[0].indicator_type, 'lookalike_domain');
  });

  it('should return 404 when querying another user’s scan via GET /api/scans/:id', async () => {
    const otherScanId = 'scan-private-456';
    mockScans.push({
      id: otherScanId,
      user_id: otherUserId,
      subject: 'Private email',
      created_at: new Date().toISOString()
    });

    const res = await fetch(`${baseUrl}/api/scans/${otherScanId}`, {
      headers: { Authorization: 'Bearer valid-user-token' }
    });

    assert.equal(res.status, 404);
  });

  it('should return aggregated metrics for the user via GET /api/metrics', async () => {
    mockScans.push(
      {
        id: 's1',
        user_id: mockUserId,
        risk_score: 10,
        verdict: 'safe',
        tactics_detected: []
      },
      {
        id: 's2',
        user_id: mockUserId,
        risk_score: 60,
        verdict: 'suspicious',
        tactics_detected: ['urgency']
      },
      {
        id: 's3',
        user_id: mockUserId,
        risk_score: 90,
        verdict: 'phishing',
        tactics_detected: ['urgency', 'authority_impersonation']
      }
    );

    const res = await fetch(`${baseUrl}/api/metrics`, {
      headers: { Authorization: 'Bearer valid-user-token' }
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.equal(body.metrics.total_scans, 3);
    assert.equal(body.metrics.safe_detected, 1);
    assert.equal(body.metrics.suspicious_detected, 1);
    assert.equal(body.metrics.phishing_detected, 1);
    assert.equal(body.metrics.average_risk_score, 53); // (10+60+90)/3 = 53.33 -> 53
    assert.equal(body.metrics.top_tactics[0].tactic, 'urgency');
    assert.equal(body.metrics.top_tactics[0].count, 2);
  });
});
