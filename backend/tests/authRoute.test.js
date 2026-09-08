import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'http';
import app from '../src/index.js';

describe('Auth Routes (POST /api/auth/register, POST /api/auth/login, GET /api/auth/me)', () => {
  let server;
  let baseUrl;

  before(async () => {
    process.env.NODE_ENV = 'test';
    server = http.createServer(app);
    await new Promise((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });
  });

  after((done) => {
    server.close(done);
  });

  function makeRequest({ method, path, headers = {}, body = null }) {
    return new Promise((resolve, reject) => {
      const url = new URL(path, baseUrl);
      const req = http.request(url, { method, headers }, (res) => {
        let raw = '';
        res.on('data', chunk => raw += chunk);
        res.on('end', () => {
          let json = null;
          try {
            json = JSON.parse(raw);
          } catch {
            json = raw;
          }
          resolve({ status: res.statusCode, body: json });
        });
      });

      req.on('error', reject);

      if (body) {
        req.write(typeof body === 'string' ? body : JSON.stringify(body));
      }
      req.end();
    });
  }

  it('should reject registration with invalid email', async () => {
    const res = await makeRequest({
      method: 'POST',
      path: '/api/auth/register',
      headers: { 'Content-Type': 'application/json' },
      body: { email: 'not-an-email', password: 'Password123!' }
    });

    assert.equal(res.status, 400);
    assert.equal(res.body.code, 'INVALID_EMAIL');
  });

  it('should reject registration with weak password (< 8 chars)', async () => {
    const res = await makeRequest({
      method: 'POST',
      path: '/api/auth/register',
      headers: { 'Content-Type': 'application/json' },
      body: { email: 'valid@example.com', password: 'short' }
    });

    assert.equal(res.status, 400);
    assert.equal(res.body.code, 'WEAK_PASSWORD');
  });

  it('should register a valid new user and return a token', async () => {
    // Unique email per run to avoid collision with the in-memory dev store
    const uniqueEmail = `alice_${Date.now().toString(36)}@phishguard.test`;
    global.__testEmail = uniqueEmail; // share with later tests

    const res = await makeRequest({
      method: 'POST',
      path: '/api/auth/register',
      headers: { 'Content-Type': 'application/json' },
      body: { email: uniqueEmail, password: 'ValidPassword123!' }
    });

    assert.equal(res.status, 201);
    assert.equal(res.body.success, true);
    assert.equal(res.body.user.email, uniqueEmail);
    assert.ok(res.body.token, 'Must return an authentication token');
  });

  it('should reject duplicate registration for existing email', async () => {
    const email = global.__testEmail || 'alice@phishguard.test';
    const res = await makeRequest({
      method: 'POST',
      path: '/api/auth/register',
      headers: { 'Content-Type': 'application/json' },
      body: { email, password: 'ValidPassword123!' }
    });

    assert.equal(res.status, 409);
    assert.equal(res.body.code, 'USER_ALREADY_EXISTS');
  });

  it('should log in successfully with registered credentials', async () => {
    const email = global.__testEmail || 'alice@phishguard.test';
    const res = await makeRequest({
      method: 'POST',
      path: '/api/auth/login',
      headers: { 'Content-Type': 'application/json' },
      body: { email, password: 'ValidPassword123!' }
    });

    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    assert.equal(res.body.user.email, email);
    assert.ok(res.body.token);
  });

  it('should reject login with wrong password', async () => {
    const email = global.__testEmail || 'alice@phishguard.test';
    const res = await makeRequest({
      method: 'POST',
      path: '/api/auth/login',
      headers: { 'Content-Type': 'application/json' },
      body: { email, password: 'WrongPassword123!' }
    });

    assert.equal(res.status, 401);
    assert.equal(res.body.code, 'INVALID_CREDENTIALS');
  });

  it('should get current user profile with valid Bearer token on GET /api/auth/me', async () => {
    const email = global.__testEmail || 'alice@phishguard.test';
    // 1. Log in to get token
    const loginRes = await makeRequest({
      method: 'POST',
      path: '/api/auth/login',
      headers: { 'Content-Type': 'application/json' },
      body: { email, password: 'ValidPassword123!' }
    });
    const token = loginRes.body.token;

    // 2. Call /api/auth/me
    const meRes = await makeRequest({
      method: 'GET',
      path: '/api/auth/me',
      headers: { 'Authorization': `Bearer ${token}` }
    });

    assert.equal(meRes.status, 200);
    assert.equal(meRes.body.success, true);
    assert.equal(meRes.body.user.email, email);
  });

  it('should reject GET /api/auth/me without Bearer token', async () => {
    const res = await makeRequest({
      method: 'GET',
      path: '/api/auth/me'
    });

    assert.equal(res.status, 401);
    assert.equal(res.body.code, 'AUTH_REQUIRED');
  });
});
