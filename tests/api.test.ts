import crypto from 'crypto';
import { execSync } from 'child_process';
import fs from 'fs';
import request from 'supertest';
import { createApp } from '../src/app';
import { closeDb } from '../src/db/database';

// ── Helpers ───────────────────────────────────────────────────────────────────

function generateSelfSignedCert(cn = 'APITest') {
  const tmpDir = `/tmp/barkchat-api-test-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  fs.mkdirSync(tmpDir, { recursive: true });

  execSync(
    `openssl req -x509 -newkey rsa:2048 \
      -keyout ${tmpDir}/key.pem \
      -out    ${tmpDir}/cert.pem \
      -days 1 -nodes \
      -subj "/CN=${cn}"`,
    { stdio: 'pipe' },
  );

  const certPem = fs.readFileSync(`${tmpDir}/cert.pem`, 'utf8');
  const privateKeyPem = fs.readFileSync(`${tmpDir}/key.pem`, 'utf8');
  fs.rmSync(tmpDir, { recursive: true });

  const fingerprint = new crypto.X509Certificate(certPem).fingerprint256
    .replace(/:/g, '')
    .toLowerCase();

  return { certPem, privateKeyPem, fingerprint };
}

async function loginUser(
  app: ReturnType<typeof createApp>,
  certPem: string,
  privateKeyPem: string,
  fingerprint: string,
) {
  const challengeRes = await request(app)
    .post('/api/auth/challenge')
    .send({ fingerprint });

  const sign = crypto.createSign('SHA256');
  sign.update(challengeRes.body.challenge as string);
  const signature = sign.sign(privateKeyPem).toString('hex');

  const loginRes = await request(app)
    .post('/api/auth/login')
    .send({ certificate: certPem, fingerprint, signature });

  return loginRes.body as { token: string; user: { id: string; display_name: string } };
}

// ── Test suite ────────────────────────────────────────────────────────────────

describe('BarkChat REST API', () => {
  const app = createApp();

  let certPem: string;
  let privateKeyPem: string;
  let fingerprint: string;
  let authToken: string;
  let userId: string;
  let channelId: string;

  beforeAll(async () => {
    const cert = generateSelfSignedCert('Alice');
    certPem = cert.certPem;
    privateKeyPem = cert.privateKeyPem;
    fingerprint = cert.fingerprint;

    // Register
    await request(app)
      .post('/api/auth/register')
      .send({ certificate: certPem, displayName: 'Alice' });

    // Login
    const session = await loginUser(app, certPem, privateKeyPem, fingerprint);
    authToken = session.token;
    userId = session.user.id;
  });

  afterAll(() => closeDb());

  // ── Health ──────────────────────────────────────────────────────────────────

  describe('Health check', () => {
    test('GET /health → 200', async () => {
      const res = await request(app).get('/health');
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('ok');
    });
  });

  // ── Auth ────────────────────────────────────────────────────────────────────

  describe('POST /api/auth/register', () => {
    test('registers a new user', async () => {
      const { certPem: c } = generateSelfSignedCert('Bob');
      const res = await request(app)
        .post('/api/auth/register')
        .send({ certificate: c, displayName: 'Bob' });

      expect(res.status).toBe(201);
      expect(res.body.display_name).toBe('Bob');
      expect(res.body.certificate_fingerprint).toBeTruthy();
    });

    test('returns 400 for missing certificate', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ displayName: 'No Cert' });
      expect(res.status).toBe(400);
    });

    test('returns 400 for invalid certificate', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ certificate: 'not-a-cert', displayName: 'Bad' });
      expect(res.status).toBe(400);
    });
  });

  describe('POST /api/auth/challenge + /api/auth/login', () => {
    test('issues a session token for valid credentials', async () => {
      expect(authToken).toMatch(/^[0-9a-f]{64}$/);
    });

    test('rejects login with invalid signature', async () => {
      await request(app).post('/api/auth/challenge').send({ fingerprint });
      const res = await request(app)
        .post('/api/auth/login')
        .send({ certificate: certPem, fingerprint, signature: 'deadbeef' });
      expect(res.status).toBe(401);
    });

    test('returns 400 when fields are missing', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ certificate: certPem });
      expect(res.status).toBe(400);
    });
  });

  describe('POST /api/auth/logout', () => {
    test('invalidates the session token', async () => {
      const cert = generateSelfSignedCert('LogoutUser');
      await request(app)
        .post('/api/auth/register')
        .send({ certificate: cert.certPem, displayName: 'LogoutUser' });
      const session = await loginUser(app, cert.certPem, cert.privateKeyPem, cert.fingerprint);

      const logoutRes = await request(app)
        .post('/api/auth/logout')
        .set('Authorization', `Bearer ${session.token}`);
      expect(logoutRes.status).toBe(200);

      // Token should now be invalid
      const meRes = await request(app)
        .get('/api/users/me')
        .set('Authorization', `Bearer ${session.token}`);
      expect(meRes.status).toBe(401);
    });
  });

  // ── Users ───────────────────────────────────────────────────────────────────

  describe('GET /api/users/me', () => {
    test('returns the current user', async () => {
      const res = await request(app)
        .get('/api/users/me')
        .set('Authorization', `Bearer ${authToken}`);
      expect(res.status).toBe(200);
      expect(res.body.id).toBe(userId);
    });

    test('returns 401 without a token', async () => {
      expect((await request(app).get('/api/users/me')).status).toBe(401);
    });
  });

  describe('GET /api/users', () => {
    test('lists registered users', async () => {
      const res = await request(app)
        .get('/api/users')
        .set('Authorization', `Bearer ${authToken}`);
      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body.length).toBeGreaterThan(0);
    });
  });

  describe('GET /api/users/:id', () => {
    test('returns user with public_key_pem', async () => {
      const res = await request(app)
        .get(`/api/users/${userId}`)
        .set('Authorization', `Bearer ${authToken}`);
      expect(res.status).toBe(200);
      expect(res.body.public_key_pem).toContain('PUBLIC KEY');
    });

    test('returns 404 for unknown user', async () => {
      const res = await request(app)
        .get('/api/users/does-not-exist')
        .set('Authorization', `Bearer ${authToken}`);
      expect(res.status).toBe(404);
    });
  });

  // ── Channels ─────────────────────────────────────────────────────────────────

  describe('POST /api/channels', () => {
    test('creates a channel', async () => {
      const res = await request(app)
        .post('/api/channels')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ name: 'general', description: 'General discussion' });

      expect(res.status).toBe(201);
      expect(res.body.name).toBe('general');
      channelId = res.body.id;
    });

    test('returns 409 for duplicate name', async () => {
      const res = await request(app)
        .post('/api/channels')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ name: 'general' });
      expect(res.status).toBe(409);
    });

    test('returns 400 for missing name', async () => {
      const res = await request(app)
        .post('/api/channels')
        .set('Authorization', `Bearer ${authToken}`)
        .send({});
      expect(res.status).toBe(400);
    });
  });

  describe('GET /api/channels', () => {
    test('lists channels', async () => {
      const res = await request(app)
        .get('/api/channels')
        .set('Authorization', `Bearer ${authToken}`);
      expect(res.status).toBe(200);
      expect(res.body.some((c: { name: string }) => c.name === 'general')).toBe(true);
    });
  });

  describe('GET /api/channels/:id', () => {
    test('returns the channel', async () => {
      const res = await request(app)
        .get(`/api/channels/${channelId}`)
        .set('Authorization', `Bearer ${authToken}`);
      expect(res.status).toBe(200);
      expect(res.body.id).toBe(channelId);
    });

    test('returns 404 for unknown channel', async () => {
      const res = await request(app)
        .get('/api/channels/no-such-channel')
        .set('Authorization', `Bearer ${authToken}`);
      expect(res.status).toBe(404);
    });
  });

  // ── Messages ─────────────────────────────────────────────────────────────────

  describe('POST /api/channels/:channelId/messages', () => {
    test('sends and returns a message', async () => {
      const res = await request(app)
        .post(`/api/channels/${channelId}/messages`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({ content: 'Hello, World!' });

      expect(res.status).toBe(201);
      expect(res.body.content).toBe('Hello, World!');
    });

    test('returns 400 for empty content', async () => {
      const res = await request(app)
        .post(`/api/channels/${channelId}/messages`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({ content: '' });
      expect(res.status).toBe(400);
    });
  });

  describe('GET /api/channels/:channelId/messages', () => {
    test('returns decrypted messages in chronological order', async () => {
      const res = await request(app)
        .get(`/api/channels/${channelId}/messages`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body[0].content).toBe('Hello, World!');
      // Chronological: earlier messages come first
      if (res.body.length > 1) {
        expect(res.body[0].created_at).toBeLessThanOrEqual(res.body[1].created_at);
      }
    });
  });

  // ── Direct messages ───────────────────────────────────────────────────────────

  describe('Direct messages', () => {
    let bobCert: ReturnType<typeof generateSelfSignedCert>;
    let bobToken: string;
    let bobUserId: string;
    let bobPublicKey: string;

    beforeAll(async () => {
      bobCert = generateSelfSignedCert('Bob-DM');
      await request(app)
        .post('/api/auth/register')
        .send({ certificate: bobCert.certPem, displayName: 'Bob-DM' });

      const session = await loginUser(
        app,
        bobCert.certPem,
        bobCert.privateKeyPem,
        bobCert.fingerprint,
      );
      bobToken = session.token;
      bobUserId = session.user.id;

      // Fetch Bob's public key
      const userRes = await request(app)
        .get(`/api/users/${bobUserId}`)
        .set('Authorization', `Bearer ${authToken}`);
      bobPublicKey = userRes.body.public_key_pem as string;
    });

    test('POST /api/dm/:userId – Alice sends Bob an encrypted DM', async () => {
      const { encryptDM } = await import('../src/crypto/encryption');
      const encrypted = encryptDM('Hey Bob, this is private!', bobPublicKey);

      const res = await request(app)
        .post(`/api/dm/${bobUserId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({ encrypted_content: encrypted });

      expect(res.status).toBe(201);
      expect(res.body.sender_id).toBe(userId);
      expect(res.body.recipient_id).toBe(bobUserId);
    });

    test('GET /api/dm/:userId – Bob retrieves the DM conversation', async () => {
      const res = await request(app)
        .get(`/api/dm/${userId}`)
        .set('Authorization', `Bearer ${bobToken}`);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body.length).toBeGreaterThan(0);
    });

    test('GET /api/dm – returns conversation list', async () => {
      const res = await request(app)
        .get('/api/dm')
        .set('Authorization', `Bearer ${bobToken}`);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body[0].peer).toBeDefined();
    });

    test('returns 400 when sending a DM to yourself', async () => {
      const { encryptDM } = await import('../src/crypto/encryption');
      const encrypted = encryptDM('selfie', bobPublicKey);

      const res = await request(app)
        .post(`/api/dm/${bobUserId}`)
        .set('Authorization', `Bearer ${bobToken}`)
        .send({ encrypted_content: encrypted });

      expect(res.status).toBe(400);
    });

    test('returns 400 when encrypted_content is missing', async () => {
      const res = await request(app)
        .post(`/api/dm/${bobUserId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({});
      expect(res.status).toBe(400);
    });
  });

  // ── Authorization guard ───────────────────────────────────────────────────────

  describe('Authorization guards', () => {
    const endpoints = [
      { method: 'get', path: '/api/channels' },
      { method: 'get', path: '/api/users' },
      { method: 'get', path: '/api/users/me' },
      { method: 'get', path: '/api/dm' },
    ];

    endpoints.forEach(({ method, path }) => {
      test(`${method.toUpperCase()} ${path} → 401 without token`, async () => {
        const res = await (request(app) as unknown as Record<string, (p: string) => request.Test>)[method](path);
        expect(res.status).toBe(401);
      });
    });

    test('rejects a syntactically valid but unknown token', async () => {
      const res = await request(app)
        .get('/api/channels')
        .set('Authorization', `Bearer ${'a'.repeat(64)}`);
      expect(res.status).toBe(401);
    });
  });

  // ── Channel deletion ──────────────────────────────────────────────────────────

  describe('DELETE /api/channels/:id', () => {
    test("non-owner cannot delete another user's channel", async () => {
      const cert = generateSelfSignedCert('Charlie');
      await request(app)
        .post('/api/auth/register')
        .send({ certificate: cert.certPem, displayName: 'Charlie' });
      const session = await loginUser(app, cert.certPem, cert.privateKeyPem, cert.fingerprint);

      const res = await request(app)
        .delete(`/api/channels/${channelId}`)
        .set('Authorization', `Bearer ${session.token}`);
      expect(res.status).toBe(403);
    });

    test('owner can delete their channel', async () => {
      // Create a temporary channel owned by Alice
      const createRes = await request(app)
        .post('/api/channels')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ name: 'to-be-deleted' });

      const deleteRes = await request(app)
        .delete(`/api/channels/${createRes.body.id}`)
        .set('Authorization', `Bearer ${authToken}`);
      expect(deleteRes.status).toBe(204);
    });
  });
});
