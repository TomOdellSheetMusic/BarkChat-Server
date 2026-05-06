import crypto from 'crypto';
import { execSync } from 'child_process';
import fs from 'fs';
import {
  parseCertificate,
  generateChallenge,
  verifyChallenge,
  registerOrGetUser,
  createSession,
  validateSession,
  revokeSession,
} from '../src/auth/certificate';
import { closeDb } from '../src/db/database';

// ── Test certificate helper ───────────────────────────────────────────────────

function generateSelfSignedCert(cn = 'TestUser'): {
  certPem: string;
  privateKeyPem: string;
  fingerprint: string;
} {
  const tmpDir = `/tmp/barkchat-auth-test-${Date.now()}`;
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

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('Certificate parsing', () => {
  let certPem: string;

  beforeAll(() => {
    ({ certPem } = generateSelfSignedCert());
  });

  test('parseCertificate extracts a 64-char hex fingerprint', () => {
    const { fingerprint } = parseCertificate(certPem);
    expect(fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  test('parseCertificate extracts the SPKI public key', () => {
    const { publicKeyPem } = parseCertificate(certPem);
    expect(publicKeyPem).toContain('PUBLIC KEY');
  });

  test('parseCertificate throws on invalid input', () => {
    expect(() => parseCertificate('not a certificate')).toThrow();
  });
});

describe('User registration', () => {
  let certPem: string;
  let fingerprint: string;

  beforeAll(() => {
    ({ certPem, fingerprint } = generateSelfSignedCert('RegUser'));
  });

  afterAll(() => closeDb());

  test('creates a new user on first call', () => {
    const user = registerOrGetUser(certPem, 'RegUser');
    expect(user.id).toBeTruthy();
    expect(user.display_name).toBe('RegUser');
    expect(user.certificate_fingerprint).toBe(fingerprint);
  });

  test('returns the same user on subsequent calls (idempotent)', () => {
    const u1 = registerOrGetUser(certPem, 'RegUser');
    const u2 = registerOrGetUser(certPem, 'DifferentName');
    expect(u1.id).toBe(u2.id);
    // Display name is set on first registration; later calls don't overwrite it.
    expect(u2.display_name).toBe('RegUser');
  });
});

describe('Challenge / response authentication', () => {
  let certPem: string;
  let privateKeyPem: string;
  let fingerprint: string;

  beforeAll(() => {
    ({ certPem, privateKeyPem, fingerprint } = generateSelfSignedCert('AuthUser'));
    registerOrGetUser(certPem, 'AuthUser');
  });

  afterAll(() => closeDb());

  test('generateChallenge returns a 64-char hex string', () => {
    const ch = generateChallenge(fingerprint);
    expect(ch).toMatch(/^[0-9a-f]{64}$/);
  });

  test('verifyChallenge accepts a valid SHA-256 signature', () => {
    const ch = generateChallenge(fingerprint);

    const sign = crypto.createSign('SHA256');
    sign.update(ch);
    const sig = sign.sign(privateKeyPem).toString('hex');

    expect(verifyChallenge(fingerprint, sig, certPem)).toBe(true);
  });

  test('verifyChallenge rejects a forged signature', () => {
    generateChallenge(fingerprint); // create one so there is a row
    const fakeSig = crypto.randomBytes(256).toString('hex');
    // Will be false AND consume the challenge
    expect(verifyChallenge(fingerprint, fakeSig, certPem)).toBe(false);
  });

  test('verifyChallenge returns false when no challenge exists', () => {
    expect(verifyChallenge('deadbeef'.repeat(8), 'fakesig', certPem)).toBe(false);
  });

  test('challenge is one-time use (second verify fails)', () => {
    const ch = generateChallenge(fingerprint);

    const sign = crypto.createSign('SHA256');
    sign.update(ch);
    const sig = sign.sign(privateKeyPem).toString('hex');

    expect(verifyChallenge(fingerprint, sig, certPem)).toBe(true);
    // The challenge was consumed; a second attempt must fail
    expect(verifyChallenge(fingerprint, sig, certPem)).toBe(false);
  });
});

describe('Session management', () => {
  let certPem: string;
  let userId: string;

  beforeAll(() => {
    ({ certPem } = generateSelfSignedCert('SessionUser'));
    const user = registerOrGetUser(certPem, 'SessionUser');
    userId = user.id;
  });

  afterAll(() => closeDb());

  test('createSession returns a 64-char hex token', () => {
    const token = createSession(userId);
    expect(token).toMatch(/^[0-9a-f]{64}$/);
  });

  test('validateSession returns the user for a valid token', () => {
    const token = createSession(userId);
    const user = validateSession(token);
    expect(user).not.toBeNull();
    expect(user!.id).toBe(userId);
  });

  test('validateSession returns null for an unknown token', () => {
    expect(validateSession('notarealtoken')).toBeNull();
  });

  test('revokeSession invalidates the token', () => {
    const token = createSession(userId);
    revokeSession(token);
    expect(validateSession(token)).toBeNull();
  });
});
