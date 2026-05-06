import crypto from 'crypto';
import { getDb } from '../db/database';
import { config } from '../config';
import { v4 as uuidv4 } from 'uuid';
import type { User } from '../types';

// ── Certificate helpers ───────────────────────────────────────────────────────

/**
 * Parse a PEM-encoded X.509 certificate and extract its SHA-256 fingerprint
 * and the SPKI public key in PEM format.
 */
export function parseCertificate(pemCert: string): {
  fingerprint: string;
  publicKeyPem: string;
} {
  const cert = new crypto.X509Certificate(pemCert);
  // fingerprint256 is colon-separated hex, e.g. "AB:CD:..."
  const fingerprint = cert.fingerprint256.replace(/:/g, '').toLowerCase();
  const publicKeyPem = cert.publicKey.export({ type: 'spki', format: 'pem' }) as string;
  return { fingerprint, publicKeyPem };
}

// ── Challenge / response ──────────────────────────────────────────────────────

/**
 * Generate a 32-byte random hex challenge for the given certificate fingerprint.
 * The challenge is stored in the database and expires after `config.challengeTtlMs`.
 */
export function generateChallenge(fingerprint: string): string {
  const challenge = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + config.challengeTtlMs;

  getDb()
    .prepare(
      `INSERT OR REPLACE INTO auth_challenges (fingerprint, challenge, expires_at)
       VALUES (?, ?, ?)`,
    )
    .run(fingerprint, challenge, expiresAt);

  return challenge;
}

/**
 * Verify a challenge-response authentication attempt (Mumble-style).
 *
 * The client signs the raw challenge string with their private key using
 * SHA-256 and sends the hex-encoded DER signature.
 *
 * Returns `true` if the signature is valid and the challenge has not expired.
 * The challenge is deleted from the database after use (one-time use).
 */
export function verifyChallenge(
  fingerprint: string,
  signatureHex: string,
  pemCert: string,
): boolean {
  const db = getDb();

  const row = db
    .prepare('SELECT challenge, expires_at FROM auth_challenges WHERE fingerprint = ?')
    .get(fingerprint) as { challenge: string; expires_at: number } | undefined;

  if (!row) return false;

  if (Date.now() > row.expires_at) {
    db.prepare('DELETE FROM auth_challenges WHERE fingerprint = ?').run(fingerprint);
    return false;
  }

  try {
    const cert = new crypto.X509Certificate(pemCert);
    const verify = crypto.createVerify('SHA256');
    verify.update(row.challenge);
    const valid = verify.verify(cert.publicKey, Buffer.from(signatureHex, 'hex'));
    // Always consume the challenge (one-time use)
    db.prepare('DELETE FROM auth_challenges WHERE fingerprint = ?').run(fingerprint);
    return valid;
  } catch {
    return false;
  }
}

// ── User registration ──────────────────────────────────────────────────────────

/**
 * Register a new user identified by their certificate, or update `last_seen`
 * if the certificate fingerprint already exists in the database.
 *
 * The `displayName` is only used during the initial registration; subsequent
 * calls with the same certificate retain the original display name.
 */
export function registerOrGetUser(pemCert: string, displayName: string): User {
  const { fingerprint, publicKeyPem } = parseCertificate(pemCert);
  const db = getDb();

  const existing = db
    .prepare('SELECT * FROM users WHERE certificate_fingerprint = ?')
    .get(fingerprint) as User | undefined;

  if (existing) {
    db.prepare('UPDATE users SET last_seen = ? WHERE id = ?').run(Date.now(), existing.id);
    return existing;
  }

  const now = Date.now();
  const user: User = {
    id: uuidv4(),
    certificate_fingerprint: fingerprint,
    display_name: displayName,
    public_key_pem: publicKeyPem,
    created_at: now,
    last_seen: now,
  };

  db.prepare(
    `INSERT INTO users
       (id, certificate_fingerprint, display_name, public_key_pem, created_at, last_seen)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(
    user.id,
    user.certificate_fingerprint,
    user.display_name,
    user.public_key_pem,
    user.created_at,
    user.last_seen,
  );

  return user;
}

// ── Session management ────────────────────────────────────────────────────────

/**
 * Create and persist a new 32-byte random session token for a user.
 * Returns the hex-encoded token.
 */
export function createSession(userId: string): string {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + config.sessionTtlMs;

  getDb()
    .prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
    .run(token, userId, expiresAt);

  return token;
}

/**
 * Validate a session token and return the associated user, or `null` if the
 * token is missing, expired, or the user no longer exists.
 */
export function validateSession(token: string): User | null {
  const db = getDb();

  const session = db
    .prepare('SELECT user_id FROM sessions WHERE token = ? AND expires_at > ?')
    .get(token, Date.now()) as { user_id: string } | undefined;

  if (!session) return null;

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id) as
    | User
    | undefined;
  if (!user) return null;

  db.prepare('UPDATE users SET last_seen = ? WHERE id = ?').run(Date.now(), user.id);
  return user;
}

/**
 * Revoke a session token (logout).
 */
export function revokeSession(token: string): void {
  getDb().prepare('DELETE FROM sessions WHERE token = ?').run(token);
}

/**
 * Remove all expired sessions and authentication challenges from the database.
 * Intended to be called periodically (e.g. every 15 minutes).
 */
export function cleanupExpired(): void {
  const now = Date.now();
  getDb().prepare('DELETE FROM sessions WHERE expires_at < ?').run(now);
  getDb().prepare('DELETE FROM auth_challenges WHERE expires_at < ?').run(now);
}
