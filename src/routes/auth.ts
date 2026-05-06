import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import {
  parseCertificate,
  generateChallenge,
  verifyChallenge,
  registerOrGetUser,
  createSession,
  revokeSession,
} from '../auth/certificate';
import { requireAuth } from '../auth/middleware';

const router = Router();

/**
 * POST /api/auth/register
 *
 * Register a user with their X.509 certificate (PEM).
 * If the certificate fingerprint already exists the existing user record is
 * returned (idempotent).
 *
 * Body: { certificate: string, displayName: string }
 */
router.post('/register', (req: Request, res: Response) => {
  const { certificate, displayName } = req.body as {
    certificate?: unknown;
    displayName?: unknown;
  };

  if (!certificate || typeof certificate !== 'string') {
    res.status(400).json({ error: 'certificate (PEM string) is required' });
    return;
  }
  if (!displayName || typeof displayName !== 'string' || !displayName.trim()) {
    res.status(400).json({ error: 'displayName is required' });
    return;
  }

  try {
    const user = registerOrGetUser(certificate, displayName.trim());
    res.status(201).json({
      id: user.id,
      display_name: user.display_name,
      certificate_fingerprint: user.certificate_fingerprint,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    res.status(400).json({ error: `Invalid certificate: ${msg}` });
  }
});

/**
 * POST /api/auth/challenge
 *
 * Obtain a one-time challenge string to sign with the client private key.
 * The challenge expires after 5 minutes.
 *
 * Body: { fingerprint: string }
 */
router.post('/challenge', (req: Request, res: Response) => {
  const { fingerprint } = req.body as { fingerprint?: unknown };

  if (!fingerprint || typeof fingerprint !== 'string') {
    res.status(400).json({ error: 'fingerprint is required' });
    return;
  }

  const challenge = generateChallenge(fingerprint.toLowerCase());
  res.json({ challenge });
});

/**
 * POST /api/auth/login
 *
 * Verify a challenge-response and issue a session token.
 *
 * Body: { certificate: string, fingerprint: string, signature: string (hex) }
 *
 * The `signature` must be the SHA-256 signature of the challenge bytes,
 * encoded as a lowercase hexadecimal string, produced with the private key
 * that corresponds to the submitted certificate.
 */
router.post('/login', (req: Request, res: Response) => {
  const { certificate, fingerprint, signature } = req.body as {
    certificate?: unknown;
    fingerprint?: unknown;
    signature?: unknown;
  };

  if (!certificate || !fingerprint || !signature) {
    res.status(400).json({
      error: 'certificate, fingerprint, and signature are all required',
    });
    return;
  }
  if (
    typeof certificate !== 'string' ||
    typeof fingerprint !== 'string' ||
    typeof signature !== 'string'
  ) {
    res.status(400).json({ error: 'All fields must be strings' });
    return;
  }

  try {
    const valid = verifyChallenge(fingerprint.toLowerCase(), signature, certificate);
    if (!valid) {
      res.status(401).json({ error: 'Invalid signature or expired challenge' });
      return;
    }

    const user = registerOrGetUser(certificate, 'Anonymous');
    const token = createSession(user.id);

    res.json({
      token,
      user: {
        id: user.id,
        display_name: user.display_name,
        certificate_fingerprint: user.certificate_fingerprint,
      },
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    res.status(400).json({ error: `Authentication failed: ${msg}` });
  }
});

/**
 * POST /api/auth/logout
 *
 * Revoke the current session token (requires a valid Bearer token).
 */
router.post('/logout', requireAuth, (req: Request, res: Response) => {
  const token = req.headers.authorization!.slice(7);
  revokeSession(token);
  res.json({ message: 'Logged out successfully' });
});

/**
 * GET /api/auth/cert-info
 *
 * Parse and return metadata from a submitted PEM certificate without storing it.
 * Useful for clients to preview a certificate before registering.
 *
 * Body: { certificate: string }
 */
router.post('/cert-info', (req: Request, res: Response) => {
  const { certificate } = req.body as { certificate?: unknown };

  if (!certificate || typeof certificate !== 'string') {
    res.status(400).json({ error: 'certificate (PEM string) is required' });
    return;
  }

  try {
    const { fingerprint, publicKeyPem } = parseCertificate(certificate);
    const cert = new crypto.X509Certificate(certificate);
    res.json({
      fingerprint,
      subject: cert.subject,
      issuer: cert.issuer,
      validFrom: cert.validFrom,
      validTo: cert.validTo,
      publicKeyPem,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    res.status(400).json({ error: `Invalid certificate: ${msg}` });
  }
});

export default router;
