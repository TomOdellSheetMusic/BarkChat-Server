import dotenv from 'dotenv';
import path from 'path';
import crypto from 'crypto';

dotenv.config();

export const config = {
  port: parseInt(process.env.PORT || '3000', 10),
  encryptionKey: process.env.ENCRYPTION_KEY || '',
  dbPath: process.env.DB_PATH || path.join(process.cwd(), 'barkchat.db'),
  trustProxy: process.env.TRUST_PROXY === 'true',
  /**
   * Allowed CORS origins (comma-separated list, or '*' for open access).
   * In production restrict to your client origin, e.g.:
   *   CORS_ORIGIN=https://chat.example.com
   */
  corsOrigin: process.env.CORS_ORIGIN || '*',
  https: {
    enabled: process.env.HTTPS_ENABLED === 'true',
    keyPath: process.env.HTTPS_KEY_PATH || './certs/server.key',
    certPath: process.env.HTTPS_CERT_PATH || './certs/server.crt',
  },
  /** Session lifetime in milliseconds (default 24 h). */
  sessionTtlMs: 24 * 60 * 60 * 1000,
  /** Authentication challenge lifetime in milliseconds (default 5 min). */
  challengeTtlMs: 5 * 60 * 1000,
  /** Rate-limit window for auth endpoints in milliseconds (default 15 min). */
  authRateLimitWindowMs: 15 * 60 * 1000,
  /** Maximum auth requests per IP per window (default 30). */
  authRateLimitMax: 30,
};

if (!config.encryptionKey) {
  config.encryptionKey = crypto.randomBytes(32).toString('hex');
  if (process.env.NODE_ENV !== 'test') {
    console.warn(
      '[BarkChat] WARNING: No ENCRYPTION_KEY set in environment. ' +
        'A temporary key was generated – stored messages will NOT be recoverable after restart. ' +
        'Set ENCRYPTION_KEY in your .env file for production deployments.',
    );
  }
}
