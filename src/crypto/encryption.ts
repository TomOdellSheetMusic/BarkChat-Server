import crypto from 'crypto';
import { config } from '../config';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;       // 96-bit IV recommended for GCM
const AUTH_TAG_LENGTH = 16; // 128-bit authentication tag

function getServerKey(): Buffer {
  if (config.encryptionKey.length !== 64) {
    throw new Error('ENCRYPTION_KEY must be exactly 64 hex characters (32 bytes)');
  }
  return Buffer.from(config.encryptionKey, 'hex');
}

// ── Server-side AES-256-GCM (channel messages) ────────────────────────────────

export interface EncryptedPayload {
  encrypted: string; // base64
  iv: string;        // base64
  authTag: string;   // base64
}

/**
 * Encrypt a plaintext string using AES-256-GCM with the server's master key.
 * Used to store channel messages at rest.
 */
export function encrypt(plaintext: string): EncryptedPayload {
  const key = getServerKey();
  const iv = crypto.randomBytes(IV_LENGTH);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });

  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);

  return {
    encrypted: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    authTag: cipher.getAuthTag().toString('base64'),
  };
}

/**
 * Decrypt an AES-256-GCM payload produced by `encrypt()`.
 * Throws if the auth tag is invalid (tampering / wrong key).
 */
export function decrypt(payload: EncryptedPayload): string {
  const key = getServerKey();
  const iv = Buffer.from(payload.iv, 'base64');
  const authTag = Buffer.from(payload.authTag, 'base64');
  const encryptedBuf = Buffer.from(payload.encrypted, 'base64');

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([decipher.update(encryptedBuf), decipher.final()]);
  return decrypted.toString('utf8');
}

// ── Client-side E2E encryption helpers (direct messages) ──────────────────────
//
// Direct messages use a hybrid scheme:
//   1. A fresh AES-256-GCM key is generated per message.
//   2. The message is encrypted with that AES key.
//   3. The AES key is encrypted with the recipient's RSA-OAEP public key.
//
// The server stores the resulting opaque blob and never decrypts it.
// Only the recipient (who holds the matching private key) can read the message.

/**
 * Encrypt a direct-message string for a recipient.
 *
 * @param plaintext          - Plaintext message content.
 * @param recipientPublicKey - Recipient's RSA public key in SPKI PEM format.
 * @returns Opaque colon-delimited base64 string suitable for storage / transit.
 */
export function encryptDM(plaintext: string, recipientPublicKey: string): string {
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(IV_LENGTH);

  const cipher = crypto.createCipheriv(ALGORITHM, aesKey, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });
  const encryptedMsg = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const encryptedAesKey = crypto.publicEncrypt(
    {
      key: recipientPublicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    aesKey,
  );

  // Format: base64(encKey):base64(iv):base64(authTag):base64(ciphertext)
  return [
    encryptedAesKey.toString('base64'),
    iv.toString('base64'),
    authTag.toString('base64'),
    encryptedMsg.toString('base64'),
  ].join(':');
}

/**
 * Decrypt a direct message produced by `encryptDM()`.
 *
 * @param encryptedPayload   - Opaque payload from `encryptDM()`.
 * @param recipientPrivateKey - Recipient's RSA private key in PKCS8 PEM format.
 * @returns Plaintext message content.
 *
 * Note: In production this operation happens on the client, not the server.
 * This function is exposed for testing and for reference client implementations.
 */
export function decryptDM(encryptedPayload: string, recipientPrivateKey: string): string {
  const [encKeyB64, ivB64, authTagB64, encMsgB64] = encryptedPayload.split(':');

  const aesKey = crypto.privateDecrypt(
    {
      key: recipientPrivateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(encKeyB64, 'base64'),
  );

  const iv = Buffer.from(ivB64, 'base64');
  const authTag = Buffer.from(authTagB64, 'base64');
  const encMsg = Buffer.from(encMsgB64, 'base64');

  const decipher = crypto.createDecipheriv(ALGORITHM, aesKey, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([decipher.update(encMsg), decipher.final()]);
  return decrypted.toString('utf8');
}
