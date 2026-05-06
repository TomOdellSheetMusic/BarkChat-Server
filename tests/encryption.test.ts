import crypto from 'crypto';
import { encrypt, decrypt, encryptDM, decryptDM } from '../src/crypto/encryption';

describe('AES-256-GCM channel-message encryption', () => {
  test('encrypts and decrypts a plaintext message', () => {
    const plaintext = 'Hello, BarkChat!';
    const payload = encrypt(plaintext);

    expect(payload.encrypted).toBeDefined();
    expect(payload.iv).toBeDefined();
    expect(payload.authTag).toBeDefined();
    expect(payload.encrypted).not.toBe(plaintext);

    expect(decrypt(payload)).toBe(plaintext);
  });

  test('uses a random IV so the same plaintext produces different ciphertext', () => {
    const p1 = encrypt('same message');
    const p2 = encrypt('same message');

    expect(p1.iv).not.toBe(p2.iv);
    expect(p1.encrypted).not.toBe(p2.encrypted);
  });

  test('throws when the auth tag is tampered with', () => {
    const payload = encrypt('tamper-auth-tag');
    expect(() =>
      decrypt({ ...payload, authTag: Buffer.alloc(16).toString('base64') }),
    ).toThrow();
  });

  test('throws when the ciphertext is tampered with', () => {
    const payload = encrypt('tamper-ciphertext');
    expect(() =>
      decrypt({ ...payload, encrypted: Buffer.alloc(16).toString('base64') }),
    ).toThrow();
  });

  test('round-trips an empty string', () => {
    expect(decrypt(encrypt(''))).toBe('');
  });

  test('round-trips unicode and special characters', () => {
    const text = '🐕 Woof! <script>alert("xss")</script> \n\t © ® ™';
    expect(decrypt(encrypt(text))).toBe(text);
  });

  test('round-trips a large string (10 KB)', () => {
    const text = 'A'.repeat(10_240);
    expect(decrypt(encrypt(text))).toBe(text);
  });
});

describe('RSA-OAEP / AES-GCM hybrid DM encryption', () => {
  let privateKeyPem: string;
  let publicKeyPem: string;

  beforeAll(() => {
    const pair = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    privateKeyPem = pair.privateKey;
    publicKeyPem = pair.publicKey;
  });

  test('encrypts and decrypts a direct message', () => {
    const message = 'This is a private direct message.';
    const encrypted = encryptDM(message, publicKeyPem);
    expect(decryptDM(encrypted, privateKeyPem)).toBe(message);
  });

  test('handles long messages (> 2048 bytes)', () => {
    const message = 'B'.repeat(4_000);
    expect(decryptDM(encryptDM(message, publicKeyPem), privateKeyPem)).toBe(message);
  });

  test('produces different ciphertext on every call (random AES key + IV)', () => {
    const msg = 'repeatable?';
    const e1 = encryptDM(msg, publicKeyPem);
    const e2 = encryptDM(msg, publicKeyPem);
    expect(e1).not.toBe(e2);
  });

  test('throws when decrypted with the wrong private key', () => {
    const { privateKey: wrongKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const encrypted = encryptDM('secret', publicKeyPem);
    expect(() => decryptDM(encrypted, wrongKey)).toThrow();
  });

  test('round-trips unicode characters', () => {
    const message = '🔐 Ultra-secret: αβγδ ∑∏∫';
    expect(decryptDM(encryptDM(message, publicKeyPem), privateKeyPem)).toBe(message);
  });
});
