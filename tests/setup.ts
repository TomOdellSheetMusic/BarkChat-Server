// This file runs before every test file in its own Jest worker context.
// Environment variables set here are visible to all module imports in the test.
import crypto from 'crypto';

process.env.NODE_ENV = 'test';
process.env.DB_PATH = ':memory:';
// Generate a fresh 32-byte hex key so encryption tests always have a valid key.
process.env.ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
