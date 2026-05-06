import Database from 'better-sqlite3';
import { config } from '../config';

let db: Database.Database | null = null;

export function getDb(): Database.Database {
  if (!db) {
    db = new Database(config.dbPath);
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');
    initSchema(db);
  }
  return db;
}

export function closeDb(): void {
  if (db) {
    db.close();
    db = null;
  }
}

function initSchema(instance: Database.Database): void {
  instance.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id                      TEXT PRIMARY KEY,
      certificate_fingerprint TEXT UNIQUE NOT NULL,
      display_name            TEXT NOT NULL,
      public_key_pem          TEXT NOT NULL,
      created_at              INTEGER NOT NULL,
      last_seen               INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS channels (
      id          TEXT PRIMARY KEY,
      name        TEXT UNIQUE NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      created_by  TEXT NOT NULL,
      created_at  INTEGER NOT NULL,
      FOREIGN KEY (created_by) REFERENCES users(id)
    );

    -- Channel messages are encrypted at rest (AES-256-GCM, server-managed key).
    CREATE TABLE IF NOT EXISTS messages (
      id                TEXT PRIMARY KEY,
      channel_id        TEXT NOT NULL,
      user_id           TEXT NOT NULL,
      encrypted_content TEXT NOT NULL,
      iv                TEXT NOT NULL,
      auth_tag          TEXT NOT NULL,
      created_at        INTEGER NOT NULL,
      FOREIGN KEY (channel_id) REFERENCES channels(id),
      FOREIGN KEY (user_id)    REFERENCES users(id)
    );

    -- Direct messages use hybrid RSA+AES client-side E2E encryption.
    -- The server stores the ciphertext and never decrypts it.
    CREATE TABLE IF NOT EXISTS direct_messages (
      id                TEXT PRIMARY KEY,
      sender_id         TEXT NOT NULL,
      recipient_id      TEXT NOT NULL,
      encrypted_content TEXT NOT NULL,
      created_at        INTEGER NOT NULL,
      FOREIGN KEY (sender_id)    REFERENCES users(id),
      FOREIGN KEY (recipient_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS auth_challenges (
      fingerprint TEXT PRIMARY KEY,
      challenge   TEXT NOT NULL,
      expires_at  INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token      TEXT PRIMARY KEY,
      user_id    TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE INDEX IF NOT EXISTS idx_messages_channel
      ON messages(channel_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_dm_recipient
      ON direct_messages(recipient_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_dm_sender
      ON direct_messages(sender_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_sessions_user
      ON sessions(user_id);
  `);
}
