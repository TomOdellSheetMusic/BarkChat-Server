import { Router, Request, Response } from 'express';
import { requireAuth } from '../auth/middleware';
import { getDb } from '../db/database';
import { encrypt, decrypt } from '../crypto/encryption';
import { v4 as uuidv4 } from 'uuid';
import type { Message, Channel } from '../types';

// mergeParams: true lets us access :channelId from the parent router path.
const router = Router({ mergeParams: true });

/**
 * GET /api/channels/:channelId/messages
 *
 * Return messages for a channel in chronological order, decrypted.
 * Supports cursor-based pagination via `?before=<messageId>&limit=<n>`.
 */
router.get('/', requireAuth, (req: Request, res: Response) => {
  const { channelId } = req.params;
  const limit = Math.min(parseInt((req.query.limit as string) || '50', 10), 100);
  const before = req.query.before as string | undefined;

  const db = getDb();

  const channel = db
    .prepare('SELECT id FROM channels WHERE id = ?')
    .get(channelId) as Channel | undefined;
  if (!channel) {
    res.status(404).json({ error: 'Channel not found' });
    return;
  }

  let rows: Message[];

  if (before) {
    const cursor = db
      .prepare('SELECT created_at FROM messages WHERE id = ?')
      .get(before) as { created_at: number } | undefined;

    if (!cursor) {
      res.status(400).json({ error: 'Invalid pagination cursor' });
      return;
    }

    rows = db
      .prepare(
        `SELECT * FROM messages
         WHERE channel_id = ? AND created_at < ?
         ORDER BY created_at DESC LIMIT ?`,
      )
      .all(channelId, cursor.created_at, limit) as Message[];
  } else {
    rows = db
      .prepare(
        `SELECT * FROM messages
         WHERE channel_id = ?
         ORDER BY created_at DESC LIMIT ?`,
      )
      .all(channelId, limit) as Message[];
  }

  const decrypted = rows.map((msg) => {
    try {
      const content = decrypt({
        encrypted: msg.encrypted_content,
        iv: msg.iv,
        authTag: msg.auth_tag,
      });
      return { id: msg.id, channel_id: msg.channel_id, user_id: msg.user_id, content, created_at: msg.created_at };
    } catch {
      return { id: msg.id, channel_id: msg.channel_id, user_id: msg.user_id, content: '[decryption failed]', created_at: msg.created_at };
    }
  });

  // Return in chronological order (oldest first)
  res.json(decrypted.reverse());
});

/**
 * POST /api/channels/:channelId/messages
 *
 * Send a message to a channel.  The server encrypts the content at rest using
 * AES-256-GCM before persisting it.
 *
 * Body: { content: string }
 */
router.post('/', requireAuth, (req: Request, res: Response) => {
  const { channelId } = req.params;
  const { content } = req.body as { content?: unknown };

  if (!content || typeof content !== 'string' || !content.trim()) {
    res.status(400).json({ error: 'Message content is required' });
    return;
  }

  const db = getDb();

  const channel = db
    .prepare('SELECT id FROM channels WHERE id = ?')
    .get(channelId) as Channel | undefined;
  if (!channel) {
    res.status(404).json({ error: 'Channel not found' });
    return;
  }

  const { encrypted, iv, authTag } = encrypt(content.trim());

  const message: Message = {
    id: uuidv4(),
    channel_id: channelId,
    user_id: req.user!.id,
    encrypted_content: encrypted,
    iv,
    auth_tag: authTag,
    created_at: Date.now(),
  };

  db.prepare(
    `INSERT INTO messages
       (id, channel_id, user_id, encrypted_content, iv, auth_tag, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    message.id,
    message.channel_id,
    message.user_id,
    message.encrypted_content,
    message.iv,
    message.auth_tag,
    message.created_at,
  );

  res.status(201).json({
    id: message.id,
    channel_id: message.channel_id,
    user_id: message.user_id,
    content: content.trim(),
    created_at: message.created_at,
  });
});

export default router;
