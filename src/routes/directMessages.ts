import { Router, Request, Response } from 'express';
import { requireAuth } from '../auth/middleware';
import { getDb } from '../db/database';
import { v4 as uuidv4 } from 'uuid';
import type { DirectMessage, User } from '../types';

const router = Router();

/**
 * GET /api/dm
 *
 * List all DM conversations for the authenticated user.
 * Returns one entry per unique peer, sorted by most-recent message.
 */
router.get('/', requireAuth, (req: Request, res: Response) => {
  const userId = req.user!.id;
  const db = getDb();

  const conversations = db
    .prepare(
      `SELECT
         CASE WHEN sender_id = ? THEN recipient_id ELSE sender_id END AS peer_id,
         MAX(created_at) AS last_message_at
       FROM direct_messages
       WHERE sender_id = ? OR recipient_id = ?
       GROUP BY peer_id
       ORDER BY last_message_at DESC`,
    )
    .all(userId, userId, userId) as { peer_id: string; last_message_at: number }[];

  const result = conversations.map((conv) => {
    const peer = db
      .prepare('SELECT id, display_name, certificate_fingerprint FROM users WHERE id = ?')
      .get(conv.peer_id) as Pick<User, 'id' | 'display_name' | 'certificate_fingerprint'> | undefined;

    return { peer, last_message_at: conv.last_message_at };
  });

  res.json(result);
});

/**
 * GET /api/dm/:userId
 *
 * Retrieve DM history between the authenticated user and `userId`.
 * Messages are returned as-is (encrypted); decryption happens on the client.
 * Supports cursor-based pagination via `?before=<messageId>&limit=<n>`.
 */
router.get('/:userId', requireAuth, (req: Request, res: Response) => {
  const myId = req.user!.id;
  const theirId = req.params.userId;
  const limit = Math.min(parseInt((req.query.limit as string) || '50', 10), 100);
  const before = req.query.before as string | undefined;

  const db = getDb();

  if (!db.prepare('SELECT id FROM users WHERE id = ?').get(theirId)) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  let rows: DirectMessage[];

  if (before) {
    const cursor = db
      .prepare('SELECT created_at FROM direct_messages WHERE id = ?')
      .get(before) as { created_at: number } | undefined;

    if (!cursor) {
      res.status(400).json({ error: 'Invalid pagination cursor' });
      return;
    }

    rows = db
      .prepare(
        `SELECT * FROM direct_messages
         WHERE ((sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?))
           AND created_at < ?
         ORDER BY created_at DESC LIMIT ?`,
      )
      .all(myId, theirId, theirId, myId, cursor.created_at, limit) as DirectMessage[];
  } else {
    rows = db
      .prepare(
        `SELECT * FROM direct_messages
         WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)
         ORDER BY created_at DESC LIMIT ?`,
      )
      .all(myId, theirId, theirId, myId, limit) as DirectMessage[];
  }

  res.json(rows.reverse());
});

/**
 * POST /api/dm/:userId
 *
 * Send a direct message to a user.
 *
 * The client is responsible for encrypting the message content with the
 * recipient's RSA public key (available via GET /api/users/:id) using the
 * `encryptDM()` helper from the crypto module.  The server stores the
 * ciphertext without decrypting it.
 *
 * Body: { encrypted_content: string }
 */
router.post('/:userId', requireAuth, (req: Request, res: Response) => {
  const senderId = req.user!.id;
  const recipientId = req.params.userId;
  const { encrypted_content } = req.body as { encrypted_content?: unknown };

  if (!encrypted_content || typeof encrypted_content !== 'string') {
    res.status(400).json({
      error:
        'encrypted_content is required. Encrypt the plaintext with the recipient\'s ' +
        'public key (GET /api/users/:id → public_key_pem) before sending.',
    });
    return;
  }

  if (senderId === recipientId) {
    res.status(400).json({ error: 'Cannot send a DM to yourself' });
    return;
  }

  const db = getDb();

  if (!db.prepare('SELECT id FROM users WHERE id = ?').get(recipientId)) {
    res.status(404).json({ error: 'Recipient not found' });
    return;
  }

  const dm: DirectMessage = {
    id: uuidv4(),
    sender_id: senderId,
    recipient_id: recipientId,
    encrypted_content,
    created_at: Date.now(),
  };

  db.prepare(
    'INSERT INTO direct_messages (id, sender_id, recipient_id, encrypted_content, created_at) VALUES (?, ?, ?, ?, ?)',
  ).run(dm.id, dm.sender_id, dm.recipient_id, dm.encrypted_content, dm.created_at);

  res.status(201).json(dm);
});

export default router;
