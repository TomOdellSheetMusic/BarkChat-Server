import { Router, Request, Response } from 'express';
import { requireAuth } from '../auth/middleware';
import { getDb } from '../db/database';
import { v4 as uuidv4 } from 'uuid';
import type { Channel } from '../types';

const router = Router();

/**
 * GET /api/channels
 * List all channels.
 */
router.get('/', requireAuth, (_req: Request, res: Response) => {
  const channels = getDb()
    .prepare('SELECT * FROM channels ORDER BY name')
    .all() as Channel[];
  res.json(channels);
});

/**
 * POST /api/channels
 * Create a new channel.
 * Body: { name: string, description?: string }
 */
router.post('/', requireAuth, (req: Request, res: Response) => {
  const { name, description = '' } = req.body as {
    name?: unknown;
    description?: unknown;
  };

  if (!name || typeof name !== 'string' || !name.trim()) {
    res.status(400).json({ error: 'Channel name is required' });
    return;
  }

  const channel: Channel = {
    id: uuidv4(),
    name: (name as string).trim(),
    description: typeof description === 'string' ? description.trim() : '',
    created_by: req.user!.id,
    created_at: Date.now(),
  };

  try {
    getDb()
      .prepare(
        'INSERT INTO channels (id, name, description, created_by, created_at) VALUES (?, ?, ?, ?, ?)',
      )
      .run(channel.id, channel.name, channel.description, channel.created_by, channel.created_at);

    res.status(201).json(channel);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes('UNIQUE constraint failed')) {
      res.status(409).json({ error: 'A channel with that name already exists' });
      return;
    }
    throw err;
  }
});

/**
 * GET /api/channels/:id
 * Get a single channel by ID.
 */
router.get('/:id', requireAuth, (req: Request, res: Response) => {
  const channel = getDb()
    .prepare('SELECT * FROM channels WHERE id = ?')
    .get(req.params.id) as Channel | undefined;

  if (!channel) {
    res.status(404).json({ error: 'Channel not found' });
    return;
  }

  res.json(channel);
});

/**
 * DELETE /api/channels/:id
 * Delete a channel and all its messages.  Only the channel creator may delete it.
 */
router.delete('/:id', requireAuth, (req: Request, res: Response) => {
  const db = getDb();
  const channel = db
    .prepare('SELECT * FROM channels WHERE id = ?')
    .get(req.params.id) as Channel | undefined;

  if (!channel) {
    res.status(404).json({ error: 'Channel not found' });
    return;
  }

  if (channel.created_by !== req.user!.id) {
    res.status(403).json({ error: 'Only the channel creator can delete it' });
    return;
  }

  db.prepare('DELETE FROM messages WHERE channel_id = ?').run(req.params.id);
  db.prepare('DELETE FROM channels WHERE id = ?').run(req.params.id);

  res.status(204).send();
});

export default router;
