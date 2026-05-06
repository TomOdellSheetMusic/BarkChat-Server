import { Router, Request, Response } from 'express';
import { requireAuth } from '../auth/middleware';
import { getDb } from '../db/database';
import type { User } from '../types';

const router = Router();

/**
 * GET /api/users/me
 * Return the currently authenticated user's profile.
 */
router.get('/me', requireAuth, (req: Request, res: Response) => {
  const u = req.user!;
  res.json({
    id: u.id,
    display_name: u.display_name,
    certificate_fingerprint: u.certificate_fingerprint,
    created_at: u.created_at,
    last_seen: u.last_seen,
  });
});

/**
 * GET /api/users
 * List all registered users (omits private key material).
 */
router.get('/', requireAuth, (_req: Request, res: Response) => {
  const users = getDb()
    .prepare(
      `SELECT id, display_name, certificate_fingerprint, created_at, last_seen
       FROM users
       ORDER BY display_name`,
    )
    .all() as Omit<User, 'public_key_pem'>[];

  res.json(users);
});

/**
 * GET /api/users/:id
 * Get a single user by ID.  Includes `public_key_pem` so senders can
 * encrypt direct messages for this user.
 */
router.get('/:id', requireAuth, (req: Request, res: Response) => {
  const user = getDb()
    .prepare(
      `SELECT id, display_name, certificate_fingerprint, public_key_pem, created_at, last_seen
       FROM users WHERE id = ?`,
    )
    .get(req.params.id) as User | undefined;

  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  res.json(user);
});

export default router;
