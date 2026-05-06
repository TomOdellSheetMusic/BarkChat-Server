import { Request, Response, NextFunction } from 'express';
import { validateSession } from './certificate';
import type { User } from '../types';

// Augment the Express Request type so downstream handlers can access `req.user`.
declare global {
  namespace Express {
    interface Request {
      user?: User;
    }
  }
}

/**
 * Express middleware that requires a valid Bearer session token in the
 * `Authorization` header.  Sets `req.user` on success; returns 401 otherwise.
 */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Missing or invalid Authorization header' });
    return;
  }

  const token = authHeader.slice(7);
  const user = validateSession(token);

  if (!user) {
    res.status(401).json({ error: 'Invalid or expired session token' });
    return;
  }

  req.user = user;
  next();
}
