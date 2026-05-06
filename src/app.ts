import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { config } from './config';
import { getDb } from './db/database';

// Routes
import authRouter from './routes/auth';
import usersRouter from './routes/users';
import channelsRouter from './routes/channels';
import messagesRouter from './routes/messages';
import dmRouter from './routes/directMessages';

export function createApp(): express.Express {
  const app = express();

  // ── Middleware ──────────────────────────────────────────────────────────────
  app.use(helmet());
  app.use(
    cors({
      origin: config.corsOrigin,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization'],
    }),
  );
  app.use(express.json({ limit: '1mb' }));

  // ── Rate limiting on authentication endpoints ────────────────────────────────
  // Applied before the auth routes to mitigate brute-force and DoS attacks.
  const authLimiter = rateLimit({
    windowMs: config.authRateLimitWindowMs,
    max: config.authRateLimitMax,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later.' },
  });

  // ── Routes ──────────────────────────────────────────────────────────────────
  app.use('/api/auth', authLimiter, authRouter);
  app.use('/api/users', usersRouter);
  app.use('/api/channels', channelsRouter);
  app.use('/api/channels/:channelId/messages', messagesRouter);
  app.use('/api/dm', dmRouter);

  // ── Health check ─────────────────────────────────────────────────────────────
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', version: '1.0.0' });
  });

  // ── Ensure database is initialised ──────────────────────────────────────────
  getDb();

  return app;
}
