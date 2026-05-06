import http from 'http';
import https from 'https';
import fs from 'fs';
import { config } from './config';
import { createApp } from './app';
import { cleanupExpired } from './auth/certificate';
import { createSignalingServer } from './signaling/signalingServer';

const app = createApp();

// ── Trust proxy ──────────────────────────────────────────────────────────────
// Enable when running behind nginx / Caddy / Traefik so that Express sees the
// real client IP from X-Forwarded-For and respects X-Forwarded-Proto for TLS.
if (config.trustProxy) {
  app.set('trust proxy', 1);
}

// ── HTTP(S) server ───────────────────────────────────────────────────────────
let server: http.Server | https.Server;

if (config.https.enabled) {
  const credentials = {
    key: fs.readFileSync(config.https.keyPath),
    cert: fs.readFileSync(config.https.certPath),
  };
  server = https.createServer(credentials, app);
  console.log('[BarkChat] TLS enabled – running HTTPS');
} else {
  server = http.createServer(app);
}

// ── WebSocket signaling ──────────────────────────────────────────────────────
createSignalingServer(server);

// ── Periodic cleanup ─────────────────────────────────────────────────────────
setInterval(cleanupExpired, 15 * 60 * 1000).unref();

// ── Start ────────────────────────────────────────────────────────────────────
server.listen(config.port, () => {
  console.log(`[BarkChat] Server listening on port ${config.port}`);
  console.log(
    `[BarkChat] WebSocket signaling → ws${config.https.enabled ? 's' : ''}://localhost:${config.port}/signaling`,
  );
  if (config.trustProxy) {
    console.log('[BarkChat] Reverse-proxy mode: trust proxy = on');
  }
});

export { app, server };
