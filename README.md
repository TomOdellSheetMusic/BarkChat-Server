# BarkChat-Server

A self-hostable, lossless voice-chat platform server with:

- **Peer-to-peer voice** via WebRTC (OPUS at maximum quality, DTLS-SRTP encrypted end-to-end)
- **Certificate-based authentication** (X.509 challenge-response, Mumble-style)
- **Encrypted channel messages** at rest (AES-256-GCM, server key)
- **End-to-end encrypted direct messages** (hybrid RSA-OAEP + AES-256-GCM; server never reads plaintext)
- **Reverse-proxy ready** (nginx / Caddy / Traefik)

---

## Architecture

```
┌─────────────────────────────────┐
│           BarkChat Client       │
│  (Web / Desktop / Mobile)       │
└────────┬────────────┬───────────┘
         │  REST API  │  WebSocket /signaling
         ▼            ▼
┌─────────────────────────────────┐
│         BarkChat Server         │
│  Express (REST) + ws (signaling)│
│  SQLite (encrypted message DB)  │
└─────────────────────────────────┘
         │ ICE candidates
         ▼
  ┌──────────────────┐
  │  STUN / TURN     │  (public server, e.g. coturn)
  └──────────────────┘
         │
   Direct P2P WebRTC connection
   (DTLS-SRTP, OPUS codec)
```

The server acts as a **signaling relay only** for voice chat. Once two peers have exchanged SDP and ICE candidates, all audio flows directly between them.

---

## Requirements

| Dependency | Version |
|------------|---------|
| Node.js    | ≥ 20    |
| npm        | ≥ 9     |
| OpenSSL    | ≥ 1.1   |

---

## Quick Start

```bash
# 1. Clone and install
git clone <repo-url> barkchat-server
cd barkchat-server
npm install

# 2. Configure
cp .env.example .env
# Edit .env – at minimum set ENCRYPTION_KEY (see below)

# 3. Run (development)
npm run dev

# 4. Run (production build)
npm run build
npm start
```

### Generate an encryption key

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Paste the result as `ENCRYPTION_KEY` in your `.env` file.

---

## Configuration (`.env`)

| Variable          | Default            | Description |
|-------------------|--------------------|-------------|
| `PORT`            | `3000`             | HTTP port |
| `ENCRYPTION_KEY`  | *(random, warn)*   | 64-char hex key for AES-256-GCM channel-message encryption |
| `DB_PATH`         | `./barkchat.db`    | Path to the SQLite database file |
| `TRUST_PROXY`     | `false`            | Set `true` when behind nginx/Caddy/Traefik |
| `HTTPS_ENABLED`   | `false`            | Enable built-in TLS (usually keep `false` and let the proxy handle TLS) |
| `HTTPS_KEY_PATH`  | `./certs/server.key` | Private key for built-in HTTPS |
| `HTTPS_CERT_PATH` | `./certs/server.crt` | Certificate for built-in HTTPS |

---

## Reverse Proxy Setup

### nginx (recommended for production)

```nginx
server {
    listen 443 ssl http2;
    server_name chat.example.com;

    ssl_certificate     /etc/letsencrypt/live/chat.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/chat.example.com/privkey.pem;

    # WebSocket signaling
    location /signaling {
        proxy_pass         http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade    $http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_set_header   Host       $host;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }

    # REST API
    location / {
        proxy_pass         http://127.0.0.1:3000;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

Set `TRUST_PROXY=true` in `.env` when using this configuration.

### Caddy

```caddyfile
chat.example.com {
    reverse_proxy /signaling localhost:3000 {
        header_up Upgrade    {http.upgrade}
        header_up Connection "upgrade"
    }
    reverse_proxy localhost:3000
}
```

---

## API Reference

All authenticated endpoints require:

```
Authorization: Bearer <session-token>
```

### Authentication

#### Register a user certificate

```
POST /api/auth/register
Content-Type: application/json

{ "certificate": "<PEM>", "displayName": "Alice" }
```

The server extracts the SHA-256 fingerprint from the X.509 certificate and uses it as the permanent user identity.

#### Get a sign challenge

```
POST /api/auth/challenge
Content-Type: application/json

{ "fingerprint": "<hex-fingerprint>" }

→ { "challenge": "<64-char hex string>" }
```

#### Login (sign the challenge)

```
POST /api/auth/login
Content-Type: application/json

{
  "certificate": "<PEM>",
  "fingerprint": "<hex-fingerprint>",
  "signature":   "<hex SHA-256 signature of the challenge>"
}

→ { "token": "<session-token>", "user": { "id", "display_name", "certificate_fingerprint" } }
```

#### Logout

```
POST /api/auth/logout   (requires Bearer token)
```

#### Parse certificate info (no storage)

```
POST /api/auth/cert-info
{ "certificate": "<PEM>" }
```

---

### Users

```
GET  /api/users          – list all users
GET  /api/users/me       – current user profile
GET  /api/users/:id      – get user by ID (includes public_key_pem for DM encryption)
```

---

### Channels

```
GET    /api/channels       – list channels
POST   /api/channels       – create channel  { name, description? }
GET    /api/channels/:id   – get channel
DELETE /api/channels/:id   – delete channel (creator only)
```

---

### Channel Messages

Messages are stored AES-256-GCM encrypted at rest. The server decrypts them transparently when serving to authenticated clients.

```
GET  /api/channels/:channelId/messages?limit=50&before=<msgId>
POST /api/channels/:channelId/messages   { content: "Hello!" }
```

---

### Direct Messages (E2E encrypted)

DMs are **end-to-end encrypted**. The server stores ciphertext only and never decrypts it.

**Sending a DM:**

1. Fetch the recipient's RSA public key: `GET /api/users/:id` → `public_key_pem`
2. Encrypt your message: `encryptDM(plaintext, publicKeyPem)` (see `src/crypto/encryption.ts`)
3. POST the ciphertext to the server

```
GET  /api/dm               – list DM conversations
GET  /api/dm/:userId       – messages with a user (paginated)
POST /api/dm/:userId       { encrypted_content: "<opaque string>" }
```

---

## WebSocket Signaling (Voice Chat)

Connect to:

```
ws[s]://<host>/signaling?token=<session-token>
```

### Client → Server messages

| Type | Fields | Description |
|------|--------|-------------|
| `join` | `roomId` | Join a voice room |
| `leave` | `roomId` | Leave a voice room |
| `offer` | `targetPeerId`, `sdp` | WebRTC offer (SDP) |
| `answer` | `targetPeerId`, `sdp` | WebRTC answer (SDP) |
| `ice-candidate` | `targetPeerId`, `candidate` | ICE candidate |

### Server → Client messages

| Type | Fields | Description |
|------|--------|-------------|
| `room-info` | `peerId`, `roomId?`, `peers[]` | Sent on connect and after join |
| `peer-joined` | `roomId`, `peerId` | A new peer joined your room |
| `peer-left` | `roomId`, `peerId` | A peer left or disconnected |
| `offer` / `answer` / `ice-candidate` | `peerId`, … | Relayed from another peer |
| `error` | `message` | Error description |

### Typical P2P voice setup sequence

```
Client A connects → receives { type: 'room-info', peerId: 'A-id' }
Client A sends    → { type: 'join', roomId: 'lobby' }
Server sends to A → { type: 'room-info', roomId: 'lobby', peers: [] }

Client B connects → receives { type: 'room-info', peerId: 'B-id' }
Client B sends    → { type: 'join', roomId: 'lobby' }
Server sends to B → { type: 'room-info', roomId: 'lobby', peers: ['A-id'] }
Server sends to A → { type: 'peer-joined', peerId: 'B-id' }

Client B sends offer → { type: 'offer', targetPeerId: 'A-id', sdp: {...} }
Server relays to A   → { type: 'offer', peerId: 'B-id', sdp: {...} }

(answer + ICE candidates exchanged similarly)

Peers establish direct WebRTC connection → OPUS audio flows P2P
```

---

## Client Certificate Generation

Clients should generate a 2048-bit (or better) RSA key pair and self-signed X.509 certificate. The server validates ownership via challenge-response; a CA is not required.

**OpenSSL (CLI):**
```bash
openssl req -x509 -newkey rsa:4096 \
  -keyout client.key -out client.crt \
  -days 3650 -nodes \
  -subj "/CN=MyUsername"
```

**Node.js (programmatic):**
```javascript
const { execSync } = require('child_process');
// or use the 'selfsigned' npm package
```

The fingerprint displayed by `POST /api/auth/cert-info` is the user's permanent identity.

---

## Audio Quality

BarkChat uses **WebRTC** with the **OPUS** codec. Recommended client settings for highest quality:

```javascript
const constraints = {
  audio: {
    echoCancellation: false,  // disable for music / studio use
    noiseSuppression: false,
    autoGainControl:  false,
    sampleRate:       48000,
    channelCount:     2,       // stereo
  }
};

// In RTCPeerConnection offer options:
const offerOptions = {
  offerToReceiveAudio: true,
};
// In SDP munging (or via codec preferences API):
// Set OPUS bitrate to 510000 bps for transparent quality
```

OPUS at 510 kbps stereo is perceptually transparent. For true lossless transport, use a TURN server that supports FLAC via a native client stack.

---

## Development

```bash
npm run dev    # ts-node watch
npm run build  # compile to ./dist
npm start      # run compiled output
npm test       # run Jest test suite
npm run lint   # TypeScript type-check only
```

---

## License

MIT

