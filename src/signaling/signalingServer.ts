import { WebSocketServer, WebSocket } from 'ws';
import { IncomingMessage, Server } from 'http';
import { validateSession } from '../auth/certificate';
import {
  registerPeer,
  unregisterPeer,
  joinRoom,
  leaveRoom,
  getPeersInRoom,
  getPeerById,
  Peer,
} from './rooms';
import { v4 as uuidv4 } from 'uuid';
import type { SignalingMessage } from '../types';

// ── Internal helpers ──────────────────────────────────────────────────────────

function send(ws: WebSocket, message: SignalingMessage): void {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(message));
  }
}

// ── Message handler ───────────────────────────────────────────────────────────

function handleMessage(peer: Peer, raw: SignalingMessage): void {
  switch (raw.type) {
    case 'join': {
      if (!raw.roomId) {
        send(peer.ws, { type: 'error', message: 'roomId is required for join' });
        return;
      }

      const existingPeers = joinRoom(peer.id, raw.roomId);

      // Inform the new peer about everyone already in the room
      send(peer.ws, {
        type: 'room-info',
        roomId: raw.roomId,
        peerId: peer.id,
        peers: existingPeers.map((p) => p.id),
      });

      // Inform existing peers that someone new has joined
      existingPeers.forEach((p) => {
        send(p.ws, { type: 'peer-joined', roomId: raw.roomId, peerId: peer.id });
      });
      break;
    }

    case 'leave': {
      if (!raw.roomId) return;

      const remaining = leaveRoom(peer.id, raw.roomId);
      remaining.forEach((p) => {
        send(p.ws, { type: 'peer-left', roomId: raw.roomId, peerId: peer.id });
      });
      break;
    }

    // WebRTC negotiation messages are forwarded verbatim to the target peer.
    case 'offer':
    case 'answer':
    case 'ice-candidate': {
      if (!raw.targetPeerId) {
        send(peer.ws, { type: 'error', message: 'targetPeerId is required' });
        return;
      }

      const target = getPeerById(raw.targetPeerId);
      if (!target) {
        send(peer.ws, {
          type: 'error',
          message: `Peer ${raw.targetPeerId} not found or has disconnected`,
        });
        return;
      }

      // Relay the message, stamping it with the sender's peer ID
      send(target.ws, { ...raw, peerId: peer.id });
      break;
    }

    default:
      send(peer.ws, { type: 'error', message: `Unknown message type: ${raw.type}` });
  }
}

// ── Public factory ────────────────────────────────────────────────────────────

/**
 * Attach a WebSocket signaling server to an existing HTTP(S) server.
 *
 * Clients connect to `ws[s]://<host>/signaling?token=<sessionToken>`.
 *
 * Protocol overview
 * ─────────────────
 * Client → Server:
 *   { type: 'join',          roomId }
 *   { type: 'leave',         roomId }
 *   { type: 'offer',         targetPeerId, sdp }
 *   { type: 'answer',        targetPeerId, sdp }
 *   { type: 'ice-candidate', targetPeerId, candidate }
 *
 * Server → Client:
 *   { type: 'room-info',  roomId, peerId, peers[] }  – upon successful join
 *   { type: 'peer-joined', roomId, peerId }           – another peer joined
 *   { type: 'peer-left',   roomId, peerId }           – a peer disconnected
 *   { type: 'offer'|'answer'|'ice-candidate', peerId, … } – relayed messages
 *   { type: 'error', message }
 */
export function createSignalingServer(server: Server): WebSocketServer {
  const wss = new WebSocketServer({ server, path: '/signaling' });

  wss.on('connection', (ws: WebSocket, req: IncomingMessage) => {
    // Authenticate via query-string token
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    const token = url.searchParams.get('token');

    if (!token) {
      send(ws, { type: 'error', message: 'Authentication token required' });
      ws.close(4001, 'Unauthorized');
      return;
    }

    const user = validateSession(token);
    if (!user) {
      send(ws, { type: 'error', message: 'Invalid or expired session token' });
      ws.close(4001, 'Unauthorized');
      return;
    }

    const peer: Peer = { id: uuidv4(), userId: user.id, ws, rooms: new Set() };
    registerPeer(peer);

    // Acknowledge connection and share the assigned peer ID
    send(ws, { type: 'room-info', peerId: peer.id });

    ws.on('message', (data: Buffer | string) => {
      let message: SignalingMessage;
      try {
        message = JSON.parse(data.toString()) as SignalingMessage;
      } catch {
        send(ws, { type: 'error', message: 'Invalid JSON' });
        return;
      }
      handleMessage(peer, message);
    });

    ws.on('close', () => {
      const affectedRooms = unregisterPeer(peer.id);
      // Notify remaining peers in every room this peer belonged to
      affectedRooms.forEach((roomId) => {
        getPeersInRoom(roomId).forEach((p) => {
          send(p.ws, { type: 'peer-left', peerId: peer.id, roomId });
        });
      });
    });

    ws.on('error', (err: Error) => {
      console.error(`[Signaling] WebSocket error for peer ${peer.id}:`, err.message);
    });
  });

  return wss;
}
