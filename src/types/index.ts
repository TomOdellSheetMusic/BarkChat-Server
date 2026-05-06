// Shared TypeScript types for BarkChat Server

export interface User {
  id: string;
  certificate_fingerprint: string;
  display_name: string;
  public_key_pem: string;
  created_at: number;
  last_seen: number;
}

export interface Channel {
  id: string;
  name: string;
  description: string;
  created_by: string;
  created_at: number;
}

export interface Message {
  id: string;
  channel_id: string;
  user_id: string;
  encrypted_content: string; // AES-256-GCM ciphertext, base64
  iv: string;                // base64 IV
  auth_tag: string;          // base64 GCM auth tag
  created_at: number;
}

export interface DirectMessage {
  id: string;
  sender_id: string;
  recipient_id: string;
  /** Hybrid-RSA+AES encrypted content (client-side E2E). Never decrypted by server. */
  encrypted_content: string;
  created_at: number;
}

// ── WebRTC Signaling ────────────────────────────────────────────────────────

export type SignalingMessageType =
  | 'join'
  | 'leave'
  | 'offer'
  | 'answer'
  | 'ice-candidate'
  | 'peer-joined'
  | 'peer-left'
  | 'room-info'
  | 'error';

export interface RTCSessionDescriptionInit {
  type: 'offer' | 'answer' | 'pranswer' | 'rollback';
  sdp?: string;
}

export interface RTCIceCandidateInit {
  candidate?: string;
  sdpMLineIndex?: number | null;
  sdpMid?: string | null;
  usernameFragment?: string | null;
}

export interface SignalingMessage {
  type: SignalingMessageType;
  roomId?: string;
  peerId?: string;
  targetPeerId?: string;
  sdp?: RTCSessionDescriptionInit;
  candidate?: RTCIceCandidateInit;
  token?: string;
  peers?: string[];
  message?: string;
}
