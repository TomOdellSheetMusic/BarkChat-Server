import WebSocket from 'ws';

export interface Peer {
  id: string;     // unique peer ID generated per connection
  userId: string; // authenticated user ID
  ws: WebSocket;
  rooms: Set<string>;
}

// Global peer registry keyed by peer ID
const globalPeers = new Map<string, Peer>();

// Room membership: room ID → Set of peer IDs
const roomMembers = new Map<string, Set<string>>();

export function registerPeer(peer: Peer): void {
  globalPeers.set(peer.id, peer);
}

/**
 * Deregister a peer and remove it from all rooms it belongs to.
 * Returns the IDs of the rooms that were affected.
 */
export function unregisterPeer(peerId: string): string[] {
  const peer = globalPeers.get(peerId);
  if (!peer) return [];

  const affected: string[] = [];

  peer.rooms.forEach((roomId) => {
    roomMembers.get(roomId)?.delete(peerId);
    if (roomMembers.get(roomId)?.size === 0) {
      roomMembers.delete(roomId);
    }
    affected.push(roomId);
  });

  globalPeers.delete(peerId);
  return affected;
}

/**
 * Add a peer to a room.
 * Returns the list of peers that were already in the room *before* this join.
 */
export function joinRoom(peerId: string, roomId: string): Peer[] {
  const peer = globalPeers.get(peerId);
  if (!peer) return [];

  // Snapshot existing members before mutation
  const existingIds = Array.from(roomMembers.get(roomId) ?? []);
  const existingPeers = existingIds
    .map((id) => globalPeers.get(id))
    .filter((p): p is Peer => p !== undefined);

  if (!roomMembers.has(roomId)) roomMembers.set(roomId, new Set());
  roomMembers.get(roomId)!.add(peerId);
  peer.rooms.add(roomId);

  return existingPeers;
}

/**
 * Remove a peer from a room.
 * Returns the remaining peers in the room after the departure.
 */
export function leaveRoom(peerId: string, roomId: string): Peer[] {
  const peer = globalPeers.get(peerId);
  if (peer) peer.rooms.delete(roomId);

  roomMembers.get(roomId)?.delete(peerId);
  if (roomMembers.get(roomId)?.size === 0) roomMembers.delete(roomId);

  return getPeersInRoom(roomId);
}

export function getPeersInRoom(roomId: string): Peer[] {
  return Array.from(roomMembers.get(roomId) ?? [])
    .map((id) => globalPeers.get(id))
    .filter((p): p is Peer => p !== undefined);
}

export function getPeerById(peerId: string): Peer | undefined {
  return globalPeers.get(peerId);
}

/** Exposed for testing – resets all in-memory state. */
export function _resetForTesting(): void {
  globalPeers.clear();
  roomMembers.clear();
}
