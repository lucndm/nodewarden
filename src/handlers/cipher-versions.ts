// Item history endpoints.
//
// The server stores one row per superseded state of a cipher. The snapshot is
// the encrypted payload as it was, so the server never sees plaintext; the
// client decrypts the snapshot and compares it with the live item.
//
// CONTRACT:
// - Every endpoint is scoped to the owner of the cipher. A version of somebody
//   else's item is not found, never forbidden.
// - A version is written in the same batch as the cipher write it belongs to,
//   so history can never claim a state the item never had.
// - Restore keeps the current state as a new version, so a restore can be
//   undone by restoring the version that was current before it.

import { Env, Cipher, CipherVersion } from '../types';
import { StorageService } from '../services/storage';
import { buildCipherVersionData, type CipherVersionInput } from '../services/storage-cipher-repo';
import { jsonResponse, errorResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import {
  cipherResponseOptionsForRequest,
  cipherToResponse,
  notifyCipherUpdateForRequest,
  notifyVaultSyncForRequest,
} from './ciphers';

// Payload fields that hold what the item contains. A restore replaces them
// wholesale; folder, favorite and archive state stay as they are.
const CIPHER_CONTENT_KEYS = [
  'login',
  'card',
  'identity',
  'secureNote',
  'sshKey',
  'bankAccount',
  'driversLicense',
  'passport',
  'fields',
  'passwordHistory',
];

export interface CipherVersionSummary {
  id: string;
  cipherId: string;
  /** Position in the item history, oldest first. */
  versionNo: number;
  kind: 'created' | 'modified';
  createdAt: string;
  revisionDate: string;
  name: string | null;
  key: string | null;
}

function toVersionSummary(version: CipherVersion, versionNo: number): CipherVersionSummary {
  return {
    id: version.id,
    cipherId: version.cipherId,
    versionNo,
    kind: version.kind,
    createdAt: version.createdAt,
    revisionDate: version.revisionDate,
    name: version.name,
    key: version.key,
  };
}

function toVersionResponse(version: CipherVersion, versionNo: number) {
  return {
    id: version.id,
    cipherId: version.cipherId,
    versionNo,
    kind: version.kind,
    createdAt: version.createdAt,
    revisionDate: version.revisionDate,
    type: version.type,
    name: version.name,
    notes: version.notes,
    key: version.key,
    reprompt: version.reprompt,
    data: version.data,
  };
}

// The snapshot of the state the item is leaving. `created` marks the state the
// item was created in, `modified` every later state.
function buildVersionInput(
  cipher: Cipher,
  userId: string,
  revisionDate: string,
  appliedUpdatedAt: string
): CipherVersionInput {
  return {
    id: generateUUID(),
    cipherId: cipher.id,
    userId,
    kind: cipher.updatedAt === cipher.createdAt ? 'created' : 'modified',
    revisionDate,
    createdAt: cipher.updatedAt,
    type: Number(cipher.type) || 1,
    name: cipher.name ?? null,
    notes: cipher.notes ?? null,
    key: cipher.key ?? null,
    reprompt: cipher.reprompt ?? 0,
    data: buildCipherVersionData(cipher),
    appliedUpdatedAt,
  };
}

function restoreCipherFromVersion(cipher: Cipher, version: CipherVersion): Cipher {
  let payload: Record<string, unknown> = {};
  try {
    const parsed = JSON.parse(version.data);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      payload = parsed as Record<string, unknown>;
    }
  } catch {
    payload = {};
  }
  const base: Record<string, unknown> = { ...cipher };
  for (const key of CIPHER_CONTENT_KEYS) delete base[key];
  const restored: Cipher = {
    ...(base as Cipher),
    ...(payload as Partial<Cipher>),
    type: version.type,
    name: version.name,
    notes: version.notes,
    key: version.key,
    reprompt: version.reprompt,
    updatedAt: new Date(Math.max(Date.now(), Date.parse(cipher.updatedAt) + 1)).toISOString(),
  };
  // The folder position is organization, not content: a restore keeps the
  // tags the item has now.
  if (Array.isArray(cipher.tags)) restored.tags = cipher.tags;
  return restored;
}

// GET /api/ciphers/:id/versions
export async function handleGetCipherVersions(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const cipher = await storage.getCipherForUser(cipherId, userId);
  if (!cipher || cipher.userId !== userId || cipher.deletedAt) {
    return errorResponse('Cipher not found', 404);
  }
  const versions = await storage.listCipherVersions(cipherId, userId);
  // The list is newest first; the number counts from the oldest state.
  const total = versions.length;
  return jsonResponse({
    object: 'list',
    data: versions.map((version, index) => toVersionSummary(version, total - index)),
  });
}

// GET /api/ciphers/:id/versions/:versionId
export async function handleGetCipherVersion(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string,
  versionId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const cipher = await storage.getCipherForUser(cipherId, userId);
  if (!cipher || cipher.userId !== userId || cipher.deletedAt) {
    return errorResponse('Cipher not found', 404);
  }
  const version = await storage.getCipherVersion(versionId, cipherId, userId);
  if (!version) {
    return errorResponse('Version not found', 404);
  }
  const versions = await storage.listCipherVersions(cipherId, userId);
  const index = versions.findIndex((entry) => entry.id === version.id);
  const versionNo = index >= 0 ? versions.length - index : versions.length + 1;
  return jsonResponse(toVersionResponse(version, versionNo));
}

// POST /api/ciphers/:id/versions/:versionId/restore
export async function handleRestoreCipherVersion(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string,
  versionId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const cipher = await storage.getCipherForUser(cipherId, userId);
  if (!cipher || cipher.userId !== userId || cipher.deletedAt) {
    return errorResponse('Cipher not found', 404);
  }
  const version = await storage.getCipherVersion(versionId, cipherId, userId);
  if (!version) {
    return errorResponse('Version not found', 404);
  }

  // Optimistic concurrency: the client sends the revision it is looking at.
  const expectedRevision = request.headers.get('if-match');
  if (expectedRevision && expectedRevision !== cipher.updatedAt) {
    return errorResponse('The client copy of this cipher is out of date. Resync the client and try again.', 409);
  }

  const restored = restoreCipherFromVersion(cipher, version);
  const revisionDate = new Date().toISOString();
  // The state the item is leaving becomes a version of its own, so the
  // restore can be undone.
  const versionInput = buildVersionInput(cipher, userId, revisionDate, restored.updatedAt);
  const written = await storage.updateCipherIfUnchanged(
    restored,
    cipher.updatedAt,
    versionInput
  );
  if (!written) {
    return errorResponse('The client copy of this cipher is out of date. Resync the client and try again.', 409);
  }
  await storage.pruneCipherVersions(cipher.id);
  const revision = await storage.updateRevisionDate(userId, revisionDate);
  notifyVaultSyncForRequest(request, env, userId, revision);
  notifyCipherUpdateForRequest(request, env, restored, revision);
  const attachments = await storage.getAttachmentsByCipher(restored.id);
  return jsonResponse(
    cipherToResponse(restored, attachments, cipherResponseOptionsForRequest(request))
  );
}
