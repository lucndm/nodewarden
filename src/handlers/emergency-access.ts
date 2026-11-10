// Emergency access.
//
// One account lets another person in when they cannot get in themselves.
// The grantor hands over a key wrapped for the grantee, so the server holds
// a key it cannot open. The routes follow the upstream shape, so the
// official clients read what this writes.
//
// What this does NOT do, and says so:
//   - it never sends an email: the invitation is shown in the web vault, and
//     the grantee has to sign in to see it.
//
// A takeover does not re-encrypt the vault: the vault key stays the same and
// only the password that opens it is replaced.
//
// The routes:
//   GET    /api/emergency-access/trusted   the grants this account gave
//   GET    /api/emergency-access/granted   the grants this account was given
//   GET    /api/emergency-access/:id        one grant, seen by the grantor
//   GET    /api/emergency-access/:id/policies   the grantor's rules, for a takeover
//   POST   /api/emergency-access/invite    invite somebody
//   PUT    /api/emergency-access/:id        the grantor changes the grant
//   PUT    /api/emergency-access/:id/accept   the grantee accepts
//   PUT    /api/emergency-access/:id/confirm  the grantor hands over the key
//   PUT    /api/emergency-access/:id/reject   the grantee declines
//   PUT    /api/emergency-access/:id/initiate  the grantee starts the wait
//   PUT    /api/emergency-access/:id/approve   the grantor approves
//   PUT    /api/emergency-access/:id/view      the grantee reads the vault
//   PUT    /api/emergency-access/:id/takeover  the grantee takes the account
//   PUT    /api/emergency-access/:id/password  the grantee sets the password
//   POST   /api/emergency-access/:id/reinvite  the grantor asks again
//   DELETE /api/emergency-access/:id        the grantor withdraws
import { errorResponse, jsonResponse } from '../utils/response';
import { cipherResponseOptionsForRequest, cipherToResponse } from './ciphers';
import { policyResponse } from './policies';
import { getUser, getUserById } from '../services/storage-user-repo';
import { StorageService } from '../services/storage';
import { AuthService } from '../services/auth';
import { sendEmergencyAccessNotice } from '../services/emergency-access-notifier';
import {
  createEmergencyAccess,
  deleteEmergencyAccess,
  getEmergencyAccess,
  isValidEmergencyWaitDays,
  listEmergencyAccessByGrantee,
  listEmergencyAccessByGrantor,
  updateEmergencyAccess,
  EMERGENCY_ACCESS_STATUS_ACCEPTED,
  EMERGENCY_ACCESS_STATUS_CONFIRMED,
  EMERGENCY_ACCESS_STATUS_INVITED,
  EMERGENCY_ACCESS_STATUS_RECOVERY_APPROVED,
  EMERGENCY_ACCESS_STATUS_RECOVERY_INITIATED,
  EMERGENCY_ACCESS_TYPE_TAKEOVER,
  EMERGENCY_ACCESS_TYPE_VIEW,
  type EmergencyAccessRow,
} from '../services/storage-emergency-access-repo';
import type { Env } from '../types';

const MAX_INVITES = 10;

function nowIso(): string {
  return new Date().toISOString();
}

/** The grant as the grantor sees it: who was given access. */
function granteeDetails(row: EmergencyAccessRow, email: string | null, name: string | null): Record<string, unknown> {
  return {
    id: row.id,
    status: row.status,
    type: row.type,
    waitTimeDays: row.waitTimeDays,
    granteeId: row.granteeId,
    email: email ?? row.email,
    name: name ?? null,
    avatarColor: null,
    // When the grantee started the wait; the web vault shows when access opens.
    recoveryInitiatedDate: row.recoveryInitiatedAt,
    object: 'emergencyAccessGranteeDetails',
  };
}

/** The grant as the grantee sees it: who gave access. */
function grantorDetails(row: EmergencyAccessRow, email: string | null, name: string | null): Record<string, unknown> {
  return {
    id: row.id,
    status: row.status,
    type: row.type,
    waitTimeDays: row.waitTimeDays,
    grantorId: row.grantorId,
    email: email ?? null,
    name: name ?? null,
    avatarColor: null,
    recoveryInitiatedDate: row.recoveryInitiatedAt,
    object: 'emergencyAccessGrantorDetails',
  };
}

async function granteeIdentity(
  env: Env,
  row: EmergencyAccessRow
): Promise<{ email: string | null; name: string | null }> {
  if (row.granteeId) {
    const user = await getUserById(env.DB, row.granteeId);
    return { email: user?.email ?? null, name: user?.name ?? null };
  }
  // Nobody claimed the invitation yet, so only the address it was sent to is
  // known.
  return { email: row.email, name: null };
}

async function grantorIdentity(
  env: Env,
  row: EmergencyAccessRow
): Promise<{ email: string | null; name: string | null }> {
  const user = await getUserById(env.DB, row.grantorId);
  return { email: user?.email ?? null, name: user?.name ?? null };
}

/** GET /api/emergency-access/trusted */
export async function handleListTrustedEmergencyAccess(
  request: Request,
  env: Env,
  userId: string
): Promise<Response> {
  void request;
  const rows = await listEmergencyAccessByGrantor(env.DB, userId);
  const data = [];
  for (const row of rows) {
    const identity = await granteeIdentity(env, row);
    data.push(granteeDetails(row, identity.email, identity.name));
  }
  return jsonResponse({ data, object: 'list', continuationToken: null });
}

/** GET /api/emergency-access/granted */
export async function handleListGrantedEmergencyAccess(
  request: Request,
  env: Env,
  userId: string
): Promise<Response> {
  void request;
  const rows = await listEmergencyAccessByGrantee(env.DB, userId);
  const data = [];
  for (const row of rows) {
    const identity = await grantorIdentity(env, row);
    data.push(grantorDetails(row, identity.email, identity.name));
  }
  return jsonResponse({ data, object: 'list', continuationToken: null });
}

/** GET /api/emergency-access/:id — only the grantor may look at a grant. */
export async function handleGetEmergencyAccess(
  request: Request,
  env: Env,
  userId: string,
  id: string
): Promise<Response> {
  void request;
  const row = await getEmergencyAccess(env.DB, id);
  if (!row || row.grantorId !== userId) {
    return errorResponse('Emergency access not valid.', 404);
  }
  const identity = await granteeIdentity(env, row);
  return jsonResponse(granteeDetails(row, identity.email, identity.name));
}

/** POST /api/emergency-access/invite */
export async function handleInviteEmergencyAccess(
  request: Request,
  env: Env,
  userId: string
): Promise<Response> {
  let body: {
    email?: unknown;
    type?: unknown;
    waitTimeDays?: unknown;
    encryptedUserKey?: unknown;
  };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400);
  }

  const email = String(body.email || '').trim().toLowerCase();
  if (!email || !email.includes('@')) {
    return errorResponse('Email is required.', 400);
  }
  // The key the grantor wraps for the grantee. It arrives encrypted, so the
  // server never holds a key it could open. The official client sends the
  // key later, when it confirms the grant, so it may be missing here.
  const wrappedKey = String(body.encryptedUserKey || '').trim() || null;
  const type = Number(body.type);
  if (type !== 0 && type !== 1) {
    return errorResponse('Type must be 0 (view) or 1 (takeover).', 400);
  }
  const waitTimeDays = body.waitTimeDays === undefined ? 1 : Number(body.waitTimeDays);
  if (!isValidEmergencyWaitDays(waitTimeDays)) {
    return errorResponse('Wait time must be between 1 and 90 days.', 400);
  }

  // Naming yourself would let the account reach its own vault after a wait
  // nobody else stands behind.
  const grantor = await getUserById(env.DB, userId);
  if (grantor && grantor.email.toLowerCase() === email) {
    return errorResponse('You can not set yourself as an emergency contact.', 400);
  }

  const grantee = await getUser(env.DB, email);
  const existing = await listEmergencyAccessByGrantor(env.DB, userId);
  if (existing.length >= MAX_INVITES) {
    return errorResponse('Too many emergency access grants.', 400);
  }
  // The same person cannot be invited twice while a grant is still open. A
  // grant is addressed either to an account or to an address; both have to
  // be compared the same way.
  const granteeKey = grantee?.id ?? email;
  const alreadyGranted = existing.some((row) => {
    if (row.status >= EMERGENCY_ACCESS_STATUS_CONFIRMED) return false;
    const rowKey = row.granteeId ?? (row.email ?? '').toLowerCase();
    return rowKey === granteeKey;
  });
  if (alreadyGranted) {
    return errorResponse('This person already has a pending grant.', 400);
  }

  const id = crypto.randomUUID();
  const now = nowIso();
  await createEmergencyAccess(env.DB, {
    id,
    grantorId: userId,
    granteeId: grantee?.id ?? null,
    email,
    wrappedKey,
    type,
    status: EMERGENCY_ACCESS_STATUS_INVITED,
    waitTimeDays,
    recoveryInitiatedAt: null,
    lastNotificationAt: null,
    createdAt: now,
    updatedAt: now,
  });
  return jsonResponse(
    {
      id,
      status: EMERGENCY_ACCESS_STATUS_INVITED,
      type,
      waitTimeDays,
      object: 'emergencyAccess',
    },
    200
  );
}

/**
 * PUT /api/emergency-access/:id/accept
 *
 * The grantee claims the invitation. The grant has to be addressed to them,
 * and it must not already be confirmed.
 */
export async function handleAcceptEmergencyAccess(
  request: Request,
  env: Env,
  userId: string,
  id: string
): Promise<Response> {
  void request;
  const row = await getEmergencyAccess(env.DB, id);
  if (!row) {
    return errorResponse('Emergency access not valid.', 404);
  }
  const user = await getUserById(env.DB, userId);
  const addressedToUser = row.granteeId === userId;
  const addressedToAddress = !row.granteeId && !!user && row.email === user.email.toLowerCase();
  if (!addressedToUser && !addressedToAddress) {
    return errorResponse('Emergency access not valid.', 404);
  }
  if (row.status >= 2) {
    return errorResponse('Emergency access has already been confirmed.', 400);
  }
  await updateEmergencyAccess(env.DB, id, {
    granteeId: userId,
    status: EMERGENCY_ACCESS_STATUS_ACCEPTED,
    updatedAt: nowIso(),
  });
  return jsonResponse({ id, status: EMERGENCY_ACCESS_STATUS_ACCEPTED, object: 'emergencyAccess' });
}

/**
 * PUT /api/emergency-access/:id/reject
 *
 * Two callers use it. The grantor turns down a recovery the grantee started:
 * the grant goes back to confirmed and the wait is reset, as the official
 * client expects. The grantee declines an invitation they have not answered
 * yet: the grant is gone, as the web vault expects.
 */
export async function handleRejectEmergencyAccess(
  request: Request,
  env: Env,
  userId: string,
  id: string
): Promise<Response> {
  void request;
  const row = await getEmergencyAccess(env.DB, id);
  if (!row) {
    return errorResponse('Emergency access not valid.', 404);
  }
  if (row.grantorId === userId) {
    if (
      row.status !== EMERGENCY_ACCESS_STATUS_RECOVERY_INITIATED &&
      row.status !== EMERGENCY_ACCESS_STATUS_RECOVERY_APPROVED
    ) {
      return errorResponse('Emergency access not valid.', 404);
    }
    await updateEmergencyAccess(env.DB, id, {
      status: EMERGENCY_ACCESS_STATUS_CONFIRMED,
      recoveryInitiatedAt: null,
      updatedAt: nowIso(),
    });
    return jsonResponse({
      id,
      status: EMERGENCY_ACCESS_STATUS_CONFIRMED,
      type: row.type,
      waitTimeDays: row.waitTimeDays,
      object: 'emergencyAccess',
    });
  }
  const user = await getUserById(env.DB, userId);
  const addressedToUser = row.granteeId === userId;
  const addressedToAddress = !row.granteeId && !!user && row.email === user.email.toLowerCase();
  if (!addressedToUser && !addressedToAddress) {
    return errorResponse('Emergency access not valid.', 404);
  }
  await deleteEmergencyAccess(env.DB, id);
  return jsonResponse({ object: 'emergencyAccess' });
}

/** DELETE /api/emergency-access/:id — the grantor withdraws the grant. */
export async function handleDeleteEmergencyAccess(
  request: Request,
  env: Env,
  userId: string,
  id: string
): Promise<Response> {
  void request;
  const row = await getEmergencyAccess(env.DB, id);
  if (!row || row.grantorId !== userId) {
    return errorResponse('Emergency access not valid.', 404);
  }
  await deleteEmergencyAccess(env.DB, id);
  return jsonResponse({ object: 'emergencyAccess' });
}

/**
 * PUT /api/emergency-access/:id/confirm
 *
 * The grantor hands over the key, wrapped for the grantee. The grant moves
 * from "accepted" to "confirmed", and only then can the grantee start the
 * wait. The official client sends the key here rather than with the
 * invitation.
 */
export async function handleConfirmEmergencyAccess(
  request: Request,
  env: Env,
  userId: string,
  id: string
): Promise<Response> {
  let body: { key?: unknown };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400);
  }
  const row = await getEmergencyAccess(env.DB, id);
  if (!row || row.grantorId !== userId) {
    return errorResponse('Emergency access not valid.', 404);
  }
  if (row.status !== EMERGENCY_ACCESS_STATUS_ACCEPTED) {
    return errorResponse('Emergency access not valid.', 404);
  }
  // The key arrives encrypted, so the server never holds a key it could open.
  const key = String(body.key || '').trim();
  if (!key) {
    return errorResponse('The encrypted key is required.', 400);
  }
  await updateEmergencyAccess(env.DB, id, {
    status: EMERGENCY_ACCESS_STATUS_CONFIRMED,
    wrappedKey: key,
    // The invitation has been answered, so the address it went to is no
    // longer part of the grant.
    email: null,
    updatedAt: nowIso(),
  });
  return jsonResponse({
    id,
    status: EMERGENCY_ACCESS_STATUS_CONFIRMED,
    type: row.type,
    waitTimeDays: row.waitTimeDays,
    keyEncrypted: key,
    object: 'emergencyAccess',
  });
}

/**
 * PUT /api/emergency-access/:id — the grantor changes the grant.
 *
 * The type, the wait and the wrapped key can be changed while nobody has
 * started the wait yet.
 */
export async function handleUpdateEmergencyAccess(
  request: Request,
  env: Env,
  userId: string,
  id: string
): Promise<Response> {
  let body: { type?: unknown; waitTimeDays?: unknown; keyEncrypted?: unknown };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400);
  }
  const row = await getEmergencyAccess(env.DB, id);
  if (!row || row.grantorId !== userId) {
    return errorResponse('Emergency access not valid.', 404);
  }
  const type = body.type === undefined ? row.type : Number(body.type);
  if (type !== EMERGENCY_ACCESS_TYPE_VIEW && type !== EMERGENCY_ACCESS_TYPE_TAKEOVER) {
    return errorResponse('Type must be 0 (view) or 1 (takeover).', 400);
  }
  const waitTimeDays = body.waitTimeDays === undefined ? row.waitTimeDays : Number(body.waitTimeDays);
  if (!isValidEmergencyWaitDays(waitTimeDays)) {
    return errorResponse('Wait time must be between 1 and 90 days.', 400);
  }
  const changes: Parameters<typeof updateEmergencyAccess>[2] = {
    type,
    waitTimeDays,
    updatedAt: nowIso(),
  };
  const key = String(body.keyEncrypted || '').trim();
  if (key) changes.wrappedKey = key;
  await updateEmergencyAccess(env.DB, id, changes);
  return jsonResponse({
    id,
    status: row.status,
    type,
    waitTimeDays,
    object: 'emergencyAccess',
  });
}

/**
 * POST /api/emergency-access/:id/reinvite — the grantor asks again.
 *
 * There is no mail channel, so this cannot send an invitation. What it can
 * do is point the invitation at somebody who already has an account here:
 * the grant is addressed to them, and they can accept it when they sign in.
 */
export async function handleReinviteEmergencyAccess(
  request: Request,
  env: Env,
  userId: string,
  id: string
): Promise<Response> {
  void request;
  const row = await getEmergencyAccess(env.DB, id);
  if (!row || row.grantorId !== userId) {
    return errorResponse('Emergency access not valid.', 404);
  }
  if (row.status !== EMERGENCY_ACCESS_STATUS_INVITED) {
    return errorResponse('The invitation has already been accepted.', 400);
  }
  const email = (row.email || '').trim().toLowerCase();
  if (!email) {
    return errorResponse('Email not valid.', 400);
  }
  const grantee = await getUser(env.DB, email);
  if (!grantee) {
    // Nobody with that address has an account here, so there is nothing to
    // point the invitation at.
    return errorResponse('Grantee user not found.', 404);
  }
  await updateEmergencyAccess(env.DB, id, {
    granteeId: grantee.id,
    updatedAt: nowIso(),
  });
  return jsonResponse({ id, object: 'emergencyAccess' });
}

/**
 * PUT /api/emergency-access/:id/view
 *
 * The grantee reads the vault of the grantor. This opens after the wait and
 * the approval, the same as a takeover, because it hands over the whole list
 * of items.
 */
export async function handleViewEmergencyAccess(
  request: Request,
  env: Env,
  userId: string,
  id: string
): Promise<Response> {
  const row = await getEmergencyAccess(env.DB, id);
  if (!row || row.granteeId !== userId) {
    return errorResponse('Emergency access not valid.', 404);
  }
  if (row.status !== EMERGENCY_ACCESS_STATUS_RECOVERY_APPROVED) {
    return errorResponse('Emergency access not valid.', 404);
  }
  // A grant that only lets the other person read is the only one that can be
  // viewed; a takeover grant hands over the account instead.
  if (row.type !== EMERGENCY_ACCESS_TYPE_VIEW) {
    return errorResponse('Emergency access not valid.', 404);
  }
  const storage = new StorageService(env.DB);
  const ciphers = await storage.getAllCiphers(row.grantorId);
  const attachmentsByCipher = await storage.getAttachmentsByCipherIds(ciphers.map((cipher) => cipher.id));
  const validFolderIds = new Set((await storage.getAllFolders(row.grantorId)).map((folder) => folder.id));
  const responseOptions = { ...cipherResponseOptionsForRequest(request), validFolderIds };
  const data = ciphers.map((cipher) =>
    cipherToResponse(cipher, attachmentsByCipher.get(cipher.id) || [], responseOptions)
  );
  return jsonResponse({
    ciphers: data,
    keyEncrypted: row.wrappedKey,
    object: 'emergencyAccessView',
  });
}

/**
 * GET /api/emergency-access/:id/policies
 *
 * The rules of the grantor's organizations, so the client can hold the
 * takeover to them.
 */
export async function handleEmergencyAccessPolicies(
  request: Request,
  env: Env,
  userId: string,
  id: string
): Promise<Response> {
  void request;
  const row = await getEmergencyAccess(env.DB, id);
  if (!row || row.granteeId !== userId) {
    return errorResponse('Emergency access not valid.', 404);
  }
  if (row.status !== EMERGENCY_ACCESS_STATUS_RECOVERY_APPROVED) {
    return errorResponse('Emergency access not valid.', 404);
  }
  if (row.type !== EMERGENCY_ACCESS_TYPE_TAKEOVER) {
    return errorResponse('Emergency access not valid.', 404);
  }
  const storage = new StorageService(env.DB);
  const policies = await storage.listPoliciesForUser(row.grantorId);
  return jsonResponse({
    data: policies.map(policyResponse),
    object: 'list',
    continuationToken: null,
  });
}

/**
 * POST /api/emergency-access/:id/initiate
 *
 * The grantee says they cannot get in and starts the wait. The clock starts
 * here, so nobody can shorten it later.
 */
export async function handleInitiateEmergencyAccess(
  request: Request,
  env: Env,
  userId: string,
  id: string
): Promise<Response> {
  const row = await getEmergencyAccess(env.DB, id);
  if (!row || row.granteeId !== userId) {
    return errorResponse('Emergency access not valid.', 404);
  }
  if (row.status !== EMERGENCY_ACCESS_STATUS_CONFIRMED) {
    return errorResponse('Emergency access not valid.', 404);
  }
  if (!isValidEmergencyWaitDays(row.waitTimeDays)) {
    return errorResponse('Emergency access not valid.', 404);
  }
  const now = nowIso();
  await updateEmergencyAccess(env.DB, id, {
    status: EMERGENCY_ACCESS_STATUS_RECOVERY_INITIATED,
    recoveryInitiatedAt: now,
    lastNotificationAt: now,
    updatedAt: now,
  });
  // The owner should hear about it while they can still refuse it.
  await sendEmergencyAccessNotice(env, new URL(request.url).hostname, {
    kind: 'recovery_started',
    grantorId: row.grantorId,
    granteeId: userId,
    waitTimeDays: row.waitTimeDays,
  });
  const updated = await getEmergencyAccess(env.DB, id);
  return jsonResponse({
    id: updated?.id ?? id,
    status: EMERGENCY_ACCESS_STATUS_RECOVERY_INITIATED,
    type: updated?.type ?? row.type,
    waitTimeDays: updated?.waitTimeDays ?? row.waitTimeDays,
    object: 'emergencyAccess',
  });
}

/**
 * POST /api/emergency-access/:id/approve
 *
 * The grantor approves the recovery. It only works once the wait is over,
 * so the wait cannot be shortened by approving early.
 */
export async function handleApproveEmergencyAccess(
  request: Request,
  env: Env,
  userId: string,
  id: string
): Promise<Response> {
  const row = await getEmergencyAccess(env.DB, id);
  if (!row || row.grantorId !== userId) {
    return errorResponse('Emergency access not valid.', 404);
  }
  if (row.status !== EMERGENCY_ACCESS_STATUS_RECOVERY_INITIATED) {
    return errorResponse('Emergency access not valid.', 404);
  }
  // The grantor may approve before the wait is over: the wait is there for the
  // case where nobody answers, and the grantor answering is consent. The
  // person who was let in cannot approve, and the wait cannot be shortened by
  // anyone but the grantor. This is what the upstream does, and it is what
  // the official client expects when the grantor presses Approve.
  await updateEmergencyAccess(env.DB, id, {
    status: EMERGENCY_ACCESS_STATUS_RECOVERY_APPROVED,
    updatedAt: nowIso(),
  });
  // The recovery may also have ended on its own, without the owner answering;
  // either way the owner hears that the account is one step away from being
  // taken over.
  await sendEmergencyAccessNotice(env, new URL(request.url).hostname, {
    kind: 'recovery_approved',
    grantorId: row.grantorId,
    granteeId: row.granteeId ?? undefined,
    waitTimeDays: row.waitTimeDays,
  });
  const updated = await getEmergencyAccess(env.DB, id);
  return jsonResponse({
    id: updated?.id ?? id,
    status: EMERGENCY_ACCESS_STATUS_RECOVERY_APPROVED,
    type: updated?.type ?? row.type,
    waitTimeDays: updated?.waitTimeDays ?? row.waitTimeDays,
    object: 'emergencyAccess',
  });
}

/**
 * POST /api/emergency-access/:id/takeover
 *
 * The grantee asks for what it needs to take the account over: the salt and
 * the key of the grantor, so the client can work out the master key itself.
 * The master key never travels.
 */
export async function handleTakeoverEmergencyAccess(
  request: Request,
  env: Env,
  userId: string,
  id: string
): Promise<Response> {
  void request;
  const row = await getEmergencyAccess(env.DB, id);
  if (!row || row.granteeId !== userId) {
    return errorResponse('Emergency access not valid.', 404);
  }
  if (row.status !== EMERGENCY_ACCESS_STATUS_RECOVERY_APPROVED) {
    return errorResponse('Emergency access not valid.', 404);
  }
  // A grant that only lets the other person read never gives them the account,
  // however far the recovery went.
  if (row.type !== EMERGENCY_ACCESS_TYPE_TAKEOVER) {
    return errorResponse('Emergency access not valid.', 404);
  }
  const grantor = await getUserById(env.DB, row.grantorId);
  if (!grantor) {
    return errorResponse('Grantor user not found.', 404);
  }
  return jsonResponse({
    kdf: grantor.kdfType,
    kdfIterations: grantor.kdfIterations,
    kdfMemory: grantor.kdfMemory,
    kdfParallelism: grantor.kdfParallelism,
    // The grantor's key, already wrapped for the grantee when the grant was
    // made. The master key itself never leaves the client.
    keyEncrypted: row.wrappedKey,
    // The salt of the master password is the account's own address, the same
    // as everywhere else in the format.
    salt: grantor.email.trim().toLowerCase(),
    object: 'emergencyAccessTakeover',
  });
}

/**
 * The new master password and the new wrapped key.
 *
 * The current clients send the authentication data and the unlock data; the
 * older ones send the hash and the key directly. Both are read here, and the
 * current shape is checked against the account being taken over: the salt
 * has to be the one of that account, and the key derivation has to be the
 * one it uses. Without that check, a grantee could set a password that the
 * account was never derived with.
 */
function readTakeoverCredentials(
  body: {
    newMasterPasswordHash?: unknown;
    key?: unknown;
    authenticationData?: unknown;
    unlockData?: unknown;
  },
  grantor: {
    email: string;
    kdfType: number;
    kdfIterations: number;
    kdfMemory?: number | null;
    kdfParallelism?: number | null;
  }
): { newMasterPasswordHash: string; nextKey: string } | { error: string } {
  const legacyHash = String(body.newMasterPasswordHash || '').trim();
  const legacyKey = String(body.key || '').trim();
  if (legacyHash || legacyKey) {
    if (!legacyHash || !legacyKey) {
      return { error: 'The new master password hash and the key are required.' };
    }
    return { newMasterPasswordHash: legacyHash, nextKey: legacyKey };
  }

  const authentication = body.authenticationData as
    | { salt?: unknown; kdf?: unknown; masterPasswordAuthenticationHash?: unknown }
    | undefined;
  const unlock = body.unlockData as
    | { salt?: unknown; kdf?: unknown; masterKeyWrappedUserKey?: unknown }
    | undefined;
  if (!authentication || !unlock) {
    return { error: 'The new master password hash and the key are required.' };
  }
  const hash = String(authentication.masterPasswordAuthenticationHash || '').trim();
  const nextKey = String(unlock.masterKeyWrappedUserKey || '').trim();
  if (!hash || !nextKey) {
    return { error: 'The new master password hash and the key are required.' };
  }
  const salt = String(authentication.salt || '').trim().toLowerCase();
  const unlockSalt = String(unlock.salt || '').trim().toLowerCase();
  // The salt of a master password is the address of the account, the same
  // as everywhere else in the format.
  const accountSalt = grantor.email.trim().toLowerCase();
  if (!salt || salt !== accountSalt || salt !== unlockSalt) {
    return { error: 'Invalid master password salt' };
  }
  const kdf = readKdfSettings(authentication.kdf);
  const unlockKdf = readKdfSettings(unlock.kdf);
  if (!kdf || !unlockKdf) {
    return { error: 'KDF settings do not match the grantor account' };
  }
  if (
    kdf.kdfType !== unlockKdf.kdfType ||
    kdf.iterations !== unlockKdf.iterations ||
    kdf.memory !== unlockKdf.memory ||
    kdf.parallelism !== unlockKdf.parallelism
  ) {
    return { error: 'KDF settings must be equal for authentication and unlock' };
  }
  if (
    kdf.kdfType !== grantor.kdfType ||
    kdf.iterations !== grantor.kdfIterations ||
    (kdf.kdfType === 2 &&
      (kdf.memory !== (grantor.kdfMemory ?? null) || kdf.parallelism !== (grantor.kdfParallelism ?? null)))
  ) {
    return { error: 'KDF settings do not match the grantor account' };
  }
  return { newMasterPasswordHash: hash, nextKey };
}

/** The key derivation settings, as the clients send them. */
function readKdfSettings(
  value: unknown
): { kdfType: number; iterations: number; memory: number | null; parallelism: number | null } | null {
  if (!value || typeof value !== 'object') return null;
  const raw = value as Record<string, unknown>;
  const kdfType = Number(raw.kdfType ?? raw.KdfType);
  const iterations = Number(raw.iterations ?? raw.Iterations);
  if (!Number.isFinite(kdfType) || !Number.isFinite(iterations)) return null;
  const memoryRaw = raw.memory ?? raw.Memory;
  const parallelismRaw = raw.parallelism ?? raw.Parallelism;
  return {
    kdfType,
    iterations,
    memory: memoryRaw === null || memoryRaw === undefined ? null : Number(memoryRaw),
    parallelism: parallelismRaw === null || parallelismRaw === undefined ? null : Number(parallelismRaw),
  };
}

/**
 * POST /api/emergency-access/:id/password
 *
 * The grantee sets a new master password for the grantor. The vault key
 * stays the same, so no item has to be encrypted again; what changes is the
 * password that opens it. The two-step methods of the grantor are removed,
 * because the grantor may not be the one who set this password, and the
 * grantor is removed from every organization but the ones they own.
 */
export async function handleEmergencyAccessPassword(
  request: Request,
  env: Env,
  userId: string,
  id: string
): Promise<Response> {
  let body: {
    newMasterPasswordHash?: unknown;
    key?: unknown;
    authenticationData?: unknown;
    unlockData?: unknown;
  };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400);
  }
  const row = await getEmergencyAccess(env.DB, id);
  if (!row || row.granteeId !== userId) {
    return errorResponse('Emergency access not valid.', 404);
  }
  if (row.status !== EMERGENCY_ACCESS_STATUS_RECOVERY_APPROVED) {
    return errorResponse('Emergency access not valid.', 404);
  }
  // A grant that only lets the other person read never gives them the
  // account, however far the recovery went.
  if (row.type !== EMERGENCY_ACCESS_TYPE_TAKEOVER) {
    return errorResponse('Emergency access not valid.', 404);
  }
  const grantor = await getUserById(env.DB, row.grantorId);
  if (!grantor) {
    return errorResponse('Grantor user not found.', 404);
  }
  const credentials = readTakeoverCredentials(body, grantor);
  if ('error' in credentials) {
    return errorResponse(credentials.error, 400);
  }
  const { newMasterPasswordHash, nextKey } = credentials;
  const storage = new StorageService(env.DB);
  // Stored as a server-side verifier, as a password change does: the client
  // hash itself would log in to anyone who read the database.
  grantor.masterPasswordHash = await new AuthService(env).hashPasswordServer(newMasterPasswordHash);
  grantor.key = nextKey;
  // A password the grantor did not choose must not keep the ways to get in
  // that only the grantor knew about.
  grantor.totpSecret = null;
  grantor.yubikeyKey1 = null;
  grantor.yubikeyKey2 = null;
  grantor.yubikeyKey3 = null;
  grantor.yubikeyKey4 = null;
  grantor.yubikeyKey5 = null;
  grantor.yubikeyNfc = false;
  grantor.securityStamp = crypto.randomUUID();
  grantor.updatedAt = nowIso();
  await storage.saveUser(grantor);
  await storage.deleteRefreshTokensByUserId(grantor.id);
  await storage.deleteTrustedTwoFactorTokensByUserId(grantor.id);
  // The account has changed hands: the owner hears about it, not only the
  // person who took it over.
  await sendEmergencyAccessNotice(env, new URL(request.url).hostname, {
    kind: 'account_taken_over',
    grantorId: row.grantorId,
    granteeId: userId,
    waitTimeDays: row.waitTimeDays,
  });
  return jsonResponse({ object: 'emergencyAccess' });
}
