// Emergency access.
//
// One account lets another person in when they cannot get in themselves.
// The grantor hands over a key wrapped for the grantee, so the server holds
// a key it cannot open. The routes follow the upstream shape, so the
// official clients read what this writes.
//
// What this does NOT do, and says so:
//   - it never sends an email: the invitation is shown in the web vault, and
//     the grantee has to sign in to see it;
//   - it does not take over an account: that needs the whole vault
//     re-encrypted under a new master key, and there is no such path here.
//
// The routes:
//   GET    /api/emergency-access/trusted   the grants this account gave
//   GET    /api/emergency-access/granted   the grants this account was given
//   GET    /api/emergency-access/:id        one grant, seen by the grantor
//   POST   /api/emergency-access/invite    invite somebody
//   PUT    /api/emergency-access/:id/accept   the grantee accepts
//   PUT    /api/emergency-access/:id/reject   the grantee declines
//   DELETE /api/emergency-access/:id        the grantor withdraws
import { errorResponse, jsonResponse } from '../utils/response';
import { getUser, getUserById } from '../services/storage-user-repo';
import { StorageService } from '../services/storage';
import { sendEmergencyAccessNotice } from '../services/emergency-access-notifier';
import {
  createEmergencyAccess,
  deleteEmergencyAccess,
  getEmergencyAccess,
  isEmergencyRecoveryAllowed,
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
  // server never holds a key it could open.
  const wrappedKey = String(body.encryptedUserKey || '').trim();
  if (!wrappedKey) {
    return errorResponse('Encrypted user key is required.', 400);
  }
  const type = Number(body.type);
  if (type !== 0 && type !== 1) {
    return errorResponse('Type must be 0 (view) or 1 (takeover).', 400);
  }
  const waitTimeDays = body.waitTimeDays === undefined ? 1 : Number(body.waitTimeDays);
  if (!isValidEmergencyWaitDays(waitTimeDays)) {
    return errorResponse('Wait time must be between 1 and 90 days.', 400);
  }
  // A takeover lets the grantee replace the master password of the grantor.
  // The vault key stays the same, so no item is encrypted again; what changes
  // is the password that opens it. The wait and the approval still stand
  // between the grant and the takeover.
  if (type !== 0 && type !== 1) {
    return errorResponse('Type must be 0 (view) or 1 (takeover).', 400);
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

/** PUT /api/emergency-access/:id/reject — the grantee declines. */
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
  if (!isEmergencyRecoveryAllowed(row)) {
    return errorResponse('The wait has not passed yet.', 400);
  }
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
  const newMasterPasswordHash = String(body.newMasterPasswordHash || '').trim();
  const nextKey = String(body.key || '').trim();
  if (!newMasterPasswordHash || !nextKey) {
    return errorResponse('The new master password hash and the key are required.', 400);
  }
  const grantor = await getUserById(env.DB, row.grantorId);
  if (!grantor) {
    return errorResponse('Grantor user not found.', 404);
  }
  const storage = new StorageService(env.DB);
  grantor.masterPasswordHash = newMasterPasswordHash;
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
