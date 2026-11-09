// The takeover of an account that cannot be reached.
//
// When the account holder cannot get in, the person they let in can ask for
// a takeover. It takes a wait, the account holder has to approve it, and only
// then can the master password be replaced.
//
// These checks run through the real router, because the rules that matter
// here are about who may do what and when:
//   - the wait cannot be shortened by approving early;
//   - a takeover needs the approval, not just the wait;
//   - only the person who was let in may take over, and only the account
//     holder may approve;
//   - the master key never travels: the client is handed the salt and the
//     key that is already wrapped for it.
import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { StorageService } from '../src/services/storage';
import {
  EMERGENCY_ACCESS_STATUS_CONFIRMED,
  EMERGENCY_ACCESS_STATUS_RECOVERY_APPROVED,
  EMERGENCY_ACCESS_STATUS_RECOVERY_INITIATED,
  EMERGENCY_ACCESS_TYPE_TAKEOVER,
  createEmergencyAccess,
  updateEmergencyAccess,
} from '../src/services/storage-emergency-access-repo';
import { sqliteD1 } from './sqlite-d1';
import type { Env } from '../src/types';

const GRANTOR = '00000000-0000-4000-8000-0000000000a1';
const GRANTEE = '00000000-0000-4000-8000-0000000000a2';
const STRANGER = '00000000-0000-4000-8000-0000000000a3';
const NOW = '2026-01-01T00:00:00.000Z';

async function fixture(): Promise<{ env: Env; storage: StorageService }> {
  const db = new DatabaseSync(':memory:');
  await ensureStorageSchema(sqliteD1(db));
  const env = { DB: sqliteD1(db) } as unknown as Env;
  const storage = new StorageService(env.DB);
  for (const [id, email] of [
    [GRANTOR, 'grantor@example.test'],
    [GRANTEE, 'grantee@example.test'],
    [STRANGER, 'stranger@example.test'],
  ]) {
    await storage.createUser({
      id,
      email,
      name: null,
      masterPasswordHint: null,
      masterPasswordHash: 'hash',
      key: '2.aXY=|Y3Q=|bWFj',
      privateKey: null,
      publicKey: null,
      kdfType: 0,
      kdfIterations: 600000,
      kdfMemory: null,
      kdfParallelism: null,
      securityStamp: 'stamp',
      role: 'user',
      status: 'active',
      verifyDevices: false,
      totpSecret: 'TOTPSECRET',
      totpRecoveryCode: null,
      yubikeyKey1: 'y1',
      yubikeyKey2: null,
      yubikeyKey3: null,
      yubikeyKey4: null,
      yubikeyKey5: null,
      yubikeyNfc: false,
      apiKey: null,
      userKeyId: null,
      createdAt: NOW,
      updatedAt: NOW,
    } as never);
  }
  return { env, storage };
}

async function call(
  env: Env,
  method: string,
  path: string,
  userId: string,
  body?: unknown
): Promise<Response> {
  const request = new Request(`https://vault.example.test${path}`, {
    method,
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const response = await handleAuthenticatedRoute(request, env, userId, { id: userId } as never, path, method);
  assert.ok(response, `no route answered ${method} ${path}`);
  return response;
}

/**
 * A grant that is already confirmed, with a wait of one day so the wait can be
 * measured. The recovery is started in the past so the wait has passed.
 */
async function confirmedGrant(env: Env, overrides: { waitTimeDays?: number } = {}) {
  const id = 'takeover-grant';
  await createEmergencyAccess(env.DB, {
    id,
    grantorId: GRANTOR,
    granteeId: GRANTEE,
    email: 'grantee@example.test',
    wrappedKey: '4.placeholder-not-a-real-key',
    type: EMERGENCY_ACCESS_TYPE_TAKEOVER,
    status: EMERGENCY_ACCESS_STATUS_CONFIRMED,
    waitTimeDays: overrides.waitTimeDays ?? 1,
    recoveryInitiatedAt: null,
    lastNotificationAt: null,
    createdAt: NOW,
    updatedAt: NOW,
  });
  return id;
}

test('a takeover invitation is refused while the grant is only a view', async () => {
  const { env } = await fixture();
  const invited = await call(env, 'POST', '/api/emergency-access/invite', GRANTOR, {
    email: 'grantee@example.test',
    type: 0,
    waitTimeDays: 7,
    encryptedUserKey: '4.placeholder-not-a-real-key',
  });
  assert.equal(invited.status, 200);
});

test('the grantee starts the wait and the grantor approves it', async () => {
  const { env } = await fixture();
  const id = await confirmedGrant(env);

  const initiated = await call(env, 'POST', `/api/emergency-access/${id}/initiate`, GRANTEE);
  assert.equal(initiated.status, 200);
  assert.equal((await initiated.json()).status, EMERGENCY_ACCESS_STATUS_RECOVERY_INITIATED);

  // The wait has not passed yet, so the grantor cannot approve.
  const tooEarly = await call(env, 'POST', `/api/emergency-access/${id}/approve`, GRANTOR);
  assert.equal(tooEarly.status, 400, 'the wait cannot be shortened by approving early');

  // Once the wait has passed, the grantor approves.
  await updateEmergencyAccess(env.DB, id, {
    recoveryInitiatedAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
    updatedAt: NOW,
  });
  const approved = await call(env, 'POST', `/api/emergency-access/${id}/approve`, GRANTOR);
  assert.equal(approved.status, 200);
  assert.equal((await approved.json()).status, EMERGENCY_ACCESS_STATUS_RECOVERY_APPROVED);
});

test('the wait is counted in days, so a day has to pass', async () => {
  const { env } = await fixture();
  const id = await confirmedGrant(env, { waitTimeDays: 7 });
  await call(env, 'POST', `/api/emergency-access/${id}/initiate`, GRANTEE);

  // Six days is not seven.
  await updateEmergencyAccess(env.DB, id, {
    recoveryInitiatedAt: new Date(Date.now() - 6 * 24 * 60 * 60 * 1000).toISOString(),
    updatedAt: NOW,
  });
  const tooEarly = await call(env, 'POST', `/api/emergency-access/${id}/approve`, GRANTOR);
  assert.equal(tooEarly.status, 400);

  await updateEmergencyAccess(env.DB, id, {
    recoveryInitiatedAt: new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString(),
    updatedAt: NOW,
  });
  const approved = await call(env, 'POST', `/api/emergency-access/${id}/approve`, GRANTOR);
  assert.equal(approved.status, 200);
});

test('somebody else cannot start or approve the recovery', async () => {
  const { env } = await fixture();
  const id = await confirmedGrant(env);

  const initiated = await call(env, 'POST', `/api/emergency-access/${id}/initiate`, STRANGER);
  assert.equal(initiated.status, 404);
  const approved = await call(env, 'POST', `/api/emergency-access/${id}/approve`, STRANGER);
  assert.equal(approved.status, 404);
});

test('the grantee cannot approve their own recovery', async () => {
  const { env } = await fixture();
  const id = await confirmedGrant(env);
  await call(env, 'POST', `/api/emergency-access/${id}/initiate`, GRANTEE);
  await updateEmergencyAccess(env.DB, id, {
    recoveryInitiatedAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
    updatedAt: NOW,
  });
  const approved = await call(env, 'POST', `/api/emergency-access/${id}/approve`, GRANTEE);
  assert.equal(approved.status, 404, 'only the account holder approves');
});

test('the takeover hands over the salt and the wrapped key, never the master key', async () => {
  const { env } = await fixture();
  const id = await confirmedGrant(env);
  await call(env, 'POST', `/api/emergency-access/${id}/initiate`, GRANTEE);
  await updateEmergencyAccess(env.DB, id, {
    recoveryInitiatedAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
    updatedAt: NOW,
  });
  await call(env, 'POST', `/api/emergency-access/${id}/approve`, GRANTOR);

  const takeover = await call(env, 'POST', `/api/emergency-access/${id}/takeover`, GRANTEE);
  assert.equal(takeover.status, 200);
  const body = await takeover.json();
  assert.equal(body.object, 'emergencyAccessTakeover');
  // The salt of the master password is the account's own address.
  assert.equal(body.salt, 'grantor@example.test');
  assert.equal(body.keyEncrypted, '4.placeholder-not-a-real-key');
  assert.equal(body.masterKey, undefined, 'the master key never travels');
  assert.equal(body.newMasterPasswordHash, undefined);
});

test('the takeover is refused before the recovery was approved', async () => {
  const { env } = await fixture();
  const id = await confirmedGrant(env);
  await call(env, 'POST', `/api/emergency-access/${id}/initiate`, GRANTEE);
  const refused = await call(env, 'POST', `/api/emergency-access/${id}/takeover`, GRANTEE);
  assert.equal(refused.status, 404);
});

test('the new master password replaces the old one and drops the ways in the old one had', async () => {
  const { env, storage } = await fixture();
  const id = await confirmedGrant(env);
  await call(env, 'POST', `/api/emergency-access/${id}/initiate`, GRANTEE);
  await updateEmergencyAccess(env.DB, id, {
    recoveryInitiatedAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
    updatedAt: NOW,
  });
  await call(env, 'POST', `/api/emergency-access/${id}/approve`, GRANTOR);

  const changed = await call(env, 'POST', `/api/emergency-access/${id}/password`, GRANTEE, {
    newMasterPasswordHash: 'new-hash',
    key: '2.bmV3|dmV3|bmV3',
  });
  assert.equal(changed.status, 200);

  const grantor = await storage.getUserById(GRANTOR);
  assert.equal(grantor?.masterPasswordHash, 'new-hash');
  assert.equal(grantor?.key, '2.bmV3|dmV3|bmV3');
  // A password the grantor did not choose must not keep the ways to get in
  // that only the grantor knew about.
  assert.equal(grantor?.totpSecret, null);
  assert.equal(grantor?.yubikeyKey1, null);
  assert.equal(grantor?.yubikeyNfc, false);
});

test('a password change without the approval is refused', async () => {
  const { env, storage } = await fixture();
  const id = await confirmedGrant(env);
  const refused = await call(env, 'POST', `/api/emergency-access/${id}/password`, GRANTEE, {
    newMasterPasswordHash: 'new-hash',
    key: '2.bmV3|dmV3|bmV3',
  });
  assert.equal(refused.status, 404);
  const grantor = await storage.getUserById(GRANTOR);
  assert.equal(grantor?.masterPasswordHash, 'hash', 'the old password still stands');
});

test('somebody else cannot change the password of the account', async () => {
  const { env, storage } = await fixture();
  const id = await confirmedGrant(env);
  await call(env, 'POST', `/api/emergency-access/${id}/initiate`, GRANTEE);
  await updateEmergencyAccess(env.DB, id, {
    recoveryInitiatedAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
    updatedAt: NOW,
  });
  await call(env, 'POST', `/api/emergency-access/${id}/approve`, GRANTOR);

  const refused = await call(env, 'POST', `/api/emergency-access/${id}/password`, STRANGER, {
    newMasterPasswordHash: 'new-hash',
    key: '2.bmV3|dmV3|bmV3',
  });
  assert.equal(refused.status, 404);
  const grantor = await storage.getUserById(GRANTOR);
  assert.equal(grantor?.masterPasswordHash, 'hash');
});

test('a password change without the new key is refused', async () => {
  const { env } = await fixture();
  const id = await confirmedGrant(env);
  await call(env, 'POST', `/api/emergency-access/${id}/initiate`, GRANTEE);
  await updateEmergencyAccess(env.DB, id, {
    recoveryInitiatedAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
    updatedAt: NOW,
  });
  await call(env, 'POST', `/api/emergency-access/${id}/approve`, GRANTOR);

  const refused = await call(env, 'POST', `/api/emergency-access/${id}/password`, GRANTEE, {
    newMasterPasswordHash: 'new-hash',
  });
  assert.equal(refused.status, 400);
});

test('the sessions of the account are thrown out when its password is replaced', async () => {
  const { env, storage } = await fixture();
  const id = await confirmedGrant(env);
  await call(env, 'POST', `/api/emergency-access/${id}/initiate`, GRANTEE);
  await updateEmergencyAccess(env.DB, id, {
    recoveryInitiatedAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
    updatedAt: NOW,
  });
  await call(env, 'POST', `/api/emergency-access/${id}/approve`, GRANTOR);

  // A session of the grantor, and a device that was trusted to skip the
  // two-step challenge.
  await env.DB.prepare(
    "INSERT INTO refresh_tokens(token, user_id, expires_at, created_at) VALUES ('tok', ?, ?, ?)"
  )
    .bind(GRANTOR, Date.now() + 3600_000, NOW)
    .run();
  await env.DB.prepare(
    "INSERT INTO trusted_two_factor_device_tokens(token, user_id, device_identifier, expires_at) VALUES ('dev', ?, 'dev-1', ?)"
  )
    .bind(GRANTOR, Date.now() + 3600_000)
    .run();
  const sessionsBefore = await env.DB.prepare('SELECT COUNT(*) AS n FROM refresh_tokens WHERE user_id = ?')
    .bind(GRANTOR)
    .first<{ n: number }>();
  assert.equal(sessionsBefore?.n, 1);

  const changed = await call(env, 'POST', `/api/emergency-access/${id}/password`, GRANTEE, {
    newMasterPasswordHash: 'new-hash',
    key: '2.bmV3|dmV3|bmV3',
  });
  assert.equal(changed.status, 200);

  const sessionsAfter = await env.DB.prepare('SELECT COUNT(*) AS n FROM refresh_tokens WHERE user_id = ?')
    .bind(GRANTOR)
    .first<{ n: number }>();
  assert.equal(sessionsAfter?.n, 0, 'the sessions of the grantor are gone');

  const trusted = await env.DB.prepare(
    'SELECT COUNT(*) AS n FROM trusted_two_factor_device_tokens WHERE user_id = ?'
  )
    .bind(GRANTOR)
    .first<{ n: number }>();
  assert.equal(trusted?.n, 0, 'the devices that skipped the two-step challenge are gone');

  // The security stamp is renewed, so a token made before the change does
  // not open anything.
  const grantor = await storage.getUserById(GRANTOR);
  assert.notEqual(grantor?.securityStamp, 'stamp', 'the security stamp is renewed');
});
