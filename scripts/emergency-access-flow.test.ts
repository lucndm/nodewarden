// The emergency access flow as the official client walks it.
//
// The official client does not send the key with the invitation: it invites
// with the address, the kind of access and the wait, the person who was let
// in accepts, and then the owner confirms and hands over the key. Only after
// that can the wait start.
//
// These checks walk that path through the real router, because every step
// depends on the one before it. They also cover what a view grant opens: the
// list of items of the owner, read only, and only after the wait.
import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { StorageService } from '../src/services/storage';
import {
  approveExpiredEmergencyAccess,
  getEmergencyAccess,
  updateEmergencyAccess,
  EMERGENCY_ACCESS_STATUS_ACCEPTED,
  EMERGENCY_ACCESS_STATUS_CONFIRMED,
  EMERGENCY_ACCESS_STATUS_INVITED,
  EMERGENCY_ACCESS_STATUS_RECOVERY_APPROVED,
  EMERGENCY_ACCESS_TYPE_TAKEOVER,
  EMERGENCY_ACCESS_TYPE_VIEW,
} from '../src/services/storage-emergency-access-repo';
import { sqliteD1 } from './sqlite-d1';
import type { Env } from '../src/types';

const GRANTOR = '00000000-0000-4000-8000-0000000000b1';
const GRANTEE = '00000000-0000-4000-8000-0000000000b2';
const NOW = '2026-01-01T00:00:00.000Z';
const WRAPPED_KEY = '4.aXY=|Y3Q=|YmV0';
// A value in the shape the clients send: encrypted, so the server cannot read it.
const ENC = (value: string) =>
  `2.${Buffer.from('iv-' + value).toString('base64')}|${Buffer.from('ct-' + value).toString('base64')}|${Buffer.from('mac-' + value).toString('base64')}`;

async function fixture(): Promise<{ env: Env; storage: StorageService }> {
  const db = new DatabaseSync(':memory:');
  await ensureStorageSchema(sqliteD1(db));
  db.exec(
    'CREATE TABLE IF NOT EXISTS rate_limit_buckets(bucket_key TEXT PRIMARY KEY, count INTEGER NOT NULL, expires_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)'
  );
  const env = { DB: sqliteD1(db) } as unknown as Env;
  const storage = new StorageService(env.DB);
  for (const [id, email] of [
    [GRANTOR, 'owner@example.test'],
    [GRANTEE, 'guest@example.test'],
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
      totpSecret: null,
      totpRecoveryCode: null,
      yubikeyKey1: null,
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
 * The invitation exactly as the official client sends it: the address, the
 * kind of access and the wait. No key.
 */
async function officialInvite(env: Env, type: number, waitTimeDays: number) {
  const response = await call(env, 'POST', '/api/emergency-access/invite', GRANTOR, {
    email: 'guest@example.test',
    type,
    waitTimeDays,
  });
  assert.equal(response.status, 200, 'the invitation is accepted without a key');
  const body = (await response.json()) as { id: string; status: number };
  assert.equal(body.status, EMERGENCY_ACCESS_STATUS_INVITED);
  return body.id;
}

test('the whole path the official client walks, without a key in the invitation', async () => {
  const { env } = await fixture();
  const id = await officialInvite(env, EMERGENCY_ACCESS_TYPE_TAKEOVER, 7);

  // The person who was let in accepts.
  const accepted = await call(env, 'PUT', `/api/emergency-access/${id}/accept`, GRANTEE, { token: 'token' });
  assert.equal(accepted.status, 200);
  assert.equal((await accepted.json()).status, EMERGENCY_ACCESS_STATUS_ACCEPTED);

  // The owner confirms and hands over the key.
  const confirmed = await call(env, 'PUT', `/api/emergency-access/${id}/confirm`, GRANTOR, { key: WRAPPED_KEY });
  assert.equal(confirmed.status, 200);
  assert.equal((await confirmed.json()).status, EMERGENCY_ACCESS_STATUS_CONFIRMED);

  const row = await getEmergencyAccess(env.DB, id);
  assert.equal(row?.wrappedKey, WRAPPED_KEY, 'the key the owner handed over is kept');
  assert.equal(row?.email, null, 'the answered invitation no longer keeps the address');

  // Only now can the wait start.
  const initiated = await call(env, 'PUT', `/api/emergency-access/${id}/initiate`, GRANTEE);
  assert.equal(initiated.status, 200);
});

test('the wait cannot start before the owner confirms', async () => {
  const { env } = await fixture();
  const id = await officialInvite(env, EMERGENCY_ACCESS_TYPE_TAKEOVER, 7);
  await call(env, 'PUT', `/api/emergency-access/${id}/accept`, GRANTEE, { token: 'token' });

  const tooSoon = await call(env, 'PUT', `/api/emergency-access/${id}/initiate`, GRANTEE);
  assert.equal(tooSoon.status, 404, 'the grant is not confirmed yet');
});

test('only the owner can confirm, and only once', async () => {
  const { env } = await fixture();
  const id = await officialInvite(env, EMERGENCY_ACCESS_TYPE_TAKEOVER, 7);
  await call(env, 'PUT', `/api/emergency-access/${id}/accept`, GRANTEE, { token: 'token' });

  const byGuest = await call(env, 'PUT', `/api/emergency-access/${id}/confirm`, GRANTEE, { key: WRAPPED_KEY });
  assert.equal(byGuest.status, 404, 'the person who was let in cannot confirm');

  const byOwner = await call(env, 'PUT', `/api/emergency-access/${id}/confirm`, GRANTOR, { key: WRAPPED_KEY });
  assert.equal(byOwner.status, 200);

  const twice = await call(env, 'PUT', `/api/emergency-access/${id}/confirm`, GRANTOR, { key: WRAPPED_KEY });
  assert.equal(twice.status, 404, 'a confirmed grant cannot be confirmed again');
});

test('a view grant opens the items of the owner, and only after the wait', async () => {
  const { env } = await fixture();
  const created = await call(env, 'POST', '/api/ciphers', GRANTOR, {
    type: 1,
    name: ENC('Owner item'),
  });
  assert.equal(created.status, 200, 'the owner has an item');

  const id = await officialInvite(env, EMERGENCY_ACCESS_TYPE_VIEW, 1);
  await call(env, 'PUT', `/api/emergency-access/${id}/accept`, GRANTEE, { token: 'token' });
  await call(env, 'PUT', `/api/emergency-access/${id}/confirm`, GRANTOR, { key: WRAPPED_KEY });
  await call(env, 'PUT', `/api/emergency-access/${id}/initiate`, GRANTEE);

  // Before the wait is over the items are not there yet.
  const early = await call(env, 'PUT', `/api/emergency-access/${id}/view`, GRANTEE);
  assert.equal(early.status, 404, 'the items are not open before the wait is over');

  // The wait passes on its own.
  await getEmergencyAccess(env.DB, id);
  await updateEmergencyAccess(env.DB, id, {
    recoveryInitiatedAt: new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString(),
    updatedAt: NOW,
  });
  const approved = await approveExpiredEmergencyAccess(env.DB);
  assert.equal(approved.length, 1, 'a view grant waits just as long, and then stands on its own');

  const view = await call(env, 'PUT', `/api/emergency-access/${id}/view`, GRANTEE);
  assert.equal(view.status, 200);
  const body = (await view.json()) as { ciphers: unknown[]; keyEncrypted: string; object: string };
  assert.equal(body.object, 'emergencyAccessView');
  assert.equal(body.keyEncrypted, WRAPPED_KEY, 'the key comes with the items');
  assert.equal(body.ciphers.length, 1, 'the items of the owner are there');
});

test('a takeover grant cannot be viewed', async () => {
  const { env } = await fixture();
  const id = await officialInvite(env, EMERGENCY_ACCESS_TYPE_TAKEOVER, 7);
  await call(env, 'PUT', `/api/emergency-access/${id}/accept`, GRANTEE, { token: 'token' });
  await call(env, 'PUT', `/api/emergency-access/${id}/confirm`, GRANTOR, { key: WRAPPED_KEY });
  await call(env, 'PUT', `/api/emergency-access/${id}/initiate`, GRANTEE);
  await updateEmergencyAccess(env.DB, id, {
    recoveryInitiatedAt: new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString(),
    updatedAt: NOW,
  });
  await approveExpiredEmergencyAccess(env.DB);

  const view = await call(env, 'PUT', `/api/emergency-access/${id}/view`, GRANTEE);
  assert.equal(view.status, 404, 'a takeover grant hands over the account, not a list of items');
});

test('the owner can change the wait and the kind of access', async () => {
  const { env } = await fixture();
  const id = await officialInvite(env, EMERGENCY_ACCESS_TYPE_TAKEOVER, 7);

  const updated = await call(env, 'PUT', `/api/emergency-access/${id}`, GRANTOR, {
    type: EMERGENCY_ACCESS_TYPE_VIEW,
    waitTimeDays: 30,
  });
  assert.equal(updated.status, 200);
  const body = (await updated.json()) as { type: number; waitTimeDays: number };
  assert.equal(body.type, EMERGENCY_ACCESS_TYPE_VIEW);
  assert.equal(body.waitTimeDays, 30);

  const row = await getEmergencyAccess(env.DB, id);
  assert.equal(row?.type, EMERGENCY_ACCESS_TYPE_VIEW);
  assert.equal(row?.waitTimeDays, 30);

  const byGuest = await call(env, 'PUT', `/api/emergency-access/${id}`, GRANTEE, { waitTimeDays: 90 });
  assert.equal(byGuest.status, 404, 'the person who was let in cannot change the grant');
});

test('the owner can ask again, which points the invitation at the account', async () => {
  const { env } = await fixture();
  const id = await officialInvite(env, EMERGENCY_ACCESS_TYPE_TAKEOVER, 7);

  const again = await call(env, 'POST', `/api/emergency-access/${id}/reinvite`, GRANTOR);
  assert.equal(again.status, 200);
  const row = await getEmergencyAccess(env.DB, id);
  assert.equal(row?.granteeId, GRANTEE, 'the invitation now points at the account of the guest');
});

test('the rules of the owner come with a takeover', async () => {
  const { env } = await fixture();
  const id = await officialInvite(env, EMERGENCY_ACCESS_TYPE_TAKEOVER, 7);
  await call(env, 'PUT', `/api/emergency-access/${id}/accept`, GRANTEE, { token: 'token' });
  await call(env, 'PUT', `/api/emergency-access/${id}/confirm`, GRANTOR, { key: WRAPPED_KEY });
  await call(env, 'PUT', `/api/emergency-access/${id}/initiate`, GRANTEE);
  await updateEmergencyAccess(env.DB, id, {
    recoveryInitiatedAt: new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString(),
    updatedAt: NOW,
  });
  await approveExpiredEmergencyAccess(env.DB);

  const policies = await call(env, 'GET', `/api/emergency-access/${id}/policies`, GRANTEE);
  assert.equal(policies.status, 200);
  const body = (await policies.json()) as { data: unknown[]; object: string };
  assert.equal(body.object, 'list');
  assert.ok(Array.isArray(body.data));
});

test('the current clients can set the new password, and the salt and the key derivation have to match', async () => {
  const { env, storage } = await fixture();
  const id = await officialInvite(env, EMERGENCY_ACCESS_TYPE_TAKEOVER, 7);
  await call(env, 'PUT', `/api/emergency-access/${id}/accept`, GRANTEE, { token: 'token' });
  await call(env, 'PUT', `/api/emergency-access/${id}/confirm`, GRANTOR, { key: WRAPPED_KEY });
  await call(env, 'PUT', `/api/emergency-access/${id}/initiate`, GRANTEE);
  await updateEmergencyAccess(env.DB, id, {
    recoveryInitiatedAt: new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString(),
    updatedAt: NOW,
  });
  await approveExpiredEmergencyAccess(env.DB);

  const kdf = { kdfType: 0, iterations: 600000, memory: null, parallelism: null };
  const payload = {
    authenticationData: {
      salt: 'owner@example.test',
      kdf,
      masterPasswordAuthenticationHash: 'new-authentication-hash',
    },
    unlockData: {
      salt: 'owner@example.test',
      kdf,
      masterKeyWrappedUserKey: '2.bmV3|dmV3|bmV3',
    },
  };

  const changed = await call(env, 'PUT', `/api/emergency-access/${id}/password`, GRANTEE, payload);
  assert.equal(changed.status, 200, 'the current shape is accepted');
  const grantor = await storage.getUserById(GRANTOR);
  assert.equal(grantor?.masterPasswordHash, 'new-authentication-hash');
  assert.equal(grantor?.key, '2.bmV3|dmV3|bmV3');
});

test('a salt that is not the one of the account is refused', async () => {
  const { env } = await fixture();
  const id = await officialInvite(env, EMERGENCY_ACCESS_TYPE_TAKEOVER, 7);
  await call(env, 'PUT', `/api/emergency-access/${id}/accept`, GRANTEE, { token: 'token' });
  await call(env, 'PUT', `/api/emergency-access/${id}/confirm`, GRANTOR, { key: WRAPPED_KEY });
  await call(env, 'PUT', `/api/emergency-access/${id}/initiate`, GRANTEE);
  await updateEmergencyAccess(env.DB, id, {
    recoveryInitiatedAt: new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString(),
    updatedAt: NOW,
  });
  await approveExpiredEmergencyAccess(env.DB);

  const kdf = { kdfType: 0, iterations: 600000, memory: null, parallelism: null };
  const refused = await call(env, 'PUT', `/api/emergency-access/${id}/password`, GRANTEE, {
    authenticationData: {
      salt: 'somebody-else@example.test',
      kdf,
      masterPasswordAuthenticationHash: 'new-authentication-hash',
    },
    unlockData: {
      salt: 'somebody-else@example.test',
      kdf,
      masterKeyWrappedUserKey: '2.bmV3|dmV3|bmV3',
    },
  });
  assert.equal(refused.status, 400, 'the salt has to be the one of the account');
});

test('a key derivation that is not the one of the account is refused', async () => {
  const { env } = await fixture();
  const id = await officialInvite(env, EMERGENCY_ACCESS_TYPE_TAKEOVER, 7);
  await call(env, 'PUT', `/api/emergency-access/${id}/accept`, GRANTEE, { token: 'token' });
  await call(env, 'PUT', `/api/emergency-access/${id}/confirm`, GRANTOR, { key: WRAPPED_KEY });
  await call(env, 'PUT', `/api/emergency-access/${id}/initiate`, GRANTEE);
  await updateEmergencyAccess(env.DB, id, {
    recoveryInitiatedAt: new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString(),
    updatedAt: NOW,
  });
  await approveExpiredEmergencyAccess(env.DB);

  const wrong = { kdfType: 0, iterations: 100000, memory: null, parallelism: null };
  const refused = await call(env, 'PUT', `/api/emergency-access/${id}/password`, GRANTEE, {
    authenticationData: {
      salt: 'owner@example.test',
      kdf: wrong,
      masterPasswordAuthenticationHash: 'new-authentication-hash',
    },
    unlockData: {
      salt: 'owner@example.test',
      kdf: wrong,
      masterKeyWrappedUserKey: '2.bmV3|dmV3|bmV3',
    },
  });
  assert.equal(refused.status, 400, 'the key derivation has to be the one of the account');
});

test('the owner can fetch the public key of the person they let in', async () => {
  const { env, storage } = await fixture();
  // The grantee has a key pair on their account, so the owner can wrap the
  // vault key with the public key of it.
  const grantee = await storage.getUserById(GRANTEE);
  assert.ok(grantee);
  grantee.publicKey = 'RSA-PUBLIC-KEY-BASE64';
  await storage.saveUser(grantee);

  const response = await call(env, 'GET', `/api/users/${GRANTEE}/public-key`, GRANTOR);
  assert.equal(response.status, 200);
  const body = (await response.json()) as { userId: string; publicKey: string; object: string };
  assert.equal(body.object, 'userKey');
  assert.equal(body.userId, GRANTEE);
  assert.equal(body.publicKey, 'RSA-PUBLIC-KEY-BASE64');
});

test('a user without a key pair has no public key to fetch', async () => {
  const { env } = await fixture();
  const response = await call(env, 'GET', `/api/users/${GRANTEE}/public-key`, GRANTOR);
  assert.equal(response.status, 404);
});
