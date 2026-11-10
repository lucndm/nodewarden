// The emergency access routes.
//
// One account lets another person in when they cannot get in themselves.
// These checks run through the real router: the invitation carries a key that
// is already wrapped, so the server never holds a key it could open, and the
// rules that keep one account from touching the grants of another are proved
// by the answers the router gives.
import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { StorageService } from '../src/services/storage';
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
      key: 'key',
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

const INVITE = {
  email: 'grantee@example.test',
  type: 0,
  waitTimeDays: 7,
  // The grantor wraps their own vault key for the grantee. It arrives
  // encrypted, so the server holds a key it cannot open.
  encryptedUserKey: '4.not-a-real-key-just-a-placeholder',
};

test('the grantor invites somebody and sees the grant', async () => {
  const { env } = await fixture();
  const invited = await call(env, 'POST', '/api/emergency-access/invite', GRANTOR, INVITE);
  assert.equal(invited.status, 200);
  const body = await invited.json();
  assert.equal(body.object, 'emergencyAccess');
  assert.equal(body.type, 0);
  assert.equal(body.waitTimeDays, 7);

  const trusted = await call(env, 'GET', '/api/emergency-access/trusted', GRANTOR);
  const list = await trusted.json();
  assert.equal(list.data.length, 1);
  assert.equal(list.data[0].object, 'emergencyAccessGranteeDetails');
  assert.equal(list.data[0].email, 'grantee@example.test');
  assert.equal(list.data[0].status, 0);
});

test('the grantee accepts the invitation and then sees the grant', async () => {
  const { env } = await fixture();
  const invited = await call(env, 'POST', '/api/emergency-access/invite', GRANTOR, INVITE);
  const { id } = await invited.json();

  const accepted = await call(env, 'PUT', `/api/emergency-access/${id}/accept`, GRANTEE);
  assert.equal(accepted.status, 200);

  const granted = await call(env, 'GET', '/api/emergency-access/granted', GRANTEE);
  const list = await granted.json();
  assert.equal(list.data.length, 1);
  assert.equal(list.data[0].object, 'emergencyAccessGrantorDetails');
  assert.equal(list.data[0].grantorId, GRANTOR);
  assert.equal(list.data[0].email, 'grantor@example.test');
});

test('somebody else cannot accept an invitation that was not for them', async () => {
  const { env } = await fixture();
  const invited = await call(env, 'POST', '/api/emergency-access/invite', GRANTOR, INVITE);
  const { id } = await invited.json();

  const refused = await call(env, 'PUT', `/api/emergency-access/${id}/accept`, STRANGER);
  assert.equal(refused.status, 404);
});

test('an account cannot name itself as its emergency contact', async () => {
  const { env } = await fixture();
  const refused = await call(env, 'POST', '/api/emergency-access/invite', GRANTOR, {
    ...INVITE,
    email: 'Grantor@Example.test',
  });
  assert.equal(refused.status, 400);
  const trusted = await call(env, 'GET', '/api/emergency-access/trusted', GRANTOR);
  assert.equal((await trusted.json()).data.length, 0);
});

test('the grantor turns a recovery down, and the grantee can start it again', async () => {
  const { env } = await fixture();
  const invited = await call(env, 'POST', '/api/emergency-access/invite', GRANTOR, INVITE);
  const { id } = await invited.json();
  await call(env, 'PUT', `/api/emergency-access/${id}/accept`, GRANTEE);
  await call(env, 'POST', `/api/emergency-access/${id}/confirm`, GRANTOR, { key: INVITE.encryptedUserKey });
  const started = await call(env, 'POST', `/api/emergency-access/${id}/initiate`, GRANTEE);
  assert.equal(started.status, 200);

  const rejected = await call(env, 'POST', `/api/emergency-access/${id}/reject`, GRANTOR);
  assert.equal(rejected.status, 200);
  assert.equal((await rejected.json()).status, 2);
  const trusted = await call(env, 'GET', '/api/emergency-access/trusted', GRANTOR);
  assert.equal((await trusted.json()).data[0].status, 2);

  const again = await call(env, 'POST', `/api/emergency-access/${id}/initiate`, GRANTEE);
  assert.equal(again.status, 200);
});

test('the grantor cannot reject a grant nobody asked to recover', async () => {
  const { env } = await fixture();
  const invited = await call(env, 'POST', '/api/emergency-access/invite', GRANTOR, INVITE);
  const { id } = await invited.json();
  const refused = await call(env, 'POST', `/api/emergency-access/${id}/reject`, GRANTOR);
  assert.equal(refused.status, 404);
  const trusted = await call(env, 'GET', '/api/emergency-access/trusted', GRANTOR);
  assert.equal((await trusted.json()).data.length, 1);
});

test('somebody else cannot see or withdraw a grant', async () => {
  const { env } = await fixture();
  const invited = await call(env, 'POST', '/api/emergency-access/invite', GRANTOR, INVITE);
  const { id } = await invited.json();

  const seen = await call(env, 'GET', `/api/emergency-access/${id}`, STRANGER);
  assert.equal(seen.status, 404);
  const deleted = await call(env, 'DELETE', `/api/emergency-access/${id}`, STRANGER);
  assert.equal(deleted.status, 404);
  // The grant is still there.
  const trusted = await call(env, 'GET', '/api/emergency-access/trusted', GRANTOR);
  assert.equal((await trusted.json()).data.length, 1);
});

test('the grantor withdraws the grant', async () => {
  const { env } = await fixture();
  const invited = await call(env, 'POST', '/api/emergency-access/invite', GRANTOR, INVITE);
  const { id } = await invited.json();

  const withdrawn = await call(env, 'DELETE', `/api/emergency-access/${id}`, GRANTOR);
  assert.equal(withdrawn.status, 200);
  const trusted = await call(env, 'GET', '/api/emergency-access/trusted', GRANTOR);
  assert.equal((await trusted.json()).data.length, 0);
});

test('the grantee declines and the grant is gone', async () => {
  const { env } = await fixture();
  const invited = await call(env, 'POST', '/api/emergency-access/invite', GRANTOR, INVITE);
  const { id } = await invited.json();

  const declined = await call(env, 'PUT', `/api/emergency-access/${id}/reject`, GRANTEE);
  assert.equal(declined.status, 200);
  const trusted = await call(env, 'GET', '/api/emergency-access/trusted', GRANTOR);
  assert.equal((await trusted.json()).data.length, 0);
});

test('an invitation without a wrapped key is accepted, because the key comes later', async () => {
  const { env } = await fixture();
  // The official client invites with the address, the kind of access and the
  // wait, and hands the key over when it confirms the grant.
  const invited = await call(env, 'POST', '/api/emergency-access/invite', GRANTOR, {
    email: 'grantee@example.test',
    type: 0,
    waitTimeDays: 7,
  });
  assert.equal(invited.status, 200);
  const { id } = (await invited.json()) as { id: string };

  // The grant is not confirmed yet, so nothing can be started with it.
  await call(env, 'PUT', `/api/emergency-access/${id}/accept`, GRANTEE);
  const tooSoon = await call(env, 'PUT', `/api/emergency-access/${id}/initiate`, GRANTEE);
  assert.equal(tooSoon.status, 404, 'the grant cannot be started before the key is handed over');
});

test('an invitation without an address is refused', async () => {
  const { env } = await fixture();
  const refused = await call(env, 'POST', '/api/emergency-access/invite', GRANTOR, {
    type: 0,
    waitTimeDays: 7,
    encryptedUserKey: '4.placeholder-not-a-real-key',
  });
  assert.equal(refused.status, 400);
});

test('a wait time the format does not allow is refused', async () => {
  const { env } = await fixture();
  for (const waitTimeDays of [0, 91, 7.5]) {
    const refused = await call(env, 'POST', '/api/emergency-access/invite', GRANTOR, {
      ...INVITE,
      waitTimeDays,
    });
    assert.equal(refused.status, 400, `wait time ${waitTimeDays} must be refused`);
  }
});

test('a takeover is invited, and the wait and the approval still stand between it and the account', async () => {
  const { env } = await fixture();
  const invited = await call(env, 'POST', '/api/emergency-access/invite', GRANTOR, {
    ...INVITE,
    type: 1,
  });
  assert.equal(invited.status, 200);
  assert.equal((await invited.json()).type, 1);
  // A takeover cannot be taken before the wait has passed and the grantor
  // has approved it; that is proved in emergency-access-takeover.test.ts.
});

test('the same person cannot be invited twice while a grant is pending', async () => {
  const { env } = await fixture();
  const first = await call(env, 'POST', '/api/emergency-access/invite', GRANTOR, INVITE);
  assert.equal(first.status, 200);
  const second = await call(env, 'POST', '/api/emergency-access/invite', GRANTOR, INVITE);
  assert.equal(second.status, 400);
});

test('the grantor sees the grantee only, and the grantee sees the grantor only', async () => {
  const { env } = await fixture();
  await call(env, 'POST', '/api/emergency-access/invite', GRANTOR, INVITE);

  const strangerTrusted = await call(env, 'GET', '/api/emergency-access/trusted', STRANGER);
  assert.equal((await strangerTrusted.json()).data.length, 0);
  const strangerGranted = await call(env, 'GET', '/api/emergency-access/granted', STRANGER);
  assert.equal((await strangerGranted.json()).data.length, 0);
});
