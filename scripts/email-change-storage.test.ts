// The pending email change.
//
// A user changes the address of the account: a code is sent to the new
// address, and the change waits for that code. The request lives in one row
// per account, so a second request replaces the first one and a wrong code
// can only be counted against the request that is pending.
//
// These checks pin the storage contract: the request is replaced, the wrong
// codes are counted, and the request is gone once it is used or refused.
import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { ensureStorageSchema } from '../src/services/storage-schema';
import { StorageService } from '../src/services/storage';
import {
  deleteEmailChangeRequest,
  getEmailChangeRequest,
  putEmailChangeRequest,
  recordEmailChangeAttempt,
} from '../src/services/storage-email-change-repo';
import { sqliteD1 } from './sqlite-d1';
import type { Env } from '../src/types';

const USER_ID = '00000000-0000-4000-8000-0000000000b1';
const OTHER_USER_ID = '00000000-0000-4000-8000-0000000000b2';
const EXPIRES_AT = 1_800_000_000_000;

async function fixture(): Promise<{ env: Env; storage: StorageService }> {
  const db = new DatabaseSync(':memory:');
  await ensureStorageSchema(sqliteD1(db));
  const env = { DB: sqliteD1(db) } as unknown as Env;
  const storage = new StorageService(env.DB);
  await storage.createUser({
    id: USER_ID,
    email: 'owner@example.test',
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
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
  } as never);
  return { env, storage };
}

test('a pending change replaces the one before it', async () => {
  const { env } = await fixture();
  await putEmailChangeRequest(env.DB, {
    userId: USER_ID,
    newEmail: 'first@example.test',
    codeHash: 'hash-first',
    expiresAt: EXPIRES_AT,
  });
  await putEmailChangeRequest(env.DB, {
    userId: USER_ID,
    newEmail: 'second@example.test',
    codeHash: 'hash-second',
    expiresAt: EXPIRES_AT + 1000,
  });

  const request = await getEmailChangeRequest(env.DB, USER_ID);
  assert.ok(request, 'the request is there');
  assert.equal(request.userId, USER_ID);
  assert.equal(request.newEmail, 'second@example.test');
  assert.equal(request.codeHash, 'hash-second');
  assert.equal(request.expiresAt, EXPIRES_AT + 1000);
  assert.equal(request.attempts, 0, 'the wrong codes start over');
});

test('the request of one account is not the request of another', async () => {
  const { env } = await fixture();
  await putEmailChangeRequest(env.DB, {
    userId: USER_ID,
    newEmail: 'mine@example.test',
    codeHash: 'hash-mine',
    expiresAt: EXPIRES_AT,
  });
  assert.equal(await getEmailChangeRequest(env.DB, OTHER_USER_ID), null);
});

test('attempts count up', async () => {
  const { env } = await fixture();
  await putEmailChangeRequest(env.DB, {
    userId: USER_ID,
    newEmail: 'mine@example.test',
    codeHash: 'hash-mine',
    expiresAt: EXPIRES_AT,
  });

  assert.equal(await recordEmailChangeAttempt(env.DB, USER_ID), 1);
  assert.equal(await recordEmailChangeAttempt(env.DB, USER_ID), 2);
  const request = await getEmailChangeRequest(env.DB, USER_ID);
  assert.ok(request);
  assert.equal(request.attempts, 2);
});

test('deleting removes the request', async () => {
  const { env } = await fixture();
  await putEmailChangeRequest(env.DB, {
    userId: USER_ID,
    newEmail: 'mine@example.test',
    codeHash: 'hash-mine',
    expiresAt: EXPIRES_AT,
  });
  await deleteEmailChangeRequest(env.DB, USER_ID);
  assert.equal(await getEmailChangeRequest(env.DB, USER_ID), null);
});

test('the storage service keeps the request of the account', async () => {
  const { storage } = await fixture();
  await storage.putEmailChangeRequest({
    userId: USER_ID,
    newEmail: 'mine@example.test',
    codeHash: 'hash-mine',
    expiresAt: EXPIRES_AT,
  });
  const request = await storage.getEmailChangeRequest(USER_ID);
  assert.ok(request);
  assert.equal(request.newEmail, 'mine@example.test');

  assert.equal(await storage.recordEmailChangeAttempt(USER_ID), 1);
  await storage.deleteEmailChangeRequest(USER_ID);
  assert.equal(await storage.getEmailChangeRequest(USER_ID), null);
});
