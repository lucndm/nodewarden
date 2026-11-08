// Checks the contract of a Send: a copy of something, shared by a link.
//
// A Send is not a vault item and grants no rights on anything. It is a copy
// with a key: the client encrypts the payload, the server keeps the encrypted
// payload and the key wrapped with the owner's key, and the link carries the
// key in its fragment. Whoever holds the link can read the copy until the
// link is closed by expiry, by the access limit or by the owner.
//
// Coverage:
//   - the owner creates a Send and finds it in the list and in the sync;
//   - another account cannot see it at all;
//   - the link opens the copy, and the answer never carries the key;
//   - a Send with a password asks for it;
//   - the access token opens the Send for the bearer;
//   - an expired Send, a disabled Send and a Send past its access limit are gone;
//   - deleting the Send closes the link;
//   - the owner sees who came and how often.
import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { handlePublicRoute } from '../src/router-public';
import { StorageService } from '../src/services/storage';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { sqliteD1 } from './sqlite-d1';
import type { Env } from '../src/types';

const NOW = '2026-11-08T00:00:00.000Z';
const OWNER = 'user-owner';
const STRANGER = 'user-stranger';
const JWT_SECRET = 'send-contract-secret-0123456789abcdef';

/** The encrypted payload and the key the client would send. */
const SEND_TEXT = {
  type: 0,
  name: 'Shared note',
  key: '2.enc-key|ciphertext|mac',
  text: { text: '2.enc-text|ciphertext|mac', hidden: false },
  deletionDate: '2026-11-30T00:00:00.000Z',
};

async function fixture(): Promise<{ env: Env; storage: StorageService }> {
  const db = new DatabaseSync(':memory:');
  await ensureStorageSchema(sqliteD1(db));
  const env = {
    DB: sqliteD1(db),
    JWT_SECRET,
  } as unknown as Env;
  const storage = new StorageService(env.DB);
  for (const [id, email] of [
    [OWNER, 'owner@example.test'],
    [STRANGER, 'stranger@example.test'],
  ]) {
    await createUser(storage, id, email);
  }
  return { env, storage };
}

async function createUser(storage: StorageService, id: string, email: string): Promise<void> {
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

async function call(
  env: Env,
  url: string,
  method: string,
  userId: string,
  body?: unknown
): Promise<Response> {
  const request = new Request(url, {
    method,
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const path = new URL(url).pathname;
  const response = await handleAuthenticatedRoute(request, env, userId, { id: userId } as never, path, method);
  assert.ok(response, `no route answered ${method} ${path}`);
  return response;
}

/** A call that needs no account: the link itself. */
async function callPublic(
  env: Env,
  url: string,
  method: string,
  body?: unknown,
  headers: Record<string, string> = {}
): Promise<Response> {
  const request = new Request(url, {
    method,
    headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const path = new URL(url).pathname;
  const response = await handlePublicRoute(request, env, path, method, async () => null);
  assert.ok(response, `no public route answered ${method} ${path}`);
  return response;
}

async function createSend(
  env: Env,
  userId: string,
  overrides: Record<string, unknown> = {}
): Promise<{ id: string; accessId: string; key: string }> {
  const response = await call(env, 'https://vault.example.test/api/sends', 'POST', userId, {
    ...SEND_TEXT,
    ...overrides,
  });
  assert.equal(response.status, 200, await response.clone().text());
  const body = (await response.json()) as { id: string; accessId: string; key: string };
  return body;
}

test('the owner creates a Send and finds it in the list and in the sync', async () => {
  const { env } = await fixture();
  const created = await createSend(env, OWNER);
  assert.ok(created.id, 'the Send has an id');
  assert.ok(created.accessId, 'the Send has an access id for the link');

  const list = await call(env, 'https://vault.example.test/api/sends', 'GET', OWNER);
  const listed = (await list.json()) as { data: Array<{ id: string; object: string }> };
  assert.equal(listed.data.length, 1);
  assert.equal(listed.data[0].id, created.id);
  assert.equal(listed.data[0].object, 'send');

  const sync = await call(env, 'https://vault.example.test/api/sync', 'GET', OWNER);
  const synced = (await sync.json()) as { sends: Array<{ id: string }> };
  assert.equal(synced.sends.length, 1);
  assert.equal(synced.sends[0].id, created.id);
});

test('another account cannot see the Send', async () => {
  const { env } = await fixture();
  const created = await createSend(env, OWNER);

  const single = await call(env, `https://vault.example.test/api/sends/${created.id}`, 'GET', STRANGER);
  assert.equal(single.status, 404, 'a Send of somebody else is not found');

  const list = await call(env, 'https://vault.example.test/api/sends', 'GET', STRANGER);
  const listed = (await list.json()) as { data: unknown[] };
  assert.deepEqual(listed.data, [], 'the list holds only the Sends of the account');
});

test('the link opens the copy and never carries the key', async () => {
  const { env } = await fixture();
  const created = await createSend(env, OWNER);

  const opened = await callPublic(env, `https://vault.example.test/api/sends/access/${created.accessId}`, 'POST', {});
  assert.equal(opened.status, 200, await opened.clone().text());
  const body = (await opened.json()) as Record<string, unknown>;
  assert.equal(body.object, 'send-access');
  assert.equal(body.text && (body.text as { text: string }).text, SEND_TEXT.text.text);
  assert.equal(body.key, undefined, 'the key stays in the link, the server does not hand it out');
  assert.equal(body.creatorIdentifier, 'owner@example.test');
});

test('a Send with a password asks for it', async () => {
  const { env } = await fixture();
  const created = await createSend(env, OWNER, { password: 'open sesame', authType: 1 });

  // The password attempts are counted per address, so the server needs one.
  const wrong = await callPublic(
    env,
    `https://vault.example.test/api/sends/access/${created.accessId}`,
    'POST',
    { password: 'wrong' },
    { 'CF-Connecting-IP': '203.0.113.7' }
  );
  assert.equal(wrong.status, 400);
  const wrongBody = (await wrong.json()) as { error?: string };
  assert.match(String(wrongBody.error), /password/i, 'the answer says what is missing');

  const right = await callPublic(
    env,
    `https://vault.example.test/api/sends/access/${created.accessId}`,
    'POST',
    { password: 'open sesame' },
    { 'CF-Connecting-IP': '203.0.113.7' }
  );
  assert.equal(right.status, 200, await right.clone().text());
});

test('the access token opens the Send for the bearer', async () => {
  const { env } = await fixture();
  const created = await createSend(env, OWNER, { password: 'open sesame', authType: 1 });

  const granted = await callPublic(
    env,
    'https://vault.example.test/identity/connect/token',
    'POST',
    { grant_type: 'send_access', send_id: created.accessId, password: 'open sesame' },
    { 'CF-Connecting-IP': '203.0.113.7' }
  );
  assert.equal(granted.status, 200, await granted.clone().text());
  const tokenBody = (await granted.json()) as { access_token: string };
  assert.ok(tokenBody.access_token, 'the grant returns a token');

  const opened = await callPublic(env, 'https://vault.example.test/api/sends/access', 'POST', undefined, {
    Authorization: `Bearer ${tokenBody.access_token}`,
  });
  assert.equal(opened.status, 200, await opened.clone().text());
  const body = (await opened.json()) as Record<string, unknown>;
  assert.equal(body.object, 'send-access');
  assert.equal(body.text && (body.text as { text: string }).text, SEND_TEXT.text.text);

  const forged = await callPublic(env, 'https://vault.example.test/api/sends/access', 'POST', undefined, {
    Authorization: 'Bearer not-a-token',
  });
  assert.equal(forged.status, 401);
});

test('an expired Send is gone', async () => {
  const { env } = await fixture();
  const created = await createSend(env, OWNER, { expirationDate: '2026-11-01T00:00:00.000Z' });

  const opened = await callPublic(env, `https://vault.example.test/api/sends/access/${created.accessId}`, 'POST', {});
  assert.equal(opened.status, 404);

  const granted = await callPublic(
    env,
    'https://vault.example.test/identity/connect/token',
    'POST',
    { grant_type: 'send_access', send_id: created.accessId },
    { 'CF-Connecting-IP': '203.0.113.7' }
  );
  assert.equal(granted.status, 400);
  const body = (await granted.json()) as { send_access_error_type?: string };
  assert.equal(body.send_access_error_type, 'send_not_available');
});

test('the access count ends the link', async () => {
  const { env } = await fixture();
  const created = await createSend(env, OWNER, { maxAccessCount: 1 });

  const first = await callPublic(env, `https://vault.example.test/api/sends/access/${created.accessId}`, 'POST', {});
  assert.equal(first.status, 200, await first.clone().text());

  const second = await callPublic(env, `https://vault.example.test/api/sends/access/${created.accessId}`, 'POST', {});
  assert.equal(second.status, 404, 'the link is used up');
});

test('a disabled Send is not reachable', async () => {
  const { env } = await fixture();
  const created = await createSend(env, OWNER, { disabled: true });

  const opened = await callPublic(env, `https://vault.example.test/api/sends/access/${created.accessId}`, 'POST', {});
  assert.equal(opened.status, 404);
});

test('deleting the Send closes the link', async () => {
  const { env } = await fixture();
  const created = await createSend(env, OWNER);

  const deleted = await call(env, `https://vault.example.test/api/sends/${created.id}`, 'DELETE', OWNER);
  assert.equal(deleted.status, 200);

  const opened = await callPublic(env, `https://vault.example.test/api/sends/access/${created.accessId}`, 'POST', {});
  assert.equal(opened.status, 404, 'the link of a deleted Send is dead');

  const list = await call(env, 'https://vault.example.test/api/sends', 'GET', OWNER);
  const listed = (await list.json()) as { data: unknown[] };
  assert.deepEqual(listed.data, []);
});

test('the owner sees who came and how often', async () => {
  const { env } = await fixture();
  const created = await createSend(env, OWNER);

  await callPublic(env, `https://vault.example.test/api/sends/access/${created.accessId}`, 'POST', {});

  const list = await call(env, 'https://vault.example.test/api/sends', 'GET', OWNER);
  const listed = (await list.json()) as { data: Array<{ id: string; accessCount: number }> };
  const send = listed.data.find((entry) => entry.id === created.id);
  assert.equal(send?.accessCount, 1, 'the owner sees how often the link was opened');
});

test('a Send that hides its creator says nothing about them', async () => {
  const { env } = await fixture();
  const created = await createSend(env, OWNER, { hideEmail: true });

  const opened = await callPublic(env, `https://vault.example.test/api/sends/access/${created.accessId}`, 'POST', {});
  assert.equal(opened.status, 200, await opened.clone().text());
  const body = (await opened.json()) as Record<string, unknown>;
  assert.equal(body.creatorIdentifier, null, 'the sender stays anonymous');
});
