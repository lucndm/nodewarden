// Vault and two-step login routes of the official clients that NodeWarden
// had only in another shape: deleting several or all folders, removing every
// WebAuthn key at once, Duo (refused on purpose), and the breach report
// (the account's own address only).
import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { AuthService } from '../src/services/auth';
import { StorageService } from '../src/services/storage';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { sqliteD1 } from './sqlite-d1';
import type { Env, User } from '../src/types';

const NOW = '2026-11-10T00:00:00.000Z';
const USER_ID = 'user-vault-two-factor';
const EMAIL = 'vault-two-factor@example.test';
const CLIENT_HASH = 'client-master-password-hash';

async function fixture(): Promise<{ env: Env; storage: StorageService }> {
  const db = new DatabaseSync(':memory:');
  await ensureStorageSchema(sqliteD1(db));
  const env = { DB: sqliteD1(db), JWT_SECRET: 'a-test-secret-that-is-long-enough-for-hmac-0123456789' } as unknown as Env;
  const storage = new StorageService(env.DB);
  await storage.createUser({
    id: USER_ID,
    email: EMAIL,
    name: null,
    masterPasswordHint: null,
    masterPasswordHash: await new AuthService(env).hashPasswordServer(CLIENT_HASH),
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
    yubikeyNfc: false,
    apiKey: null,
    userKeyId: null,
    createdAt: NOW,
    updatedAt: NOW,
  } as never);
  return { env, storage };
}

async function currentUser(storage: StorageService): Promise<User> {
  const user = await storage.getUserById(USER_ID);
  assert.ok(user);
  return user;
}

async function call(
  env: Env,
  storage: StorageService,
  path: string,
  method: string,
  body?: unknown
): Promise<{ status: number; body: any }> {
  const request = new Request(`https://vault.example.test${path}`, {
    method,
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const pathname = new URL(request.url).pathname;
  const response = await handleAuthenticatedRoute(request, env, USER_ID, await currentUser(storage), pathname, method);
  assert.ok(response, `no route answered ${method} ${path}`);
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null };
}


const ENC = (value: string) =>
  `2.${Buffer.from(`iv-${value}`).toString('base64')}|${Buffer.from(`ct-${value}`).toString('base64')}|${Buffer.from(`mac-${value}`).toString('base64')}`;

async function folderIds(env: Env, storage: StorageService): Promise<string[]> {
  const listed = await call(env, storage, '/api/folders', 'GET');
  return (listed.body?.data || []).map((folder: { id: string }) => folder.id);
}

test('several folders are deleted at once, and then all of them', async () => {
  const { env, storage } = await fixture();
  for (const name of ['Work', 'Home', 'Travel']) {
    const created = await call(env, storage, '/api/folders', 'POST', { name: ENC(name) });
    assert.equal(created.status, 200, JSON.stringify(created.body));
  }
  const [first, ...rest] = await folderIds(env, storage);

  const bulk = await call(env, storage, '/api/folders', 'DELETE', { ids: [first] });
  assert.equal(bulk.status, 204);
  assert.deepEqual((await folderIds(env, storage)).sort(), rest.sort());

  const all = await call(env, storage, '/api/folders/all', 'DELETE');
  assert.equal(all.status, 204);
  assert.deepEqual(await folderIds(env, storage), []);

  // Nothing left is not an error.
  assert.equal((await call(env, storage, '/api/folders/all', 'DELETE')).status, 204);
});

test('removing every WebAuthn key needs the master password or a token', async () => {
  const { env, storage } = await fixture();
  const refused = await call(env, storage, '/api/two-factor/webauthn/all', 'DELETE', { masterPasswordHash: 'wrong' });
  assert.equal(refused.status, 400);
  const done = await call(env, storage, '/api/two-factor/webauthn/all', 'DELETE', { masterPasswordHash: CLIENT_HASH });
  assert.equal(done.status, 200, JSON.stringify(done.body));
});

test('Duo answers 501', async () => {
  const { env, storage } = await fixture();
  for (const [path, method] of [
    ['/api/two-factor/get-duo', 'POST'],
    ['/api/two-factor/duo', 'PUT'],
    ['/api/two-factor/duo', 'DELETE'],
  ]) {
    const answer = await call(env, storage, path, method, { masterPasswordHash: CLIENT_HASH });
    assert.equal(answer.status, 501, `${method} ${path}`);
  }
});

test('the breach report checks only the account address', async () => {
  const { env, storage } = await fixture();
  const other = await call(env, storage, '/api/hibp/breach?username=someone-else%40example.test', 'GET');
  assert.equal(other.status, 400);
  const missing = await call(env, storage, '/api/hibp/breach', 'GET');
  assert.equal(missing.status, 400);
});
