// The account routes of the official clients that sit beside the profile:
// the avatar color, "log out of all sessions", and the routes NodeWarden
// answers with 501 on purpose.
//
// Coverage:
//   - the avatar color is stored, shown in the profile, and kept by other
//     writes of the account; a color in another form is refused;
//   - a new security stamp needs the master password, and replaces the stamp
//     every access token carries;
//   - key rotation, organization SSO and deleting the account answer 501;
//   - so do the mail-backed account routes: changing the email, and deleting
//     the account by an emailed link, which is sent without a login.
import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { handlePublicRoute } from '../src/router-public';
import { AuthService } from '../src/services/auth';
import { StorageService } from '../src/services/storage';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { sqliteD1 } from './sqlite-d1';
import type { Env, User } from '../src/types';

const NOW = '2026-11-10T00:00:00.000Z';
const USER_ID = 'user-account-lifecycle';
const EMAIL = 'account-lifecycle@example.test';
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
  const response = await handleAuthenticatedRoute(request, env, USER_ID, await currentUser(storage), path, method);
  assert.ok(response, `no route answered ${method} ${path}`);
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null };
}


test('the avatar color is stored and shown in the profile', async () => {
  const { env, storage } = await fixture();
  const set = await call(env, storage, '/api/accounts/avatar', 'PUT', { avatarColor: '#2f6fdb' });
  assert.equal(set.status, 200, JSON.stringify(set.body));
  assert.equal(set.body.avatarColor, '#2f6fdb');
  assert.equal(set.body.object, 'profile');

  // Another write of the account does not clear the color.
  const user = await currentUser(storage);
  await storage.saveUser({ ...user, name: 'Renamed' });
  const profile = await call(env, storage, '/api/accounts/profile', 'GET');
  assert.equal(profile.body.avatarColor, '#2f6fdb');

  const cleared = await call(env, storage, '/api/accounts/avatar', 'PUT', { avatarColor: null });
  assert.equal(cleared.status, 200);
  assert.equal(cleared.body.avatarColor, null);
});

test('an avatar color in another form is refused', async () => {
  const { env, storage } = await fixture();
  for (const avatarColor of ['#fff', 'blue', '#12345g', 42]) {
    const refused = await call(env, storage, '/api/accounts/avatar', 'PUT', { avatarColor });
    assert.equal(refused.status, 400, String(avatarColor));
  }
  assert.equal((await currentUser(storage)).avatarColor, null);
});

test('a new security stamp needs the master password', async () => {
  const { env, storage } = await fixture();
  const refused = await call(env, storage, '/api/accounts/security-stamp', 'POST', { masterPasswordHash: 'wrong' });
  assert.equal(refused.status, 400);
  assert.equal((await currentUser(storage)).securityStamp, 'stamp');

  const done = await call(env, storage, '/api/accounts/security-stamp', 'POST', { masterPasswordHash: CLIENT_HASH });
  assert.equal(done.status, 200);
  const stamp = (await currentUser(storage)).securityStamp;
  assert.notEqual(stamp, 'stamp', 'the stamp every access token carries is replaced');
});

test('key rotation, organization SSO, deleting the account and changing the email answer 501', async () => {
  const { env, storage } = await fixture();
  for (const [path, method] of [
    ['/api/accounts/key-management/rotate-user-account-keys', 'POST'],
    ['/api/accounts/sso/user-identifier', 'GET'],
    ['/api/accounts/sso/00000000-0000-4000-8000-000000000001', 'DELETE'],
    ['/api/accounts', 'DELETE'],
    ['/api/accounts/email', 'POST'],
  ]) {
    const answer = await call(env, storage, path, method, method === 'GET' ? undefined : {});
    assert.equal(answer.status, 501, `${method} ${path}`);
  }
});

test('deleting the account by an emailed link answers 501 without a login', async () => {
  const { env } = await fixture();
  for (const path of ['/api/accounts/delete-recover', '/api/accounts/delete-recover-token']) {
    const request = new Request(`https://vault.example.test${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: EMAIL }),
    });
    const response = await handlePublicRoute(request, env, path, 'POST', async () => null);
    assert.ok(response, `the public router answers ${path}`);
    assert.equal(response.status, 501, path);
  }
});

test('the profile changes only what the body carries', async () => {
  const { env, storage } = await fixture();
  await storage.saveUser({ ...(await currentUser(storage)), masterPasswordHint: 'the old hint' });

  // The official clients send the name alone; the hint stays.
  const renamed = await call(env, storage, '/api/accounts/profile', 'PUT', { name: '  New Name  ' });
  assert.equal(renamed.status, 200, JSON.stringify(renamed.body));
  assert.equal(renamed.body.name, 'New Name');
  assert.equal((await currentUser(storage)).masterPasswordHint, 'the old hint');

  // NodeWarden's web vault sends the hint alone; the name stays.
  const hinted = await call(env, storage, '/api/accounts/profile', 'PUT', { masterPasswordHint: 'a new hint' });
  assert.equal(hinted.status, 200);
  const user = await currentUser(storage);
  assert.equal(user.name, 'New Name');
  assert.equal(user.masterPasswordHint, 'a new hint');

  const tooLong = await call(env, storage, '/api/accounts/profile', 'PUT', { name: 'x'.repeat(51) });
  assert.equal(tooLong.status, 400);
  assert.equal((await currentUser(storage)).name, 'New Name');
});
