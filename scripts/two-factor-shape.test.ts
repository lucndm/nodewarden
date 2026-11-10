// Checks that the two-step login setup answers the way the official clients
// read it, and that the token it hands out stands in for the master password.
//
// The official clients read each setup nested under its provider
// (`authenticator`, `yubiKey`, `webAuthn`), and send the `userVerificationToken`
// back with the change instead of the master password. NodeWarden's web vault
// keeps sending the master password, so both have to work.
//
// Coverage:
//   - each get-* answer is nested and carries a token;
//   - the token lets a change through without the master password;
//   - a forged token, or a token for another provider, is refused;
//   - deleting the YubiKey leaves the authenticator alone;
//   - the authenticator is turned off only with a token for the key in use.
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
const USER_ID = 'user-two-factor';
const EMAIL = 'two-factor@example.test';
const CLIENT_HASH = 'client-master-password-hash';
const TOTP_KEY = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const YUBIKEY_PUBLIC_ID = 'cccccccccccb';

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

async function saveUser(storage: StorageService, change: Partial<User>): Promise<void> {
  const user = await currentUser(storage);
  await storage.saveUser({ ...user, ...change });
}

test('get-authenticator answers nested and hands out a token', async () => {
  const { env, storage } = await fixture();
  const answer = await call(env, storage, '/api/two-factor/get-authenticator', 'POST', { masterPasswordHash: CLIENT_HASH });
  assert.equal(answer.status, 200, JSON.stringify(answer.body));
  assert.equal(typeof answer.body.authenticator.key, 'string');
  assert.equal(answer.body.authenticator.enabled, false);
  assert.equal(typeof answer.body.userVerificationToken, 'string');
  assert.equal(answer.body.key, undefined, 'no flat key');
  assert.equal(answer.body.Key, undefined, 'no flat Key');
});

test('the authenticator token lets the change reach the code check', async () => {
  const { env, storage } = await fixture();
  const setup = await call(env, storage, '/api/two-factor/get-authenticator', 'POST', { masterPasswordHash: CLIENT_HASH });
  const answer = await call(env, storage, '/api/two-factor/authenticator', 'PUT', {
    key: setup.body.authenticator.key,
    token: '000000',
    userVerificationToken: setup.body.userVerificationToken,
  });
  assert.equal(answer.status, 400);
  assert.equal(answer.body.error, 'Invalid token.', 'the token was accepted; only the code is wrong');
});

test('get-yubikey answers nested and hands out a token', async () => {
  const { env, storage } = await fixture();
  const answer = await call(env, storage, '/api/two-factor/get-yubikey', 'POST', { masterPasswordHash: CLIENT_HASH });
  assert.equal(answer.status, 200, JSON.stringify(answer.body));
  assert.equal(answer.body.yubiKey.enabled, false);
  assert.equal(typeof answer.body.userVerificationToken, 'string');
});

test('a YubiKey is saved with the token and no master password', async () => {
  const { env, storage } = await fixture();
  const setup = await call(env, storage, '/api/two-factor/get-yubikey', 'POST', { masterPasswordHash: CLIENT_HASH });
  // A bare public id is stored without asking Yubico, so the request goes
  // through as soon as the token is accepted.
  const answer = await call(env, storage, '/api/two-factor/yubikey', 'PUT', {
    key1: YUBIKEY_PUBLIC_ID,
    nfc: false,
    userVerificationToken: setup.body.userVerificationToken,
  });
  assert.notEqual(answer.body?.error, 'User verification failed.');
  assert.equal(answer.status, 200, JSON.stringify(answer.body));
  assert.equal(answer.body.yubiKey.enabled, true);
  assert.equal(answer.body.yubiKey.key1, YUBIKEY_PUBLIC_ID);
  assert.equal(answer.body.userVerificationToken, undefined, 'the change hands out no new token');
});

test('get-webauthn answers nested and hands out a token', async () => {
  const { env, storage } = await fixture();
  const answer = await call(env, storage, '/api/two-factor/get-webauthn', 'POST', { masterPasswordHash: CLIENT_HASH });
  assert.equal(answer.status, 200, JSON.stringify(answer.body));
  assert.equal(answer.body.webAuthn.enabled, false);
  assert.ok(Array.isArray(answer.body.webAuthn.keys));
  assert.equal(typeof answer.body.userVerificationToken, 'string');
});

test('the WebAuthn token gets a registration challenge, wrapped under options', async () => {
  const { env, storage } = await fixture();
  const setup = await call(env, storage, '/api/two-factor/get-webauthn', 'POST', { masterPasswordHash: CLIENT_HASH });
  const answer = await call(env, storage, '/api/two-factor/get-webauthn-challenge', 'POST', {
    userVerificationToken: setup.body.userVerificationToken,
  });
  assert.equal(answer.status, 200, JSON.stringify(answer.body));
  assert.equal(typeof answer.body.options.challenge, 'string');
  assert.equal(answer.body.options.status, 'ok');
  assert.equal(answer.body.options.errorMessage, '');
});

test('a forged token gets no challenge', async () => {
  const { env, storage } = await fixture();
  const answer = await call(env, storage, '/api/two-factor/get-webauthn-challenge', 'POST', { userVerificationToken: 'x.y' });
  assert.equal(answer.status, 400);
  assert.equal(answer.body.error, 'User verification failed.');
});

test('a YubiKey token is no WebAuthn token', async () => {
  const { env, storage } = await fixture();
  const yubiKey = await call(env, storage, '/api/two-factor/get-yubikey', 'POST', { masterPasswordHash: CLIENT_HASH });
  const answer = await call(env, storage, '/api/two-factor/get-webauthn-challenge', 'POST', {
    userVerificationToken: yubiKey.body.userVerificationToken,
  });
  assert.equal(answer.status, 400);
  assert.equal(answer.body.error, 'User verification failed.');
});

test('deleting the YubiKey leaves the authenticator on', async () => {
  const { env, storage } = await fixture();
  // Both providers on, stored the way the handlers store them.
  await saveUser(storage, { totpSecret: TOTP_KEY, yubikeyKey1: YUBIKEY_PUBLIC_ID });
  const setup = await call(env, storage, '/api/two-factor/get-yubikey', 'POST', { masterPasswordHash: CLIENT_HASH });
  // The official client sends only the token, no `type`.
  const answer = await call(env, storage, '/api/two-factor/yubikey', 'DELETE', {
    userVerificationToken: setup.body.userVerificationToken,
  });
  assert.equal(answer.status, 200, JSON.stringify(answer.body));
  const user = await currentUser(storage);
  assert.equal(user.yubikeyKey1, null, 'the YubiKey is gone');
  assert.equal(user.totpSecret, TOTP_KEY, 'the authenticator is still on');
});

test('the authenticator is turned off with a token for the key in use', async () => {
  const { env, storage } = await fixture();
  await saveUser(storage, { totpSecret: TOTP_KEY });
  const setup = await call(env, storage, '/api/two-factor/get-authenticator', 'POST', { masterPasswordHash: CLIENT_HASH });
  assert.equal(setup.body.authenticator.enabled, true);
  const answer = await call(env, storage, '/api/two-factor/authenticator', 'DELETE', {
    key: setup.body.authenticator.key,
    userVerificationToken: setup.body.userVerificationToken,
  });
  assert.equal(answer.status, 200, JSON.stringify(answer.body));
  assert.equal((await currentUser(storage)).totpSecret, null);
});

test('a token handed out for a fresh, unsaved key does not turn the authenticator off', async () => {
  const { env, storage } = await fixture();
  // The fresh key comes from a setup read while the authenticator was off.
  const fresh = await call(env, storage, '/api/two-factor/get-authenticator', 'POST', { masterPasswordHash: CLIENT_HASH });
  await saveUser(storage, { totpSecret: TOTP_KEY });
  const answer = await call(env, storage, '/api/two-factor/authenticator', 'DELETE', {
    key: fresh.body.authenticator.key,
    userVerificationToken: fresh.body.userVerificationToken,
  });
  assert.equal(answer.status, 400);
  assert.equal(answer.body.error, 'User verification failed.');
  assert.equal((await currentUser(storage)).totpSecret, TOTP_KEY, 'the authenticator is still on');
});
