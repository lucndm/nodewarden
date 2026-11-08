// Checks the measures that protect an account, and that they are enforced.
//
// The rule the product follows: a measure that cannot be enforced is not
// offered. What is enforced today is the two-step challenge at login, the
// session of a device that was trusted to skip it, and the end of every
// session when the password or the account key changes.
//
// Coverage:
//   - a device that was trusted to skip the two-step challenge can log in
//     while it is trusted;
//   - changing the password ends that trust, so the same device is asked for
//     the second factor again;
//   - changing the password ends the other sessions;
//   - replacing the account key ends the other sessions and the trusted
//     devices as well;
//   - new device verification is refused with a reason, not silently ignored.
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

const EMAIL = 'account-protection@example.test';
const PASSWORD = Buffer.from(`hash-${EMAIL}`).toString('base64');
const DEVICE = 'protected-device';
const REMEMBER_PROVIDER = '5';

function enc(value: string): string {
  return `2.${Buffer.from(`iv-${value}`).toString('base64')}|${Buffer.from(`ct-${value}`).toString('base64')}|${Buffer.from(`mac-${value}`).toString('base64')}`;
}

async function fixture(options: { twoFactor?: boolean } = {}): Promise<{ env: Env; storage: StorageService; userId: string }> {
  const db = new DatabaseSync(':memory:');
  await ensureStorageSchema(sqliteD1(db));
  const env = { DB: sqliteD1(db), JWT_SECRET: 'account-protection-secret-0123456789' } as unknown as Env;
  const storage = new StorageService(env.DB);

  const request = new Request('https://vault.example.test/api/accounts/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: 'https://vault.example.test' },
    body: JSON.stringify({
      email: EMAIL,
      name: 'Account Protection',
      masterPasswordHash: PASSWORD,
      key: enc('vault-key'),
      kdf: 0,
      kdfIterations: 600000,
      keys: {
        publicKey: Buffer.from('public-key').toString('base64'),
        encryptedPrivateKey: enc('private-key'),
      },
    }),
  });
  const registered = await handlePublicRoute(request, env, '/api/accounts/register', 'POST', async () => null);
  assert.ok(registered, 'the register route answered');
  assert.equal(registered.status, 200, await registered.clone().text());

  const user = await storage.getUser(EMAIL);
  assert.ok(user, 'the account exists');
  // The account has a second factor, so the challenge is part of the login.
  if (options.twoFactor !== false) {
    await storage.saveUser({ ...user, totpSecret: 'JBSWY3DPEHPK3PXP' } as never);
  }
  return { env, storage, userId: user.id };
}

async function call(env: Env, path: string, method: string, userId: string, body?: unknown): Promise<Response> {
  const request = new Request(`https://vault.example.test${path}`, {
    method,
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const response = await handleAuthenticatedRoute(request, env, userId, { id: userId } as never, path, method);
  assert.ok(response, `no route answered ${method} ${path}`);
  return response;
}

/** A login that carries the token of a trusted device. */
async function loginWithTrustedDevice(env: Env, trustedToken: string, password = PASSWORD): Promise<Response> {
  const request = new Request('https://vault.example.test/identity/connect/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'CF-Connecting-IP': '203.0.113.9' },
    body: new URLSearchParams({
      grant_type: 'password',
      username: EMAIL,
      password,
      scope: 'api offline_access',
      deviceIdentifier: DEVICE,
      deviceName: 'protected device',
      deviceType: '14',
      twoFactorProvider: REMEMBER_PROVIDER,
      twoFactorToken: trustedToken,
    }).toString(),
  });
  const response = await handlePublicRoute(request, env, '/identity/connect/token', 'POST', async () => null);
  assert.ok(response, 'the token route answered');
  return response;
}

test('a trusted device can skip the second factor, until the password changes', async () => {
  const { env, storage, userId } = await fixture();
  const trustedToken = 'trusted-device-token';
  await storage.saveTrustedTwoFactorDeviceToken(trustedToken, userId, DEVICE, Date.now() + 60 * 60 * 1000);

  const before = await loginWithTrustedDevice(env, trustedToken);
  assert.equal(before.status, 200, await before.clone().text());
  assert.ok((await before.json()) as { access_token?: string });

  // The password changes: every other session has to end, including the
  // device that was trusted to skip the second factor.
  const changed = await call(env, '/api/accounts/password', 'POST', userId, {
    currentPasswordHash: PASSWORD,
    newMasterPasswordHash: Buffer.from('hash-new').toString('base64'),
    newKey: enc('new-vault-key'),
  });
  assert.equal(changed.status, 200, await changed.clone().text());

  // The new password works, but the device is asked for the second factor
  // again: the trust did not survive the password change.
  const after = await loginWithTrustedDevice(env, trustedToken, Buffer.from('hash-new').toString('base64'));
  assert.notEqual(after.status, 200, 'the trusted device is asked for the second factor again');
  const body = (await after.json()) as { TwoFactorProviders?: unknown };
  assert.ok(body.TwoFactorProviders, 'the answer is the two-step challenge');
});

test('changing the password ends the other sessions', async () => {
  const { env, userId } = await fixture({ twoFactor: false });
  const login = await handlePublicRoute(
    new Request('https://vault.example.test/identity/connect/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'CF-Connecting-IP': '203.0.113.9' },
      body: new URLSearchParams({
        grant_type: 'password',
        username: EMAIL,
        password: PASSWORD,
        scope: 'api offline_access',
        deviceIdentifier: 'other-device',
        deviceName: 'other device',
        deviceType: '14',
      }).toString(),
    }),
    env,
    '/identity/connect/token',
    'POST',
    async () => null
  );
  assert.ok(login);
  const sessions = await env.DB.prepare('SELECT COUNT(*) AS count FROM refresh_tokens WHERE user_id = ?').bind(userId).first<{ count: number }>();
  assert.ok(Number(sessions?.count || 0) > 0, 'the login left a session behind');

  const changed = await call(env, '/api/accounts/password', 'POST', userId, {
    currentPasswordHash: PASSWORD,
    newMasterPasswordHash: Buffer.from('hash-new').toString('base64'),
    newKey: enc('new-vault-key'),
  });
  assert.equal(changed.status, 200);
  const after = await env.DB.prepare('SELECT COUNT(*) AS count FROM refresh_tokens WHERE user_id = ?').bind(userId).first<{ count: number }>();
  assert.equal(Number(after?.count || 0), 0, 'the sessions are gone');
});

test('replacing the account key ends the other sessions', async () => {
  const { env, storage, userId } = await fixture({ twoFactor: false });
  const trustedToken = 'trusted-device-token';
  await storage.saveTrustedTwoFactorDeviceToken(trustedToken, userId, DEVICE, Date.now() + 60 * 60 * 1000);
  const stampBefore = (await storage.getUserById(userId))?.securityStamp;

  const replaced = await call(env, '/api/accounts/keys', 'POST', userId, {
    masterPasswordHash: PASSWORD,
    key: enc('rotated-vault-key'),
    encryptedPrivateKey: enc('rotated-private-key'),
  });
  assert.equal(replaced.status, 200, await replaced.clone().text());

  const user = await storage.getUserById(userId);
  assert.notEqual(user?.securityStamp, stampBefore, 'the security stamp moved');
  const after = await env.DB.prepare('SELECT COUNT(*) AS count FROM refresh_tokens WHERE user_id = ?').bind(userId).first<{ count: number }>();
  assert.equal(Number(after?.count || 0), 0, 'the sessions are gone');
  const trusted = await env.DB
    .prepare('SELECT COUNT(*) AS count FROM trusted_two_factor_device_tokens WHERE user_id = ?')
    .bind(userId)
    .first<{ count: number }>();
  assert.equal(Number(trusted?.count || 0), 0, 'the trusted devices are gone');
});

test('new device verification is refused with a reason', async () => {
  const { env, userId } = await fixture();
  const enabled = await call(env, '/api/accounts/verify-devices', 'PUT', userId, { enabled: true });
  assert.equal(enabled.status, 400);
  const body = (await enabled.json()) as { error?: string };
  assert.match(String(body.error || ''), /two-factor|not available/i);
});
