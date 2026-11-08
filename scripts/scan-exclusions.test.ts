// Checks the contract of the password scan exclusions.
//
// A scan sends a hash prefix of a password to a breach database. Some items
// the user does not want that for, so the exclusion is kept by the server
// beside the item: it is a setting of the account, not a property of the
// item, and other clients and exports never see it.
//
// Coverage:
//   - the owner keeps an item out of the check and the list says so;
//   - another account neither sees the exclusion nor may make one;
//   - an unknown scope is refused;
//   - putting the item back in removes it from the list;
//   - the exclusion does not touch the item: its revision date stands;
//   - an excluded item has no result to show, and it is never "clean".
import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { StorageService } from '../src/services/storage';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { sqliteD1 } from './sqlite-d1';
import {
  clearPasswordSecurityCache,
  getPasswordSecurityFinding,
  recordPasswordSecurityFindings,
} from '../webapp/src/lib/password-security-cache';
import { setPasswordSecurityExclusions } from '../webapp/src/lib/password-security-exclusions';
import type { Env } from '../src/types';

const NOW = '2026-11-08T00:00:00.000Z';
const OWNER = 'user-owner';
const STRANGER = 'user-stranger';
const CIPHER = '00000000-0000-4000-8000-00000000000a';

async function fixture(): Promise<{ env: Env; storage: StorageService }> {
  const db = new DatabaseSync(':memory:');
  await ensureStorageSchema(sqliteD1(db));
  const env = { DB: sqliteD1(db) } as unknown as Env;
  const storage = new StorageService(env.DB);
  for (const [id, email] of [
    [OWNER, 'owner@example.test'],
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
  await storage.saveCipher({
    id: CIPHER,
    userId: OWNER,
    type: 1,
    name: '2.name',
    notes: null,
    favorite: false,
    folderId: null,
    key: null,
    login: { username: '2.user', password: '2.pass', uris: null, totp: null },
    createdAt: NOW,
    updatedAt: NOW,
    deletedAt: null,
  } as never);
  return { env, storage };
}

async function call(env: Env, url: string, method: string, userId: string, body?: unknown): Promise<Response> {
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

test('the owner keeps an item out of the check', async () => {
  const { env } = await fixture();
  const excluded = await call(
    env,
    `https://vault.example.test/api/security/scan-exclusions/${CIPHER}`,
    'PUT',
    OWNER,
    { scope: 'password-health' }
  );
  assert.equal(excluded.status, 200, await excluded.clone().text());
  const body = (await excluded.json()) as { cipherId: string; scope: string };
  assert.equal(body.cipherId, CIPHER);
  assert.equal(body.scope, 'password-health');

  const list = await call(env, 'https://vault.example.test/api/security/scan-exclusions', 'GET', OWNER);
  const listed = (await list.json()) as { data: Array<{ cipherId: string }> };
  assert.equal(listed.data.length, 1);
  assert.equal(listed.data[0].cipherId, CIPHER);

  // The exclusion is a setting of the account: it does not change the item.
  const revision = await env.DB.prepare('SELECT updated_at FROM ciphers WHERE id = ?').bind(CIPHER).first<{ updated_at: string }>();
  assert.equal(revision?.updated_at, NOW, 'the item itself is untouched');
});

test('another account neither sees the exclusion nor may make one', async () => {
  const { env } = await fixture();
  await call(env, `https://vault.example.test/api/security/scan-exclusions/${CIPHER}`, 'PUT', OWNER, {
    scope: 'password-health',
  });

  const list = await call(env, 'https://vault.example.test/api/security/scan-exclusions', 'GET', STRANGER);
  const listed = (await list.json()) as { data: unknown[] };
  assert.deepEqual(listed.data, [], 'the exclusion belongs to the account that made it');

  const refused = await call(
    env,
    `https://vault.example.test/api/security/scan-exclusions/${CIPHER}`,
    'PUT',
    STRANGER,
    { scope: 'password-health' }
  );
  assert.equal(refused.status, 404, 'an item of somebody else is not found');
});

test('an unknown scope is refused', async () => {
  const { env } = await fixture();
  const refused = await call(
    env,
    `https://vault.example.test/api/security/scan-exclusions/${CIPHER}`,
    'PUT',
    OWNER,
    { scope: 'everything-forever' }
  );
  assert.equal(refused.status, 400);
});

test('putting the item back in removes it from the list', async () => {
  const { env } = await fixture();
  await call(env, `https://vault.example.test/api/security/scan-exclusions/${CIPHER}`, 'PUT', OWNER, {
    scope: 'password-health',
  });
  const included = await call(
    env,
    `https://vault.example.test/api/security/scan-exclusions/${CIPHER}`,
    'DELETE',
    OWNER
  );
  assert.equal(included.status, 204);

  const list = await call(env, 'https://vault.example.test/api/security/scan-exclusions', 'GET', OWNER);
  const listed = (await list.json()) as { data: unknown[] };
  assert.deepEqual(listed.data, []);
});

test('an excluded item has no result, and it is never clean', () => {
  clearPasswordSecurityCache();
  setPasswordSecurityExclusions([]);
  recordPasswordSecurityFindings(
    {
      eligibleCount: 1,
      checkedCount: 1,
      exposedCount: 0,
      reusedCount: 0,
      weakCount: 0,
      unavailableCount: 0,
      items: [],
    },
    [
      {
        id: CIPHER,
        type: 1,
        revisionDate: NOW,
        login: { decPassword: 'a-password', decUsername: 'user', uris: null, totp: null },
      } as never,
    ],
    Date.now()
  );
  assert.ok(getPasswordSecurityFinding(CIPHER, NOW), 'the scan answered for the item');

  // Once the item is kept out of the check, its result is not shown and it
  // is certainly not called clean.
  setPasswordSecurityExclusions([CIPHER]);
  assert.equal(getPasswordSecurityFinding(CIPHER, NOW), null);
  setPasswordSecurityExclusions([]);
});
