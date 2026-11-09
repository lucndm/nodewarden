// The sync response must carry the collections of every shared item, at the
// size a real vault reaches.
//
// A vault that was moved into an organization holds hundreds of shared items,
// and the sync response names the collections they sit in so the client can
// place them. That read used one statement with one bound parameter per item,
// which is more parameters than D1 accepts in a statement, so the whole sync
// failed and the member saw an organization with nothing in it.
//
// These checks run the real storage against a vault of that size:
//   - the collections of every shared item come back;
//   - the read succeeds with more items than a statement can bind at once;
//   - the items keep the collections they belong to.
import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { StorageService } from '../src/services/storage';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { sqliteD1 } from './sqlite-d1';
import type { Env } from '../src/types';

const NOW = '2026-11-08T00:00:00.000Z';
const OWNER = 'user-1';
const ORG = 'org-1';
const COLLECTION = 'col-1';
// A statement binds one parameter per item, and D1 takes a hundred. The vault
// that runs into this is a real one: its moved items are counted in the
// hundreds.
const SHARED_ITEMS = 875;

async function fixture(): Promise<{ env: Env; storage: StorageService }> {
  const db = new DatabaseSync(':memory:');
  await ensureStorageSchema(sqliteD1(db));
  const env = { DB: sqliteD1(db) } as unknown as Env;
  const storage = new StorageService(env.DB);

  await storage.createUser({
    id: OWNER,
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
    createdAt: NOW,
    updatedAt: NOW,
  } as never);

  await env.DB.prepare(
    'INSERT INTO organizations (id, name, private_key, public_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)'
  )
    .bind(ORG, 'Acme', 'enc-private-key', 'public-key', NOW, NOW)
    .run();
  await env.DB.prepare(
    'INSERT INTO organization_users (id, user_id, org_id, type, status, key, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  )
    .bind('ou-owner', OWNER, ORG, 0, 2, '4.wrapped', NOW, NOW)
    .run();
  await env.DB.prepare(
    'INSERT INTO collections (id, org_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)'
  )
    .bind(COLLECTION, ORG, 'General', NOW, NOW)
    .run();

  for (let index = 0; index < SHARED_ITEMS; index += 1) {
    const cipherId = `cipher-${index}`;
    await env.DB.prepare(
      'INSERT INTO ciphers (id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, organization_id) ' +
        'VALUES (?, ?, 1, NULL, ?, NULL, 0, ?, 0, NULL, ?, ?, ?)'
    )
      .bind(cipherId, OWNER, '2.name', '{}', NOW, NOW, ORG)
      .run();
    await env.DB.prepare(
      'INSERT INTO collection_ciphers (cipher_id, collection_id) VALUES (?, ?)'
    )
      .bind(cipherId, COLLECTION)
      .run();
  }

  return { env, storage };
}

test('the collections of every shared item come back in a vault of hundreds of items', async () => {
  const { storage } = await fixture();

  const cipherIds = Array.from({ length: SHARED_ITEMS }, (_, index) => `cipher-${index}`);
  const collections = await storage.getCollectionIdsByCipherIds(cipherIds);

  assert.equal(collections.size, SHARED_ITEMS);
  for (const cipherId of cipherIds) {
    assert.deepEqual(collections.get(cipherId), [COLLECTION], `the collections of ${cipherId}`);
  }
});

test('the shared items of that vault are visible to the member', async () => {
  const { storage } = await fixture();

  const ciphers = await storage.getVisibleCiphers(OWNER);

  assert.equal(ciphers.length, SHARED_ITEMS);
});

test('a bulk action over hundreds of items keeps the ones the member may write', async () => {
  const { storage } = await fixture();

  const cipherIds = Array.from({ length: SHARED_ITEMS }, (_, index) => `cipher-${index}`);
  const writable = await storage.filterWritableCipherIds(cipherIds, OWNER);

  assert.equal(writable.length, SHARED_ITEMS);
});

test('the rights of hundreds of collections come back', async () => {
  const { env, storage } = await fixture();

  // The vault has one collection; the read is asked about many ids so the
  // statement binds more than D1 accepts.
  const collectionIds = Array.from({ length: SHARED_ITEMS }, (_, index) => `col-${index}`);
  const rights = await storage.getCollectionRightsForCollections(OWNER, collectionIds);

  assert.equal(rights.size, 1);
  assert.equal(rights.get(COLLECTION)?.manage, true);
  void env;
});
