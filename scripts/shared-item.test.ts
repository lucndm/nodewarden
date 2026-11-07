// Checks that a shared item can be created, read and changed by the members
// who are allowed to, and by nobody else.
//
// An item in an organization belongs to the organization and sits in
// collections. Which member sees it and who may change it follows from the
// rights they hold on those collections, and the answer comes from the server
// rather than from the interface.
//
// Coverage:
//   - a member with write rights puts an item in a collection;
//   - the item comes back with its organization and its collections;
//   - a member with read-only rights sees it but cannot change it;
//   - a member who reaches no collection of it does not see it at all;
//   - placing an item in another organization's collection is refused;
//   - a shared item cannot be left in no collection;
//   - moving it to another collection needs write rights on the target.
import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { StorageService } from '../src/services/storage';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { sqliteD1 } from './sqlite-d1';
import type { Env } from '../src/types';

const NOW = '2026-11-07T00:00:00.000Z';
const OWNER = 'user-owner';
const WRITER = 'user-writer';
const READER = 'user-reader';
const OUTSIDER = 'user-outsider';
const ORG = 'org-1';
const OTHER_ORG = 'org-2';
const COL_SHARED = 'col-shared';
const COL_READONLY = 'col-readonly';
const COL_OTHER = 'col-other';

const ENC = (value: string) =>
  `2.${Buffer.from(`iv-${value}`).toString('base64')}|${Buffer.from(`ct-${value}`).toString('base64')}|${Buffer.from(`mac-${value}`).toString('base64')}`;

async function fixture(): Promise<{ env: Env; storage: StorageService }> {
  const db = new DatabaseSync(':memory:');
  await ensureStorageSchema(sqliteD1(db));
  const env = { DB: sqliteD1(db) } as unknown as Env;
  const storage = new StorageService(env.DB);

  for (const [id, email] of [
    [OWNER, 'owner@example.test'],
    [WRITER, 'writer@example.test'],
    [READER, 'reader@example.test'],
    [OUTSIDER, 'outsider@example.test'],
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

  for (const id of [ORG, OTHER_ORG]) {
    await env.DB.prepare(
      'INSERT INTO organizations (id, name, private_key, public_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)'
    )
      .bind(id, id, 'enc-private', 'public', NOW, NOW)
      .run();
  }

  // Only the owner is an owner; the others are plain members, so what they
  // reach depends on the collections they were given.
  const memberships: Array<[string, string, string, number]> = [
    ['ou-owner', OWNER, ORG, 0],
    ['ou-writer', WRITER, ORG, 2],
    ['ou-reader', READER, ORG, 2],
    ['ou-outsider', OUTSIDER, OTHER_ORG, 2],
  ];
  for (const [id, userId, orgId, type] of memberships) {
    await env.DB.prepare(
      'INSERT INTO organization_users (id, user_id, org_id, type, status, key, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    )
      .bind(id, userId, orgId, type, 2, 'wrapped', NOW, NOW)
      .run();
  }

  for (const [id, orgId, name] of [
    [COL_SHARED, ORG, 'Shared'],
    [COL_READONLY, ORG, 'Read only'],
    [COL_OTHER, OTHER_ORG, 'Other'],
  ]) {
    await env.DB.prepare('INSERT INTO collections (id, org_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
      .bind(id, orgId, name, NOW, NOW)
      .run();
  }

  // The writer may write the shared collection; the reader may only read it.
  // The owner is an owner, so every collection of the organization is open.
  for (const [collectionId, orgUserId, readOnly] of [
    [COL_SHARED, 'ou-writer', 0],
    [COL_SHARED, 'ou-reader', 1],
    [COL_READONLY, 'ou-writer', 1],
  ] as const) {
    await env.DB.prepare(
      'INSERT INTO collection_users (collection_id, org_user_id, read_only, hide_passwords, manage) VALUES (?, ?, ?, 0, 0)'
    )
      .bind(collectionId, orgUserId, readOnly)
      .run();
  }

  return { env, storage };
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

const sharedItem = {
  type: 1,
  name: ENC('Shared login'),
  notes: null,
  login: { username: ENC('user'), password: ENC('pass'), uris: null, totp: null },
  organizationId: ORG,
  collectionIds: [COL_SHARED],
  key: ENC('item-key'),
};

async function createShared(env: Env): Promise<{ id: string }> {
  const response = await call(env, 'https://vault.example.test/api/ciphers', 'POST', WRITER, sharedItem);
  assert.equal(response.status, 200, await response.clone().text());
  return (await response.json()) as { id: string };
}

test('a member with write rights puts an item in a collection', async () => {
  const { env } = await fixture();
  const created = await createShared(env);

  assert.ok(created.id);
  const detail = await call(env, `https://vault.example.test/api/ciphers/${created.id}`, 'GET', WRITER);
  assert.equal(detail.status, 200);
  const cipher = (await detail.json()) as { organizationId: string; collectionIds: string[] };
  assert.equal(cipher.organizationId, ORG, 'the item names its organization');
  assert.deepEqual(cipher.collectionIds, [COL_SHARED], 'the item names the collection it sits in');
});

test('the item reaches the members who may read it, and nobody else', async () => {
  const { env } = await fixture();
  const created = await createShared(env);

  // The writer and the reader both reach it.
  for (const userId of [WRITER, READER, OWNER]) {
    const response = await call(env, `https://vault.example.test/api/ciphers/${created.id}`, 'GET', userId);
    assert.equal(response.status, 200, `${userId} must reach the item`);
  }

  // A member of another organization does not.
  const outsider = await call(env, `https://vault.example.test/api/ciphers/${created.id}`, 'GET', OUTSIDER);
  assert.equal(outsider.status, 404);

  // It shows up in the reader's list and in their sync, with its collections.
  const list = await call(env, 'https://vault.example.test/api/ciphers', 'GET', READER);
  assert.equal(list.status, 200);
  const listed = (await list.json()) as { data: Array<{ id: string; collectionIds?: string[] }> };
  const inList = listed.data.find((entry) => entry.id === created.id);
  assert.ok(inList, 'a shared item belongs in the list');
  assert.deepEqual(inList.collectionIds, [COL_SHARED]);

  const sync = await call(env, 'https://vault.example.test/api/sync', 'GET', READER);
  assert.equal(sync.status, 200);
  const synced = (await sync.json()) as { ciphers: Array<{ id: string; collectionIds?: string[] }> };
  const inSync = synced.ciphers.find((entry) => entry.id === created.id);
  assert.ok(inSync, 'a shared item belongs in the sync');
  assert.deepEqual(inSync.collectionIds, [COL_SHARED]);

  // The outsider sees it in neither.
  const outsiderList = await call(env, 'https://vault.example.test/api/ciphers', 'GET', OUTSIDER);
  const outsiderData = (await outsiderList.json()) as { data: Array<{ id: string }> };
  assert.equal(outsiderData.data.some((entry) => entry.id === created.id), false);
});

test('a member with read-only rights sees the item but cannot change it', async () => {
  const { env } = await fixture();
  const created = await createShared(env);

  const update = await call(env, `https://vault.example.test/api/ciphers/${created.id}`, 'PUT', READER, {
    ...sharedItem,
    name: ENC('Changed'),
  });
  assert.equal(update.status, 403, 'a read-only member must not change the item');

  // The writer may, and the change sticks.
  const writerUpdate = await call(env, `https://vault.example.test/api/ciphers/${created.id}`, 'PUT', WRITER, {
    ...sharedItem,
    name: ENC('Changed'),
  });
  assert.equal(writerUpdate.status, 200);
  const detail = await call(env, `https://vault.example.test/api/ciphers/${created.id}`, 'GET', READER);
  const cipher = (await detail.json()) as { name: string };
  assert.equal(cipher.name, ENC('Changed'));
});

test('an item cannot be put in another organization or left in no collection', async () => {
  const { env } = await fixture();

  const otherOrganization = await call(env, 'https://vault.example.test/api/ciphers', 'POST', WRITER, {
    ...sharedItem,
    organizationId: OTHER_ORG,
  });
  assert.equal(otherOrganization.status, 404, 'a collection of another organization is not reachable');

  const noCollection = await call(env, 'https://vault.example.test/api/ciphers', 'POST', WRITER, {
    ...sharedItem,
    collectionIds: [],
  });
  assert.equal(noCollection.status, 400, 'a shared item nobody could reach must not exist');

  const readOnlyCollection = await call(env, 'https://vault.example.test/api/ciphers', 'POST', WRITER, {
    ...sharedItem,
    collectionIds: [COL_READONLY],
  });
  assert.equal(readOnlyCollection.status, 403, 'write rights on the collection are required');
});

test('moving an item to another collection needs write rights on the target', async () => {
  const { env } = await fixture();
  const created = await createShared(env);

  const denied = await call(env, `https://vault.example.test/api/ciphers/${created.id}`, 'PUT', WRITER, {
    ...sharedItem,
    collectionIds: [COL_READONLY],
  });
  assert.equal(denied.status, 403);

  const allowed = await call(env, `https://vault.example.test/api/ciphers/${created.id}`, 'PUT', OWNER, {
    ...sharedItem,
    collectionIds: [COL_READONLY],
  });
  assert.equal(allowed.status, 200);
  const cipher = (await allowed.json()) as { collectionIds: string[] };
  assert.deepEqual(cipher.collectionIds, [COL_READONLY]);

  // The reader reached the item through the shared collection only, so it is
  // gone from their vault now.
  const readerDetail = await call(env, `https://vault.example.test/api/ciphers/${created.id}`, 'GET', READER);
  assert.equal(readerDetail.status, 404);
});

test('the item cannot be moved to another organization by an edit', async () => {
  const { env } = await fixture();
  const created = await createShared(env);

  const update = await call(env, `https://vault.example.test/api/ciphers/${created.id}`, 'PUT', WRITER, {
    ...sharedItem,
    organizationId: OTHER_ORG,
  });
  assert.equal(update.status, 200);
  const cipher = (await update.json()) as { organizationId: string };
  assert.equal(cipher.organizationId, ORG, 'the organization of a shared item does not change on an edit');
});
