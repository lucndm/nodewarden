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

test('a bulk action only touches the items the member may change', async () => {
  const { env } = await fixture();
  const created = await createShared(env);

  // The reader may only read it, so a bulk delete by the reader changes nothing.
  const readerDelete = await call(env, 'https://vault.example.test/api/ciphers/delete', 'POST', READER, {
    ids: [created.id],
  });
  assert.equal(readerDelete.status, 204);
  const stillThere = await call(env, `https://vault.example.test/api/ciphers/${created.id}`, 'GET', READER);
  assert.equal(stillThere.status, 200, 'a read-only member must not delete the item');

  // An outsider naming the id changes nothing either.
  const outsiderDelete = await call(env, 'https://vault.example.test/api/ciphers/delete', 'POST', OUTSIDER, {
    ids: [created.id],
  });
  assert.equal(outsiderDelete.status, 204);
  const afterOutsider = await call(env, `https://vault.example.test/api/ciphers/${created.id}`, 'GET', WRITER);
  assert.equal(afterOutsider.status, 200, 'an outsider must not delete the item');

  // The writer may move it into a folder of their own, and it sticks.
  const folder = await call(env, 'https://vault.example.test/api/folders', 'POST', WRITER, {
    name: ENC('Writing'),
  });
  assert.equal(folder.status, 200);
  const folderId = ((await folder.json()) as { id: string }).id;
  const writerMove = await call(env, 'https://vault.example.test/api/ciphers/move', 'PUT', WRITER, {
    ids: [created.id],
    folderId,
  });
  assert.equal(writerMove.status, 204);
  const moved = (await (
    await call(env, `https://vault.example.test/api/ciphers/${created.id}`, 'GET', WRITER)
  ).json()) as { folderId: string | null };
  assert.equal(moved.folderId, folderId, 'the writer may move a shared item');

  // The writer may soft delete it: they have write rights on the collection.
  const writerDelete = await call(env, 'https://vault.example.test/api/ciphers/delete', 'POST', WRITER, {
    ids: [created.id],
  });
  assert.equal(writerDelete.status, 204);
  const deleted = (await (
    await call(env, `https://vault.example.test/api/ciphers/${created.id}`, 'GET', WRITER)
  ).json()) as { deletedDate?: string | null };
  assert.ok(deleted.deletedDate, 'the writer may soft delete the item');
});

test('permanent deletion of a shared item takes manage rights', async () => {
  const { env } = await fixture();
  const created = await createShared(env);

  // The writer may edit the item but not manage the collection, so it survives.
  const writerPermanent = await call(
    env,
    'https://vault.example.test/api/ciphers/delete-permanent',
    'POST',
    WRITER,
    { ids: [created.id] }
  );
  assert.equal(writerPermanent.status, 204);
  const survives = await call(env, `https://vault.example.test/api/ciphers/${created.id}`, 'GET', WRITER);
  assert.equal(survives.status, 200, 'an editor must not destroy a shared item');

  // The organization owner manages every collection, so they may.
  const ownerPermanent = await call(
    env,
    'https://vault.example.test/api/ciphers/delete-permanent',
    'POST',
    OWNER,
    { ids: [created.id] }
  );
  assert.equal(ownerPermanent.status, 204);
  const gone = await call(env, `https://vault.example.test/api/ciphers/${created.id}`, 'GET', OWNER);
  assert.equal(gone.status, 404);
});

test('a bulk archive and restore follow the same rights', async () => {
  const { env } = await fixture();
  const created = await createShared(env);

  const readerArchive = await call(env, 'https://vault.example.test/api/ciphers/archive', 'POST', READER, {
    ids: [created.id],
  });
  assert.equal(readerArchive.status, 200);
  const notArchived = (await (
    await call(env, `https://vault.example.test/api/ciphers/${created.id}`, 'GET', READER)
  ).json()) as { archivedDate?: string | null };
  assert.equal(notArchived.archivedDate ?? null, null, 'a read-only member must not archive the item');

  const writerArchive = await call(env, 'https://vault.example.test/api/ciphers/archive', 'POST', WRITER, {
    ids: [created.id],
  });
  assert.equal(writerArchive.status, 200);
  const archived = (await (
    await call(env, `https://vault.example.test/api/ciphers/${created.id}`, 'GET', WRITER)
  ).json()) as { archivedDate?: string | null };
  assert.ok(archived.archivedDate, 'the writer may archive the item');
});

test('single-item actions follow the same rights as the bulk ones', async () => {
  const { env } = await fixture();
  const created = await createShared(env);

  // The reader may not delete it one at a time either. A soft delete is a PUT;
  // a POST on the same path is the permanent one.
  const readerDelete = await call(
    env,
    `https://vault.example.test/api/ciphers/${created.id}/delete`,
    'PUT',
    READER
  );
  assert.equal(readerDelete.status, 403, 'a read-only member must be refused, not silently ignored');

  // An outsider does not learn that the item exists.
  const outsiderDelete = await call(
    env,
    `https://vault.example.test/api/ciphers/${created.id}/delete`,
    'PUT',
    OUTSIDER
  );
  assert.equal(outsiderDelete.status, 404);

  // The writer may delete and restore it.
  const writerDelete = await call(
    env,
    `https://vault.example.test/api/ciphers/${created.id}/delete`,
    'PUT',
    WRITER
  );
  assert.equal(writerDelete.status, 200);
  const deleted = (await (
    await call(env, `https://vault.example.test/api/ciphers/${created.id}`, 'GET', WRITER)
  ).json()) as { deletedDate?: string | null };
  assert.ok(deleted.deletedDate, 'the writer may delete the item');

  const restored = await call(
    env,
    `https://vault.example.test/api/ciphers/${created.id}/restore`,
    'PUT',
    WRITER
  );
  assert.equal(restored.status, 200);
  const afterRestore = (await (
    await call(env, `https://vault.example.test/api/ciphers/${created.id}`, 'GET', WRITER)
  ).json()) as { deletedDate?: string | null };
  assert.equal(afterRestore.deletedDate ?? null, null, 'the writer may restore the item');

  // An editor may not destroy it for everyone, but the organization owner may.
  const writerPermanent = await call(
    env,
    `https://vault.example.test/api/ciphers/${created.id}/delete`,
    'POST',
    WRITER
  );
  assert.equal(writerPermanent.status, 403);

  const ownerPermanent = await call(
    env,
    `https://vault.example.test/api/ciphers/${created.id}/delete`,
    'POST',
    OWNER
  );
  assert.equal(ownerPermanent.status, 204, 'a permanent delete answers with no content');
  assert.equal(
    (await call(env, `https://vault.example.test/api/ciphers/${created.id}`, 'GET', OWNER)).status,
    404
  );
});

test('the paged read shows the shared items the member may read', async () => {
  const { env } = await fixture();
  const created = await createShared(env);

  // The writer owns one personal item as well, so the page has both kinds.
  const personal = await call(env, 'https://vault.example.test/api/ciphers', 'POST', WRITER, {
    type: 1,
    name: ENC('Personal login'),
    login: { username: ENC('user'), password: ENC('pass'), uris: null, totp: null },
  });
  assert.equal(personal.status, 200);

  const page = await call(env, 'https://vault.example.test/api/ciphers?pageSize=1&continuationToken=0', 'GET', WRITER);
  assert.equal(page.status, 200);
  const first = (await page.json()) as {
    data: Array<{ id: string }>;
    continuationToken: string | null;
  };
  assert.equal(first.data.length, 1, 'the page holds one item');
  assert.ok(first.continuationToken, 'a page with more items carries a token');

  // Reading the rest of the pages yields the shared item too.
  const seen = new Set(first.data.map((entry) => entry.id));
  let token: string | null = first.continuationToken;
  for (let guard = 0; token && guard < 10; guard += 1) {
    const next = await call(
      env,
      `https://vault.example.test/api/ciphers?pageSize=1&continuationToken=${encodeURIComponent(token)}`,
      'GET',
      WRITER
    );
    const body = (await next.json()) as { data: Array<{ id: string }>; continuationToken: string | null };
    for (const entry of body.data) seen.add(entry.id);
    token = body.continuationToken;
  }
  assert.ok(seen.has(created.id), 'the shared item appears in the paged read');
  assert.equal(seen.size, 2, 'and the page holds exactly the two items the writer may read');

  // The reader pages over the shared item only.
  const readerPage = await call(env, 'https://vault.example.test/api/ciphers?pageSize=10&continuationToken=0', 'GET', READER);
  const readerBody = (await readerPage.json()) as { data: Array<{ id: string }> };
  assert.deepEqual(readerBody.data.map((entry) => entry.id), [created.id]);

  // The outsider pages over nothing.
  const outsiderPage = await call(
    env,
    'https://vault.example.test/api/ciphers?pageSize=10&continuationToken=0',
    'GET',
    OUTSIDER
  );
  const outsiderBody = (await outsiderPage.json()) as { data: Array<{ id: string }> };
  assert.equal(outsiderBody.data.length, 0);
});
