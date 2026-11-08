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

test('an admin grants a member the rights on a collection, and can take them back', async () => {
  const { env, storage } = await fixture();
  const created = await createShared(env);

  const readerMembership = await storage.getOrganizationUserForUser(ORG, READER);
  assert.ok(readerMembership, 'the reader is a member');

  // Grant the reader write rights on the shared collection.
  const granted = await call(
    env,
    `https://vault.example.test/api/organizations/${ORG}/users/${readerMembership.id}`,
    'PUT',
    OWNER,
    { collections: [{ id: COL_SHARED, readOnly: false, hidePasswords: false, manage: false }] }
  );
  assert.equal(granted.status, 200);
  const body = (await granted.json()) as { collections: Array<{ id: string; readOnly: boolean }> };
  assert.deepEqual(body.collections, [
    { id: COL_SHARED, readOnly: false, hidePasswords: false, manage: false },
  ]);

  // The reader may now change the item.
  const update = await call(env, `https://vault.example.test/api/ciphers/${created.id}`, 'PUT', READER, {
    ...sharedItem,
    name: ENC('Changed by reader'),
  });
  assert.equal(update.status, 200, 'the granted rights take effect at once');

  // Taking the rights away refuses the next write.
  const revoked = await call(
    env,
    `https://vault.example.test/api/organizations/${ORG}/users/${readerMembership.id}`,
    'PUT',
    OWNER,
    { collections: [{ id: COL_SHARED, readOnly: true, hidePasswords: false, manage: false }] }
  );
  assert.equal(revoked.status, 200);
  const denied = await call(env, `https://vault.example.test/api/ciphers/${created.id}`, 'PUT', READER, {
    ...sharedItem,
    name: ENC('Changed again'),
  });
  assert.equal(denied.status, 403, 'withdrawn rights take effect at once');
});

test('only an owner or an admin may hand out rights', async () => {
  const { env, storage } = await fixture();
  await createShared(env);

  const readerMembership = await storage.getOrganizationUserForUser(ORG, READER);
  assert.ok(readerMembership);

  const attempt = await call(
    env,
    `https://vault.example.test/api/organizations/${ORG}/users/${readerMembership.id}`,
    'PUT',
    WRITER,
    { collections: [{ id: COL_SHARED, readOnly: false, manage: true }] }
  );
  assert.equal(attempt.status, 404, 'a plain member must not grant rights');

  // A collection of another organization cannot be handed out either.
  const crossOrg = await call(
    env,
    `https://vault.example.test/api/organizations/${ORG}/users/${readerMembership.id}`,
    'PUT',
    OWNER,
    { collections: [{ id: COL_OTHER, readOnly: false }] }
  );
  assert.equal(crossOrg.status, 404);
});

test('removing a member takes their access away at once', async () => {
  const { env, storage } = await fixture();
  const created = await createShared(env);

  const writerMembership = await storage.getOrganizationUserForUser(ORG, WRITER);
  assert.ok(writerMembership);

  const before = await call(env, `https://vault.example.test/api/ciphers/${created.id}`, 'GET', WRITER);
  assert.equal(before.status, 200);

  const removed = await call(
    env,
    `https://vault.example.test/api/organizations/${ORG}/users/${writerMembership.id}`,
    'DELETE',
    OWNER
  );
  assert.equal(removed.status, 204);

  const after = await call(env, `https://vault.example.test/api/ciphers/${created.id}`, 'GET', WRITER);
  assert.equal(after.status, 404, 'a removed member sees nothing of the organization');
  assert.equal((await storage.getCollectionsForUser(WRITER)).length, 0);
  assert.equal((await storage.getOrganizationsForUser(WRITER)).length, 0);
});

test('the owner cannot be removed, and nobody removes another member by guessing', async () => {
  const { env, storage } = await fixture();
  const ownerMembership = await storage.getOrganizationUserForUser(ORG, OWNER);
  const readerMembership = await storage.getOrganizationUserForUser(ORG, READER);
  assert.ok(ownerMembership);
  assert.ok(readerMembership);

  const removeOwner = await call(
    env,
    `https://vault.example.test/api/organizations/${ORG}/users/${ownerMembership.id}`,
    'DELETE',
    OWNER
  );
  assert.equal(removeOwner.status, 400);

  // The reader is not an admin, so they may not remove anyone.
  const readerAttempt = await call(
    env,
    `https://vault.example.test/api/organizations/${ORG}/users/${readerMembership.id}`,
    'DELETE',
    READER
  );
  assert.equal(readerAttempt.status, 404);
});

test('a new collection is reachable by the owner', async () => {
  const { env } = await fixture();

  const created = await call(env, `https://vault.example.test/api/organizations/${ORG}/collections`, 'POST', OWNER, {
    name: 'Fresh',
  });
  assert.equal(created.status, 200);
  const collection = (await created.json()) as { id: string; name: string; organizationId: string };
  assert.equal(collection.name, 'Fresh');
  assert.equal(collection.organizationId, ORG);

  const list = await call(env, 'https://vault.example.test/api/collections', 'GET', OWNER);
  const body = (await list.json()) as { data: Array<{ id: string }> };
  assert.ok(body.data.some((entry) => entry.id === collection.id), 'the owner reaches the new collection');

  // A plain member who was not given it does not.
  const writerList = await call(env, 'https://vault.example.test/api/collections', 'GET', WRITER);
  const writerBody = (await writerList.json()) as { data: Array<{ id: string }> };
  assert.equal(writerBody.data.some((entry) => entry.id === collection.id), false);
});

test('a key rotation replaces the key of every member and every shared item', async () => {
  const { env, storage } = await fixture();
  const created = await createShared(env);

  const ownerMembership = await storage.getOrganizationUserForUser(ORG, OWNER);
  const writerMembership = await storage.getOrganizationUserForUser(ORG, WRITER);
  assert.ok(ownerMembership);
  assert.ok(writerMembership);

  const beforeRevision = (await storage.getRevisionDate(READER));
  const rotation = await call(
    env,
    `https://vault.example.test/api/organizations/${ORG}/rotate-key`,
    'POST',
    OWNER,
    {
      privateKey: ENC('org-private-key-2'),
      members: [
        { membershipId: ownerMembership.id, key: ENC('org-key-for-owner-2') },
        { membershipId: writerMembership.id, key: ENC('org-key-for-writer-2') },
      ],
      ciphers: [{ id: created.id, key: ENC('item-key-2'), data: JSON.stringify({ login: {}, tags: [] }) }],
    }
  );
  assert.equal(rotation.status, 200);
  const result = (await rotation.json()) as { members: number; ciphers: number };
  assert.equal(result.members, 2);
  assert.equal(result.ciphers, 1);

  // The new blobs are stored; the old ones are gone.
  const organizations = await storage.getOrganizationsForUser(OWNER);
  assert.equal(organizations[0].privateKey, ENC('org-private-key-2'));
  const ownerList = (await (
    await call(env, 'https://vault.example.test/api/organizations', 'GET', OWNER)
  ).json()) as { data: Array<{ key: string }> };
  assert.equal(ownerList.data[0].key, ENC('org-key-for-owner-2'));
  const writerList = (await (
    await call(env, 'https://vault.example.test/api/organizations', 'GET', WRITER)
  ).json()) as { data: Array<{ key: string }> };
  assert.equal(writerList.data[0].key, ENC('org-key-for-writer-2'));

  const cipher = await storage.getCipher(created.id);
  assert.ok(cipher);
  assert.equal(cipher.key, ENC('item-key-2'), 'the item key is re-wrapped under the new key');

  // Every member's revision moves, so their client fetches the new blobs.
  const afterRevision = await storage.getRevisionDate(READER);
  assert.notEqual(afterRevision, beforeRevision, 'a rotation makes the readers resync');
});

test('only the owner rotates the key', async () => {
  const { env, storage } = await fixture();
  await createShared(env);
  const ownerMembership = await storage.getOrganizationUserForUser(ORG, OWNER);
  assert.ok(ownerMembership);

  for (const userId of [WRITER, READER, OUTSIDER]) {
    const attempt = await call(
      env,
      `https://vault.example.test/api/organizations/${ORG}/rotate-key`,
      'POST',
      userId,
      { members: [{ membershipId: ownerMembership.id, key: ENC('stolen') }] }
    );
    assert.equal(attempt.status, 404, `${userId} must not rotate the key`);
  }
});

test('a rotation naming another organization is refused whole', async () => {
  const { env, storage } = await fixture();
  const created = await createShared(env);

  // A membership of this organization is fine; a cipher of another one is not.
  const ownerMembership = await storage.getOrganizationUserForUser(ORG, OWNER);
  assert.ok(ownerMembership);
  await env.DB.prepare(
    'INSERT INTO ciphers (id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, organization_id) ' +
      'VALUES (?, ?, 1, NULL, ?, NULL, 0, ?, 0, NULL, ?, ?, ?)'
  )
    .bind('cipher-other-org', OWNER, ENC('other'), '{}', NOW, NOW, OTHER_ORG)
    .run();

  const attempt = await call(
    env,
    `https://vault.example.test/api/organizations/${ORG}/rotate-key`,
    'POST',
    OWNER,
    {
      members: [{ membershipId: ownerMembership.id, key: ENC('new') }],
      ciphers: [{ id: 'cipher-other-org', key: ENC('new'), data: '{}' }],
    }
  );
  assert.equal(attempt.status, 404);

  // Nothing changed, not even the part that was valid.
  const organizations = await storage.getOrganizationsForUser(OWNER);
  assert.equal(organizations[0].privateKey, 'enc-private');
  const before = (await (
    await call(env, 'https://vault.example.test/api/organizations', 'GET', OWNER)
  ).json()) as { data: Array<{ key: string }> };
  assert.equal(before.data[0].key, 'wrapped', 'a refused rotation leaves every key as it was');
  const cipher = await storage.getCipher(created.id);
  assert.ok(cipher);
  assert.notEqual(cipher.key, ENC('new'));
});

test('removing a member flags the key rotation, and rotating clears it', async () => {
  const { env, storage } = await fixture();
  await createShared(env);

  const before = (await storage.getOrganizationsForUser(OWNER))[0];
  assert.equal(before.keyRotationRequired, false, 'a fresh organization needs no rotation');

  const writerMembership = await storage.getOrganizationUserForUser(ORG, WRITER);
  assert.ok(writerMembership);
  await call(
    env,
    `https://vault.example.test/api/organizations/${ORG}/users/${writerMembership.id}`,
    'DELETE',
    OWNER
  );

  const flagged = (await (
    await call(env, 'https://vault.example.test/api/organizations', 'GET', OWNER)
  ).json()) as { data: Array<{ keyRotationRequired: boolean }> };
  assert.equal(flagged.data[0].keyRotationRequired, true, 'the removal says the key has to be replaced');

  // Rotating clears the marker: the key the removed member held is replaced.
  const rotation = await call(env, `https://vault.example.test/api/organizations/${ORG}/rotate-key`, 'POST', OWNER, {
    members: [{ membershipId: (await storage.getOrganizationUserForUser(ORG, OWNER))!.id, key: ENC('rotated') }],
    ciphers: [],
  });
  assert.equal(rotation.status, 200);

  const cleared = (await (
    await call(env, 'https://vault.example.test/api/organizations', 'GET', OWNER)
  ).json()) as { data: Array<{ keyRotationRequired: boolean }> };
  assert.equal(cleared.data[0].keyRotationRequired, false, 'a rotation clears the marker');
});

test('a rotation is bounded so one call cannot push an arbitrary body', async () => {
  const { env, storage } = await fixture();
  const created = await createShared(env);
  const ownerMembership = await storage.getOrganizationUserForUser(ORG, OWNER);
  assert.ok(ownerMembership);

  // Too many items for one call.
  const many = Array.from({ length: 201 }, (_, index) => ({
    id: `cipher-${index}`,
    key: ENC('k'),
    data: '{}',
  }));
  const tooMany = await call(env, `https://vault.example.test/api/organizations/${ORG}/rotate-key`, 'POST', OWNER, {
    members: [{ membershipId: ownerMembership.id, key: ENC('k') }],
    ciphers: many,
  });
  assert.equal(tooMany.status, 413);

  // A single item whose payload is over the per-item ceiling.
  const tooBig = await call(env, `https://vault.example.test/api/organizations/${ORG}/rotate-key`, 'POST', OWNER, {
    members: [{ membershipId: ownerMembership.id, key: ENC('k') }],
    ciphers: [{ id: created.id, key: ENC('k'), data: 'x'.repeat(70_000) }],
  });
  assert.equal(tooBig.status, 413);
});

test('only the owner can read what a rotation needs', async () => {
  const { env } = await fixture();
  const created = await createShared(env);

  const owner = await call(env, `https://vault.example.test/api/organizations/${ORG}/rotation-data`, 'GET', OWNER);
  assert.equal(owner.status, 200, await owner.clone().text());
  const data = (await owner.json()) as {
    organization: { id: string; privateKey: string | null };
    members: Array<{ membershipId: string; userId: string; publicKey: string | null }>;
    ciphers: Array<{ id: string; key: string | null; name: string | null; data: unknown }>;
  };
  assert.equal(data.organization.id, ORG);
  assert.equal(data.organization.privateKey, 'enc-private');
  assert.equal(data.members.length, 3, 'the confirmed members come back');
  assert.ok(data.members.every((member) => !!member.membershipId));

  const cipher = data.ciphers.find((entry) => entry.id === created.id);
  assert.ok(cipher, 'the shared item comes back');
  assert.equal(cipher.key, ENC('item-key'), 'the item key comes back as stored');
  assert.equal(cipher.name, ENC('Shared login'), 'the name comes back as stored');
  // The payload comes back exactly as the server stores it, so a rotation
  // re-encrypts what is there and not what the request said.
  const payload = cipher.data as { login: { username: string; password: string } };
  assert.equal(payload.login.username, sharedItem.login.username, 'the payload comes back as stored');
  assert.equal(payload.login.password, sharedItem.login.password, 'the payload comes back as stored');

  // A plain member has no say in a rotation, so they get nothing.
  for (const memberId of [WRITER, READER]) {
    const denied = await call(env, `https://vault.example.test/api/organizations/${ORG}/rotation-data`, 'GET', memberId);
    assert.equal(denied.status, 404, `${memberId} must not read the rotation data`);
  }

  // Someone outside the organization gets nothing either.
  const outsider = await call(env, `https://vault.example.test/api/organizations/${ORG}/rotation-data`, 'GET', OUTSIDER);
  assert.equal(outsider.status, 404);
});

test('a removed member is not part of the rotation', async () => {
  const { env, storage } = await fixture();
  const writerMembership = await storage.getOrganizationUserForUser(ORG, WRITER);
  assert.ok(writerMembership);
  await call(env, `https://vault.example.test/api/organizations/${ORG}/users/${writerMembership.id}`, 'DELETE', OWNER);

  const owner = await call(env, `https://vault.example.test/api/organizations/${ORG}/rotation-data`, 'GET', OWNER);
  const data = (await owner.json()) as { members: Array<{ userId: string }> };
  assert.equal(data.members.length, 2, 'the removed member is not in the rotation');
  assert.ok(!data.members.some((member) => member.userId === WRITER), 'the removed member keeps no key');
});

test('the owner reads the member list, and nobody else does', async () => {
  const { env } = await fixture();

  const owner = await call(env, `https://vault.example.test/api/organizations/${ORG}/users`, 'GET', OWNER);
  assert.equal(owner.status, 200, await owner.clone().text());
  const members = (await owner.json()) as {
    data: Array<{ id: string; userId: string; email: string | null; type: number; collections: unknown[] }>;
  };
  assert.equal(members.data.length, 3, 'every membership comes back');
  const ownerRow = members.data.find((member) => member.userId === OWNER);
  assert.ok(ownerRow, 'the owner is in the list');
  assert.equal(ownerRow.email, 'owner@example.test', 'the member is named by their address');
  assert.equal(ownerRow.type, 0, 'the owner keeps their role');

  // A plain member has no say in who is in the organization.
  for (const memberId of [WRITER, READER]) {
    const denied = await call(env, `https://vault.example.test/api/organizations/${ORG}/users`, 'GET', memberId);
    assert.equal(denied.status, 404, `${memberId} must not read the member list`);
  }
});

test('only the owner hands out a role', async () => {
  const { env } = await fixture();

  // The writer is a plain member, so it may not even try.
  const byMember = await call(env, `https://vault.example.test/api/organizations/${ORG}/users/ou-writer`, 'PUT', WRITER, {
    type: 1,
  });
  assert.equal(byMember.status, 404, 'a plain member may not change roles');

  // The owner may.
  const byOwner = await call(env, `https://vault.example.test/api/organizations/${ORG}/users/ou-writer`, 'PUT', OWNER, {
    type: 1,
  });
  assert.equal(byOwner.status, 200, await byOwner.clone().text());

  // Nobody becomes an owner through this route.
  const toOwner = await call(env, `https://vault.example.test/api/organizations/${ORG}/users/ou-writer`, 'PUT', OWNER, {
    type: 0,
  });
  assert.equal(toOwner.status, 400);
});

test('sharing a personal item into a collection needs write rights on it', async () => {
  const { env } = await fixture();
  const personal = await call(env, 'https://vault.example.test/api/ciphers', 'POST', READER, {
    type: 1,
    name: ENC('Personal login'),
    login: { username: ENC('me'), password: ENC('pw') },
  });
  assert.equal(personal.status, 200, await personal.clone().text());
  const personalId = ((await personal.json()) as { id: string }).id;

  // The reader only reads the shared collection, so it may not share into it.
  const refused = await call(env, `https://vault.example.test/api/ciphers/${personalId}/share`, 'PUT', READER, {
    cipher: { type: 1, name: ENC('Personal login'), login: { username: ENC('me') } },
    organizationId: ORG,
    collectionIds: [COL_SHARED],
  });
  assert.equal(refused.status, 403, 'a read-only member cannot share into the collection');

  // The writer may, and the item comes back as an organization item.
  const accepted = await call(env, `https://vault.example.test/api/ciphers/${personalId}/share`, 'PUT', READER, {
    cipher: { type: 1, name: ENC('Personal login'), login: { username: ENC('me') } },
    organizationId: ORG,
    collectionIds: [COL_READONLY],
  });
  void accepted;
  // The reader holds no write rights anywhere, so that is refused as well.
  assert.equal(accepted.status, 403);

  const writerPersonal = await call(env, 'https://vault.example.test/api/ciphers', 'POST', WRITER, {
    type: 1,
    name: ENC('Writer login'),
    login: { username: ENC('me'), password: ENC('pw') },
  });
  const writerItemId = ((await writerPersonal.json()) as { id: string }).id;
  const shared = await call(env, `https://vault.example.test/api/ciphers/${writerItemId}/share`, 'PUT', WRITER, {
    cipher: { type: 1, name: ENC('Writer login'), login: { username: ENC('me') } },
    organizationId: ORG,
    collectionIds: [COL_SHARED],
  });
  assert.equal(shared.status, 200, await shared.clone().text());
  const sharedBody = (await shared.json()) as { organizationId: string; collectionIds: string[] };
  assert.equal(sharedBody.organizationId, ORG, 'the item belongs to the organization');
  assert.deepEqual(sharedBody.collectionIds, [COL_SHARED], 'the item sits in the collection it was given');

  // A shared item cannot be shared again into another organization.
  const again = await call(env, `https://vault.example.test/api/ciphers/${writerItemId}/share`, 'PUT', WRITER, {
    cipher: { type: 1, name: ENC('Writer login') },
    organizationId: OTHER_ORG,
    collectionIds: [COL_OTHER],
  });
  assert.equal(again.status, 400);

  // The collections of a shared item can be changed afterwards, which is what
  // the newer clients do in a second call.
  const moved = await call(env, `https://vault.example.test/api/ciphers/${writerItemId}/collections_v2`, 'PUT', WRITER, {
    collectionIds: [COL_READONLY],
  });
  void moved;
  assert.equal(moved.status, 403, 'a read-only collection cannot take the item');
});
