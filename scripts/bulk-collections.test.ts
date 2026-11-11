// Assigning collections to several items of an organization at once.
//
// The "Assign to collections" dialog of the web vault, the extension and the
// desktop app sends one request for many items, and calls it twice when a
// collection is taken away: once to add the collections that stay, once to
// remove the one that goes.
//
// Coverage:
//   - the owner adds a collection to two items, and the members see it;
//   - the owner takes a collection away;
//   - an item that would be left without a collection refuses the whole
//     request, and nothing changes;
//   - a member who may not write the collection, an account outside the
//     organization and a collection of another organization are refused;
//   - an item that does not exist, and a personal item, are skipped;
//   - a malformed body is refused.
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  ORG,
  OWNER,
  WRITER,
  READER,
  OUTSIDER,
  COL_SHARED,
  COL_READONLY,
  COL_OTHER,
  ENC,
  fixture,
  call,
} from './organization-fixture';
import { handleAuthenticatedRoute } from '../src/router-authenticated';
import type { Env } from '../src/types';

const BULK_URL = 'https://vault.example.test/api/ciphers/bulk-collections';

const bulk = (env: Env, userId: string, body: unknown) => call(env, BULK_URL, 'POST', userId, body);

const item = (name: string) => ({
  type: 1,
  name: ENC(name),
  login: { username: ENC(`${name}-user`), password: ENC(`${name}-pass`) },
});

async function createItem(env: Env, body: Record<string, unknown>): Promise<string> {
  const response = await call(env, 'https://vault.example.test/api/ciphers', 'POST', WRITER, body);
  assert.equal(response.status, 200, await response.clone().text());
  const created = await response.json();
  return created.id;
}

const createOrganizationItem = (env: Env, name: string) =>
  createItem(env, { ...item(name), organizationId: ORG, collectionIds: [COL_SHARED] });

const createPersonalItem = (env: Env, name: string) => createItem(env, item(name));

/** The collections an item sits in. */
async function linksOf(env: Env, cipherId: string): Promise<string[]> {
  const rows = await env.DB
    .prepare('SELECT collection_id FROM collection_ciphers WHERE cipher_id = ?')
    .bind(cipherId)
    .all<{ collection_id: string }>();
  return rows.results.map((row) => row.collection_id).sort();
}

async function revisionOf(env: Env, userId: string): Promise<string> {
  const row = await env.DB
    .prepare('SELECT revision_date FROM user_revisions WHERE user_id = ?')
    .bind(userId)
    .first<{ revision_date: string }>();
  return row?.revision_date ?? '';
}

test('the owner adds a collection to two items at once', async () => {
  const { env } = await fixture();
  const first = await createOrganizationItem(env, 'first');
  const second = await createOrganizationItem(env, 'second');
  await createPersonalItem(env, 'personal');
  const readerBefore = await revisionOf(env, READER);

  const response = await bulk(env, OWNER, {
    organizationId: ORG,
    cipherIds: [first, second],
    collectionIds: [COL_READONLY],
    removeCollections: false,
  });
  assert.equal(response.status, 204, await response.clone().text());
  assert.deepEqual(await linksOf(env, first), [COL_READONLY, COL_SHARED].sort());
  assert.deepEqual(await linksOf(env, second), [COL_READONLY, COL_SHARED].sort());
  assert.notEqual(await revisionOf(env, READER), readerBefore, 'the reader sees the new collection');
});

test('the owner takes a collection away from two items at once', async () => {
  const { env } = await fixture();
  const first = await createOrganizationItem(env, 'first');
  const second = await createOrganizationItem(env, 'second');
  await createPersonalItem(env, 'personal');
  await bulk(env, OWNER, {
    organizationId: ORG,
    cipherIds: [first, second],
    collectionIds: [COL_READONLY],
  });

  const response = await bulk(env, OWNER, {
    organizationId: ORG,
    cipherIds: [first, second],
    collectionIds: [COL_SHARED],
    removeCollections: true,
  });
  assert.equal(response.status, 204, await response.clone().text());
  assert.deepEqual(await linksOf(env, first), [COL_READONLY]);
  assert.deepEqual(await linksOf(env, second), [COL_READONLY]);
});

test('an item that would be left without a collection refuses the whole request', async () => {
  const { env } = await fixture();
  const first = await createOrganizationItem(env, 'first');
  const second = await createOrganizationItem(env, 'second');
  await createPersonalItem(env, 'personal');

  const response = await bulk(env, OWNER, {
    organizationId: ORG,
    cipherIds: [first, second],
    collectionIds: [COL_SHARED],
    removeCollections: true,
  });
  assert.equal(response.status, 400, await response.clone().text());
  assert.deepEqual(await linksOf(env, first), [COL_SHARED]);
  assert.deepEqual(await linksOf(env, second), [COL_SHARED]);
});

test('the request is refused when the member may not write the collections', async () => {
  const { env } = await fixture();
  const first = await createOrganizationItem(env, 'first');
  const second = await createOrganizationItem(env, 'second');
  await createPersonalItem(env, 'personal');

  const readOnly = await bulk(env, WRITER, {
    organizationId: ORG,
    cipherIds: [first, second],
    collectionIds: [COL_READONLY],
  });
  assert.equal(readOnly.status, 403, await readOnly.clone().text());

  const outsider = await bulk(env, OUTSIDER, {
    organizationId: ORG,
    cipherIds: [first, second],
    collectionIds: [COL_SHARED],
  });
  assert.equal(outsider.status, 404, await outsider.clone().text());

  const otherOrganization = await bulk(env, OWNER, {
    organizationId: ORG,
    cipherIds: [first, second],
    collectionIds: [COL_OTHER],
  });
  assert.equal(otherOrganization.status, 404, await otherOrganization.clone().text());

  assert.deepEqual(await linksOf(env, first), [COL_SHARED], 'nothing was written');
  assert.deepEqual(await linksOf(env, second), [COL_SHARED], 'nothing was written');
});

test('an item that does not exist, and a personal item, are skipped', async () => {
  const { env } = await fixture();
  const first = await createOrganizationItem(env, 'first');
  const second = await createOrganizationItem(env, 'second');
  const personal = await createPersonalItem(env, 'personal');

  const response = await bulk(env, OWNER, {
    organizationId: ORG,
    cipherIds: [first, second, personal, '00000000-0000-4000-8000-0000000000aa'],
    collectionIds: [COL_READONLY],
  });
  assert.equal(response.status, 204, await response.clone().text());
  assert.deepEqual(await linksOf(env, first), [COL_READONLY, COL_SHARED].sort());
  assert.deepEqual(await linksOf(env, second), [COL_READONLY, COL_SHARED].sort());
  assert.deepEqual(await linksOf(env, personal), [], 'a personal item sits in no collection');
});

test('a malformed request is refused', async () => {
  const { env } = await fixture();
  await createOrganizationItem(env, 'first');
  await createOrganizationItem(env, 'second');
  await createPersonalItem(env, 'personal');

  const noOrganization = await bulk(env, OWNER, {
    cipherIds: ['00000000-0000-4000-8000-0000000000aa'],
    collectionIds: [COL_SHARED],
  });
  assert.equal(noOrganization.status, 400, await noOrganization.clone().text());

  const noCollection = await bulk(env, OWNER, {
    organizationId: ORG,
    cipherIds: ['00000000-0000-4000-8000-0000000000aa'],
    collectionIds: [],
  });
  assert.equal(noCollection.status, 400, await noCollection.clone().text());

  const noItem = await bulk(env, OWNER, {
    organizationId: ORG,
    cipherIds: [],
    collectionIds: [COL_SHARED],
  });
  assert.equal(noItem.status, 400, await noItem.clone().text());

  const broken = await handleAuthenticatedRoute(
    new Request(BULK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{ not json',
    }),
    env,
    OWNER,
    { id: OWNER } as never,
    '/api/ciphers/bulk-collections',
    'POST'
  );
  assert.ok(broken, 'the route answers');
  assert.equal(broken.status, 400, await broken.clone().text());
});
