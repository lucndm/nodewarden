// Importing items: into the account's own vault, and into an organization the
// way the official web vault does it.
//
// Coverage:
//   - a personal import creates its folders and puts the items in them;
//   - an owner imports into an organization, creating a collection, and the
//     items belong to the organization and that collection only;
//   - a member imports into a collection they may write, but cannot create
//     one, nor import into one they only read;
//   - an account outside the organization is refused;
//   - an item left without a collection, or a relationship that points
//     nowhere, refuses the whole import before anything is written;
//   - the organization in the query wins over one written in an item.
import assert from 'node:assert/strict';
import test from 'node:test';

import { ORG, OTHER_ORG, OWNER, WRITER, READER, OUTSIDER, COL_SHARED, COL_READONLY, ENC, fixture, call } from './organization-fixture';
import type { Env } from '../src/types';

const item = (name: string) => ({
  type: 1,
  name: ENC(name),
  login: { username: ENC(`${name}-user`), password: ENC(`${name}-pass`) },
});

const importOrganization = (env: Env, userId: string, body: unknown, orgId = ORG) =>
  call(env, `https://vault.example.test/api/ciphers/import-organization?organizationId=${orgId}`, 'POST', userId, body);

async function countCiphers(env: Env): Promise<number> {
  const row = await env.DB.prepare('SELECT COUNT(*) AS n FROM ciphers').first<{ n: number }>();
  return Number(row?.n || 0);
}

test('a personal import creates its folders and fills them', async () => {
  const { env } = await fixture();
  const response = await call(env, 'https://vault.example.test/api/ciphers/import', 'POST', WRITER, {
    folders: [{ name: ENC('Imported') }],
    ciphers: [item('one'), item('two')],
    folderRelationships: [{ key: 0, value: 0 }],
  });
  assert.equal(response.status, 200, await response.clone().text());
  const rows = await env.DB.prepare('SELECT folder_id, organization_id FROM ciphers WHERE user_id = ? ORDER BY name').bind(WRITER).all<{ folder_id: string | null; organization_id: string | null }>();
  assert.equal(rows.results.length, 2);
  assert.equal(rows.results.filter((row) => row.folder_id).length, 1, 'one item went into the imported folder');
  assert.ok(rows.results.every((row) => row.organization_id === null), 'personal items stay personal');
});

test('an owner imports into the organization and creates a collection', async () => {
  const { env } = await fixture();
  const response = await importOrganization(env, OWNER, {
    ciphers: [item('a'), { ...item('b'), organizationId: OTHER_ORG, folderId: 'some-folder' }],
    collections: [{ name: ENC('Imported collection') }, { id: COL_SHARED, name: ENC('Shared') }],
    collectionRelationships: [{ key: 0, value: 0 }, { key: 1, value: 0 }, { key: 1, value: 1 }],
  });
  assert.equal(response.status, 200, await response.clone().text());

  const created = await env.DB.prepare('SELECT id FROM collections WHERE org_id = ? AND id NOT IN (?, ?)').bind(ORG, COL_SHARED, COL_READONLY).all<{ id: string }>();
  assert.equal(created.results.length, 1, 'one new collection');
  const newCollection = created.results[0].id;

  const ciphers = await env.DB.prepare('SELECT id, organization_id, folder_id FROM ciphers ORDER BY created_at').all<{ id: string; organization_id: string; folder_id: string | null }>();
  assert.equal(ciphers.results.length, 2);
  for (const cipher of ciphers.results) {
    assert.equal(cipher.organization_id, ORG, 'the organization in the query wins');
    assert.equal(cipher.folder_id, null, 'a shared item has no personal folder');
  }
  const links = await env.DB.prepare('SELECT cipher_id, collection_id FROM collection_ciphers').all<{ cipher_id: string; collection_id: string }>();
  assert.equal(links.results.length, 3);
  assert.ok(links.results.some((link) => link.collection_id === newCollection));
  assert.ok(links.results.some((link) => link.collection_id === COL_SHARED));
});

test('a member imports into a collection they may write, and no further', async () => {
  const { env } = await fixture();
  const into = (collectionId: string | undefined) => ({
    ciphers: [item('x')],
    collections: [collectionId ? { id: collectionId, name: ENC('c') } : { name: ENC('new') }],
    collectionRelationships: [{ key: 0, value: 0 }],
  });

  assert.equal((await importOrganization(env, WRITER, into(COL_SHARED))).status, 200);
  assert.equal((await importOrganization(env, WRITER, into(undefined))).status, 403, 'a member cannot create a collection');
  assert.equal((await importOrganization(env, WRITER, into(COL_READONLY))).status, 403, 'nor import into one they only read');
  assert.equal((await importOrganization(env, READER, into(COL_SHARED))).status, 403);
  assert.equal((await importOrganization(env, OUTSIDER, into(COL_SHARED))).status, 404, 'an outsider does not see the organization');
  assert.equal(await countCiphers(env), 1, 'only the allowed import wrote an item');

  // The imported item reaches the member through the collection.
  const sync = (await (await call(env, 'https://vault.example.test/api/sync', 'GET', WRITER)).json()) as {
    ciphers: Array<{ organizationId: string | null; collectionIds?: string[] }>;
  };
  const shared = sync.ciphers.filter((cipher) => cipher.organizationId === ORG);
  assert.equal(shared.length, 1);
  assert.deepEqual(shared[0].collectionIds, [COL_SHARED]);
});

test('a malformed import writes nothing', async () => {
  const { env } = await fixture();
  const withoutCollection = await importOrganization(env, OWNER, {
    ciphers: [item('a'), item('b')],
    collections: [{ id: COL_SHARED, name: ENC('Shared') }],
    collectionRelationships: [{ key: 0, value: 0 }],
  });
  assert.equal(withoutCollection.status, 400, 'an item left without a collection');
  const badRelationship = await importOrganization(env, OWNER, {
    ciphers: [item('a')],
    collections: [{ id: COL_SHARED, name: ENC('Shared') }],
    collectionRelationships: [{ key: 0, value: 5 }],
  });
  assert.equal(badRelationship.status, 400, 'a relationship that points nowhere');
  assert.equal((await call(env, 'https://vault.example.test/api/ciphers/import-organization', 'POST', OWNER, { ciphers: [] })).status, 400, 'no organization');
  assert.equal(await countCiphers(env), 0);
  const collections = await env.DB.prepare('SELECT COUNT(*) AS n FROM collections WHERE org_id = ?').bind(ORG).first<{ n: number }>();
  assert.equal(Number(collections?.n), 2, 'no collection was created');
});
