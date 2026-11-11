// The names of collections are encrypted with the organization key.
//
// A collection name is read by the official clients as an encrypted string,
// and a name in plain text stops them: the Android app refuses to sync with
// "CollectionDecrypt: The encrypted string is malformed". The web vault used
// to create the first collection of an organization with the plain name
// "Default", so the server takes encrypted names only and the web vault seals
// the names that are still plain.
//
// Coverage:
//   - an organization is created only with an encrypted collection name;
//   - a collection is created only with an encrypted name;
//   - an import creates a collection only with an encrypted name;
//   - the owner renames a collection, and the members see the new name;
//   - a member, an outsider and another organization's collection are refused;
//   - a name in plain text is refused;
//   - the body of the admin console is refused rather than half-answered;
//   - the web vault seals a plain name, and leaves the other collections be.
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  COL_OTHER,
  COL_SHARED,
  ENC,
  ORG,
  OTHER_ORG,
  OUTSIDER,
  OWNER,
  WRITER,
  call,
  fixture,
} from './organization-fixture';
import { decryptBw } from '../webapp/src/lib/crypto';
import { sealPlainCollectionNames } from '../webapp/src/lib/collection-name-repair';
import type { Env } from '../src/types';

const COLLECTION_URL = (orgId: string, collectionId: string) =>
  `https://vault.example.test/api/organizations/${orgId}/collections/${collectionId}`;

const createOrganization = (env: Env, body: unknown) =>
  call(env, 'https://vault.example.test/api/organizations', 'POST', OWNER, body);

const createCollection = (env: Env, body: unknown) =>
  call(env, `https://vault.example.test/api/organizations/${ORG}/collections`, 'POST', OWNER, body);

async function countOrganizations(env: Env): Promise<number> {
  const row = await env.DB.prepare('SELECT COUNT(*) AS n FROM organizations').first<{ n: number }>();
  return Number(row?.n || 0);
}

async function collectionNames(env: Env, orgId: string): Promise<string[]> {
  const rows = await env.DB.prepare('SELECT name FROM collections WHERE org_id = ? ORDER BY name')
    .bind(orgId)
    .all<{ name: string }>();
  return rows.results.map((row) => row.name);
}

test('an organization is created only with an encrypted collection name', async () => {
  const { env } = await fixture();
  const before = await countOrganizations(env);

  const plain = await createOrganization(env, {
    name: 'Acme',
    collectionName: 'Default',
    key: '4.wrapped',
  });
  assert.equal(plain.status, 400);
  assert.equal(await countOrganizations(env), before, 'no organization was created');

  const missing = await createOrganization(env, { name: 'Acme', key: '4.wrapped' });
  assert.equal(missing.status, 400);
  assert.equal(await countOrganizations(env), before, 'no organization was created');

  const created = await createOrganization(env, {
    name: 'Acme',
    collectionName: ENC('Default'),
    key: '4.wrapped',
  });
  assert.equal(created.status, 200, await created.clone().text());
  const organization = (await created.json()) as { id: string };
  const names = await collectionNames(env, organization.id);
  assert.deepEqual(names, [ENC('Default')], 'the collection carries the name it was given');
});

test('a collection is created only with an encrypted name', async () => {
  const { env } = await fixture();

  const plain = await createCollection(env, { name: 'Fresh' });
  assert.equal(plain.status, 400);

  const created = await createCollection(env, { name: ENC('Fresh') });
  assert.equal(created.status, 200, await created.clone().text());
  const collection = (await created.json()) as { id: string; name: string };
  assert.equal(collection.name, ENC('Fresh'));
});

test('an import creates a collection only with an encrypted name', async () => {
  const { env } = await fixture();
  const before = await collectionNames(env, ORG);

  const response = await call(
    env,
    `https://vault.example.test/api/ciphers/import-organization?organizationId=${ORG}`,
    'POST',
    OWNER,
    {
      ciphers: [{ type: 1, name: ENC('item') }],
      collections: [{ name: 'Plain' }],
      collectionRelationships: [{ key: 0, value: 0 }],
    }
  );
  assert.equal(response.status, 400);
  assert.deepEqual(await collectionNames(env, ORG), before, 'no collection was created');
  const ciphers = await env.DB.prepare('SELECT COUNT(*) AS n FROM ciphers').first<{ n: number }>();
  assert.equal(Number(ciphers?.n), 0, 'no item was written');
});

test('the owner renames a collection and the members see the new name', async () => {
  const { env } = await fixture();

  const renamed = await call(env, COLLECTION_URL(ORG, COL_SHARED), 'PUT', OWNER, {
    name: ENC('Renamed'),
  });
  assert.equal(renamed.status, 200, await renamed.clone().text());
  const collection = (await renamed.json()) as { id: string; name: string; object: string };
  assert.equal(collection.id, COL_SHARED);
  assert.equal(collection.name, ENC('Renamed'));
  assert.equal(collection.object, 'collectionDetails');

  const sync = (await (await call(env, 'https://vault.example.test/api/sync', 'GET', WRITER)).json()) as {
    collections: Array<{ id: string; name: string }>;
  };
  const seen = sync.collections.find((entry) => entry.id === COL_SHARED);
  assert.equal(seen?.name, ENC('Renamed'), 'the writer sees the new name');
});

test('a rename is refused to anyone but an owner or an admin', async () => {
  const { env } = await fixture();

  const writer = await call(env, COLLECTION_URL(ORG, COL_SHARED), 'PUT', WRITER, {
    name: ENC('Renamed'),
  });
  assert.equal(writer.status, 404);

  const outsider = await call(env, COLLECTION_URL(ORG, COL_SHARED), 'PUT', OUTSIDER, {
    name: ENC('Renamed'),
  });
  assert.equal(outsider.status, 404);

  // The collection of another organization is not the one that was asked for.
  const other = await call(env, COLLECTION_URL(ORG, COL_OTHER), 'PUT', OWNER, {
    name: ENC('Renamed'),
  });
  assert.equal(other.status, 404);
  assert.ok((await collectionNames(env, OTHER_ORG)).includes('Other'), 'the collection kept its name');
});

test('a rename refuses a name in plain text', async () => {
  const { env } = await fixture();

  const response = await call(env, COLLECTION_URL(ORG, COL_SHARED), 'PUT', OWNER, { name: 'Renamed' });
  assert.equal(response.status, 400);
  assert.ok((await collectionNames(env, ORG)).includes('Shared'), 'the collection kept its name');
});

test('a rename refuses the body of the admin console', async () => {
  const { env } = await fixture();

  const response = await call(env, COLLECTION_URL(ORG, COL_SHARED), 'PUT', OWNER, {
    name: ENC('Renamed'),
    groups: [],
    users: [],
  });
  assert.equal(response.status, 501);
  assert.ok((await collectionNames(env, ORG)).includes('Shared'), 'the collection kept its name');
});

// The web vault seals the plain names of the collections of an organization
// the member owns or administers, and leaves the rest alone.
const encKey = new Uint8Array(32).fill(7);
const macKey = new Uint8Array(32).fill(9);

interface RecordedRequest {
  url: string;
  method: string;
  body: { name?: string } | null;
}

function recordingFetch(responses: Array<{ ok: boolean }> = []) {
  const requests: RecordedRequest[] = [];
  const authedFetch = async (url: string, init?: RequestInit) => {
    requests.push({
      url,
      method: init?.method || 'GET',
      body: init?.body ? (JSON.parse(String(init.body)) as { name?: string }) : null,
    });
    const outcome = responses.shift() ?? { ok: true };
    return new Response(outcome.ok ? '{}' : '{"error":"refused"}', {
      status: outcome.ok ? 200 : 400,
    });
  };
  return { requests, authedFetch };
}

const organization = (id: string, type: number, status = 2) => ({
  id,
  name: id,
  key: '4.wrapped',
  status,
  type,
  keyRotationRequired: false,
});

const collection = (id: string, organizationId: string, name: string) => ({
  id,
  organizationId,
  name,
  readOnly: false,
  hidePasswords: false,
  manage: true,
});

test('the web vault seals the plain names of the organizations it administers', async () => {
  const { requests, authedFetch } = recordingFetch();
  const renamed = await sealPlainCollectionNames({
    authedFetch,
    collections: [collection('col-plain', 'org-1', 'Default')],
    organizations: [organization('org-1', 0)],
    organizationKeys: new Map([['org-1', { encKey, macKey }]]),
  });
  assert.equal(renamed, 1);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].method, 'PUT');
  assert.ok(requests[0].url.endsWith('/api/organizations/org-1/collections/col-plain'));
  const sealed = requests[0].body?.name ?? '';
  assert.equal(new TextDecoder().decode(await decryptBw(sealed, encKey, macKey)), 'Default');
});

test('the web vault leaves the names it cannot seal alone', async () => {
  const { requests, authedFetch } = recordingFetch();
  const renamed = await sealPlainCollectionNames({
    authedFetch,
    collections: [
      collection('col-encrypted', 'org-1', ENC('Default')),
      collection('col-member', 'org-2', 'Default'),
      collection('col-unconfirmed', 'org-3', 'Default'),
      collection('col-nokey', 'org-4', 'Default'),
    ],
    organizations: [
      organization('org-1', 0),
      organization('org-2', 2),
      organization('org-3', 0, 1),
      organization('org-4', 0),
    ],
    organizationKeys: new Map([
      ['org-1', { encKey, macKey }],
      ['org-2', { encKey, macKey }],
      ['org-3', { encKey, macKey }],
    ]),
  });
  assert.equal(renamed, 0);
  assert.equal(requests.length, 0);
});

test('a collection the server refuses does not stop the next one', async () => {
  const { requests, authedFetch } = recordingFetch([{ ok: false }, { ok: true }]);
  const renamed = await sealPlainCollectionNames({
    authedFetch,
    collections: [
      collection('col-refused', 'org-1', 'One'),
      collection('col-renamed', 'org-1', 'Two'),
    ],
    organizations: [organization('org-1', 0)],
    organizationKeys: new Map([['org-1', { encKey, macKey }]]),
  });
  assert.equal(renamed, 1);
  assert.equal(requests.length, 2);
});
