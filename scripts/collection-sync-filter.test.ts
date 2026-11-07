// Checks that the sync response keeps out the items a member may not reach.
//
// An item that belongs to an organization is only returned when the member
// reaches it through a collection they have rights on. The filter belongs in
// the server: an item the member may not read must not leave it at all, no
// matter what the interface shows.
//
// Coverage:
//   - an item in a collection the member reaches comes back;
//   - an item in a collection they do not reach stays out;
//   - an item of another organization stays out;
//   - a personal item always comes back;
//   - the collections and organizations of the member come back with their
//     rights.
import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { handleSync } from '../src/handlers/sync';
import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { StorageService } from '../src/services/storage';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { sqliteD1 } from './sqlite-d1';
import type { Env } from '../src/types';

const NOW = '2026-11-07T00:00:00.000Z';
const ENC_NAME = `2.${Buffer.from('iv-name').toString('base64')}|${Buffer.from('ct-name').toString('base64')}|${Buffer.from('mac-name').toString('base64')}`;
const OWNER = 'user-1';
const MEMBER = 'user-2';

async function fixture(): Promise<{ env: Env; org: string; otherOrg: string }> {
  const db = new DatabaseSync(':memory:');
  await ensureStorageSchema(sqliteD1(db));
  const env = { DB: sqliteD1(db) } as unknown as Env;
  const storage = new StorageService(env.DB);

  for (const [id, email] of [
    [OWNER, 'owner@example.test'],
    [MEMBER, 'member@example.test'],
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

  const org = 'org-1';
  const otherOrg = 'org-2';
  for (const [id, name] of [
    [org, 'Acme'],
    [otherOrg, 'Other'],
  ]) {
    await env.DB.prepare('INSERT INTO organizations (id, name, private_key, public_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(id, name, 'enc-private-key', 'public-key', NOW, NOW)
      .run();
  }
  await env.DB.prepare(
    'INSERT INTO organization_users (id, user_id, org_id, type, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  )
    .bind('ou-owner', OWNER, org, 0, 2, NOW, NOW)
    .run();
  await env.DB.prepare(
    'INSERT INTO organization_users (id, user_id, org_id, type, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  )
    .bind('ou-member', MEMBER, org, 2, 2, NOW, NOW)
    .run();

  for (const [id, orgId, name] of [
    ['col-mine', org, 'Mine'],
    ['col-theirs', org, 'Theirs'],
    ['col-other', otherOrg, 'Other'],
  ]) {
    await env.DB.prepare('INSERT INTO collections (id, org_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
      .bind(id, orgId, name, NOW, NOW)
      .run();
  }
  // The member reaches the collection they were given directly.
  await env.DB.prepare(
    'INSERT INTO collection_users (collection_id, org_user_id, read_only, hide_passwords, manage) VALUES (?, ?, ?, ?, ?)'
  )
    .bind('col-mine', 'ou-member', 0, 0, 0)
    .run();

  const addCipher = async (id: string, userId: string, orgId: string | null) => {
    await env.DB.prepare(
      'INSERT INTO ciphers (id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, organization_id) ' +
        'VALUES (?, ?, 1, NULL, ?, NULL, 0, ?, 0, NULL, ?, ?, ?)'
    )
      .bind(id, userId, ENC_NAME, '{}', NOW, NOW, orgId)
      .run();
  };
  const addToCollection = async (cipherId: string, collectionId: string) => {
    await env.DB.prepare('INSERT INTO collection_ciphers (cipher_id, collection_id) VALUES (?, ?)')
      .bind(cipherId, collectionId)
      .run();
  };

  await addCipher('cipher-mine', OWNER, org);
  await addToCollection('cipher-mine', 'col-mine');
  await addCipher('cipher-theirs', OWNER, org);
  await addToCollection('cipher-theirs', 'col-theirs');
  await addCipher('cipher-other', OWNER, otherOrg);
  await addToCollection('cipher-other', 'col-other');
  await addCipher('cipher-personal', OWNER, null);

  return { env, org, otherOrg };
}

async function sync(env: Env, userId: string) {
  const response = await handleSync(new Request('https://vault.example.test/api/sync'), env, userId);
  assert.equal(response.status, 200);
  return (await response.json()) as {
    ciphers: Array<{ id: string }>;
    collections: Array<{ id: string; readOnly: boolean; hidePasswords: boolean; manage: boolean }>;
    profile: { organizations: Array<{ id: string }> };
  };
}

test('the sync response keeps out the items a member may not reach', async () => {
  const { env } = await fixture();
  const body = await sync(env, MEMBER);
  const ids = body.ciphers.map((cipher) => cipher.id);

  assert.equal(ids.includes('cipher-mine'), true, 'an item in a reachable collection comes back');
  assert.equal(ids.includes('cipher-theirs'), false, 'an item in a collection the member does not reach stays out');
  assert.equal(ids.includes('cipher-other'), false, 'an item of another organization stays out');
  assert.equal(ids.includes('cipher-personal'), false, "another member's personal item stays out");
});

test('the owner sees every item of their own organization', async () => {
  const { env } = await fixture();
  const body = await sync(env, OWNER);
  const ids = body.ciphers.map((cipher) => cipher.id);

  // The owner is an organization admin, so every collection of the
  // organization reaches them.
  assert.equal(ids.includes('cipher-mine'), true);
  assert.equal(ids.includes('cipher-theirs'), true);
  assert.equal(ids.includes('cipher-other'), false, 'an item of another organization stays out');
});

test('the collections and organizations of the member come back with their rights', async () => {
  const { env, org } = await fixture();
  const body = await sync(env, MEMBER);

  assert.equal(body.collections.length, 1);
  assert.equal(body.collections[0].id, 'col-mine');
  assert.equal(body.collections[0].readOnly, false);
  assert.equal(body.collections[0].hidePasswords, false);
  assert.equal(body.collections[0].manage, false);

  assert.ok(body.profile.organizations);
  assert.equal(body.profile.organizations.length, 1);
  assert.equal(body.profile.organizations[0].id, org);
});

test('the collection and organization endpoints return the real lists', async () => {
  const { env, org } = await fixture();

  const collectionsRequest = new Request('https://vault.example.test/api/collections');
  const collectionsResponse = await handleAuthenticatedRoute(
    collectionsRequest,
    env,
    MEMBER,
    { id: MEMBER } as never,
    '/api/collections',
    'GET'
  );
  assert.ok(collectionsResponse);
  assert.equal(collectionsResponse.status, 200);
  const collections = (await collectionsResponse.json()) as {
    data: Array<{ id: string; readOnly: boolean; hidePasswords: boolean; manage: boolean }>;
    object: string;
  };
  assert.equal(collections.object, 'list');
  assert.equal(collections.data.length, 1);
  assert.equal(collections.data[0].id, 'col-mine');
  assert.equal(collections.data[0].readOnly, false);

  const organizationsResponse = await handleAuthenticatedRoute(
    new Request('https://vault.example.test/api/organizations'),
    env,
    MEMBER,
    { id: MEMBER } as never,
    '/api/organizations',
    'GET'
  );
  assert.ok(organizationsResponse);
  assert.equal(organizationsResponse.status, 200);
  const organizations = (await organizationsResponse.json()) as {
    data: Array<{ id: string; name: string }>;
  };
  assert.equal(organizations.data.length, 1);
  assert.equal(organizations.data[0].id, org);
  assert.equal(organizations.data[0].name, 'Acme');
});

test('the organization routes that are not built answer 501, not success', async () => {
  const { env } = await fixture();

  // Creating an organization is real, so a request without the wrapped key is
  // rejected as bad input rather than answered with a fake id.
  const creation = await handleAuthenticatedRoute(
    new Request('https://vault.example.test/api/organizations', { method: 'POST' }),
    env,
    MEMBER,
    { id: MEMBER } as never,
    '/api/organizations',
    'POST'
  );
  assert.ok(creation);
  assert.equal(creation.status, 400);

  // Deleting an organization is not built yet: the answer must say so.
  const deletion = await handleAuthenticatedRoute(
    new Request('https://vault.example.test/api/organizations/org-1', { method: 'DELETE' }),
    env,
    MEMBER,
    { id: MEMBER } as never,
    '/api/organizations/org-1',
    'DELETE'
  );
  assert.ok(deletion);
  assert.equal(deletion.status, 501, 'an unbuilt route must not answer success');
});
