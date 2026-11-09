// What a folder becomes after the move into an organization.
//
// The production vault holds 300 folders but the organization ended up with
// 35 collections, and only 34 of them carry items. This test pins down the
// rule that explains it, because the rule decides what the audit has to
// report:
//
//   - a folder that holds items becomes a collection, and its items land in
//     that collection;
//   - a folder with no items has nothing to put anywhere, so it becomes no
//     collection at all;
//   - a folder whose name does not open (a broken ciphertext) leaves its
//     items without a collection of their own, and they fall into the
//     general collection together with the items that had no folder.
//
// It also pins the case that is easy to get wrong: two folders with the same
// name share one collection, so the items of both end up together.
import assert from 'node:assert/strict';
import test from 'node:test';
import { webcrypto } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { base64ToBytes, bytesToBase64, encryptBw } from '../webapp/src/lib/crypto';
import { migratePersonalVaultIntoOrganization } from '../webapp/src/lib/organization-migration';
import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { StorageService } from '../src/services/storage';
import { sqliteD1 } from './sqlite-d1';
import type { Env, User } from '../src/types';

const { subtle } = webcrypto;
const OWNER = '00000000-0000-4000-8000-0000000000a1';
const ORGANIZATION = '00000000-0000-4000-8000-0000000000o1';
const MEMBERSHIP = '00000000-0000-4000-8000-0000000000m1';
const COLLECTION = '00000000-0000-4000-8000-0000000000c1';
const NOW = '2026-01-01T00:00:00.000Z';

function halves(raw: Uint8Array): { encKey: Uint8Array; macKey: Uint8Array } {
  return { encKey: raw.slice(0, 32), macKey: raw.slice(32) };
}

async function keyPair(): Promise<{ publicKey: string; privateKey: CryptoKey }> {
  const pair = (await subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' },
    true,
    ['encrypt', 'decrypt']
  )) as CryptoKeyPair;
  const spki = new Uint8Array(await subtle.exportKey('spki', pair.publicKey));
  return { publicKey: bytesToBase64(spki), privateKey: pair.privateKey };
}

/** Wraps a key for the member with their RSA public key, in the `4.` form. */
async function wrap(publicKey: string, key: Uint8Array): Promise<string> {
  const imported = await subtle.importKey(
    'spki',
    base64ToBytes(publicKey).buffer as ArrayBuffer,
    { name: 'RSA-OAEP', hash: 'SHA-1' },
    false,
    ['encrypt']
  );
  const blob = new Uint8Array(
    await subtle.encrypt({ name: 'RSA-OAEP' }, imported, key.buffer.slice(0, 64) as ArrayBuffer)
  );
  return `4.${bytesToBase64(blob)}`;
}

function makeUser(): User {
  return {
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
    emergencyAccessGrants: null,
    apiKey: null,
    userKeyId: null,
    createdAt: NOW,
    updatedAt: NOW,
  } as unknown as User;
}

async function makeEnv(): Promise<{ env: Env; storage: StorageService }> {
  const sqlite = new DatabaseSync(':memory:');
  const db = sqliteD1(sqlite);
  await ensureStorageSchema(db);
  const env = {
    DB: db,
    NOTIFICATIONS_HUB: {
      idFromName: (name: string) => name,
      get: () => ({ fetch: async () => new Response(null, { status: 204 }) }),
    },
  } as unknown as Env;
  return { env, storage: new StorageService(db) };
}

type FolderSpec = { id: string; name: string; items: number };

/** A stable UUID per folder and item, because the history route takes UUIDs only. */
function itemIdFor(folderId: string, index: number): string {
  let hash = 0;
  for (const character of `${folderId}:${index}`) hash = (hash * 31 + character.charCodeAt(0)) >>> 0;
  const tail = hash.toString(16).padStart(12, '0');
  return `00000000-0000-4000-8000-${tail}`;
}

/**
 * A personal vault with the given folders, and an organization the owner
 * holds the key of. A folder whose name is empty is stored with a broken
 * ciphertext, the way a truncated one would land in the database.
 */
async function vault(folders: FolderSpec[]) {
  const { env, storage } = await makeEnv();
  const owner = await keyPair();
  const vaultKey = new Uint8Array(64).fill(7);
  const vaultHalves = halves(vaultKey);
  const organizationKey = new Uint8Array(64).fill(9);
  const itemKey = new Uint8Array(64).fill(3);
  const itemHalves = halves(itemKey);

  await storage.saveUser(makeUser());
  await env.DB.prepare('UPDATE users SET private_key = ?, public_key = ? WHERE id = ?')
    .bind(
      await encryptBw(
        new Uint8Array(await subtle.exportKey('pkcs8', owner.privateKey)),
        vaultHalves.encKey,
        vaultHalves.macKey
      ),
      owner.publicKey,
      OWNER
    )
    .run();
  await env.DB.prepare(
    'INSERT INTO organizations (id, name, private_key, public_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)'
  )
    .bind(ORGANIZATION, 'homelab', null, owner.publicKey, NOW, NOW)
    .run();
  await env.DB.prepare(
    'INSERT INTO organization_users (id, user_id, org_id, type, status, key, created_at, updated_at) ' +
      'VALUES (?, ?, ?, 0, 2, ?, ?, ?)'
  )
    .bind(MEMBERSHIP, OWNER, ORGANIZATION, await wrap(owner.publicKey, organizationKey), NOW, NOW)
    .run();
  await env.DB.prepare('INSERT INTO collections (id, org_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
    .bind(COLLECTION, ORGANIZATION, 'Default', NOW, NOW)
    .run();
  await env.DB.prepare(
    'INSERT INTO collection_users (collection_id, org_user_id, read_only, hide_passwords, manage) VALUES (?, ?, 0, 0, 0)'
  )
    .bind(COLLECTION, MEMBERSHIP)
    .run();

  const items: Array<{ id: string; folderId: string | null }> = [];
  for (const folder of folders) {
    // An empty name is stored as a ciphertext whose mac is cut short, so it
    // cannot be opened.
    const encryptedName = folder.name
      ? await encryptBw(new TextEncoder().encode(folder.name), vaultHalves.encKey, vaultHalves.macKey)
      : '2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAA';
    await env.DB.prepare(
      'INSERT INTO folders (id, user_id, name, tag_name, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)'
    )
      .bind(folder.id, OWNER, encryptedName, folder.name || null, NOW, NOW)
      .run();

    for (let index = 0; index < folder.items; index += 1) {
      const itemId = itemIdFor(folder.id, index);
      items.push({ id: itemId, folderId: folder.id });
      await env.DB.prepare(
        'INSERT INTO ciphers (id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, organization_id) ' +
          'VALUES (?, ?, 1, ?, ?, NULL, 0, ?, 0, ?, ?, ?, NULL)'
      )
        .bind(
          itemId,
          OWNER,
          folder.id,
          await encryptBw(new TextEncoder().encode(`Item ${index}`), itemHalves.encKey, itemHalves.macKey),
          JSON.stringify({ tags: [], login: {} }),
          await encryptBw(itemKey, vaultHalves.encKey, vaultHalves.macKey),
          NOW,
          NOW
        )
        .run();
    }
  }

  // One item with no folder at all.
  const looseItemId = '00000000-0000-4000-8000-0000000000c8';
  items.push({ id: looseItemId, folderId: null });
  await env.DB.prepare(
    'INSERT INTO ciphers (id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, organization_id) ' +
      'VALUES (?, ?, 1, NULL, ?, NULL, 0, ?, 0, ?, ?, ?, NULL)'
  )
    .bind(
      looseItemId,
      OWNER,
      await encryptBw(new TextEncoder().encode('Loose'), itemHalves.encKey, itemHalves.macKey),
      JSON.stringify({ tags: [], login: {} }),
      await encryptBw(itemKey, vaultHalves.encKey, vaultHalves.macKey),
      NOW,
      NOW
    )
    .run();

  return { env, storage, owner, vaultHalves, organizationKey, items };
}

async function migrate(env: Env, vaultHalves: { encKey: Uint8Array; macKey: Uint8Array }) {
  const authedFetch = async (url: string, init?: RequestInit): Promise<Response> => {
    const path = new URL(url, 'https://vault.example.test').pathname;
    const response = await handleAuthenticatedRoute(
      new Request(`https://vault.example.test${url}`, init),
      env,
      OWNER,
      { id: OWNER } as never,
      path,
      init?.method ?? 'GET'
    );
    assert.ok(response, `no route answered ${path}`);
    return response;
  };

  const folders = (await env.DB.prepare('SELECT id, name FROM folders WHERE user_id = ?').bind(OWNER).all<{
    id: string;
    name: string;
  }>()).results;
  const ciphers = (await env.DB.prepare(
    'SELECT id, key, name, notes, folder_id, data FROM ciphers WHERE user_id = ? AND organization_id IS NULL'
  ).bind(OWNER).all<{
    id: string;
    key: string | null;
    name: string;
    notes: string | null;
    folder_id: string | null;
    data: string;
  }>()).results;

  return migratePersonalVaultIntoOrganization({
    authedFetch,
    userEncKey: bytesToBase64(vaultHalves.encKey),
    userMacKey: bytesToBase64(vaultHalves.macKey),
    encryptedPrivateKey: (await env.DB.prepare('SELECT private_key FROM users WHERE id = ?').bind(OWNER).first<{
      private_key: string;
    }>())!.private_key,
    organization: { id: ORGANIZATION, wrappedKey: (await env.DB.prepare('SELECT key FROM organization_users WHERE id = ?').bind(MEMBERSHIP).first<{
      key: string;
    }>())!.key },
    folders: folders.map((folder) => ({ id: folder.id, name: folder.name })),
    items: ciphers.map((cipher) => ({
      id: cipher.id,
      key: cipher.key,
      name: cipher.name,
      notes: cipher.notes,
      folderId: cipher.folder_id,
      fields: [],
      attachments: [],
      versions: [],
    })),
    existingCollections: [{ id: COLLECTION, name: 'Default' }],
  });
}

/** The collection each item ended up in, by item id. */
async function placement(env: Env) {
  const rows = (await env.DB.prepare(
    'SELECT CC.cipher_id AS cipher_id, CC.collection_id AS collection_id, C.name AS name ' +
      'FROM collection_ciphers CC INNER JOIN collections C ON C.id = CC.collection_id'
  ).all<{ cipher_id: string; collection_id: string; name: string }>()).results;
  const byItem = new Map<string, string>();
  const collectionItems = new Map<string, number>();
  for (const row of rows) {
    byItem.set(row.cipher_id, row.collection_id);
    collectionItems.set(row.collection_id, (collectionItems.get(row.collection_id) ?? 0) + 1);
  }
  return { byItem, collectionItems };
}

test('every folder becomes a collection and the items follow their folder', async () => {
  const { env, vaultHalves } = await vault([
    { id: 'folder-with-items', name: 'Work', items: 3 },
    { id: 'folder-without-items', name: 'Empty', items: 0 },
  ]);

  const result = await migrate(env, vaultHalves);
  assert.equal(result.failed.length, 0, 'nothing should fail');

  const { byItem } = await placement(env);
  const collections = (await env.DB.prepare('SELECT id, name FROM collections WHERE org_id = ?').bind(ORGANIZATION).all<{
    id: string;
    name: string;
  }>()).results;

  // The organization started with one empty collection of its own, every
  // folder becomes one, and the items with no folder share the general one.
  assert.equal(collections.length, 4, 'the default, one per folder, and the general one');
  assert.equal(byItem.get(itemIdFor('folder-with-items', 0)), byItem.get(itemIdFor('folder-with-items', 2)));
  assert.equal(byItem.get('00000000-0000-4000-8000-0000000000c8') !== byItem.get(itemIdFor('folder-with-items', 0)), true);

  // A folder without items still becomes a collection, and it stays empty.
  const counts = (await env.DB.prepare(
    'SELECT C.id AS id, COUNT(CC.cipher_id) AS n FROM collections C ' +
      'LEFT JOIN collection_ciphers CC ON CC.collection_id = C.id GROUP BY C.id'
  ).all<{ id: string; n: number }>()).results;
  assert.equal(counts.length, 4, 'the default, one per folder, and the general one');
  assert.equal(counts.filter((row) => row.n === 0).length, 2, 'the default and the folder without items stay empty');
});

test('a folder whose name does not open leaves its items in the general collection', async () => {
  const { env, vaultHalves } = await vault([
    { id: 'folder-readable', name: 'Work', items: 2 },
    { id: 'folder-broken', name: '', items: 2 },
  ]);

  const result = await migrate(env, vaultHalves);
  assert.equal(result.failed.length, 1, 'the folder that could not be read is reported');
  assert.equal(result.failed[0].id, 'folder-broken');

  const { byItem } = await placement(env);
  const general = byItem.get('00000000-0000-4000-8000-0000000000c8');
  // The item with no folder and the items of the broken folder share it.
  assert.equal(byItem.get(itemIdFor('folder-broken', 0)), general);
  assert.equal(byItem.get(itemIdFor('folder-broken', 1)), general);
  // The readable folder keeps its own.
  assert.notEqual(byItem.get(itemIdFor('folder-readable', 0)), general);
});

test('two folders with the same name share one collection', async () => {
  const { env, vaultHalves } = await vault([
    { id: 'folder-one', name: 'Shared', items: 2 },
    { id: 'folder-two', name: 'Shared', items: 3 },
  ]);

  const result = await migrate(env, vaultHalves);
  assert.equal(result.failed.length, 0);

  const { byItem } = await placement(env);
  assert.equal(
    byItem.get(itemIdFor('folder-one', 0)),
    byItem.get(itemIdFor('folder-two', 0)),
    'folders that share a name share the collection'
  );

  const collections = (await env.DB.prepare('SELECT id FROM collections WHERE org_id = ?').bind(ORGANIZATION).all<{
    id: string;
  }>()).results;
  // The default, the one collection the two folders share, and the general one.
  assert.equal(collections.length, 3);
});
