// Moving a personal vault into an organization.
//
// The server cannot read the vault, so the move happens on the client: the
// folders become collections, and every item is re-encrypted under the
// organization key before it is handed over.
//
// This runs the whole path: it builds an organization with a wrapped key, puts
// a folder and an item in the personal vault, migrates, and then proves
//
//   - the folder became a collection whose name opens with the organization
//     key;
//   - the item is in the organization and in that collection;
//   - the item's name and payload open with the organization key, and with no
//     other key;
//   - the item's attachment and history travel with it;
//   - running the move again does not touch what already moved.
import assert from 'node:assert/strict';
import test from 'node:test';
import { webcrypto } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { base64ToBytes, bytesToBase64, decryptBw, encryptBw } from '../webapp/src/lib/crypto';
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
const FOLDER = '00000000-0000-4000-8000-0000000000f1';
const ITEM = '00000000-0000-4000-8000-0000000000c9';
const ATTACHMENT = '00000000-0000-4000-8000-0000000000a1';
const VERSION = '00000000-0000-4000-8000-0000000000d1';
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
    yubikeyNfc: false,
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

/**
 * A personal vault with one folder and one item, and an organization the
 * owner holds the key of.
 */
async function vault() {
  const { env, storage } = await makeEnv();
  const owner = await keyPair();
  const vaultKey = new Uint8Array(64).fill(7);
  const vaultHalves = halves(vaultKey);
  const organizationKey = new Uint8Array(64).fill(9);
  const organizationHalves = halves(organizationKey);
  const itemKey = new Uint8Array(64).fill(3);
  const itemHalves = halves(itemKey);
  const attachmentKey = new Uint8Array(64).fill(5);

  await storage.saveUser(makeUser());
  await env.DB.prepare(
    'UPDATE users SET private_key = ?, public_key = ? WHERE id = ?'
  )
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
  await env.DB.prepare('INSERT INTO collection_users (collection_id, org_user_id, read_only, hide_passwords, manage) VALUES (?, ?, 0, 0, 0)')
    .bind(COLLECTION, MEMBERSHIP)
    .run();

  const folderName = await encryptBw(new TextEncoder().encode('Work'), vaultHalves.encKey, vaultHalves.macKey);
  await env.DB.prepare('INSERT INTO folders (id, user_id, name, tag_name, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(FOLDER, OWNER, folderName, 'Work', NOW, NOW)
    .run();

  const itemName = await encryptBw(new TextEncoder().encode('Shared login'), itemHalves.encKey, itemHalves.macKey);
  const itemPassword = await encryptBw(new TextEncoder().encode('hunter2'), itemHalves.encKey, itemHalves.macKey);
  const itemUsername = await encryptBw(new TextEncoder().encode('vault-user'), itemHalves.encKey, itemHalves.macKey);
  await env.DB.prepare(
    'INSERT INTO ciphers (id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, organization_id) ' +
      'VALUES (?, ?, 1, ?, ?, NULL, 0, ?, 0, ?, ?, ?, NULL)'
  )
    .bind(
      ITEM,
      OWNER,
      FOLDER,
      itemName,
      JSON.stringify({ tags: ['Work'], login: { username: itemUsername, password: itemPassword } }),
      await encryptBw(itemKey, vaultHalves.encKey, vaultHalves.macKey),
      NOW,
      NOW
    )
    .run();
  await env.DB.prepare('INSERT INTO attachments (id, cipher_id, file_name, size, size_name, key) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(
      ATTACHMENT,
      ITEM,
      'note.txt',
      12,
      '12 Bytes',
      await encryptBw(attachmentKey, itemHalves.encKey, itemHalves.macKey)
    )
    .run();
  await env.DB.prepare(
    'INSERT INTO cipher_versions (id, cipher_id, user_id, kind, revision_date, created_at, type, name, notes, key, reprompt, data) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  )
    .bind(
      VERSION,
      ITEM,
      OWNER,
      'modified',
      NOW,
      NOW,
      1,
      await encryptBw(new TextEncoder().encode('Older name'), itemHalves.encKey, itemHalves.macKey),
      null,
      await encryptBw(itemKey, vaultHalves.encKey, vaultHalves.macKey),
      0,
      JSON.stringify({ login: {}, tags: [] })
    )
    .run();

  return { env, storage, owner, vaultHalves, organizationHalves, itemHalves, attachmentKey };
}

test('a personal vault moves into the organization', async () => {
  const { env, owner, vaultHalves, organizationHalves, itemHalves, attachmentKey } = await vault();

  const authedFetch = async (url: string, init?: RequestInit) => {
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

  const item = (await env.DB.prepare('SELECT name, notes, key, folder_id FROM ciphers WHERE id = ?').bind(ITEM).first<{
    name: string;
    notes: string | null;
    key: string | null;
    folder_id: string | null;
  }>())!;

  const result = await migratePersonalVaultIntoOrganization({
    authedFetch,
    userEncKey: bytesToBase64(vaultHalves.encKey),
    userMacKey: bytesToBase64(vaultHalves.macKey),
    encryptedPrivateKey: (
      await env.DB.prepare('SELECT private_key FROM users WHERE id = ?').bind(OWNER).first<{ private_key: string }>()
    )!.private_key,
    organization: { id: ORGANIZATION, wrappedKey: await wrap(owner.publicKey, new Uint8Array(64).fill(9)) },
    folders: [
      {
        id: FOLDER,
        name: (
          await env.DB.prepare('SELECT name FROM folders WHERE id = ?').bind(FOLDER).first<{ name: string }>()
        )!.name,
      },
    ],
    items: [
      {
        id: ITEM,
        key: item.key,
        name: item.name,
        notes: item.notes,
        folderId: item.folder_id,
        fields: JSON.parse(
          (
            await env.DB.prepare('SELECT data FROM ciphers WHERE id = ?').bind(ITEM).first<{ data: string }>()
          )!.data
        ) as Record<string, unknown>,
        attachments: [
          {
            id: ATTACHMENT,
            key: (
              await env.DB.prepare('SELECT key FROM attachments WHERE id = ?').bind(ATTACHMENT).first<{ key: string }>()
            )!.key,
          },
        ],
        versions: [],
      },
    ],
    existingCollections: [],
  });

  assert.equal(result.failed.length, 0, `nothing failed: ${JSON.stringify(result.failed)}`);
  assert.equal(result.items, 1, 'the item moved');
  assert.equal(result.collections, 2, 'the folder became a collection, and the items without a folder got one');

  // The item is in the organization now, in a collection of its own.
  const moved = (await env.DB.prepare('SELECT organization_id, folder_id, name, key, data FROM ciphers WHERE id = ?')
    .bind(ITEM)
    .first<{ organization_id: string | null; folder_id: string | null; name: string; key: string; data: string }>())!;
  assert.equal(moved.organization_id, ORGANIZATION, 'the item belongs to the organization');
  assert.equal(moved.folder_id, null, 'the personal folder is gone');
  const collections = await env.DB.prepare('SELECT collection_id FROM collection_ciphers WHERE cipher_id = ?').bind(ITEM).all<{
    collection_id: string;
  }>();
  assert.equal(collections.results.length, 1, 'the item sits in a collection');

  // The name and the payload open with the organization key and no other.
  const newItemKey = await decryptBw(moved.key, organizationHalves.encKey, organizationHalves.macKey);
  const newItemHalves = halves(newItemKey);
  assert.equal(
    new TextDecoder().decode(await decryptBw(moved.name, newItemHalves.encKey, newItemHalves.macKey)),
    'Shared login',
    'the name is readable with the item key'
  );
  const payload = JSON.parse(moved.data) as { tags: string[]; login: { username: string; password: string } };
  assert.equal(
    new TextDecoder().decode(await decryptBw(payload.login.password, newItemHalves.encKey, newItemHalves.macKey)),
    'hunter2',
    'the payload is readable with the item key'
  );
  await assert.rejects(
    () => decryptBw(moved.name, itemHalves.encKey, itemHalves.macKey),
    'the old item key must not read the moved item'
  );
  assert.deepEqual(payload.tags, [], 'the personal tags are gone');

  // The collection's name opens with the organization key.
  const collection = (await env.DB.prepare('SELECT name FROM collections WHERE org_id = ? AND id != ?')
    .bind(ORGANIZATION, COLLECTION)
    .first<{ name: string }>())!;
  assert.equal(
    new TextDecoder().decode(await decryptBw(collection.name, organizationHalves.encKey, organizationHalves.macKey)),
    'Work',
    'the collection carries the folder name'
  );

  // The attachment and the history travel with the item.
  const attachment = (await env.DB.prepare('SELECT key FROM attachments WHERE id = ?').bind(ATTACHMENT).first<{
    key: string;
  }>())!;
  assert.deepEqual(
    await decryptBw(attachment.key, newItemHalves.encKey, newItemHalves.macKey),
    attachmentKey,
    'the attachment opens with the item key the move installed'
  );
  const version = (await env.DB.prepare('SELECT key, name FROM cipher_versions WHERE id = ?').bind(VERSION).first<{
    key: string;
    name: string;
  }>())!;
  assert.equal(version.key, moved.key, 'the history follows the item key');
  assert.equal(
    new TextDecoder().decode(await decryptBw(version.name, newItemHalves.encKey, newItemHalves.macKey)),
    'Older name',
    'the history keeps its name'
  );
});

test('a second move leaves what already moved alone', async () => {
  const { env, owner, vaultHalves } = await vault();

  const authedFetch = async (url: string, init?: RequestInit) => {
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

  const privateKey = (
    await env.DB.prepare('SELECT private_key FROM users WHERE id = ?').bind(OWNER).first<{ private_key: string }>()
  )!.private_key;

  // The item is already in the organization: the move leaves it there.
  await env.DB.prepare('UPDATE ciphers SET organization_id = ? WHERE id = ?').bind(ORGANIZATION, ITEM).run();
  const before = (await env.DB.prepare('SELECT key, name FROM ciphers WHERE id = ?').bind(ITEM).first<{
    key: string;
    name: string;
  }>())!;

  const result = await migratePersonalVaultIntoOrganization({
    authedFetch,
    userEncKey: bytesToBase64(vaultHalves.encKey),
    userMacKey: bytesToBase64(vaultHalves.macKey),
    encryptedPrivateKey: privateKey,
    organization: { id: ORGANIZATION, wrappedKey: await wrap(owner.publicKey, new Uint8Array(64).fill(9)) },
    folders: [],
    items: [],
    existingCollections: [],
  });

  assert.equal(result.items, 0, 'nothing moved');
  const after = (await env.DB.prepare('SELECT key, name FROM ciphers WHERE id = ?').bind(ITEM).first<{
    key: string;
    name: string;
  }>())!;
  assert.equal(after.key, before.key, 'the item key is untouched');
  assert.equal(after.name, before.name, 'the item name is untouched');
});
