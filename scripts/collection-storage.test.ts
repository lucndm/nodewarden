// Storage tests for the organizations, collections and groups of the
// Bitwarden sharing model.
//
// The rights a member holds on a collection live in the database, and an item
// the member may not reach must not leave the server. These tests check that
// the storage reads the rights the way the official server does, and that the
// filter that keeps an item out of the sync response works.
//
// Coverage:
//   - a member sees the organizations, collections and groups they belong to;
//   - a revoked or unconfirmed membership grants nothing;
//   - the rights of a collection come from the direct assignment, and from the
//     group when there is no direct one;
//   - an item the member cannot reach is not in the shared item list;
//   - an item in a collection of another member's organization is not either.
import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { StorageService } from '../src/services/storage';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { sqliteD1 } from './sqlite-d1';
import type { Env } from '../src/types';

const NOW = '2026-11-07T00:00:00.000Z';
const OWNER = 'user-1';
const MEMBER = 'user-2';
const OUTSIDER = 'user-3';

async function fixture(): Promise<{ env: Env; org: string; otherOrg: string }> {
  const db = new DatabaseSync(':memory:');
  await ensureStorageSchema(sqliteD1(db));
  const env = { DB: sqliteD1(db) } as unknown as Env;
  const storage = new StorageService(env.DB);

  for (const [id, email] of [
    [OWNER, 'owner@example.test'],
    [MEMBER, 'member@example.test'],
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

  const org = 'org-1';
  await env.DB.prepare(
    'INSERT INTO organizations (id, name, private_key, public_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)'
  )
    .bind(org, 'Acme', 'enc-private-key', 'public-key', NOW, NOW)
    .run();
  const otherOrg = 'org-2';
  await env.DB.prepare(
    'INSERT INTO organizations (id, name, private_key, public_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)'
  )
    .bind(otherOrg, 'Other', 'enc-private-key', 'public-key', NOW, NOW)
    .run();

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
  await env.DB.prepare(
    'INSERT INTO organization_users (id, user_id, org_id, type, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  )
    .bind('ou-outsider', OUTSIDER, otherOrg, 2, 2, NOW, NOW)
    .run();

  await env.DB.prepare(
    'INSERT INTO collections (id, org_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)'
  )
    .bind('col-open', org, 'Open', NOW, NOW)
    .run();
  await env.DB.prepare(
    'INSERT INTO collections (id, org_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)'
  )
    .bind('col-readonly', org, 'Read only', NOW, NOW)
    .run();
  await env.DB.prepare(
    'INSERT INTO collections (id, org_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)'
  )
    .bind('col-other', otherOrg, 'Other', NOW, NOW)
    .run();

  // The owner may edit the open collection; the member may only read it.
  await env.DB.prepare(
    'INSERT INTO collection_users (collection_id, org_user_id, read_only, hide_passwords, manage) VALUES (?, ?, ?, ?, ?)'
  )
    .bind('col-open', 'ou-owner', 0, 0, 0)
    .run();
  await env.DB.prepare(
    'INSERT INTO collection_users (collection_id, org_user_id, read_only, hide_passwords, manage) VALUES (?, ?, ?, ?, ?)'
  )
    .bind('col-open', 'ou-member', 1, 1, 0)
    .run();
  await env.DB.prepare(
    'INSERT INTO collection_users (collection_id, org_user_id, read_only, hide_passwords, manage) VALUES (?, ?, ?, ?, ?)'
  )
    .bind('col-readonly', 'ou-member', 1, 0, 0)
    .run();

  // A group that reaches the open collection with manage rights.
  await env.DB.prepare('INSERT INTO groups (id, org_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
    .bind('group-1', org, 'Admins', NOW, NOW)
    .run();
  await env.DB.prepare('INSERT INTO group_users (group_id, org_user_id) VALUES (?, ?)')
    .bind('group-1', 'ou-member')
    .run();
  await env.DB.prepare(
    'INSERT INTO collection_groups (collection_id, group_id, read_only, hide_passwords, manage) VALUES (?, ?, ?, ?, ?)'
  )
    .bind('col-open', 'group-1', 0, 0, 1)
    .run();

  return { env, org, otherOrg };
}

test('a member sees the organizations, collections and groups they belong to', async () => {
  const { env } = await fixture();
  const storage = new StorageService(env.DB);

  const orgs = await storage.getOrganizationsForUser(MEMBER);
  assert.equal(orgs.length, 1);
  assert.equal(orgs[0].id, 'org-1');
  assert.equal(orgs[0].name, 'Acme');

  const collections = await storage.getCollectionsForUser(MEMBER);
  assert.deepEqual(collections.map((c) => c.id).sort(), ['col-open', 'col-readonly']);

  const groups = await storage.getGroupsForUser(MEMBER);
  assert.deepEqual(groups.map((g) => g.id), ['group-1']);

  // The outsider belongs to another organization and sees none of this one.
  assert.equal((await storage.getOrganizationsForUser(OUTSIDER)).length, 1);
  assert.equal((await storage.getOrganizationsForUser(OUTSIDER))[0].id, 'org-2');
  assert.equal((await storage.getCollectionsForUser(OUTSIDER)).length, 0);
});

test('a revoked membership grants nothing', async () => {
  const { env } = await fixture();
  const storage = new StorageService(env.DB);
  await env.DB.prepare('UPDATE organization_users SET status = -1 WHERE id = ?').bind('ou-member').run();

  assert.equal((await storage.getOrganizationsForUser(MEMBER)).length, 0);
  assert.equal((await storage.getCollectionsForUser(MEMBER)).length, 0);
  assert.equal((await storage.getSharedCipherIdsForUser(MEMBER)).size, 0);
});

test('the rights of a collection come from the direct assignment, or the group', async () => {
  const { env } = await fixture();
  const storage = new StorageService(env.DB);

  const memberRights = await storage.getCollectionRights(MEMBER);
  const byId = new Map(memberRights.map((r) => [r.collectionId, r]));

  // The direct assignment wins over the group grant on the same collection.
  const open = byId.get('col-open');
  assert.ok(open);
  assert.equal(open.direct, true);
  assert.equal(open.readOnly, true);
  assert.equal(open.manage, false);

  // The collection with no group grant keeps the direct one.
  const readOnly = byId.get('col-readonly');
  assert.ok(readOnly);
  assert.equal(readOnly.readOnly, true);
  assert.equal(readOnly.hidePasswords, false);

  // The owner of the organization reaches every collection of it, and the
  // direct assignment on the collection they were given stands as it is.
  const ownerRights = await storage.getCollectionRights(OWNER);
  const ownerById = new Map(ownerRights.map((rights) => [rights.collectionId, rights]));
  assert.deepEqual([...ownerById.keys()].sort(), ['col-open', 'col-readonly']);
  const ownerOpen = ownerById.get('col-open');
  assert.ok(ownerOpen);
  assert.equal(ownerOpen.readOnly, false);
  assert.equal(ownerOpen.manage, true, 'an owner manages the collections they were assigned too');
  // The collection they were not assigned reaches them through the owner role.
  const ownerOther = ownerById.get('col-readonly');
  assert.ok(ownerOther);
  assert.equal(ownerOther.manage, true, 'an owner manages every collection of the organization');
});

test('an item the member cannot reach is not in the shared item list', async () => {
  const { env, org, otherOrg } = await fixture();
  const storage = new StorageService(env.DB);
  await env.DB.prepare(
    'INSERT INTO ciphers (id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, organization_id) ' +
    'VALUES (?, ?, 1, NULL, ?, NULL, 0, ?, 0, NULL, ?, ?, ?)'
  )
    .bind('cipher-shared', OWNER, 'enc-name', '{}', NOW, NOW, org)
    .run();
  await env.DB.prepare('INSERT INTO collection_ciphers (cipher_id, collection_id) VALUES (?, ?)')
    .bind('cipher-shared', 'col-open')
    .run();

  // The member reaches the item through a collection they have rights on.
  const memberShared = await storage.getSharedCipherIdsForUser(MEMBER);
  assert.equal(memberShared.has('cipher-shared'), true);

  // The outsider reaches no collection of this organization.
  const outsiderShared = await storage.getSharedCipherIdsForUser(OUTSIDER);
  assert.equal(outsiderShared.has('cipher-shared'), false);

  // The rights of the item follow the collection the member reaches.
  const access = await storage.getItemAccess('cipher-shared', MEMBER);
  assert.ok(access);
  assert.equal(access.readOnly, true);
  assert.equal(access.hidePasswords, true);
  assert.equal(access.manage, false);

  // An item in a collection of another organization is out of reach.
  await env.DB.prepare(
    'INSERT INTO ciphers (id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, organization_id) ' +
    'VALUES (?, ?, 1, NULL, ?, NULL, 0, ?, 0, NULL, ?, ?, ?)'
  )
    .bind('cipher-other', OWNER, 'enc-name', '{}', NOW, NOW, otherOrg)
    .run();
  await env.DB.prepare('INSERT INTO collection_ciphers (cipher_id, collection_id) VALUES (?, ?)')
    .bind('cipher-other', 'col-other')
    .run();
  assert.equal((await storage.getSharedCipherIdsForUser(MEMBER)).has('cipher-other'), false);
  assert.equal(await storage.getItemAccess('cipher-other', MEMBER), null);
});

test('an install created before the sharing model is upgraded in place', async () => {
  // Production carries data written by the build that had no organizations.
  // Upgrading must add the tables and the column without touching the rows.
  const db = new DatabaseSync(':memory:');
  const d1 = sqliteD1(db);
  await ensureStorageSchema(d1);

  // Take the database back to the shape the older build left behind.
  for (const table of [
    'collection_ciphers',
    'collection_groups',
    'collection_users',
    'group_users',
    'groups',
    'collections',
    'organization_users',
    'organizations',
  ]) {
    db.exec(`DROP TABLE ${table}`);
  }
  db.exec('DROP INDEX idx_ciphers_org');
  db.exec('ALTER TABLE ciphers DROP COLUMN organization_id');

  db.prepare(
    'INSERT INTO users (id, email, master_password_hash, key, kdf_type, kdf_iterations, security_stamp, role, status, verify_devices, yubikey_nfc, created_at, updated_at) ' +
      'VALUES (?, ?, ?, ?, 0, 600000, ?, ?, ?, 0, 0, ?, ?)'
  ).run('user-1', 'old@example.test', 'hash', 'key', 'stamp', 'user', 'active', NOW, NOW);
  db.prepare(
    'INSERT INTO ciphers (id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at) ' +
      'VALUES (?, ?, 1, NULL, ?, NULL, 0, ?, 0, NULL, ?, ?)'
  ).run('old-cipher', 'user-1', 'enc', '{}', NOW, NOW);

  // The next request runs the schema bootstrap again, the way it does when the
  // stored version differs from the build's version.
  await ensureStorageSchema(d1);

  for (const table of ['organizations', 'organization_users', 'collections', 'groups', 'group_users', 'collection_users', 'collection_groups', 'collection_ciphers']) {
    const found = db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?")
      .get(table) as { name: string } | undefined;
    assert.ok(found, `${table} must exist after the upgrade`);
  }

  const columns = db.prepare('PRAGMA table_info(ciphers)').all() as Array<{ name: string }>;
  assert.ok(
    columns.some((column) => column.name === 'organization_id'),
    'ciphers.organization_id must exist after the upgrade'
  );

  const stored = db.prepare('SELECT id, name, organization_id FROM ciphers WHERE id = ?').get('old-cipher') as
    | { id: string; name: string; organization_id: string | null }
    | undefined;
  assert.ok(stored, 'the row written by the older build must survive');
  assert.equal(stored.name, 'enc', 'the upgrade must not rewrite the row');
  assert.equal(stored.organization_id, null, 'an item written before sharing stays personal');
});

test('an install that already had the organization key column is migrated', async () => {
  // The first version of the sharing schema kept the organization key on the
  // organization row. That build is on production, so the upgrade has to move
  // the column away without losing anything.
  const db = new DatabaseSync(':memory:');
  const d1 = sqliteD1(db);
  await ensureStorageSchema(d1);

  // The old tables reference each other; drop dependants first.
  for (const table of ['collection_ciphers', 'collection_groups', 'collection_users', 'group_users', 'groups', 'collections']) {
    db.exec(`DROP TABLE ${table}`);
  }
  db.exec('DROP TABLE organization_users');
  db.exec('DROP TABLE organizations');
  db.exec(
    'CREATE TABLE organizations (id TEXT PRIMARY KEY, name TEXT NOT NULL, key TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)'
  );
  db.exec(
    'CREATE TABLE organization_users (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, org_id TEXT NOT NULL, ' +
      'type INTEGER NOT NULL DEFAULT 2, status INTEGER NOT NULL DEFAULT 2, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)'
  );
  db.exec("INSERT INTO organizations VALUES ('org-old', 'Acme', 'wrapped-for-owner', 't', 't')");

  await ensureStorageSchema(d1);

  const columns = db.prepare('PRAGMA table_info(organizations)').all() as Array<{ name: string }>;
  const names = columns.map((column) => column.name);
  assert.equal(names.includes('key'), false, 'the per-organization key column must be gone');
  assert.ok(names.includes('private_key'), 'the private key column must be added');
  assert.ok(names.includes('public_key'), 'the public key column must be added');

  const row = db.prepare('SELECT id, name FROM organizations WHERE id = ?').get('org-old') as
    | { id: string; name: string }
    | undefined;
  assert.ok(row, 'the organization written by the older build must survive');
  assert.equal(row.name, 'Acme');

  const userColumns = (db.prepare('PRAGMA table_info(organization_users)').all() as Array<{ name: string }>).map(
    (column) => column.name
  );
  assert.ok(userColumns.includes('key'), 'the per-member key column must be added');
});
