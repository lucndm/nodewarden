// Checks the collection rights against the official server's own SQL.
//
// The official Bitwarden clients take the rights of an item from the server as
// three booleans, so the server has to combine the grants of a member exactly
// the way the official server does. That way is written in SQL, so this check
// runs that SQL against SQLite and compares the result with the resolver.
//
// The SQL is a transcription of the official server's
// src/Sql/dbo/Vault/Stored Procedures/Cipher/CipherDetails_ReadByUserId.sql:
// the grants are collected from the direct collection assignments and the
// group assignments, a direct assignment hides the group grants for the same
// collection, each grant is ranked by manage, edit and view password, and the
// item takes the highest rank it can reach.
//
// Coverage:
//   - the resolver agrees with the official SQL on a matrix of grants;
//   - a direct assignment hides the group grant for the same collection;
//   - the better of two group grants for one collection wins.
import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { resolveItemAccess, type CollectionGrant } from '../src/services/collection-access';

const USER = 'user-1';
const ORG = 'org-1';

function setup(): DatabaseSync {
  const db = new DatabaseSync(':memory:');
  db.exec(`
    CREATE TABLE organizations (id TEXT PRIMARY KEY);
    CREATE TABLE organization_users (id TEXT PRIMARY KEY, user_id TEXT, org_id TEXT, status INTEGER);
    CREATE TABLE groups (id TEXT PRIMARY KEY, org_id TEXT);
    CREATE TABLE group_users (group_id TEXT, org_user_id TEXT);
    CREATE TABLE collections (id TEXT PRIMARY KEY, org_id TEXT);
    CREATE TABLE collection_users (collection_id TEXT, org_user_id TEXT, read_only INTEGER, hide_passwords INTEGER, manage INTEGER);
    CREATE TABLE collection_groups (collection_id TEXT, group_id TEXT, read_only INTEGER, hide_passwords INTEGER, manage INTEGER);
    CREATE TABLE ciphers (id TEXT PRIMARY KEY, org_id TEXT);
    CREATE TABLE collection_ciphers (cipher_id TEXT, collection_id TEXT);
  `);
  db.prepare('INSERT INTO organizations (id) VALUES (?)').run(ORG);
  db.prepare('INSERT INTO organization_users (id, user_id, org_id, status) VALUES (?, ?, ?, ?)').run(
    'ou-1',
    USER,
    ORG,
    2
  );
  return db;
}

/** The official SQL, transcribed, returning the rights of one cipher. */
function officialSqlRights(db: DatabaseSync, cipherId: string) {
  const sql = `
    WITH CollectionAccess AS (
      SELECT CU.collection_id, CU.read_only, CU.hide_passwords, CU.manage
      FROM collection_users CU
      WHERE CU.org_user_id = 'ou-1'
      UNION ALL
      SELECT CG.collection_id, CG.read_only, CG.hide_passwords, CG.manage
      FROM collection_groups CG
      INNER JOIN group_users GU ON GU.group_id = CG.group_id AND GU.org_user_id = 'ou-1'
      WHERE NOT EXISTS (
        SELECT 1 FROM collection_users CU
        WHERE CU.collection_id = CG.collection_id AND CU.org_user_id = 'ou-1'
      )
    ),
    CollectionPermissions AS (
      SELECT collection_id,
        MAX(
          CASE WHEN manage = 1 THEN 4 ELSE 0 END
          + CASE WHEN read_only = 0 THEN 2 ELSE 0 END
          + CASE WHEN hide_passwords = 0 THEN 1 ELSE 0 END
        ) AS rank
      FROM CollectionAccess GROUP BY collection_id
    ),
    CipherAccess AS (
      SELECT MAX(CP.rank) AS rank
      FROM CollectionPermissions CP
      INNER JOIN collection_ciphers CC ON CC.collection_id = CP.collection_id
      WHERE CC.cipher_id = ? GROUP BY CC.cipher_id
    )
    SELECT
      (rank / 2) % 2 AS edit,
      rank % 2 AS view_password,
      rank / 4 AS manage
    FROM CipherAccess
  `;
  const row = db.prepare(sql).get(cipherId) as
    | { edit: number; view_password: number; manage: number }
    | undefined;
  if (!row) return null;
  return {
    readOnly: row.edit === 0,
    hidePasswords: row.view_password === 0,
    manage: row.manage === 1,
  };
}

interface Fixture {
  db: DatabaseSync;
  grants: CollectionGrant[];
}

/** Puts one cipher in a collection, granted to the member in some way. */
function fixture(
  cipherId: string,
  collectionId: string,
  mode: 'direct' | 'group',
  flags: { readOnly: boolean; hidePasswords: boolean; manage: boolean },
  extraGroup?: { groupId: string; flags: typeof flags }
): Fixture {
  const db = setup();
  db.prepare('INSERT INTO ciphers (id, org_id) VALUES (?, ?)').run(cipherId, ORG);
  db.prepare('INSERT INTO collections (id, org_id) VALUES (?, ?)').run(collectionId, ORG);
  db.prepare('INSERT INTO collection_ciphers (cipher_id, collection_id) VALUES (?, ?)').run(cipherId, collectionId);
  const row = (flags.readOnly ? 1 : 0) + ',' + (flags.hidePasswords ? 1 : 0) + ',' + (flags.manage ? 1 : 0);

  if (mode === 'direct') {
    db.prepare(
      'INSERT INTO collection_users (collection_id, org_user_id, read_only, hide_passwords, manage) VALUES (?, ?, ?, ?, ?)'
    ).run(collectionId, 'ou-1', flags.readOnly ? 1 : 0, flags.hidePasswords ? 1 : 0, flags.manage ? 1 : 0);
  } else {
    db.prepare('INSERT INTO groups (id, org_id) VALUES (?, ?)').run('g-1', ORG);
    db.prepare('INSERT INTO group_users (group_id, org_user_id) VALUES (?, ?)').run('g-1', 'ou-1');
    db.prepare(
      'INSERT INTO collection_groups (collection_id, group_id, read_only, hide_passwords, manage) VALUES (?, ?, ?, ?, ?)'
    ).run(collectionId, 'g-1', flags.readOnly ? 1 : 0, flags.hidePasswords ? 1 : 0, flags.manage ? 1 : 0);
  }

  if (extraGroup) {
    db.prepare('INSERT INTO groups (id, org_id) VALUES (?, ?)').run(extraGroup.groupId, ORG);
    db.prepare('INSERT INTO group_users (group_id, org_user_id) VALUES (?, ?)').run(extraGroup.groupId, 'ou-1');
    db.prepare(
      'INSERT INTO collection_groups (collection_id, group_id, read_only, hide_passwords, manage) VALUES (?, ?, ?, ?, ?)'
    ).run(
      collectionId,
      extraGroup.groupId,
      extraGroup.flags.readOnly ? 1 : 0,
      extraGroup.flags.hidePasswords ? 1 : 0,
      extraGroup.flags.manage ? 1 : 0
    );
  }
  void row;

  const grants: CollectionGrant[] = [
    {
      collectionId,
      direct: mode === 'direct',
      readOnly: flags.readOnly,
      hidePasswords: flags.hidePasswords,
      manage: flags.manage,
    },
  ];
  if (extraGroup) {
    grants.push({
      collectionId,
      direct: false,
      readOnly: extraGroup.flags.readOnly,
      hidePasswords: extraGroup.flags.hidePasswords,
      manage: extraGroup.flags.manage,
    });
  }
  return { db, grants };
}

test('the resolver agrees with the official SQL on every kind of grant', () => {
  const kinds = [
    { readOnly: false, hidePasswords: false, manage: false },
    { readOnly: true, hidePasswords: false, manage: false },
    { readOnly: false, hidePasswords: true, manage: false },
    { readOnly: true, hidePasswords: true, manage: false },
    { readOnly: false, hidePasswords: false, manage: true },
    { readOnly: true, hidePasswords: true, manage: true },
  ];

  for (const mode of ['direct', 'group'] as const) {
    for (const flags of kinds) {
      const { db, grants } = fixture('cipher-1', 'collection-1', mode, flags);
      const official = officialSqlRights(db, 'cipher-1');
      const resolved = resolveItemAccess(grants);
      assert.ok(official, 'the official SQL must find the item');
      assert.ok(resolved, 'the resolver must find the item');
      assert.equal(resolved.readOnly, official.readOnly, `readOnly for ${mode} ${JSON.stringify(flags)}`);
      assert.equal(resolved.hidePasswords, official.hidePasswords, `hidePasswords for ${mode} ${JSON.stringify(flags)}`);
      assert.equal(resolved.manage, official.manage, `manage for ${mode} ${JSON.stringify(flags)}`);
    }
  }
});

test('a direct assignment hides the group grant for the same collection', () => {
  const { db, grants } = fixture('cipher-1', 'collection-1', 'direct', {
    readOnly: true,
    hidePasswords: true,
    manage: false,
  });
  // The member is also in a group that would grant everything on that
  // collection. The direct assignment still wins.
  db.prepare('INSERT INTO groups (id, org_id) VALUES (?, ?)').run('g-2', ORG);
  db.prepare('INSERT INTO group_users (group_id, org_user_id) VALUES (?, ?)').run('g-2', 'ou-1');
  db.prepare(
    'INSERT INTO collection_groups (collection_id, group_id, read_only, hide_passwords, manage) VALUES (?, ?, ?, ?, ?)'
  ).run('collection-1', 'g-2', 0, 0, 1);
  grants.push({
    collectionId: 'collection-1',
    direct: false,
    readOnly: false,
    hidePasswords: false,
    manage: true,
  });

  const official = officialSqlRights(db, 'cipher-1');
  const resolved = resolveItemAccess(grants);
  assert.ok(official);
  assert.ok(resolved);
  assert.equal(resolved.readOnly, official.readOnly);
  assert.equal(resolved.hidePasswords, official.hidePasswords);
  assert.equal(resolved.manage, official.manage);
  assert.equal(resolved.manage, false, 'the group must not widen the direct assignment');
});

test('the better of two group grants for one collection wins', () => {
  const { db, grants } = fixture('cipher-1', 'collection-1', 'group', {
    readOnly: true,
    hidePasswords: true,
    manage: false,
  }, {
    groupId: 'g-2',
    flags: { readOnly: false, hidePasswords: false, manage: false },
  });

  const official = officialSqlRights(db, 'cipher-1');
  const resolved = resolveItemAccess(grants);
  assert.ok(official);
  assert.ok(resolved);
  assert.equal(resolved.readOnly, official.readOnly);
  assert.equal(resolved.hidePasswords, official.hidePasswords);
  assert.equal(resolved.manage, official.manage);
  assert.equal(resolved.readOnly, false, 'the better group grant must win');
});

test('an item in no collection the member reaches is invisible', () => {
  const { db } = fixture('cipher-1', 'collection-1', 'direct', {
    readOnly: false,
    hidePasswords: false,
    manage: false,
  });
  // The member has no access to that collection at all.
  db.exec('DELETE FROM collection_users');
  assert.equal(officialSqlRights(db, 'cipher-1'), null);
  assert.equal(resolveItemAccess([]), null);
});
