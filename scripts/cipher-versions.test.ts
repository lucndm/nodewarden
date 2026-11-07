// Item history (cipher versions) tests.
//
// The server stores the encrypted payload of every superseded state of an
// item, so a client can compare and restore old content without the server
// ever seeing plaintext.
//
// Coverage:
//   - a content edit records the state it replaced;
//   - no-op writes and folder moves record nothing;
//   - a write that loses the race records nothing;
//   - versions are private to their owner;
//   - a deleted item has no history, a purged item loses it;
//   - history is capped at the newest states;
//   - restoring brings back old content and keeps the current state.
import assert from 'node:assert/strict';
import test from 'node:test';

import { DatabaseSync } from 'node:sqlite';

import { installTestGlobals } from './test-env';
installTestGlobals();

import {
  handleCreateCipher,
  handleDeleteCipher,
  handlePermanentDeleteCipher,
  handleUpdateCipher,
} from '../src/handlers/ciphers';
import {
  handleGetCipherVersion,
  handleGetCipherVersions,
  handleRestoreCipherVersion,
} from '../src/handlers/cipher-versions';
import { sqliteD1 } from './sqlite-d1';
import { ensureStorageSchema } from '../src/services/storage-schema';
import type { Env } from '../src/types';

const ENC = (value: string) =>
  `2.${Buffer.from('iv-' + value).toString('base64')}|${Buffer.from('ct-' + value).toString('base64')}|${Buffer.from('mac-' + value).toString('base64')}`;

const OWNER = 'user-1';
const OTHER = 'user-2';

interface VersionSummary {
  id: string;
  cipherId: string;
  versionNo: number;
  kind: 'created' | 'modified';
  createdAt: string;
  revisionDate: string;
  name: string | null;
  key: string | null;
}

async function fixture() {
  const sqlite = new DatabaseSync(':memory:');
  const db = sqliteD1(sqlite);
  await ensureStorageSchema(db);
  const insertUser = sqlite.prepare(
    'INSERT INTO users(id, email, master_password_hash, key, kdf_type, kdf_iterations, security_stamp, role, status, created_at, updated_at) ' +
    'VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  );
  for (const userId of [OWNER, OTHER]) {
    insertUser.run(
      userId,
      `${userId}@example.test`,
      'hash',
      'key',
      0,
      100000,
      'stamp',
      'user',
      'active',
      '2026-11-01T00:00:00.000Z',
      '2026-11-01T00:00:00.000Z'
    );
  }
  return { sqlite, db, env: { DB: db } as unknown as Env };
}

interface CreatedCipher {
  id: string;
  revisionDate: string;
  name: string | null;
  login: { username: string | null; password: string | null } | null;
}

async function createCipher(env: Env, userId = OWNER): Promise<CreatedCipher> {
  const response = await handleCreateCipher(
    new Request('https://vault.example.test/api/ciphers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: 1,
        name: ENC('Title 1'),
        notes: ENC('Notes 1'),
        login: { username: ENC('user1'), password: ENC('pass1') },
      }),
    }),
    env,
    userId
  );
  assert.equal(response.status, 200, 'create must succeed');
  return (await response.json()) as CreatedCipher;
}

async function updateCipher(
  env: Env,
  id: string,
  body: Record<string, unknown>,
  userId = OWNER
): Promise<Response> {
  return handleUpdateCipher(
    new Request(`https://vault.example.test/api/ciphers/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
    env,
    userId,
    id
  );
}

async function listVersions(env: Env, id: string, userId = OWNER): Promise<VersionSummary[]> {
  const response = await handleGetCipherVersions(
    new Request(`https://vault.example.test/api/ciphers/${id}/versions`),
    env,
    userId,
    id
  );
  assert.equal(response.status, 200, 'version list must succeed');
  const body = (await response.json()) as { data: VersionSummary[] };
  return body.data;
}

test('a content edit records the state it replaced', async () => {
  const { env } = await fixture();
  const created = await createCipher(env);
  assert.deepEqual(await listVersions(env, created.id), [], 'a new item has no history yet');

  const updated = await updateCipher(env, created.id, {
    type: 1,
    name: ENC('Title 2'),
    notes: ENC('Notes 2'),
    login: { username: ENC('user2'), password: ENC('pass2'), totp: ENC('totp2') },
    revisionDate: created.revisionDate,
  });
  assert.equal(updated.status, 200);

  const versions = await listVersions(env, created.id);
  assert.equal(versions.length, 1, 'one edit records one version');
  assert.equal(versions[0].kind, 'created', 'the state the item was created in');
  assert.equal(versions[0].name, ENC('Title 1'), 'the version keeps the old name');
  assert.equal(versions[0].cipherId, created.id);
  assert.equal(versions[0].versionNo, 1);

  const snapshot = await handleGetCipherVersion(
    new Request(`https://vault.example.test/api/ciphers/${created.id}/versions/${versions[0].id}`),
    env,
    OWNER,
    created.id,
    versions[0].id
  );
  assert.equal(snapshot.status, 200);
  const snapshotBody = (await snapshot.json()) as {
    name: string;
    notes: string;
    data: string;
    versionNo: number;
  };
  assert.equal(snapshotBody.name, ENC('Title 1'));
  assert.equal(snapshotBody.notes, ENC('Notes 1'));
  assert.equal(snapshotBody.versionNo, 1);
  const payload = JSON.parse(snapshotBody.data) as { login?: { username?: string } };
  assert.equal(payload.login?.username, ENC('user1'), 'the version keeps the old username');

  await updateCipher(env, created.id, {
    type: 1,
    name: ENC('Title 3'),
    login: { username: ENC('user3'), password: ENC('pass3') },
  });
  const afterSecond = await listVersions(env, created.id);
  assert.equal(afterSecond.length, 2);
  assert.equal(afterSecond[0].name, ENC('Title 2'), 'newest version first');
  assert.equal(afterSecond[0].kind, 'modified');
  assert.equal(afterSecond[1].name, ENC('Title 1'));
  assert.equal(afterSecond[1].versionNo, 1);
  assert.equal(afterSecond[0].versionNo, 2);
});

test('no-op writes and folder moves record nothing', async () => {
  const { env } = await fixture();
  const created = await createCipher(env);

  const noop = await updateCipher(env, created.id, {
    type: 1,
    name: ENC('Title 1'),
    notes: ENC('Notes 1'),
    login: { username: ENC('user1'), password: ENC('pass1') },
    revisionDate: created.revisionDate,
  });
  assert.equal(noop.status, 200);
  assert.deepEqual(await listVersions(env, created.id), [], 'a no-op write records nothing');

  const moved = await updateCipher(env, created.id, {
    type: 1,
    name: ENC('Title 1'),
    notes: ENC('Notes 1'),
    login: { username: ENC('user1'), password: ENC('pass1') },
    tags: ['work'],
  });
  assert.equal(moved.status, 200);
  assert.deepEqual(
    await listVersions(env, created.id),
    [],
    'moving an item between folders is organization, not content'
  );
});

test('a write that loses the race records no version', async () => {
  const { env, db } = await fixture();
  const created = await createCipher(env);

  // A competing save lands between the handler read and its write.
  const prepare = db.prepare.bind(db);
  let injected = false;
  (db as any).prepare = (sql: string) => {
    const statement = prepare(sql);
    if (injected || !sql.includes('UPDATE ciphers SET type=?, folder_id=?')) return statement;
    const bind = statement.bind.bind(statement);
    statement.bind = (...values: unknown[]) => {
      bind(...values);
      const run = statement.run.bind(statement);
      statement.run = async () => {
        injected = true;
        await db
          .prepare(
            'UPDATE ciphers SET name=?, updated_at=? WHERE id=? AND user_id=?'
          )
          .bind(ENC('Concurrent'), '2026-11-02T00:00:00.000Z', created.id, OWNER)
          .run();
        return run();
      };
      return statement;
    };
    return statement;
  };

  const response = await updateCipher(env, created.id, {
    type: 1,
    name: ENC('Title 2'),
    login: { username: ENC('user2'), password: ENC('pass2') },
  });
  assert.equal(response.status, 400, 'a stale write is rejected');
  assert.deepEqual(
    await listVersions(env, created.id),
    [],
    'a rejected write leaves no version behind'
  );
});

test('versions are private to their owner', async () => {
  const { env } = await fixture();
  const created = await createCipher(env);
  await updateCipher(env, created.id, {
    type: 1,
    name: ENC('Title 2'),
    login: { username: ENC('user2'), password: ENC('pass2') },
  });
  const versions = await listVersions(env, created.id);
  assert.equal(versions.length, 1);

  const foreignList = await handleGetCipherVersions(
    new Request(`https://vault.example.test/api/ciphers/${created.id}/versions`),
    env,
    OTHER,
    created.id
  );
  assert.equal(foreignList.status, 404, 'another owner sees no history');

  const foreignSnapshot = await handleGetCipherVersion(
    new Request(`https://vault.example.test/api/ciphers/${created.id}/versions/${versions[0].id}`),
    env,
    OTHER,
    created.id,
    versions[0].id
  );
  assert.equal(foreignSnapshot.status, 404, 'another owner cannot read a snapshot');

  const foreignRestore = await handleRestoreCipherVersion(
    new Request(`https://vault.example.test/api/ciphers/${created.id}/versions/${versions[0].id}/restore`, {
      method: 'POST',
    }),
    env,
    OTHER,
    created.id,
    versions[0].id
  );
  assert.equal(foreignRestore.status, 404, 'another owner cannot restore a version');
});

test('a deleted item has no history and a purged item loses it', async () => {
  const { env, sqlite } = await fixture();
  const created = await createCipher(env);
  await updateCipher(env, created.id, {
    type: 1,
    name: ENC('Title 2'),
    login: { username: ENC('user2'), password: ENC('pass2') },
  });
  assert.equal((await listVersions(env, created.id)).length, 1);

  const trashed = await handleDeleteCipher(
    new Request(`https://vault.example.test/api/ciphers/${created.id}`, { method: 'DELETE' }),
    env,
    OWNER,
    created.id
  );
  assert.equal(trashed.status, 200);
  const afterTrash = await handleGetCipherVersions(
    new Request(`https://vault.example.test/api/ciphers/${created.id}/versions`),
    env,
    OWNER,
    created.id
  );
  assert.equal(afterTrash.status, 404, 'a trashed item has no history');

  const purged = await handlePermanentDeleteCipher(
    new Request(`https://vault.example.test/api/ciphers/${created.id}/delete`, { method: 'DELETE' }),
    env,
    OWNER,
    created.id
  );
  assert.equal(purged.status, 204, 'a purged item is gone');
  const remaining = sqlite
    .prepare('SELECT COUNT(*) AS count FROM cipher_versions WHERE cipher_id = ?')
    .get(created.id) as { count: number };
  assert.equal(Number(remaining.count), 0, 'a purged item leaves no version rows');
});

test('history is capped at the newest states', async () => {
  const { env } = await fixture();
  const created = await createCipher(env);
  for (let index = 2; index <= 26; index += 1) {
    const response = await updateCipher(env, created.id, {
      type: 1,
      name: ENC(`Title ${index}`),
      login: { username: ENC(`user${index}`), password: ENC(`pass${index}`) },
    });
    assert.equal(response.status, 200);
  }
  const versions = await listVersions(env, created.id);
  assert.equal(versions.length, 20, 'only the newest states are kept');
  assert.equal(versions[0].name, ENC('Title 25'), 'newest state first');
  assert.equal(versions[versions.length - 1].name, ENC('Title 6'));
});

test('restoring brings back old content and keeps the current state', async () => {
  const { env } = await fixture();
  const created = await createCipher(env);
  await updateCipher(env, created.id, {
    type: 1,
    name: ENC('Title 2'),
    notes: ENC('Notes 2'),
    login: { username: ENC('user2'), password: ENC('pass2') },
  });
  const current = await handleUpdateCipher(
    new Request(`https://vault.example.test/api/ciphers/${created.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: 1,
        name: ENC('Title 3'),
        notes: ENC('Notes 3'),
        login: { username: ENC('user3'), password: ENC('pass3') },
      }),
    }),
    env,
    OWNER,
    created.id
  );
  assert.equal(current.status, 200);
  const currentBody = (await current.json()) as CreatedCipher;

  const versions = await listVersions(env, created.id);
  assert.equal(versions.length, 2);
  const oldest = versions[versions.length - 1];
  assert.equal(oldest.name, ENC('Title 1'));

  const restored = await handleRestoreCipherVersion(
    new Request(`https://vault.example.test/api/ciphers/${created.id}/versions/${oldest.id}/restore`, {
      method: 'POST',
      headers: { 'If-Match': currentBody.revisionDate },
    }),
    env,
    OWNER,
    created.id,
    oldest.id
  );
  assert.equal(restored.status, 200);
  const restoredBody = (await restored.json()) as CreatedCipher;
  assert.equal(restoredBody.id, created.id, 'the item keeps its id');
  assert.equal(restoredBody.name, ENC('Title 1'), 'the old name is back');
  assert.equal(restoredBody.login?.username, ENC('user1'), 'the old username is back');
  assert.notEqual(restoredBody.revisionDate, currentBody.revisionDate, 'the revision moved');

  const afterRestore = await listVersions(env, created.id);
  assert.equal(afterRestore.length, 3, 'the state the item left became a version');
  assert.equal(afterRestore[0].name, ENC('Title 3'), 'the replaced state is kept');
});

test('a restore with a stale revision is refused', async () => {
  const { env } = await fixture();
  const created = await createCipher(env);
  await updateCipher(env, created.id, {
    type: 1,
    name: ENC('Title 2'),
    login: { username: ENC('user2'), password: ENC('pass2') },
  });
  const versions = await listVersions(env, created.id);
  const oldest = versions[versions.length - 1];

  const refused = await handleRestoreCipherVersion(
    new Request(`https://vault.example.test/api/ciphers/${created.id}/versions/${oldest.id}/restore`, {
      method: 'POST',
      headers: { 'If-Match': '2020-01-01T00:00:00.000Z' },
    }),
    env,
    OWNER,
    created.id,
    oldest.id
  );
  assert.equal(refused.status, 409, 'a stale revision cannot restore');

  const versionsAfter = await listVersions(env, created.id);
  assert.equal(versionsAfter.length, 1, 'a refused restore changes nothing');
});
