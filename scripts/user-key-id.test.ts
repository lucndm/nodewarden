// The official Bitwarden CLI (2026.9 and newer) posts the id of the current
// user key once after the login and aborts the login when the endpoint is
// missing:
//   KeyIdBackfillError: API call failed during user key id backfill
// The id is client-reported metadata that cannot decrypt anything, so the
// server only records it, write-once, and hands it back in /api/sync.
import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync, type SQLInputValue } from 'node:sqlite';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { handleSync } from '../src/handlers/sync';
import { StorageService } from '../src/services/storage';
import { ensureStorageSchema } from '../src/services/storage-schema';
import type { Env } from '../src/types';

const USER_ID = '00000000-0000-4000-8000-000000000042';
const KEY_ID = 'a'.repeat(32);
const OTHER_KEY_ID = 'b'.repeat(32);
const PATH = '/api/accounts/key-management/user-key-id';

/** Runs the production schema on an in-memory SQLite database. */
function sqliteD1(sqlite: DatabaseSync): D1Database {
  const db = {
    prepare(sql: string) {
      let values: SQLInputValue[] = [];
      const statement = {
        bind(...bound: SQLInputValue[]) {
          values = bound;
          return statement;
        },
        async run() {
          const result = sqlite.prepare(sql).run(...values);
          return { success: true, meta: { changes: Number(result.changes) } };
        },
        async all() {
          return { success: true, results: sqlite.prepare(sql).all(...values) };
        },
        async first() {
          return sqlite.prepare(sql).get(...values) ?? null;
        },
      };
      return statement;
    },
  };
  // The D1 binding type is much wider than the subset used here.
  return db as unknown as D1Database;
}

async function fixture() {
  const sqlite = new DatabaseSync(':memory:');
  const db = sqliteD1(sqlite);
  await ensureStorageSchema(db);
  const env = { DB: db, JWT_SECRET: 'test-secret-0123456789' } as unknown as Env;
  const storage = new StorageService(db);
  await storage.saveUser({
    id: USER_ID,
    email: 'tester@example.com',
    name: 'Tester',
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
    totpSecret: null,
    totpRecoveryCode: null,
    yubikeyKey1: null,
    yubikeyKey2: null,
    yubikeyKey3: null,
    yubikeyKey4: null,
    yubikeyKey5: null,
    yubikeyNfc: false,
    apiKey: null,
    createdAt: '2026-01-01T00:00:00Z',
    updatedAt: '2026-01-01T00:00:00Z',
  });

  const post = async (body: unknown): Promise<Response> => {
    const request = new Request(`https://vault.example.test${PATH}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const user = await storage.getUserById(USER_ID);
    assert.ok(user, 'the seeded user must exist');
    const response = await handleAuthenticatedRoute(request, env, USER_ID, user, PATH, 'POST');
    assert.ok(response, 'the route must be handled');
    return response;
  };
  const sync = async (): Promise<{ UserDecryption?: { UserKeyId?: string | null } }> => {
    const request = new Request('https://vault.example.test/api/sync', { method: 'GET' });
    const response = await handleSync(request, env, USER_ID);
    return (await response.json()) as { UserDecryption?: { UserKeyId?: string | null } };
  };

  return {
    db,
    env,
    storage,
    post,
    sync,
    revisions: () => Number(sqlite.prepare('SELECT COUNT(*) AS count FROM user_revisions').get()?.count ?? 0),
  };
}

test('the user key id is recorded once and returned in the sync response', async () => {
  const f = await fixture();
  const response = await f.post({ userKeyId: KEY_ID });
  assert.equal(response.status, 200);
  assert.equal((await f.storage.getUserById(USER_ID))?.userKeyId, KEY_ID);
  assert.equal(f.revisions(), 1, 'the revision must be bumped so the sync carries the id');
  const body = await f.sync();
  assert.equal(body.UserDecryption?.UserKeyId, KEY_ID);
});

test('the PascalCase alias of the official client is accepted', async () => {
  const f = await fixture();
  const response = await f.post({ UserKeyId: KEY_ID });
  assert.equal(response.status, 200);
  assert.equal((await f.storage.getUserById(USER_ID))?.userKeyId, KEY_ID);
});

test('posting the same id again is accepted and changes nothing', async () => {
  const f = await fixture();
  assert.equal((await f.post({ userKeyId: KEY_ID })).status, 200);
  assert.equal(f.revisions(), 1);
  assert.equal((await f.post({ userKeyId: KEY_ID })).status, 200);
  assert.equal(f.revisions(), 1, 'a repeated id must not bump the revision');
  assert.equal((await f.storage.getUserById(USER_ID))?.userKeyId, KEY_ID);
});

test('a different id is refused once the id is recorded', async () => {
  const f = await fixture();
  assert.equal((await f.post({ userKeyId: KEY_ID })).status, 200);
  const response = await f.post({ userKeyId: OTHER_KEY_ID });
  assert.equal(response.status, 400);
  assert.match(await response.text(), /already set/i);
  assert.equal((await f.storage.getUserById(USER_ID))?.userKeyId, KEY_ID);
});

test('an id that is not 32 lowercase hex characters is refused', async () => {
  const f = await fixture();
  for (const invalid of ['not-hex', 'A'.repeat(32), 'a'.repeat(31), 'a'.repeat(33), 42, null]) {
    const response = await f.post({ userKeyId: invalid });
    assert.equal(response.status, 400, `userKeyId ${JSON.stringify(invalid)} must be refused`);
  }
  assert.equal((await f.storage.getUserById(USER_ID))?.userKeyId, null);
  assert.equal(f.revisions(), 0);
});

test('a request without a body is refused', async () => {
  const f = await fixture();
  const request = new Request(`https://vault.example.test${PATH}`, { method: 'POST' });
  const user = await f.storage.getUserById(USER_ID);
  assert.ok(user, 'the seeded user must exist');
  const response = await handleAuthenticatedRoute(request, f.env, USER_ID, user, PATH, 'POST');
  assert.ok(response, 'the route must be handled');
  assert.equal(response.status, 400);
});
