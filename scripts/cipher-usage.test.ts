// Backend password-copy usage counters (NodeWarden web vault "Most used"
// sorting).
//
// The counters live in their own cipher columns, so a copy never touches the
// cipher payload, its revision date, its updated_at or the sync notifications.
//
// Coverage:
//   - POST /api/ciphers/:id/usage counts one copy and returns the counter;
//   - GET /api/ciphers/usage returns the counters of the owner only;
//   - foreign, missing, non-login, archived and deleted ciphers are refused;
//   - recording a copy leaves the revision date and updated_at untouched;
//   - counters survive edits, archive and restore and vanish on a permanent
//     delete;
//   - a backup export/import round-trip keeps the counters.
import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import { zipSync } from 'fflate';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { StorageService } from '../src/services/storage';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { buildBackupArchive, parseBackupArchive, validateBackupPayloadContents } from '../src/services/backup-archive';
import { importBackupArchiveBytes } from '../src/services/backup-import';
import { sqliteD1 } from './sqlite-d1';
import { CipherType } from '../src/types';
import type { Cipher, CipherUsage, Env, User } from '../src/types';

const OWNER = '00000000-0000-4000-8000-0000000000a1';
const OTHER = '00000000-0000-4000-8000-0000000000b2';
const LOGIN_ID = '00000000-0000-4000-8000-0000000000c1';
const NOTE_ID = '00000000-0000-4000-8000-0000000000c2';
const ARCHIVED_ID = '00000000-0000-4000-8000-0000000000c3';
const DELETED_ID = '00000000-0000-4000-8000-0000000000c4';
const OTHER_LOGIN_ID = '00000000-0000-4000-8000-0000000000c5';
const MISSING_ID = '00000000-0000-4000-8000-0000000000c6';
const SEED_REVISION = '2026-01-01T00:00:00.000Z';

const ENC = (value: string) =>
  `2.${Buffer.from('iv-' + value).toString('base64')}|${Buffer.from('ct-' + value).toString('base64')}|${Buffer.from('mac-' + value).toString('base64')}`;

function makeUser(id: string, email: string): User {
  return {
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
    createdAt: SEED_REVISION,
    updatedAt: SEED_REVISION,
  };
}

function makeCipher(id: string, userId: string, type: CipherType, extra: Partial<Cipher> = {}): Cipher {
  const cipher: Cipher = {
    id,
    userId,
    type,
    folderId: null,
    name: ENC('Example'),
    notes: null,
    favorite: false,
    login: type === CipherType.Login
      ? {
          username: ENC('user'),
          password: ENC('pass'),
          uris: null,
          totp: null,
          autofillOnPageLoad: null,
          fido2Credentials: null,
          uri: null,
          passwordRevisionDate: null,
        }
      : null,
    card: null,
    identity: null,
    secureNote: type === CipherType.Login ? null : { type: 0 },
    sshKey: null,
    fields: null,
    passwordHistory: null,
    reprompt: 0,
    key: null,
    createdAt: SEED_REVISION,
    updatedAt: SEED_REVISION,
    archivedAt: null,
    deletedAt: null,
  };
  Object.assign(cipher, extra);
  return cipher;
}

async function fixture() {
  const sqlite = new DatabaseSync(':memory:');
  const db = sqliteD1(sqlite);
  await ensureStorageSchema(db);
  const env = {
    DB: db,
    NOTIFICATIONS_HUB: {
      idFromName: (name: string) => name,
      get: () => ({
        fetch: async () => new Response(null, { status: 204 }),
      }),
    },
  } as unknown as Env;
  const storage = new StorageService(db);
  await storage.saveUser(makeUser(OWNER, 'owner@example.com'));
  await storage.saveUser(makeUser(OTHER, 'other@example.com'));
  await storage.saveCipher(makeCipher(LOGIN_ID, OWNER, CipherType.Login));
  await storage.saveCipher(makeCipher(NOTE_ID, OWNER, CipherType.SecureNote));
  await storage.saveCipher(makeCipher(ARCHIVED_ID, OWNER, CipherType.Login, { archivedAt: SEED_REVISION }));
  await storage.saveCipher(makeCipher(DELETED_ID, OWNER, CipherType.Login, { deletedAt: SEED_REVISION }));
  await storage.saveCipher(makeCipher(OTHER_LOGIN_ID, OTHER, CipherType.Login));
  await db
    .prepare('INSERT INTO user_revisions(user_id, revision_date) VALUES(?, ?)')
    .bind(OWNER, SEED_REVISION)
    .run();

  const currentUser = await storage.getUserById(OWNER);
  assert.ok(currentUser, 'the seeded owner must exist');

  const route = async (path: string, method: string, body?: unknown): Promise<Response> => {
    const request = new Request(`https://vault.example.test${path}`, {
      method,
      headers: { 'Content-Type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const response = await handleAuthenticatedRoute(request, env, OWNER, currentUser, path, method);
    assert.ok(response, `${method} ${path} must be handled`);
    return response;
  };

  const copy = async (id: string): Promise<Response> => route(`/api/ciphers/${id}/usage`, 'POST');
  const usage = async (): Promise<Record<string, CipherUsage>> => {
    const response = await route('/api/ciphers/usage', 'GET');
    assert.equal(response.status, 200);
    return (await response.json()) as Record<string, CipherUsage>;
  };
  const cipherRow = (id: string) => {
    const row = sqlite.prepare('SELECT usage_count, last_used_at, updated_at FROM ciphers WHERE id = ?').get(id);
    return {
      usageCount: Number(row?.usage_count ?? 0),
      lastUsedAt: row?.last_used_at == null ? null : String(row.last_used_at),
      updatedAt: String(row?.updated_at ?? ''),
    };
  };
  const revision = (): string =>
    String(sqlite.prepare('SELECT revision_date FROM user_revisions WHERE user_id = ?').get(OWNER)?.revision_date ?? '');

  return { db, env, storage, route, copy, usage, cipherRow, revision, sqlite };
}

test('a password copy counts once and the counter is returned', async () => {
  const f = await fixture();

  const first = await f.copy(LOGIN_ID);
  assert.equal(first.status, 200);
  const firstBody = (await first.json()) as CipherUsage;
  assert.equal(firstBody.useCount, 1);
  assert.equal(typeof firstBody.lastUsedAt, 'string');

  const second = await f.copy(LOGIN_ID);
  assert.equal(second.status, 200);
  const secondBody = (await second.json()) as CipherUsage;
  assert.equal(secondBody.useCount, 2);

  const map = await f.usage();
  assert.equal(map[LOGIN_ID].useCount, 2);
  assert.equal(map[LOGIN_ID].lastUsedAt, secondBody.lastUsedAt, 'the newest copy wins');
  assert.equal(Object.keys(map).length, 1, 'only counted ciphers are listed');
});

test('the usage map only contains the ciphers of the current owner', async () => {
  const f = await fixture();
  await f.copy(LOGIN_ID);

  const map = await f.usage();
  assert.deepEqual(Object.keys(map), [LOGIN_ID]);
  assert.equal(map[OTHER_LOGIN_ID], undefined, 'another owner never appears');
  assert.equal(map[NOTE_ID], undefined, 'ciphers without a copy are omitted');
});

test('foreign, missing and ineligible ciphers are refused', async () => {
  const f = await fixture();

  for (const id of [OTHER_LOGIN_ID, MISSING_ID, NOTE_ID, ARCHIVED_ID, DELETED_ID]) {
    const response = await f.copy(id);
    assert.equal(response.status, 404, `${id} must not be counted`);
  }

  assert.deepEqual(await f.usage(), {}, 'no counter was written');
  assert.equal(f.cipherRow(LOGIN_ID).usageCount, 0);
});

test('recording a copy leaves the revision date and updated_at untouched', async () => {
  const f = await fixture();
  const before = f.cipherRow(LOGIN_ID);
  assert.equal(f.revision(), SEED_REVISION);

  const response = await f.copy(LOGIN_ID);
  assert.equal(response.status, 200);

  const after = f.cipherRow(LOGIN_ID);
  assert.equal(after.usageCount, 1);
  assert.equal(after.updatedAt, before.updatedAt, 'the cipher is not modified');
  assert.equal(f.revision(), SEED_REVISION, 'the vault revision date is not bumped');
});

test('counters survive edits, archive and restore and vanish on a permanent delete', async () => {
  const f = await fixture();
  await f.copy(LOGIN_ID);

  const edited = await f.route(`/api/ciphers/${LOGIN_ID}`, 'PUT', { type: 1, name: ENC('Renamed') });
  assert.equal(edited.status, 200);
  assert.equal((await f.usage())[LOGIN_ID].useCount, 1, 'an edit keeps the counter');

  const archived = await f.route(`/api/ciphers/${LOGIN_ID}/archive`, 'PUT');
  assert.equal(archived.status, 200);
  assert.equal((await f.usage())[LOGIN_ID].useCount, 1, 'archiving keeps the counter');
  assert.equal((await f.copy(LOGIN_ID)).status, 404, 'an archived cipher cannot be counted');

  const unarchived = await f.route(`/api/ciphers/${LOGIN_ID}/unarchive`, 'PUT');
  assert.equal(unarchived.status, 200);
  assert.equal((await f.usage())[LOGIN_ID].useCount, 1, 'unarchiving keeps the counter');

  const trashed = await f.route(`/api/ciphers/${LOGIN_ID}/delete`, 'PUT');
  assert.equal(trashed.status, 200);
  assert.equal((await f.usage())[LOGIN_ID].useCount, 1, 'a soft delete keeps the counter');

  const restored = await f.route(`/api/ciphers/${LOGIN_ID}/restore`, 'PUT');
  assert.equal(restored.status, 200);
  assert.equal((await f.usage())[LOGIN_ID].useCount, 1, 'restoring keeps the counter');

  const purged = await f.route(`/api/ciphers/${LOGIN_ID}/delete`, 'POST');
  assert.equal(purged.status, 204);
  assert.equal((await f.usage())[LOGIN_ID], undefined, 'a permanent delete drops the counter');
});

test('a backup export and import round-trip keeps the counters', async () => {
  const f = await fixture();
  await f.copy(LOGIN_ID);
  await f.copy(LOGIN_ID);
  const lastUsedAt = f.cipherRow(LOGIN_ID).lastUsedAt;

  const archive = await buildBackupArchive(f.env, new Date(), { includeAttachments: false });
  const exported = parseBackupArchive(archive.bytes).payload.db.ciphers.find((row) => row.id === LOGIN_ID);
  assert.ok(exported, 'the cipher must be exported');
  assert.equal(Number(exported.usage_count), 2, 'the counter is part of the archive');
  assert.equal(exported.last_used_at, lastUsedAt);

  const result = await importBackupArchiveBytes(archive.bytes, f.env, OWNER, true);
  assert.equal(result.result.imported.ciphers, 5);

  const restored = f.cipherRow(LOGIN_ID);
  assert.equal(restored.usageCount, 2, 'the counter survives a restore');
  assert.equal(restored.lastUsedAt, lastUsedAt);
});

test('a legacy archive without counters restores as never used', async () => {
  const f = await fixture();
  await f.copy(LOGIN_ID);

  const archive = await buildBackupArchive(f.env, new Date(), { includeAttachments: false });
  const payload = parseBackupArchive(archive.bytes).payload;
  const legacy = zipSync({
    'manifest.json': new TextEncoder().encode(JSON.stringify(payload.manifest)),
    'db.json': new TextEncoder().encode(JSON.stringify({
      ...payload.db,
      ciphers: payload.db.ciphers.map((row) => {
        const withoutCounters = { ...row };
        delete withoutCounters.usage_count;
        delete withoutCounters.last_used_at;
        return withoutCounters;
      }),
    })),
  });

  await importBackupArchiveBytes(legacy, f.env, OWNER, true);

  const restored = f.cipherRow(LOGIN_ID);
  assert.equal(restored.usageCount, 0, 'a legacy archive restores as never used');
  assert.equal(restored.lastUsedAt, null);
});

test('an archive with a malformed usage counter or timestamp is rejected', async () => {
  const f = await fixture();
  await f.copy(LOGIN_ID);

  const archive = await buildBackupArchive(f.env, new Date(), { includeAttachments: false });
  const parsed = parseBackupArchive(archive.bytes);
  const withCipherRows = (rows: Record<string, unknown>[]) => ({
    ...parsed.payload,
    db: { ...parsed.payload.db, ciphers: rows },
  });

  for (const broken of [1.5, true, -1, '3']) {
    assert.throws(
      () => validateBackupPayloadContents(
        withCipherRows(parsed.payload.db.ciphers.map((row) => ({ ...row, usage_count: broken }))),
        parsed.files
      ),
      /invalid cipher usage count/,
      `usage_count ${String(broken)} must be rejected`
    );
  }

  assert.throws(
    () => validateBackupPayloadContents(
      withCipherRows(parsed.payload.db.ciphers.map((row) => ({ ...row, last_used_at: 'not-a-date' }))),
      parsed.files
    ),
    /invalid cipher usage timestamp/
  );
});
