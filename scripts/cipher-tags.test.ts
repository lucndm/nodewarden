// Handler-level tests for cipher tags (NodeWarden web-vault organization
// feature). Bitwarden has no tags; the field rides on the cipher payload and
// is preserved across official-client edits.
//
// Coverage:
//   - create stores a normalized tag list;
//   - a full update WITHOUT a tags field (what official Bitwarden clients
//     send) preserves existing tags;
//   - a full update WITH tags replaces them; tags: null clears them;
//   - normalizeCipherTags trims/dedupes/caps and rejects non-arrays.
import assert from 'node:assert/strict';
import test from 'node:test';

import { DatabaseSync } from 'node:sqlite';

import { installTestGlobals } from './test-env';
installTestGlobals();

import {
  handleCreateCipher,
  handleUpdateCipher,
  normalizeCipherTags,
} from '../src/handlers/ciphers';
import {
  handleCreateFolder,
  handleDeleteFolder,
  handleUpdateFolder,
} from '../src/handlers/folders';
import { StorageService } from '../src/services/storage';
import { handleSync } from '../src/handlers/sync';
import { handleGetRevisionDate } from '../src/handlers/accounts';
import { MemoryD1 } from './memory-d1';
import { sqliteD1 } from './sqlite-d1';
import { ensureStorageSchema } from '../src/services/storage-schema';
import type { Env } from '../src/types';

const ENC = (value: string) =>
  `2.${Buffer.from('iv-' + value).toString('base64')}|${Buffer.from('ct-' + value).toString('base64')}|${Buffer.from('mac-' + value).toString('base64')}`;

async function createCipherWithTags(envArg: Env, tags: unknown): Promise<Record<string, unknown>> {
  const response = await handleCreateCipher(
    new Request('https://vault.example.test/api/ciphers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 1, name: ENC('Example'), tags }),
    }),
    envArg,
    'user-1'
  );
  assert.equal(response.status, 200, 'create must succeed');
  return (await response.json()) as Record<string, unknown>;
}

test('normalizeCipherTags trims, dedupes case-insensitively, caps and rejects junk', () => {
  assert.equal(normalizeCipherTags('not-an-array'), null);
  assert.equal(normalizeCipherTags(null), null);
  assert.deepEqual(normalizeCipherTags([]), null, 'empty list collapses to null');
  assert.deepEqual(
    normalizeCipherTags(['  work ', 'Work', 'WORK', '', '  ', 'finance', 'x'.repeat(100)]),
    ['work', 'finance', 'x'.repeat(64)]
  );
  const many = Array.from({ length: 40 }, (_, i) => `tag${i}`);
  assert.equal(normalizeCipherTags(many)!.length, 24);
  // A client replaying a pre-repair payload must not be able to write the
  // folder's ciphertext back into the tag field.
  assert.deepEqual(
    normalizeCipherTags([ENC('Shared'), 'real', '2.abc|def|ghi']),
    ['real'],
    'ciphertext-shaped entries are never stored as tags'
  );
  assert.equal(normalizeCipherTags([ENC('only')]), null);
});

test('full update round-trip: absent tags preserved, present tags replaced, null clears', async () => {
  const db = new MemoryD1();
  const envArg = { DB: db } as unknown as Env;
  const created = await createCipherWithTags(envArg, ['work']);

  const preserved = await handleUpdateCipher(
    new Request(`https://vault.example.test/api/ciphers/${created.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 1, name: ENC('Renamed 1') }),
    }),
    envArg,
    'user-1',
    String(created.id)
  );
  assert.equal(preserved.status, 200);
  const preservedBody = (await preserved.json()) as { tags?: string[] };
  assert.deepEqual(preservedBody.tags, ['work'], 'absent tags field must not wipe tags');

  const replaced = await handleUpdateCipher(
    new Request(`https://vault.example.test/api/ciphers/${created.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 1, name: ENC('Renamed 2'), tags: ['travel', 'to-do'] }),
    }),
    envArg,
    'user-1',
    String(created.id)
  );
  assert.equal(replaced.status, 200);
  const replacedBody = (await replaced.json()) as { tags?: string[] };
  assert.deepEqual(replacedBody.tags, ['travel', 'to-do']);

  const cleared = await handleUpdateCipher(
    new Request(`https://vault.example.test/api/ciphers/${created.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 1, name: ENC('Renamed 3'), tags: null }),
    }),
    envArg,
    'user-1',
    String(created.id)
  );
  assert.equal(cleared.status, 200);
  const clearedBody = (await cleared.json()) as { tags?: string[] | null };
  assert.equal(clearedBody.tags, null, 'explicit null clears tags');
});

test('official-client folderId writes map to first-tag semantics', async () => {
  const db = new MemoryD1();
  const envArg = { DB: db } as unknown as Env;
  const storage = new StorageService(db);
  await storage.saveFolder({ id: 'folder-work', userId: 'user-1', name: 'Work', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() });

  // Mobile creates a cipher directly inside folder "Work" (no tags field).
  const created = await handleCreateCipher(
    new Request('https://vault.example.test/api/ciphers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 1, name: ENC('From mobile'), folderId: 'folder-work' }),
    }),
    envArg,
    'user-1'
  );
  assert.equal(created.status, 200);
  const createdBody = (await created.json()) as { id: string; tags?: string[] | null; folderId?: string | null };
  assert.deepEqual(createdBody.tags, ['Work']);
  assert.equal(createdBody.folderId, 'folder-work', 'registry id is mirrored into folder_id');

  // Mobile moves it to another folder: first tag follows.
  await storage.saveFolder({ id: 'folder-personal', userId: 'user-1', name: 'Personal', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() });
  const moved = await handleUpdateCipher(
    new Request(`https://vault.example.test/api/ciphers/${createdBody.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 1, name: ENC('From mobile'), folderId: 'folder-personal' }),
    }),
    envArg,
    'user-1',
    String(createdBody.id)
  );
  assert.equal(moved.status, 200);
  const movedBody = (await moved.json()) as { tags?: string[] | null; folderId?: string | null };
  assert.deepEqual(movedBody.tags, ['Personal']);
  assert.equal(movedBody.folderId, 'folder-personal');

  // Web vault sets explicit tags: they win and folder mirrors the first tag.
  const tagged = await handleUpdateCipher(
    new Request(`https://vault.example.test/api/ciphers/${createdBody.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 1, name: ENC('From mobile'), tags: ['finance', 'shared'] }),
    }),
    envArg,
    'user-1',
    String(createdBody.id)
  );
  assert.equal(tagged.status, 200);
  const taggedBody = (await tagged.json()) as { tags?: string[] | null; folderId?: string | null };
  assert.deepEqual(taggedBody.tags, ['finance', 'shared']);
  const financeFolder = await storage.getFolderForUser(String(taggedBody.folderId), 'user-1');
  assert.equal(financeFolder?.name, 'finance', 'tag registry row exists for the new first tag');
});

test('folder rename propagates to tags, folder delete strips them', async () => {
  const db = new MemoryD1();
  const envArg = { DB: db } as unknown as Env;
  const storage = new StorageService(db);
  const now = new Date().toISOString();
  await storage.saveFolder({ id: 'folder-a', userId: 'user-1', name: 'Old', createdAt: now, updatedAt: now });
  const created = await handleCreateCipher(
    new Request('https://vault.example.test/api/ciphers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 1, name: ENC('Item'), folderId: 'folder-a' }),
    }),
    envArg,
    'user-1'
  );
  const createdBody = (await created.json()) as { id: string };

  const renamed = await handleUpdateFolder(
    new Request('https://vault.example.test/api/folders/folder-a', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'New' }),
    }),
    envArg,
    'user-1',
    'folder-a'
  );
  assert.equal(renamed.status, 200);
  const afterRename = await storage.getCipherForUser(String(createdBody.id), 'user-1');
  assert.deepEqual(afterRename?.tags, ['New']);
  assert.equal(afterRename?.folderId, 'folder-a', 'folder id survives the rename');

  const deleted = await handleDeleteFolder(
    new Request('https://vault.example.test/api/folders/folder-a', { method: 'DELETE' }),
    envArg,
    'user-1',
    'folder-a'
  );
  assert.equal(deleted.status, 204);
  const afterDelete = await storage.getCipherForUser(String(createdBody.id), 'user-1');
  assert.deepEqual(afterDelete?.tags ?? null, null);
  assert.equal(afterDelete?.folderId ?? null, null);
});

test('renaming and deleting primary and secondary folders keeps tag positions consistent', async () => {
  const db = new MemoryD1();
  const envArg = { DB: db } as unknown as Env;
  const storage = new StorageService(db);
  const now = new Date().toISOString();
  for (const [id, name] of [['folder-a', 'Work'], ['folder-b', 'Shared']] as const) {
    await storage.saveFolder({ id, userId: 'user-1', name, createdAt: now, updatedAt: now });
  }
  const created = await createCipherWithTags(envArg, ['Work', 'Shared']);
  const id = String(created.id);
  const rename = async (folderId: string, name: string) => handleUpdateFolder(new Request(`https://vault.example.test/api/folders/${folderId}`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name }),
  }), envArg, 'user-1', folderId);
  const remove = async (folderId: string) => handleDeleteFolder(new Request(`https://vault.example.test/api/folders/${folderId}`, { method: 'DELETE' }), envArg, 'user-1', folderId);
  assert.equal((await rename('folder-b', 'Team')).status, 200);
  assert.deepEqual((await storage.getCipherForUser(id, 'user-1'))?.tags, ['Work', 'Team']);
  assert.equal((await storage.getCipherForUser(id, 'user-1'))?.folderId, 'folder-a');
  assert.equal((await remove('folder-a')).status, 204);
  assert.deepEqual((await storage.getCipherForUser(id, 'user-1'))?.tags, ['Team']);
  assert.equal((await storage.getCipherForUser(id, 'user-1'))?.folderId, 'folder-b');
  assert.equal((await rename('folder-b', 'Friends')).status, 200);
  assert.deepEqual((await storage.getCipherForUser(id, 'user-1'))?.tags, ['Friends']);
  assert.equal((await remove('folder-b')).status, 204);
  assert.equal((await storage.getCipherForUser(id, 'user-1'))?.folderId, null);
  assert.deepEqual((await storage.getCipherForUser(id, 'user-1'))?.tags ?? [], []);
});

test('migration backfills tags from legacy folder assignments', async () => {
  const db = new MemoryD1();
  const storage = new StorageService(db);
  const now = new Date().toISOString();
  await storage.saveFolder({ id: 'folder-legacy', userId: 'user-1', name: 'Legacy', createdAt: now, updatedAt: now });

  // Simulate a pre-tags row: folder_id set, no tags in data.
  await db
    .prepare('INSERT INTO ciphers(id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, archived_at, deleted_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .bind('legacy-1', 'user-1', 1, 'folder-legacy', 'Enc-name', null, 0, JSON.stringify({ type: 1, name: 'Enc-name' }), 0, null, now, now, null, null)
    .run();

  const changed = await storage.migrateFolderCiphersToTags('user-1');
  assert.equal(changed, true);
  const migrated = await storage.getCipherForUser('legacy-1', 'user-1');
  assert.deepEqual(migrated?.tags, ['Legacy']);
  assert.equal(migrated?.folderId, 'folder-legacy', 'legacy folder id is preserved');

  // Second run is a no-op.
  const changedAgain = await storage.migrateFolderCiphersToTags('user-1');
  assert.equal(changedAgain, false);
});

test('migration drops folder ciphertext that older builds wrote into item tags', async () => {
  const db = new MemoryD1();
  const storage = new StorageService(db);
  const now = new Date().toISOString();
  // A folder created by an official client: encrypted name, no plain tag.
  const folderName = ENC('Shared');
  await storage.saveFolder({ id: 'folder-enc', userId: 'user-1', name: folderName, tagName: null, createdAt: now, updatedAt: now });

  const insert = (cipherId: string, tags: unknown) =>
    db
      .prepare('INSERT INTO ciphers(id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, archived_at, deleted_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(cipherId, 'user-1', 1, 'folder-enc', ENC('Item'), null, 0, JSON.stringify({ type: 1, name: ENC('Item'), tags }), 0, null, now, now, null, null)
      .run();

  // Exactly the production shape: tags[0] is the folder's own ciphertext.
  await insert('dirty-1', [folderName]);
  // A real tag alongside the residue must survive.
  await insert('dirty-2', [folderName, 'Real tag']);

  const changed = await storage.migrateFolderCiphersToTags('user-1');
  assert.equal(changed, true);

  const cleaned = await storage.getCipherForUser('dirty-1', 'user-1');
  assert.deepEqual(cleaned?.tags ?? [], [], 'ciphertext must not stay in a tag field');
  assert.equal(cleaned?.folderId, 'folder-enc', 'the folder position lives in folder_id');

  const kept = await storage.getCipherForUser('dirty-2', 'user-1');
  assert.deepEqual(kept?.tags, ['Real tag']);

  const folder = await storage.getFolderForUser('folder-enc', 'user-1');
  assert.equal(folder?.tagName, null, 'the repair must not write a plaintext folder name');
  assert.equal(folder?.name, folderName, 'the encrypted name is untouched');

  // Idempotent: a second pass finds nothing left to clean.
  assert.equal(await storage.migrateFolderCiphersToTags('user-1'), false);
});

test('sync bumps the account revision after the tag repair rewrites ciphers', async () => {
  // The sync handler touches the passkey schema (PRAGMA), so this one runs on
  // the real SQL statements rather than the MemoryD1 shim.
  const sqlite = new DatabaseSync(':memory:');
  try {
    const db = sqliteD1(sqlite);
    await ensureStorageSchema(db);
    const envArg = {
      DB: db,
      NOTIFICATIONS_HUB: { idFromName: (name: string) => name, get: () => ({ fetch: async () => new Response(null, { status: 204 }) }) },
    } as unknown as Env;
    const storage = new StorageService(db);
    const now = new Date().toISOString();
    await storage.saveUser({
      id: 'user-1', email: 'user-1@example.test', name: null, masterPasswordHint: null,
      masterPasswordHash: 'hash', key: '2.key', privateKey: null, publicKey: null,
      kdfType: 0, kdfIterations: 600000, securityStamp: 'stamp', role: 'user', status: 'active',
      totpSecret: null, totpRecoveryCode: null, yubikeyKey1: null, yubikeyKey2: null, yubikeyKey3: null,
      yubikeyKey4: null, yubikeyKey5: null, yubikeyNfc: false, apiKey: null,
      createdAt: now, updatedAt: now,
    } as never);

    const folderName = ENC('Shared');
    await storage.saveFolder({ id: 'folder-enc', userId: 'user-1', name: folderName, tagName: null, createdAt: now, updatedAt: now });
    await db
      .prepare('INSERT INTO ciphers(id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, archived_at, deleted_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .bind('dirty', 'user-1', 1, 'folder-enc', ENC('Item'), null, 0, JSON.stringify({ type: 1, name: ENC('Item'), tags: [folderName] }), 0, null, now, now, null, null)
      .run();

    const revisionBefore = await storage.getRevisionDate('user-1');
    assert.equal((await handleSync(new Request('https://vault.example.test/api/sync'), envArg, 'user-1')).status, 200);
    const revisionAfter = await storage.getRevisionDate('user-1');
    assert.notEqual(revisionAfter, revisionBefore, 'clients cache by revision, so a rewrite must move it');
    assert.deepEqual((await storage.getCipherForUser('dirty', 'user-1'))?.tags ?? [], []);

    // A later sync has nothing left to repair and must not keep bumping it.
    await handleSync(new Request('https://vault.example.test/api/sync'), envArg, 'user-1');
    assert.equal(await storage.getRevisionDate('user-1'), revisionAfter);
  } finally {
    sqlite.close();
  }
});

test('the revision endpoint runs the tag repair once and moves the revision', async () => {
  // Clients poll /api/accounts/revision-date and skip /sync while the revision
  // holds still, so the repair must be reachable from this endpoint.
  const sqlite = new DatabaseSync(':memory:');
  try {
    const db = sqliteD1(sqlite);
    await ensureStorageSchema(db);
    const envArg = { DB: db } as unknown as Env;
    const storage = new StorageService(db);
    const now = new Date().toISOString();
    await storage.saveUser({
      id: 'user-1', email: 'user-1@example.test', name: null, masterPasswordHint: null,
      masterPasswordHash: 'hash', key: '2.key', privateKey: null, publicKey: null,
      kdfType: 0, kdfIterations: 600000, securityStamp: 'stamp', role: 'user', status: 'active',
      totpSecret: null, totpRecoveryCode: null, yubikeyKey1: null, yubikeyKey2: null, yubikeyKey3: null,
      yubikeyKey4: null, yubikeyKey5: null, yubikeyNfc: false, apiKey: null,
      createdAt: now, updatedAt: now,
    } as never);

    const folderName = ENC('Shared');
    await storage.saveFolder({ id: 'folder-enc', userId: 'user-1', name: folderName, tagName: null, createdAt: now, updatedAt: now });
    await db
      .prepare('INSERT INTO ciphers(id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, archived_at, deleted_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .bind('dirty', 'user-1', 1, 'folder-enc', ENC('Item'), null, 0, JSON.stringify({ type: 1, name: ENC('Item'), tags: [folderName] }), 0, null, now, now, null, null)
      .run();

    const revisionBefore = await storage.getRevisionDate('user-1');
    const first = await handleGetRevisionDate(new Request('https://vault.example.test/api/accounts/revision-date'), envArg, 'user-1');
    assert.equal(first.status, 200);
    const stampAfter = new Date(await storage.getRevisionDate('user-1')).getTime();
    assert.notEqual(stampAfter, new Date(revisionBefore).getTime(), 'the repair must surface as a new revision');
    assert.equal(await first.json(), stampAfter, 'and the response has to carry that new revision');
    assert.deepEqual((await storage.getCipherForUser('dirty', 'user-1'))?.tags ?? [], []);

    // The account is marked done: polling again neither rescans nor bumps.
    const second = await handleGetRevisionDate(new Request('https://vault.example.test/api/accounts/revision-date'), envArg, 'user-1');
    assert.equal(await second.json(), stampAfter);
  } finally {
    sqlite.close();
  }
});

test('the tag repair moves the revision even when the clock stands still', async (ctx) => {
  // A repair that runs in the same millisecond as the revision before it
  // would leave the revision standing, and a client that caches by revision
  // would keep the payload it already has. The clock is frozen here so that
  // case is the only case.
  installTestGlobals();
  ctx.mock.timers.enable({ apis: ['Date'] });
  ctx.mock.timers.setTime(Date.parse('2026-11-08T00:00:00.000Z'));
  const sqlite = new DatabaseSync(':memory:');
  try {
    const db = sqliteD1(sqlite);
    await ensureStorageSchema(db);
    const envArg = {
      DB: db,
      NOTIFICATIONS_HUB: { idFromName: (name: string) => name, get: () => ({ fetch: async () => new Response(null, { status: 204 }) }) },
    } as unknown as Env;
    const storage = new StorageService(db);
    const now = new Date().toISOString();
    await storage.saveUser({
      id: 'user-1', email: 'user-1@example.test', name: null, masterPasswordHint: null,
      masterPasswordHash: 'hash', key: '2.key', privateKey: null, publicKey: null,
      kdfType: 0, kdfIterations: 600000, securityStamp: 'stamp', role: 'user', status: 'active',
      totpSecret: null, totpRecoveryCode: null, yubikeyKey1: null, yubikeyKey2: null,
      yubikeyKey3: null, yubikeyKey4: null, yubikeyKey5: null, yubikeyNfc: false, apiKey: null,
      createdAt: now, updatedAt: now,
    } as never);

    const folderName = ENC('Shared');
    await storage.saveFolder({ id: 'folder-enc', userId: 'user-1', name: folderName, tagName: null, createdAt: now, updatedAt: now });
    await db
      .prepare('INSERT INTO ciphers(id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, archived_at, deleted_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .bind('dirty', 'user-1', 1, 'folder-enc', ENC('Item'), null, 0, JSON.stringify({ type: 1, name: ENC('Item'), tags: [folderName] }), 0, null, now, now, null, null)
      .run();

    const before = await storage.getRevisionDate('user-1');
    assert.equal((await handleSync(new Request('https://vault.example.test/api/sync'), envArg, 'user-1')).status, 200);
    const after = await storage.getRevisionDate('user-1');
    assert.notEqual(after, before, 'the repair must move the revision even with a frozen clock');
    assert.deepEqual((await storage.getCipherForUser('dirty', 'user-1'))?.tags ?? [], []);
  } finally {
    sqlite.close();
  }
});

test('the revision moves even when the change lands in the same millisecond', async () => {
  // Clients cache the payload by revision, so a change that leaves the
  // revision standing is a change they never see. The clock has millisecond
  // resolution, so two changes can easily share one millisecond.
  const db = new MemoryD1();
  const storage = new StorageService(db);
  const now = new Date().toISOString();
  await storage.saveUser({
    id: 'user-1', email: 'user-1@example.test', name: null, masterPasswordHint: null,
    masterPasswordHash: 'hash', key: '2.key', privateKey: null, publicKey: null,
    kdfType: 0, kdfIterations: 600000, securityStamp: 'stamp', role: 'user', status: 'active',
    totpSecret: null, totpRecoveryCode: null, yubikeyKey1: null, yubikeyKey2: null,
    yubikeyKey3: null, yubikeyKey4: null, yubikeyKey5: null, yubikeyNfc: false, apiKey: null,
    createdAt: now, updatedAt: now,
  } as never);

  const before = await storage.getRevisionDate('user-1');
  const moved = await storage.moveRevisionDate('user-1');
  assert.ok(
    new Date(moved).getTime() > new Date(before).getTime(),
    'the revision has to move, whatever the clock says'
  );
  assert.equal(await storage.getRevisionDate('user-1'), moved);
});

test('folder create endpoint registers tags for empty folders', async () => {
  const db = new MemoryD1();
  const envArg = { DB: db } as unknown as Env;
  const created = await handleCreateFolder(
    new Request('https://vault.example.test/api/folders', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Empty tag' }),
    }),
    envArg,
    'user-1'
  );
  assert.equal(created.status, 200);
  const body = (await created.json()) as { id: string; name: string };
  assert.equal(body.name, 'Empty tag');
  const storage = new StorageService(db);
  const folder = await storage.getFolderForUser(body.id, 'user-1');
  assert.equal(folder?.name, 'Empty tag');
});
