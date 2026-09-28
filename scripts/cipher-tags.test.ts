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
import { MemoryD1 } from './memory-d1';
import type { Env } from '../src/types';

const ENC = (value: string) =>
  `2.${Buffer.from('iv-' + value).toString('base64')}|${Buffer.from('ct-' + value).toString('base64')}|${Buffer.from('mac-' + value).toString('base64')}`;

function env(): Env {
  return { DB: new MemoryD1() } as unknown as Env;
}

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

test('migration backfills tags from legacy folder assignments', async () => {
  const db = new MemoryD1();
  const envArg = { DB: db } as unknown as Env;
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
