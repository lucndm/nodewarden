// The admin backup archive is the only way a vault leaves the server, so the
// folder/tag layout must survive a full export and import round-trip.
//
// NodeWarden stores a tag twice: folders.tag_name holds the plain tag and
// ciphers.data.tags holds the item's tag list, while ciphers.folder_id points
// at the folder row that owns the first tag. A restore that loses any of the
// three moves items into a different folder or drops their tags, and official
// Bitwarden clients only see folders - never tags - so a lost tag_name is
// invisible until an item lands in the wrong place.
//
// Coverage:
//   - the exported archive carries folders.tag_name and the item placement;
//   - importing that archive into a fresh instance restores the same folders,
//     tags and item placement;
//   - a folder without a tag (an official client folder) keeps no tag;
//   - an archive from before the tag_name column restores without a tag.
import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import { zipSync } from 'fflate';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { buildBackupArchive, parseBackupArchive } from '../src/services/backup-archive';
import { importBackupArchiveBytes } from '../src/services/backup-import';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { StorageService } from '../src/services/storage';
import { sqliteD1 } from './sqlite-d1';
import type { Cipher, Env, Folder, User } from '../src/types';

const OWNER = '00000000-0000-4000-8000-0000000000a1';
const WORK_FOLDER = '00000000-0000-4000-8000-0000000000f1';
const EXTRA_FOLDER = '00000000-0000-4000-8000-0000000000f2';
const UNTAGGED_FOLDER = '00000000-0000-4000-8000-0000000000f3';
const LOGIN_ID = '00000000-0000-4000-8000-0000000000c1';
const REVISION = '2026-01-01T00:00:00.000Z';

// An encrypted folder name: the official client only ever sees ciphertext.
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
    role: 'admin',
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
    createdAt: REVISION,
    updatedAt: REVISION,
  };
}

function makeFolder(id: string, name: string, tagName: string | null): Folder {
  return { id, userId: OWNER, name, tagName, createdAt: REVISION, updatedAt: REVISION };
}

/** A login item placed in `folderId` and carrying `tags`. */
function makeLogin(folderId: string | null, tags: string[]): Cipher {
  return {
    id: LOGIN_ID,
    userId: OWNER,
    type: 1,
    folderId,
    name: ENC('Example'),
    notes: null,
    favorite: false,
    login: {
      username: ENC('user'),
      password: ENC('pass'),
      uris: null,
      totp: null,
      autofillOnPageLoad: null,
      fido2Credentials: null,
      uri: null,
      passwordRevisionDate: null,
    },
    card: null,
    identity: null,
    secureNote: null,
    sshKey: null,
    fields: null,
    passwordHistory: null,
    reprompt: 0,
    key: null,
    tags,
    createdAt: REVISION,
    updatedAt: REVISION,
    archivedAt: null,
    deletedAt: null,
  };
}

async function makeEnv(): Promise<{ env: Env; storage: StorageService; sqlite: DatabaseSync }> {
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
  return { env, storage: new StorageService(db), sqlite };
}

/**
 * A source vault with three folders: two carry a tag, one is an official
 * client folder without a tag. One item sits in the tagged folder with a
 * second tag in its tag list.
 */
async function sourceVault() {
  const { env, storage, sqlite } = await makeEnv();
  await storage.saveUser(makeUser(OWNER, 'owner@example.com'));
  await storage.saveFolder(makeFolder(WORK_FOLDER, ENC('Work'), 'Work'));
  await storage.saveFolder(makeFolder(EXTRA_FOLDER, ENC('Extra'), 'Extra'));
  await storage.saveFolder(makeFolder(UNTAGGED_FOLDER, ENC('Client folder'), null));
  await storage.saveCipher(makeLogin(WORK_FOLDER, ['Work', 'Extra']));
  return { env, storage, sqlite };
}

/** A fresh instance an archive can be restored into. */
async function targetInstance() {
  const { env, storage, sqlite } = await makeEnv();
  await storage.saveUser(makeUser(OWNER, 'owner@example.com'));
  return { env, storage, sqlite };
}

function folderRows(sqlite: DatabaseSync) {
  return sqlite
    .prepare('SELECT id, user_id, name, tag_name FROM folders ORDER BY id')
    .all()
    .map((row) => row as { id: string; user_id: string; name: string; tag_name: string | null });
}

function cipherRow(sqlite: DatabaseSync, id: string) {
  const row = sqlite.prepare('SELECT folder_id, data FROM ciphers WHERE id = ?').get(id) as
    | { folder_id: string | null; data: string }
    | undefined;
  assert.ok(row, `cipher ${id} must exist`);
  const data = JSON.parse(row.data) as { tags?: string[] };
  return { folderId: row.folder_id, tags: data.tags ?? [] };
}

test('the exported archive carries the folder tags and the item placement', async () => {
  const { env } = await sourceVault();

  const archive = await buildBackupArchive(env, new Date(), { includeAttachments: false });
  const payload = parseBackupArchive(archive.bytes).payload;

  const folders = payload.db.folders;
  assert.equal(folders.length, 3, 'every folder is part of the archive');
  const byId = new Map(folders.map((row) => [String(row.id), row]));
  assert.equal(byId.get(WORK_FOLDER)?.tag_name, 'Work', 'the folder tag is exported');
  assert.equal(byId.get(EXTRA_FOLDER)?.tag_name, 'Extra', 'the second folder tag is exported');
  assert.equal(byId.get(UNTAGGED_FOLDER)?.tag_name, null, 'an untagged folder exports without a tag');

  const cipher = payload.db.ciphers.find((row) => row.id === LOGIN_ID);
  assert.ok(cipher, 'the item is part of the archive');
  assert.equal(cipher.folder_id, WORK_FOLDER, 'the item keeps its folder');
  const data = JSON.parse(String(cipher.data)) as { tags?: string[] };
  assert.deepEqual(data.tags, ['Work', 'Extra'], 'the item keeps its tag list');
});

test('an import into a fresh instance restores the folders, tags and item placement', async () => {
  const { env } = await sourceVault();
  const archive = await buildBackupArchive(env, new Date(), { includeAttachments: false });

  const target = await targetInstance();
  const result = await importBackupArchiveBytes(archive.bytes, target.env, OWNER, false);

  assert.equal(result.result.imported.folders, 3, 'every folder is restored');
  assert.equal(result.result.imported.ciphers, 1, 'the item is restored');

  assert.deepEqual(
    folderRows(target.sqlite).map((row) => [row.id, row.tag_name]),
    [
      [WORK_FOLDER, 'Work'],
      [EXTRA_FOLDER, 'Extra'],
      [UNTAGGED_FOLDER, null],
    ],
    'the restored folders keep their ids and their tags'
  );

  const cipher = cipherRow(target.sqlite, LOGIN_ID);
  assert.equal(cipher.folderId, WORK_FOLDER, 'the restored item stays in its folder');
  assert.deepEqual(cipher.tags, ['Work', 'Extra'], 'the restored item keeps its tag list');
});

test('an archive from before the tag_name column restores without a tag', async () => {
  const { env } = await sourceVault();
  const archive = await buildBackupArchive(env, new Date(), { includeAttachments: false });
  const payload = parseBackupArchive(archive.bytes).payload;
  const legacy = zipSync({
    'manifest.json': new TextEncoder().encode(JSON.stringify(payload.manifest)),
    'db.json': new TextEncoder().encode(JSON.stringify({
      ...payload.db,
      folders: payload.db.folders.map((row) => {
        const withoutTag = { ...row };
        delete withoutTag.tag_name;
        return withoutTag;
      }),
    })),
  });

  const target = await targetInstance();
  await importBackupArchiveBytes(legacy, target.env, OWNER, false);

  const rows = folderRows(target.sqlite);
  assert.equal(rows.length, 3, 'the folders are restored');
  assert.deepEqual(
    rows.map((row) => row.tag_name),
    [null, null, null],
    'a legacy archive restores folders without inventing a tag'
  );
  assert.equal(cipherRow(target.sqlite, LOGIN_ID).folderId, WORK_FOLDER, 'the item placement is kept');
});
