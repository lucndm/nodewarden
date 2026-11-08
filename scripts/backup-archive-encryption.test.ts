// The backup archive is the only way a vault leaves the server, so sealing it
// with a passphrase is what keeps the key material off a remote.
//
// The archive holds the accounts' master password hashes, their wrapped keys
// and the organization keys. In plaintext, whoever holds the file holds the
// key material of the vault.
//
// Coverage:
//   - an archive written with a passphrase is sealed and opens again with it;
//   - a wrong passphrase does not open it, and says so;
//   - an archive written without a passphrase is still a readable zip, so the
//     archives that exist today keep working;
//   - a restore reads a sealed archive with the passphrase in the settings.
import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { buildBackupArchive, parseBackupArchive } from '../src/services/backup-archive';
import { decryptBackupArchive, isEncryptedBackupArchive } from '../src/services/backup-archive-crypto';
import { importBackupArchiveBytes } from '../src/services/backup-import';
import { saveBackupSettings } from '../src/services/backup-config';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { StorageService } from '../src/services/storage';
import { sqliteD1 } from './sqlite-d1';
import type { Env, User } from '../src/types';

const OWNER = '00000000-0000-4000-8000-0000000000a1';
const LOGIN_ID = '00000000-0000-4000-8000-0000000000c1';
const REVISION = '2026-01-01T00:00:00.000Z';
const PASSPHRASE = 'a passphrase only the administrator knows';

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
    yubikeyNfc: false,
    apiKey: null,
    userKeyId: null,
    createdAt: REVISION,
    updatedAt: REVISION,
  } as unknown as User;
}

async function makeEnv(): Promise<{ env: Env; storage: StorageService; sqlite: DatabaseSync }> {
  const sqlite = new DatabaseSync(':memory:');
  const db = sqliteD1(sqlite);
  await ensureStorageSchema(db);
  const env = {
    DB: db,
    JWT_SECRET: 'test-secret',
    NOTIFICATIONS_HUB: {
      idFromName: (name: string) => name,
      get: () => ({
        fetch: async () => new Response(null, { status: 204 }),
      }),
    },
  } as unknown as Env;
  return { env, storage: new StorageService(db), sqlite };
}

async function vaultWithOneItem() {
  const { env, storage, sqlite } = await makeEnv();
  await storage.saveUser(makeUser(OWNER, 'owner@example.com'));
  await storage.saveCipher({
    id: LOGIN_ID,
    userId: OWNER,
    type: 1,
    folderId: null,
    name: '2.iv|ct|mac',
    notes: null,
    favorite: false,
    data: JSON.stringify({ login: {}, tags: [] }),
    reprompt: 0,
    key: null,
    createdAt: REVISION,
    updatedAt: REVISION,
    archivedAt: null,
    deletedAt: null,
    organizationId: null,
  } as never);
  return { env, storage, sqlite };
}

test('an archive written with a passphrase is sealed and opens again with it', async () => {
  const { env } = await vaultWithOneItem();

  const archive = await buildBackupArchive(env, new Date(), {
    includeAttachments: false,
    passphrase: PASSPHRASE,
  });

  assert.ok(isEncryptedBackupArchive(archive.bytes), 'the archive is sealed');
  assert.throws(() => parseBackupArchive(archive.bytes), 'a sealed archive is not a readable zip');

  const opened = await decryptBackupArchive(archive.bytes, PASSPHRASE);
  const payload = parseBackupArchive(opened).payload;
  assert.equal(payload.db.ciphers.length, 1, 'the item is in the opened archive');
});

test('a wrong passphrase does not open the archive', async () => {
  const { env } = await vaultWithOneItem();
  const archive = await buildBackupArchive(env, new Date(), {
    includeAttachments: false,
    passphrase: PASSPHRASE,
  });

  await assert.rejects(
    () => decryptBackupArchive(archive.bytes, 'not the passphrase'),
    'the wrong passphrase is refused'
  );
});

test('an archive written without a passphrase stays a readable zip', async () => {
  const { env } = await vaultWithOneItem();
  const archive = await buildBackupArchive(env, new Date(), { includeAttachments: false });

  assert.equal(isEncryptedBackupArchive(archive.bytes), false, 'the archive is not sealed');
  const payload = parseBackupArchive(archive.bytes).payload;
  assert.equal(payload.db.ciphers.length, 1, 'the archive reads as it always did');
});

test('a restore reads a sealed archive with the passphrase in the settings', async () => {
  const { env } = await vaultWithOneItem();
  const archive = await buildBackupArchive(env, new Date(), {
    includeAttachments: false,
    passphrase: PASSPHRASE,
  });

  const target = await makeEnv();
  await target.storage.saveUser(makeUser(OWNER, 'owner@example.com'));
  await saveBackupSettings(target.storage, target.env, {
    destinations: [],
    archivePassphrase: PASSPHRASE,
  });

  const result = await importBackupArchiveBytes(archive.bytes, target.env, OWNER, false);
  assert.equal(result.result.imported.ciphers, 1, 'the sealed archive restores');
});
