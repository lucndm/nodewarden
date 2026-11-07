// Restore rehearsal for an instance backup archive.
//
// Proves that an archive really restores into a fresh instance: the file
// checksum matches its name, the import runs, and the restored vault holds the
// same rows as the archive.
//
// The archive is restored into a throwaway local Worker with its own D1; no
// remote database is touched.
//
// Usage:
//   npx tsx scripts/local-restore-rehearsal.mts <backup.zip>
import { readFileSync, readdirSync } from 'node:fs';
import { basename } from 'node:path';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { unzipSync } from 'fflate';

import { startLocalWorker, createChecks } from './local-worker.mjs';

const archivePath = process.argv[2];
if (!archivePath) {
  console.error('usage: local-restore-rehearsal.mts <backup.zip>');
  process.exit(2);
}

const bytes = new Uint8Array(readFileSync(archivePath));
const zip = unzipSync(bytes);
const manifest = JSON.parse(Buffer.from(zip['manifest.json']).toString());
const archiveDb = JSON.parse(Buffer.from(zip['db.json']).toString());

const encLike = /^\d+\.[^|]*\|[^|]*\|[^|]*$/;
const plainFolderNames = (rows) =>
  (rows || []).filter((row) => {
    const name = String(row.name || '').trim();
    if (!name) return false;
    if (encLike.test(name)) return false;
    return !/^\d+\./.test(name);
  });
const ciphertextTags = (rows) =>
  (rows || []).filter((row) => {
    let data = {};
    try {
      data = JSON.parse(row.data || '{}');
    } catch {
      return false;
    }
    const tags = Array.isArray(data.tags) ? data.tags : [];
    return tags.some((tag) => typeof tag === 'string' && encLike.test(tag.trim()));
  });

async function api(baseUrl, path, options = {}) {
  const { method = 'GET', token, body, form, headers = {} } = options;
  const init = { method, headers: { ...headers } };
  if (token) init.headers.Authorization = `Bearer ${token}`;
  if (form) {
    init.headers['Content-Type'] = 'application/x-www-form-urlencoded';
    init.body = new URLSearchParams(form).toString();
  } else if (body !== undefined) {
    if (typeof FormData !== 'undefined' && body instanceof FormData) {
      // fetch adds the multipart boundary itself.
      init.body = body;
    } else {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
  }
  const response = await fetch(`${baseUrl}${path}`, init);
  const text = await response.text();
  let parsed = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = text;
  }
  return { status: response.status, body: parsed };
}

async function main() {
  const worker = await startLocalWorker({ label: 'restore-rehearsal' });
    try {
    console.log(`local Worker: ${worker.baseUrl}`);
    console.log(`archive: ${basename(archivePath)} (${bytes.byteLength} bytes)`);
    const checks = createChecks('backup restore rehearsal');

    const hash = createHash('sha256').update(bytes).digest('hex');
    const expectedPrefix = /_([0-9a-f]{5})\.zip$/i.exec(basename(archivePath))?.[1]?.toLowerCase() || null;
    if (expectedPrefix) {
      checks.equal('the file name carries the checksum of the file', hash.slice(0, 5), expectedPrefix);
    } else {
      checks.ok('the file name carries a checksum', false, 'no _xxxxx.zip suffix');
    }
    checks.equal('the archive was written by this version', manifest.appVersion, '1.8.2');

    // A throwaway admin, so the import has an owner to run as.
    const email = 'rehearsal-admin@example.test';
    const passwordHash = Buffer.from('rehearsal-master-hash').toString('base64');
    const registered = await api(worker.baseUrl, '/api/accounts/register', {
      method: 'POST',
      headers: { Origin: worker.baseUrl },
      body: {
        email,
        name: 'Rehearsal',
        masterPasswordHash: passwordHash,
        key: '2.aXY=|Y3Q=|bWFj',
        kdf: 0,
        kdfIterations: 600000,
        keys: { publicKey: Buffer.from('public-key').toString('base64'), encryptedPrivateKey: '2.aXY=|Y3Q=|bWFj' },
      },
    });
    checks.equal('register a throwaway admin', registered.status, 200, JSON.stringify(registered.body));

    const token = (
      await api(worker.baseUrl, '/identity/connect/token', {
        method: 'POST',
        form: {
          grant_type: 'password',
          username: email,
          password: passwordHash,
          scope: 'api offline_access',
          deviceIdentifier: 'restore-rehearsal',
          deviceName: 'restore rehearsal',
          deviceType: '14',
        },
      })
    ).body?.access_token;
    if (!checks.ok('the admin gets a token', !!token)) return;

    const form = new FormData();
    form.set('file', new File([bytes], basename(archivePath)));
    form.set('masterPasswordHash', passwordHash);
    form.set('replaceExisting', '1');
    const imported = await api(worker.baseUrl, '/api/admin/backup/import', {
      method: 'POST',
      token,
      body: form,
    });
    checks.equal('the archive imports', imported.status, 200, JSON.stringify(imported.body).slice(0, 300));
    const importedCounts = imported.body?.imported || {};
    checks.equal('every folder is restored', importedCounts.folders, (archiveDb.folders || []).length);
    checks.equal('every item is restored', importedCounts.ciphers, (archiveDb.ciphers || []).length);
    checks.equal('the account is restored', importedCounts.users, (archiveDb.users || []).length);

    // The import replaces the accounts, so the throwaway admin is gone: the
    // restored instance is read straight from its own database.
    const d1Dir = `${worker.persistDir}/v3/d1/miniflare-D1DatabaseObject`;
    const d1File = readdirSync(d1Dir).find((name) => name.endsWith('.sqlite') && name !== 'metadata.sqlite');
    if (!checks.ok('the restored database file exists', !!d1File, d1Dir)) return;
    const restored = new DatabaseSync(`${d1Dir}/${d1File}`, { readOnly: true });
    const restoredUsers = restored.prepare('SELECT id, email FROM users').all() as Array<{ id: string; email: string }>;
    const restoredFolders = restored.prepare('SELECT id, user_id, name, tag_name FROM folders').all() as Array<Record<string, unknown>>;
    const restoredCiphers = restored.prepare('SELECT id, user_id, type, folder_id, name, data FROM ciphers').all() as Array<Record<string, unknown>>;
    restored.close();

    const archiveFolderIds = new Set((archiveDb.folders || []).map((row) => row.id));
    const archiveCipherIds = new Set((archiveDb.ciphers || []).map((row) => row.id));
    const archiveUserIds = new Set((archiveDb.users || []).map((row) => row.id));
    checks.equal(
      'the restored folders are the archive folders',
      restoredFolders.filter((folder) => archiveFolderIds.has(String(folder.id))).length,
      archiveFolderIds.size
    );
    checks.equal(
      'the restored items are the archive items',
      restoredCiphers.filter((cipher) => archiveCipherIds.has(String(cipher.id))).length,
      archiveCipherIds.size
    );
    checks.equal(
      'the restored account is the archive account',
      restoredUsers.filter((user) => archiveUserIds.has(user.id)).length,
      archiveUserIds.size
    );
    checks.equal(
      'the restored item payload is the archive payload',
      restoredCiphers.filter((cipher) => {
        const archived = (archiveDb.ciphers || []).find((row) => row.id === cipher.id);
        return archived && archived.data === cipher.data && archived.name === cipher.name;
      }).length,
      archiveCipherIds.size
    );
    checks.equal('the restored instance holds no plaintext folder name', plainFolderNames(restoredFolders).length, 0);
    checks.equal('the restored instance holds no ciphertext-shaped tag', ciphertextTags(restoredCiphers).length, 0);

    checks.finish();
  } finally {
    await worker.stop();
  }
}

process.exitCode = await main();
