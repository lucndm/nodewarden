// The cutover inventory decides which accounts still hold plain-text folder
// names. Under-reporting is the dangerous direction: an operator who trusts a
// short list cuts over with folders that official clients render with an empty
// name. So the checks below pin the grouping, the plain-text-only rule and the
// "never drop a row" behaviour for folders whose user is missing.
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { zipSync } from 'fflate';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { encryptBw } from '../webapp/src/lib/crypto';
import { formatInventory, inventoryArchive } from './folder-plaintext-inventory';

const encKey = new Uint8Array(32).fill(7);
const macKey = new Uint8Array(32).fill(9);

function writeArchive(db: unknown): string {
  const dir = mkdtempSync(join(tmpdir(), 'nw-inventory-'));
  const path = join(dir, 'nodewarden_backup_test.zip');
  writeFileSync(
    path,
    zipSync({
      'manifest.json': new TextEncoder().encode('{}'),
      'db.json': new TextEncoder().encode(JSON.stringify(db)),
    })
  );
  return path;
}

test('the inventory reports plain-text folder names per account only', async () => {
  const encryptedName = await encryptBw(new TextEncoder().encode('Work'), encKey, macKey);
  const path = writeArchive({
    users: [
      { id: 'u1', email: 'first@example.test' },
      { id: 'u2', email: 'second@example.test' },
    ],
    folders: [
      { id: 'f-plain', user_id: 'u1', name: 'Legacy JSON Folder', tag_name: null },
      { id: 'f-enc', user_id: 'u1', name: encryptedName, tag_name: 'Work' },
      { id: 'f-padded', user_id: 'u2', name: ' Spaced ', tag_name: null },
      { id: 'f-empty', user_id: 'u2', name: '', tag_name: null },
    ],
  });

  const summary = await inventoryArchive(path);
  const text = formatInventory(summary);

  assert.equal(summary.users.length, 2);
  assert.equal(summary.users[0].email, 'first@example.test');
  assert.equal(summary.users[0].folders, 2);
  assert.deepEqual(
    summary.users[0].plain.map((entry) => [entry.id, entry.name, entry.state]),
    [['f-plain', 'Legacy JSON Folder', 'plaintext']]
  );
  assert.equal(summary.users[1].folders, 2);
  assert.deepEqual(
    summary.users[1].plain.map((entry) => [entry.id, entry.state]),
    [['f-padded', 'padded']]
  );

  // The encrypted name is never offered for conversion, and the count is honest.
  assert.equal(text.includes('first@example.test'), true);
  assert.equal(text.includes('"Legacy JSON Folder" [plaintext] id=f-plain'), true);
  assert.equal(text.includes(encryptedName), false);
  assert.equal(text.includes('2 plain-text folder name(s) across 2 account(s)'), true);
});

test('the inventory never drops a folder row whose user is missing', async () => {
  const path = writeArchive({
    users: [{ id: 'u1', email: 'first@example.test' }],
    folders: [{ id: 'orphan-folder', user_id: 'u-missing', name: 'Legacy JSON Folder' }],
  });

  const summary = await inventoryArchive(path);
  const text = formatInventory(summary);

  assert.equal(summary.orphans.length, 1);
  assert.equal(text.includes('1 folder row(s) reference a user missing from the archive'), true);
  assert.equal(text.includes('"Legacy JSON Folder" id=orphan-folder user=u-missing'), true);
});

test('an archive with nothing to convert says so', async () => {
  const encryptedName = await encryptBw(new TextEncoder().encode('Work'), encKey, macKey);
  const path = writeArchive({
    users: [{ id: 'u1', email: 'first@example.test' }],
    folders: [{ id: 'f-enc', user_id: 'u1', name: encryptedName, tag_name: 'Work' }],
  });

  const text = formatInventory(await inventoryArchive(path));
  assert.equal(text.includes('no plain-text folder names; nothing to convert'), true);
});

test('a file that is not a backup archive fails loudly', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'nw-inventory-'));
  const path = join(dir, 'not-an-archive.zip');
  writeFileSync(path, 'definitely not a zip');

  await assert.rejects(() => inventoryArchive(path), /not a readable backup archive/);
});

// Guards the truncation the tag column applies: names longer than the server's
// 64-character tag limit are reported so the operator sees them before a
// conversion attempt silently refuses them.
test('a name longer than the tag limit is still listed as plain text', async () => {
  const path = writeArchive({
    users: [{ id: 'u1', email: 'first@example.test' }],
    folders: [{ id: 'f-long', user_id: 'u1', name: 'x'.repeat(65) }],
  });

  const summary = await inventoryArchive(path);
  assert.deepEqual(
    summary.users[0].plain.map((entry) => [entry.id, entry.state]),
    [['f-long', 'too_long']]
  );
  assert.equal(formatInventory(summary).includes('1 plain-text folder name(s)'), true);
});
