// The Web Vault re-encrypts legacy plain-text folder names with the account
// key. Two rules must hold: the inventory only lists names that really are
// plain text, and a name is only rewritten when the rewrite cannot rename the
// tag that the folder already carries.
import assert from 'node:assert/strict';
import test from 'node:test';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { bytesToBase64, encryptBw } from '../webapp/src/lib/crypto';
import {
  convertPlaintextFolderNames,
  decideFolderRewrite,
  inspectFolderNames,
  selectPlainTextFolders,
} from '../webapp/src/lib/folder-legacy-encryption';

const encKey = new Uint8Array(32).fill(7);
const macKey = new Uint8Array(32).fill(9);
const key = { encB64: bytesToBase64(encKey), macB64: bytesToBase64(macKey) };

test('the inventory lists plain-text folder names only', async () => {
  const encrypted = await encryptBw(new TextEncoder().encode('Work'), encKey, macKey);
  const entries = await inspectFolderNames(
    [
      { id: 'plain', name: 'Personal' },
      { id: 'encrypted', name: encrypted },
      { id: 'unreadable', name: '2.abc|def|ghi' },
      { id: 'padded', name: ' Personal ' },
      { id: 'long', name: 'x'.repeat(65) },
      { id: 'empty', name: '' },
    ],
    key
  );

  assert.deepEqual(
    entries.map((entry) => [entry.id, entry.state]),
    [
      ['plain', 'plaintext'],
      ['encrypted', 'encrypted'],
      ['unreadable', 'unreadable'],
      ['padded', 'padded'],
      ['long', 'too_long'],
      ['empty', 'empty'],
    ]
  );
  // The stored name is kept exactly as the server holds it.
  assert.equal(entries.find((entry) => entry.id === 'padded')?.name, ' Personal ');
  assert.deepEqual(
    selectPlainTextFolders(entries).map((entry) => entry.id),
    ['plain', 'padded', 'long']
  );
});

test('a rewrite is refused when it would rename the tag of the folder', () => {
  assert.deepEqual(decideFolderRewrite('Work', null), { action: 'write' });
  assert.deepEqual(decideFolderRewrite('Work', 'Work'), { action: 'write' });
  // The tag differs from the name: rewriting it would rename that tag.
  assert.deepEqual(decideFolderRewrite('Work', 'Ops'), { action: 'skip', reason: 'tag_mismatch' });
  // The server trims the tag it receives, so a padded name would rename it.
  assert.deepEqual(decideFolderRewrite(' Work ', null), { action: 'skip', reason: 'padded' });
  // The server cuts a tag at 64 characters.
  assert.deepEqual(decideFolderRewrite('x'.repeat(65), null), { action: 'skip', reason: 'too_long' });
});

test('a failed folder is reported and the remaining folders still convert', async () => {
  const entries = await inspectFolderNames(
    [
      { id: 'a', name: 'Alpha' },
      { id: 'b', name: 'Bravo' },
      { id: 'c', name: 'x'.repeat(65) },
    ],
    key
  );
  const converted: string[] = [];

  const result = await convertPlaintextFolderNames(entries, async (entry) => {
    if (entry.id === 'a') throw new Error('boom');
    if (entry.id === 'c') return { status: 'skipped', reason: 'too long for a tag' };
    converted.push(entry.id);
    return { status: 'converted' };
  });

  assert.equal(result.converted, 1);
  assert.deepEqual(result.skipped, [{ id: 'c', name: 'x'.repeat(65), reason: 'too long for a tag' }]);
  assert.deepEqual(result.failed, [{ id: 'a', name: 'Alpha', reason: 'boom' }]);
  assert.deepEqual(converted, ['b']);
});
