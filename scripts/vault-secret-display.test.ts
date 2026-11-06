// The vault detail view shows two rules that the UI must never soften:
// deleting an active item only moves it to the trash, and only an item that
// already sits in the trash is removed for good. Both the button and the
// confirmation dialog read the same helper, so they cannot disagree.
import assert from 'node:assert/strict';
import test from 'node:test';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { maskSecret, vaultDeleteAction } from '../webapp/src/components/vault/vault-page-helpers';
import type { Cipher } from '../webapp/src/lib/types';
import { firstCipherUri, hasUnresolvedCipherUri } from '../webapp/src/lib/website-utils';

const activeCipher: Cipher = { id: 'a', type: 1 };
const trashedCipher: Cipher = { id: 'b', type: 1, deletedDate: '2026-11-01T10:00:00.000Z' };

test('an active item is only moved to the trash', () => {
  assert.deepEqual(vaultDeleteAction(activeCipher), { permanent: false, labelKey: 'txt_move_to_trash' });
});

test('an item that already sits in the trash is deleted for good', () => {
  assert.deepEqual(vaultDeleteAction(trashedCipher), { permanent: true, labelKey: 'txt_delete_permanently' });
});

test('no target never means a permanent delete', () => {
  assert.equal(vaultDeleteAction(null).permanent, false);
});

test('a masked secret never shows any part of the value', () => {
  const masked = maskSecret('4111111111111111');
  assert.match(masked, /^\*+$/);
  assert.ok(!/\d/.test(masked));
});

test('list URI ignores encrypted entries and uses the next readable website', () => {
  const cipher: Cipher = { id: 'c', type: 1, login: { uris: [
    { uri: '2.Zm9v|YmFy' },
    { uri: 'https://example.test' },
  ] } };
  assert.equal(firstCipherUri(cipher), 'https://example.test');
  assert.equal(firstCipherUri({ id: 'd', type: 1, login: { uris: [{ uri: '2.Zm9v|YmFy' }] } }), '');
});

test('editing must wait for an unreadable URI to decrypt', () => {
  assert.equal(hasUnresolvedCipherUri({ id: 'e', type: 1, login: { uris: [{ uri: '2.Zm9v|YmFy', decUri: '' }] } }), true);
  assert.equal(hasUnresolvedCipherUri({ id: 'f', type: 1, login: { uris: [{ uri: '2.Zm9v|YmFy', decUri: 'https://example.test' }] } }), false);
});
