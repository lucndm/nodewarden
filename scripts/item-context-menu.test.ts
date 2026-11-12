// The context menu of a list item offers the actions the item allows. These
// tests cover the list of entries, so a menu never offers an action the item
// cannot do. No value of an item is printed.
import assert from 'node:assert/strict';
import test from 'node:test';

import { buildItemMenu, type ItemMenuAction, type ItemMenuEntry } from '../webapp/src/lib/item-menu';
import type { Cipher } from '../webapp/src/lib/types';

function login(loginFields: Partial<NonNullable<Cipher['login']>> = {}, cipher: Partial<Cipher> = {}): Cipher {
  return {
    id: 'cipher-1',
    type: 1,
    login: {
      decUsername: 'user@example.com',
      decPassword: 'secret',
      decTotp: 'JBSWY3DPEHPK3PXP',
      ...loginFields,
    },
    ...cipher,
  } as Cipher;
}

function groupActions(group: ItemMenuEntry[]): ItemMenuAction[] {
  return group.map((entry) => entry.action);
}

function allActions(entries: ItemMenuEntry[][]): ItemMenuAction[] {
  return entries.flat().map((entry) => entry.action);
}

function labelOf(entries: ItemMenuEntry[][], action: ItemMenuAction): string | undefined {
  return entries.flat().find((entry) => entry.action === action)?.labelKey;
}

test('a login offers the copies its fields hold', () => {
  const entries = buildItemMenu(login(), { trash: false, canEdit: true, scanExcluded: false });

  assert.deepEqual(groupActions(entries[0]), ['copy-username', 'copy-password', 'copy-totp']);
  assert.equal(labelOf(entries, 'copy-username'), 'txt_copy_email');
  assert.equal(labelOf(entries, 'copy-password'), 'txt_copy_password');
  assert.equal(labelOf(entries, 'copy-totp'), 'txt_copy_verification_code');
});

test('the copy of a username says what it holds', () => {
  const email = buildItemMenu(login(), { trash: false, canEdit: true, scanExcluded: false });
  assert.equal(labelOf(email, 'copy-username'), 'txt_copy_email');

  const phone = buildItemMenu(login({ decUsername: '+84901234567' }), { trash: false, canEdit: true, scanExcluded: false });
  assert.equal(labelOf(phone, 'copy-username'), 'txt_copy_phone');

  const plain = buildItemMenu(login({ decUsername: 'john.doe' }), { trash: false, canEdit: true, scanExcluded: false });
  assert.equal(labelOf(plain, 'copy-username'), 'txt_copy_username');
});

test('a login without a one time code does not offer it', () => {
  const entries = buildItemMenu(login({ decTotp: '' }), { trash: false, canEdit: true, scanExcluded: false });

  assert.deepEqual(groupActions(entries[0]), ['copy-username', 'copy-password']);
});

test('an item in the trash can only come back or go away', () => {
  const entries = buildItemMenu(login(), { trash: true, canEdit: true, scanExcluded: false });

  assert.deepEqual(allActions(entries), ['restore', 'delete-permanently']);
  assert.equal(labelOf(entries, 'restore'), 'txt_restore');
  assert.equal(labelOf(entries, 'delete-permanently'), 'txt_delete_permanently');
  assert.equal(entries.flat().find((entry) => entry.action === 'delete-permanently')?.danger, true);
});

test('an item the member may only read keeps the copies and the history', () => {
  const entries = buildItemMenu(login(), { trash: false, canEdit: false, scanExcluded: false });

  assert.deepEqual(allActions(entries), ['copy-username', 'copy-password', 'copy-totp', 'view-history', 'toggle-scan-exclusion']);
});

test('the favorite and the check follow the state of the item', () => {
  const favorite = buildItemMenu(login({}, { favorite: true }), { trash: false, canEdit: true, scanExcluded: false });
  assert.equal(labelOf(favorite, 'toggle-favorite'), 'txt_remove_from_favorites');

  const plain = buildItemMenu(login(), { trash: false, canEdit: true, scanExcluded: false });
  assert.equal(labelOf(plain, 'toggle-favorite'), 'txt_add_to_favorites');

  const excluded = buildItemMenu(login(), { trash: false, canEdit: true, scanExcluded: true });
  assert.equal(labelOf(excluded, 'toggle-scan-exclusion'), 'txt_scan_include_again');

  const checked = buildItemMenu(login(), { trash: false, canEdit: true, scanExcluded: false });
  assert.equal(labelOf(checked, 'toggle-scan-exclusion'), 'txt_scan_exclude');
});

test('an archived item offers to come back from the archive', () => {
  const entries = buildItemMenu(login({}, { archivedDate: '2026-01-01T00:00:00.000Z' }), {
    trash: false,
    canEdit: true,
    scanExcluded: false,
  });

  assert.equal(labelOf(entries, 'toggle-archive'), 'txt_unarchive');
});

test('a shared item the member may only read keeps its secrets to itself', () => {
  const entries = buildItemMenu(
    { ...login(), edit: false, viewPassword: false } as Cipher,
    { trash: false, canEdit: true, scanExcluded: false }
  );

  assert.deepEqual(allActions(entries), ['copy-username', 'view-history', 'toggle-scan-exclusion']);
});
