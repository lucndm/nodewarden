// Contract tests for the collection rights of a shared item.
//
// The official Bitwarden clients take the rights of an item from the server
// as three booleans, so the server has to combine the grants of a member the
// same way the official server does. These tests pin that contract, so the
// storage and the sync filter can be built on top of it without re-deciding
// it.
//
// The rules mirror the official server, in
// src/Sql/dbo/Vault/Stored Procedures/Cipher/CipherDetails_ReadByUserId.sql.
//
// Coverage:
//   - an item nobody can reach is invisible;
//   - a single collection decides the rights on its own;
//   - the rights come from the highest grant the member can reach, and manage
//     outranks edit, which outranks viewing the password;
//   - a direct collection assignment wins over a group assignment;
//   - a group assignment still applies when there is no direct one;
//   - the write and edit rules follow from the flags.
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  canEditCollection,
  canReadItem,
  canWriteItem,
  resolveItemAccess,
  type CollectionGrant,
} from '../src/services/collection-access';

function direct(collectionId: string, flags: Partial<CollectionGrant> = {}): CollectionGrant {
  return {
    collectionId,
    direct: true,
    readOnly: false,
    hidePasswords: false,
    manage: false,
    ...flags,
  };
}

function group(collectionId: string, flags: Partial<CollectionGrant> = {}): CollectionGrant {
  return { ...direct(collectionId, flags), direct: false };
}

test('an item nobody can reach is invisible', () => {
  assert.equal(resolveItemAccess([]), null);
  assert.equal(canReadItem(null), false);
  assert.equal(canWriteItem(null), false);
  assert.equal(canEditCollection(null), false);
});

test('one collection decides the rights on its own', () => {
  const access = resolveItemAccess([direct('c1', { readOnly: true })]);
  assert.ok(access);
  assert.equal(access.readOnly, true);
  assert.equal(access.hidePasswords, false);
  assert.equal(access.manage, false);
  assert.equal(access.viaCollection, 'c1');
});

test('the item takes the highest grant the member can reach', () => {
  // Edit outranks viewing the password: the editable collection wins.
  const edit = resolveItemAccess([
    direct('viewOnly', { readOnly: true, hidePasswords: true }),
    direct('editable', { readOnly: false, hidePasswords: true }),
  ]);
  assert.ok(edit);
  assert.equal(edit.readOnly, false);
  assert.equal(edit.hidePasswords, true);
  assert.equal(edit.manage, false);
  assert.equal(edit.viaCollection, 'editable');

  // Manage outranks edit.
  const managed = resolveItemAccess([
    direct('editable', { readOnly: false, hidePasswords: false }),
    direct('managed', { readOnly: true, hidePasswords: true, manage: true }),
  ]);
  assert.ok(managed);
  assert.equal(managed.manage, true);
  assert.equal(managed.readOnly, true);
  assert.equal(managed.hidePasswords, true);
  assert.equal(managed.viaCollection, 'managed');
});

test('viewing the password outranks a read-only grant', () => {
  const access = resolveItemAccess([
    direct('c1', { readOnly: true, hidePasswords: true }),
  ]);
  assert.ok(access);
  assert.equal(access.readOnly, true);
  assert.equal(access.hidePasswords, true);
  assert.equal(canWriteItem(access), false, 'a read-only item cannot be written');
});

test('a direct collection assignment wins over a group assignment', () => {
  // The group would widen the rights; the direct assignment withholds them.
  const access = resolveItemAccess([
    group('c1', { readOnly: false, hidePasswords: false, manage: true }),
    direct('c1', { readOnly: true, hidePasswords: true, manage: false }),
  ]);
  assert.ok(access);
  assert.equal(access.readOnly, true);
  assert.equal(access.hidePasswords, true);
  assert.equal(access.manage, false);

  // The other way round: the direct assignment widens what the group withheld.
  const widened = resolveItemAccess([
    group('c1', { readOnly: true, hidePasswords: true, manage: false }),
    direct('c1', { readOnly: false, hidePasswords: false, manage: true }),
  ]);
  assert.ok(widened);
  assert.equal(widened.readOnly, false);
  assert.equal(widened.hidePasswords, false);
  assert.equal(widened.manage, true);
});

test('a group assignment still applies when there is no direct one', () => {
  const access = resolveItemAccess([
    direct('mine', { readOnly: true, hidePasswords: true }),
    group('theirs', { readOnly: false, hidePasswords: false }),
  ]);
  assert.ok(access);
  assert.equal(access.readOnly, false, 'the group grant outranks the direct one on another collection');
  assert.equal(access.viaCollection, 'theirs');
});

test('the same collection granted twice keeps the better grant', () => {
  // Two direct grants for one collection cannot happen through the API (the
  // table has one row per member and collection), but when they are supplied
  // the better one wins, which is what the official SQL does with MAX(rank).
  const access = resolveItemAccess([
    direct('c1', { readOnly: true }),
    direct('c1', { readOnly: false }),
  ]);
  assert.ok(access);
  assert.equal(access.readOnly, false, 'the better direct grant wins');
  assert.equal(access.viaCollection, 'c1');
});

test('writing needs the item not to be read-only, or manage rights', () => {
  const readOnly = resolveItemAccess([direct('c1', { readOnly: true })]);
  assert.equal(canWriteItem(readOnly), false, 'a read-only item cannot be written');

  const writable = resolveItemAccess([direct('c1', { readOnly: false })]);
  assert.equal(canWriteItem(writable), true);

  // Manage rights overrule read-only: the member may manage the collection.
  const managed = resolveItemAccess([direct('c1', { readOnly: true, manage: true })]);
  assert.equal(canWriteItem(managed), true);
});

test('editing a collection needs the rights and the password, or manage', () => {
  const readOnly = resolveItemAccess([direct('c1', { readOnly: true })]);
  assert.equal(canEditCollection(readOnly), false);

  const hidden = resolveItemAccess([direct('c1', { readOnly: false, hidePasswords: true })]);
  assert.equal(canEditCollection(hidden), false, 'a hidden password must not be editable away');

  const editable = resolveItemAccess([direct('c1', { readOnly: false, hidePasswords: false })]);
  assert.equal(canEditCollection(editable), true);

  const managed = resolveItemAccess([direct('c1', { readOnly: true, hidePasswords: true, manage: true })]);
  assert.equal(canEditCollection(managed), true, 'manage overrules the other flags');
});
