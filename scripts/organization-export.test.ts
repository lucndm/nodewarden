// An organization export holds the items and the collections of one
// organization. The rules that must hold: the personal export keeps its
// shape, an organization export leaves the personal data out, and an
// encrypted organization export is written with the organization key.
import assert from 'node:assert/strict';
import test from 'node:test';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { bytesToBase64, decryptStr, encryptBw } from '../webapp/src/lib/crypto';
import {
  buildAccountEncryptedBitwardenJsonString,
  buildBitwardenCsvString,
  buildBitwardenOrganizationCsvString,
  buildPlainBitwardenJsonDocument,
  type ExportScope,
} from '../webapp/src/lib/export-formats';
import type { Cipher } from '../webapp/src/lib/types';

// The sync response carries the organization and the collections of an item,
// so the fixture holds them next to the cipher.
type OrganizationCipher = Cipher & { organizationId?: string | null; collectionIds?: string[] };

const userEnc = new Uint8Array(32).fill(1);
const userMac = new Uint8Array(32).fill(2);
const orgAEnc = new Uint8Array(32).fill(3);
const orgAMac = new Uint8Array(32).fill(4);
const orgBEnc = new Uint8Array(32).fill(5);
const orgBMac = new Uint8Array(32).fill(6);

const ORGANIZATION_A = 'org-a';
const ORGANIZATION_B = 'org-b';

function encryptText(text: string, enc: Uint8Array, mac: Uint8Array): Promise<string> {
  return encryptBw(new TextEncoder().encode(text), enc, mac);
}

/** An item, with its own key wrapped by the key of the vault that holds it. */
async function makeCipher(args: {
  id: string;
  name: string;
  ownerEnc: Uint8Array;
  ownerMac: Uint8Array;
  organizationId?: string | null;
  collectionIds?: string[];
  deletedDate?: string | null;
  folderId?: string | null;
  favorite?: boolean;
}): Promise<OrganizationCipher> {
  const itemKey = new TextEncoder().encode(args.id.padEnd(64, '0').slice(0, 64));
  const itemEnc = itemKey.slice(0, 32);
  const itemMac = itemKey.slice(32, 64);
  return {
    id: args.id,
    type: 1,
    name: await encryptText(args.name, itemEnc, itemMac),
    notes: await encryptText(`notes of ${args.name}`, itemEnc, itemMac),
    key: await encryptBw(itemKey, args.ownerEnc, args.ownerMac),
    login: {
      username: await encryptText(`user of ${args.name}`, itemEnc, itemMac),
      password: await encryptText(`password of ${args.name}`, itemEnc, itemMac),
      totp: null,
      uris: [],
    },
    folderId: args.folderId ?? null,
    favorite: args.favorite ?? false,
    reprompt: 0,
    creationDate: '2024-01-01T00:00:00.000Z',
    revisionDate: '2024-01-02T00:00:00.000Z',
    deletedDate: args.deletedDate ?? null,
    organizationId: args.organizationId ?? null,
    collectionIds: args.collectionIds ?? [],
  };
}

async function makeFixture() {
  const folders = [
    {
      id: 'folder-1',
      name: await encryptText('Personal', userEnc, userMac),
    },
  ];

  const ciphers: OrganizationCipher[] = [
    await makeCipher({ id: 'personal-1', name: 'Personal One', ownerEnc: userEnc, ownerMac: userMac, folderId: 'folder-1', favorite: true }),
    await makeCipher({ id: 'personal-2', name: 'Personal Two', ownerEnc: userEnc, ownerMac: userMac }),
    await makeCipher({ id: 'org-a-1', name: 'Alpha', ownerEnc: orgAEnc, ownerMac: orgAMac, organizationId: ORGANIZATION_A, collectionIds: ['collection-1', 'collection-2'], folderId: 'folder-1', favorite: true }),
    await makeCipher({ id: 'org-a-2', name: 'Bravo', ownerEnc: orgAEnc, ownerMac: orgAMac, organizationId: ORGANIZATION_A, collectionIds: ['collection-2'] }),
    await makeCipher({ id: 'org-a-3', name: 'Charlie', ownerEnc: orgAEnc, ownerMac: orgAMac, organizationId: ORGANIZATION_A, deletedDate: '2024-02-01T00:00:00.000Z' }),
    await makeCipher({ id: 'org-b-1', name: 'Delta', ownerEnc: orgBEnc, ownerMac: orgBMac, organizationId: ORGANIZATION_B }),
  ];

  // One collection carries an encrypted name, the way an official client
  // writes it; the other one is an older collection with a plain name.
  const collectionOneName = await encryptText('Team Alpha', orgAEnc, orgAMac);
  const collectionTwoName = 'Legacy Beta';

  const scope: ExportScope = {
    kind: 'organization',
    organizationId: ORGANIZATION_A,
    collections: [
      { id: 'collection-1', name: 'Team Alpha', encryptedName: collectionOneName, externalId: null },
      { id: 'collection-2', name: collectionTwoName, encryptedName: collectionTwoName, externalId: null },
    ],
  };

  return { folders, ciphers, scope, collectionOneName, collectionTwoName };
}

function readItems(doc: Record<string, unknown>): Array<Record<string, unknown>> {
  const items = doc.items;
  assert.ok(Array.isArray(items));
  return items as Array<Record<string, unknown>>;
}

test('the personal export keeps the items and the folders of the member alone', async () => {
  const { folders, ciphers } = await makeFixture();

  const doc = await buildPlainBitwardenJsonDocument({
    folders,
    ciphers,
    userEncB64: bytesToBase64(userEnc),
    userMacB64: bytesToBase64(userMac),
  });

  assert.equal(doc.encrypted, false);
  assert.deepEqual(Object.keys(doc).sort(), ['encrypted', 'folders', 'items']);
  assert.equal((doc.folders as Array<Record<string, unknown>>).length, 1);
  const items = readItems(doc);
  assert.equal(items.length, 2);
  assert.deepEqual(items.map((item) => item.id).sort(), ['personal-1', 'personal-2']);
  // The shape of a personal item stays the same.
  assert.deepEqual(Object.keys(items[0]).sort(), [
    'bankAccount',
    'card',
    'collectionIds',
    'creationDate',
    'driversLicense',
    'favorite',
    'fields',
    'folderId',
    'id',
    'identity',
    'login',
    'name',
    'notes',
    'passport',
    'passwordHistory',
    'reprompt',
    'revisionDate',
    'secureNote',
    'sshKey',
    'type',
  ]);
  // The fields an organization export leaves out stay in the personal one.
  assert.equal(items[0].favorite, true);
  assert.equal(items[0].folderId, 'folder-1');
  assert.equal(items[0].collectionIds, null);

  const csv = buildBitwardenCsvString(doc).replace(/^\uFEFF/, '').split('\r\n');
  assert.equal(csv[0], 'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp');
});

test('the export of an organization holds its items and its collections', async () => {
  const { folders, ciphers, scope } = await makeFixture();

  const doc = await buildPlainBitwardenJsonDocument({
    folders,
    ciphers,
    userEncB64: bytesToBase64(orgAEnc),
    userMacB64: bytesToBase64(orgAMac),
    scope,
  });

  assert.equal(doc.encrypted, false);
  // An organization has no folders of its own.
  assert.equal('folders' in doc, false);
  assert.deepEqual(doc.collections, [
    { id: 'collection-1', organizationId: ORGANIZATION_A, name: 'Team Alpha', externalId: null },
    { id: 'collection-2', organizationId: ORGANIZATION_A, name: 'Legacy Beta', externalId: null },
  ]);

  const items = readItems(doc);
  // The deleted item and the items of the other organization stay out.
  assert.deepEqual(items.map((item) => item.id).sort(), ['org-a-1', 'org-a-2']);
  for (const item of items) {
    assert.equal(item.organizationId, ORGANIZATION_A);
    // A folder and a favorite belong to the member alone.
    assert.equal('folderId' in item, false);
    assert.equal('favorite' in item, false);
    assert.ok(Array.isArray(item.collectionIds));
  }
  assert.deepEqual(items.find((item) => item.id === 'org-a-1')?.collectionIds, ['collection-1', 'collection-2']);
  assert.equal(items.find((item) => item.id === 'org-a-1')?.name, 'Alpha');
});

test('the CSV of an organization names the collections of every item', async () => {
  const { folders, ciphers, scope } = await makeFixture();

  const doc = await buildPlainBitwardenJsonDocument({
    folders,
    ciphers,
    userEncB64: bytesToBase64(orgAEnc),
    userMacB64: bytesToBase64(orgAMac),
    scope,
  });

  const rows = buildBitwardenOrganizationCsvString(doc).replace(/^\uFEFF/, '').split('\r\n');
  assert.equal(
    rows[0],
    'collections,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp'
  );
  assert.ok(rows[1].startsWith('"Team Alpha,Legacy Beta"'));
  assert.ok(rows[1].includes('Alpha'));
  assert.ok(rows[2].startsWith('"Legacy Beta"'));
});

test('the encrypted export of an organization is written with the organization key', async () => {
  const { folders, ciphers, scope, collectionOneName, collectionTwoName } = await makeFixture();

  const parsed = JSON.parse(
    await buildAccountEncryptedBitwardenJsonString({
      folders,
      ciphers,
      userEncB64: bytesToBase64(orgAEnc),
      userMacB64: bytesToBase64(orgAMac),
      scope,
    })
  ) as {
    encrypted: boolean;
    encKeyValidation_DO_NOT_EDIT: string;
    collections: Array<{ id: string; name: string }>;
    items: Array<Record<string, unknown>>;
  };

  assert.equal(parsed.encrypted, true);
  // The organization key opens the validation.
  assert.ok((await decryptStr(parsed.encKeyValidation_DO_NOT_EDIT, orgAEnc, orgAMac)).length > 0);

  // The encrypted collection keeps the name the server holds, the plain one is
  // encrypted with the organization key.
  assert.equal(parsed.collections[0].name, collectionOneName);
  const names = await Promise.all(parsed.collections.map((collection) => decryptStr(collection.name, orgAEnc, orgAMac)));
  assert.deepEqual(names, ['Team Alpha', collectionTwoName]);
  assert.equal(parsed.items.length, 2);
});

test('the items of another organization stay out of the export', async () => {
  const { folders, ciphers, scope } = await makeFixture();

  const doc = await buildPlainBitwardenJsonDocument({
    folders,
    ciphers,
    userEncB64: bytesToBase64(orgAEnc),
    userMacB64: bytesToBase64(orgAMac),
    scope,
  });

  const ids = readItems(doc).map((item) => String(item.id));
  assert.equal(ids.includes('org-b-1'), false);
  assert.equal(ids.includes('org-a-3'), false);
});
