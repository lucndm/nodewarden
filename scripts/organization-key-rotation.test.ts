// Checks a client-side organization key rotation with real keys.
//
// A rotation is what makes removing a member mean something: the member keeps
// the organization key they already unwrapped, so the only way to keep new
// items away from them is to stop protecting those items with that key.
//
// This runs the whole path: it builds an organization key, wraps it for two
// members, puts an item in the organization, rotates, and then proves
//
//   - each remaining member opens the new organization key with their own key;
//   - the item key is new, and the old organization key does not open it;
//   - the payload decrypts under the new item key and not under the old one;
//   - the organization private key survives the rotation under the new key;
//   - a payload that is not encrypted text is left alone.
import assert from 'node:assert/strict';
import test from 'node:test';
import { webcrypto } from 'node:crypto';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { base64ToBytes, bytesToBase64, decryptBw, encryptBw } from '../webapp/src/lib/crypto';
import { rotateOrganizationKey } from '../webapp/src/lib/organization-key-rotation';

const { subtle } = webcrypto;

function randomKey(): Uint8Array {
  return webcrypto.getRandomValues(new Uint8Array(64));
}

function halves(raw: Uint8Array): { encKey: Uint8Array; macKey: Uint8Array } {
  return { encKey: raw.slice(0, 32), macKey: raw.slice(32) };
}

async function memberKeyPair(): Promise<{ publicKey: string; privateKey: CryptoKey }> {
  const pair = (await subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' },
    true,
    ['encrypt', 'decrypt']
  )) as CryptoKeyPair;
  const spki = new Uint8Array(await subtle.exportKey('spki', pair.publicKey));
  return { publicKey: bytesToBase64(spki), privateKey: pair.privateKey };
}

/** Opens a `4.` RSA-wrapped key with the member's private key. */
async function unwrapForMember(privateKey: CryptoKey, wrapped: string): Promise<Uint8Array> {
  assert.ok(wrapped.startsWith('4.'), 'a member key is wrapped in the 4. form');
  const body = base64ToBytes(wrapped.slice(2));
  return new Uint8Array(
    await subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer)
  );
}

test('a rotation leaves the new key to every remaining member and to nobody else', async () => {
  const owner = await memberKeyPair();
  const member = await memberKeyPair();

  // The organization as it stands: one key, one item with its own key, and a
  // payload encrypted under that item key.
  const oldOrganizationKey = randomKey();
  const oldKeyHalves = halves(oldOrganizationKey);
  const oldItemKey = randomKey();
  const oldItemHalves = halves(oldItemKey);
  const encryptedName = await encryptBw(new TextEncoder().encode('Shared login'), oldItemHalves.encKey, oldItemHalves.macKey);
  const encryptedPassword = await encryptBw(new TextEncoder().encode('hunter2'), oldItemHalves.encKey, oldItemHalves.macKey);
  const organizationPrivateKey = await encryptBw(
    new TextEncoder().encode('the organization private key'),
    oldKeyHalves.encKey,
    oldKeyHalves.macKey
  );

  const result = await rotateOrganizationKey({
    oldOrganizationKey,
    organizationPrivateKey,
    members: [
      { userId: 'owner', publicKey: owner.publicKey },
      { userId: 'member', publicKey: member.publicKey },
    ],
    ciphers: [
      {
        id: 'cipher-1',
        key: await encryptBw(oldItemKey, oldKeyHalves.encKey, oldKeyHalves.macKey),
        data: {
          type: 1,
          name: encryptedName,
          login: { username: 'plain-user', password: encryptedPassword },
          tags: ['Work'],
        },
      },
    ],
  });

  // Each member opens the new organization key with their own private key.
  const ownerKey = await unwrapForMember(owner.privateKey, result.memberKeys[0].key);
  const memberKey = await unwrapForMember(member.privateKey, result.memberKeys[1].key);
  assert.deepEqual(ownerKey, memberKey, 'both members hold the same new organization key');
  assert.notDeepEqual(ownerKey, oldOrganizationKey, 'and it is not the old key');
  assert.equal(ownerKey.length, 64);

  // The organization private key survives, under the new key only.
  assert.ok(result.organizationPrivateKey);
  const newHalves = halves(ownerKey);
  const privateKeyPlain = await decryptBw(result.organizationPrivateKey, newHalves.encKey, newHalves.macKey);
  assert.equal(new TextDecoder().decode(privateKeyPlain), 'the organization private key');
  await assert.rejects(
    () => decryptBw(result.organizationPrivateKey!, oldKeyHalves.encKey, oldKeyHalves.macKey),
    'the old organization key must not open the rotated private key'
  );

  // The item key is new, and the old organization key does not open it.
  const newItemKey = await decryptBw(result.ciphers[0].key, newHalves.encKey, newHalves.macKey);
  assert.notDeepEqual(newItemKey, oldItemKey, 'the item gets a fresh key');
  await assert.rejects(
    () => decryptBw(result.ciphers[0].key, oldKeyHalves.encKey, oldKeyHalves.macKey),
    'the old organization key must not open the new item key'
  );

  // The payload decrypts under the new item key, and no longer under the old.
  const newItemHalves = halves(newItemKey);
  const payload = result.ciphers[0].data as {
    type: number;
    name: string;
    login: { username: string; password: string };
    tags: string[];
  };
  assert.equal(
    new TextDecoder().decode(await decryptBw(payload.name, newItemHalves.encKey, newItemHalves.macKey)),
    'Shared login'
  );
  assert.equal(
    new TextDecoder().decode(await decryptBw(payload.login.password, newItemHalves.encKey, newItemHalves.macKey)),
    'hunter2'
  );
  await assert.rejects(
    () => decryptBw(payload.name, oldItemHalves.encKey, oldItemHalves.macKey),
    'the old item key must not read the rotated payload'
  );

  // Values that were never encrypted are left exactly as they were.
  assert.equal(payload.type, 1);
  assert.equal(payload.login.username, 'plain-user');
  assert.deepEqual(payload.tags, ['Work']);
});

test('an item that used the organization key directly gets its own key', async () => {
  const owner = await memberKeyPair();
  const oldOrganizationKey = randomKey();
  const oldHalves = halves(oldOrganizationKey);
  const encryptedNotes = await encryptBw(new TextEncoder().encode('note text'), oldHalves.encKey, oldHalves.macKey);

  const result = await rotateOrganizationKey({
    oldOrganizationKey,
    organizationPrivateKey: null,
    members: [{ userId: 'owner', publicKey: owner.publicKey }],
    // No `key`: this item's payload is protected by the organization key.
    ciphers: [{ id: 'cipher-legacy', key: null, data: { notes: encryptedNotes } }],
  });

  const newOrganizationKey = await unwrapForMember(owner.privateKey, result.memberKeys[0].key);
  const newHalves = halves(newOrganizationKey);
  const itemKey = await decryptBw(result.ciphers[0].key, newHalves.encKey, newHalves.macKey);
  const itemHalves = halves(itemKey);
  assert.notDeepEqual(itemKey, oldOrganizationKey, 'the item no longer shares the organization key');
  assert.equal(
    new TextDecoder().decode(await decryptBw((result.ciphers[0].data as { notes: string }).notes, itemHalves.encKey, itemHalves.macKey)),
    'note text'
  );
  assert.equal(result.organizationPrivateKey, null, 'an organization with no private key stays without one');
});

test('a payload that cannot be read stops the rotation', async () => {
  const owner = await memberKeyPair();
  const oldOrganizationKey = randomKey();
  const oldHalves = halves(oldOrganizationKey);
  // A well-formed encrypted string that was made with another key.
  const otherKey = halves(randomKey());
  const foreign = await encryptBw(new TextEncoder().encode('someone else'), otherKey.encKey, otherKey.macKey);

  const wrappedItemKey = await encryptBw(randomKey(), oldHalves.encKey, oldHalves.macKey);

  await assert.rejects(
    () =>
      rotateOrganizationKey({
        oldOrganizationKey,
        organizationPrivateKey: null,
        members: [{ userId: 'owner', publicKey: owner.publicKey }],
        ciphers: [{ id: 'cipher-1', key: wrappedItemKey, data: { name: foreign } }],
      }),
    /Could not read the encrypted value/,
    'a half-rotated payload must never be produced'
  );
});
