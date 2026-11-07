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
import { applyOrganizationKeyRotation, openOrganizationKey, rotateOrganizationKey } from '../webapp/src/lib/organization-key-rotation';

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
      { membershipId: 'owner', publicKey: owner.publicKey },
      { membershipId: 'member', publicKey: member.publicKey },
    ],
    ciphers: [
      {
        id: 'cipher-1',
        key: await encryptBw(oldItemKey, oldKeyHalves.encKey, oldKeyHalves.macKey),
        name: encryptedName,
        notes: null,
        data: {
          type: 1,
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
    login: { username: string; password: string };
    tags: string[];
  };
  assert.ok(result.ciphers[0].name, 'the name is re-encrypted with the payload');
  assert.equal(
    new TextDecoder().decode(await decryptBw(result.ciphers[0].name!, newItemHalves.encKey, newItemHalves.macKey)),
    'Shared login'
  );
  assert.equal(
    new TextDecoder().decode(await decryptBw(payload.login.password, newItemHalves.encKey, newItemHalves.macKey)),
    'hunter2'
  );
  await assert.rejects(
    () => decryptBw(result.ciphers[0].name!, oldItemHalves.encKey, oldItemHalves.macKey),
    'the old item key must not read the rotated name'
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
    members: [{ membershipId: 'owner', publicKey: owner.publicKey }],
    // No `key`: this item's payload is protected by the organization key.
    ciphers: [{ id: 'cipher-legacy', key: null, name: null, notes: encryptedNotes, data: {} }],
  });

  const newOrganizationKey = await unwrapForMember(owner.privateKey, result.memberKeys[0].key);
  const newHalves = halves(newOrganizationKey);
  const itemKey = await decryptBw(result.ciphers[0].key, newHalves.encKey, newHalves.macKey);
  const itemHalves = halves(itemKey);
  assert.notDeepEqual(itemKey, oldOrganizationKey, 'the item no longer shares the organization key');
  assert.ok(result.ciphers[0].notes);
  assert.equal(
    new TextDecoder().decode(await decryptBw(result.ciphers[0].notes!, itemHalves.encKey, itemHalves.macKey)),
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
        members: [{ membershipId: 'owner', publicKey: owner.publicKey }],
        ciphers: [{ id: 'cipher-1', key: wrappedItemKey, name: foreign, notes: null, data: {} }],
      }),
    /Could not read the encrypted value/,
    'a half-rotated payload must never be produced'
  );
});

test('a member opens the organization key with their own private key', async () => {
  const pair = (await subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' },
    true,
    ['encrypt', 'decrypt']
  )) as CryptoKeyPair;
  const publicKeyB64 = bytesToBase64(new Uint8Array(await subtle.exportKey('spki', pair.publicKey)));
  const privateKeyPkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', pair.privateKey));

  // What the server stores for this member: their private key under their own
  // vault key, and the organization key wrapped with their public key.
  const userKey = halves(randomKey());
  const encryptedPrivateKey = await encryptBw(privateKeyPkcs8, userKey.encKey, userKey.macKey);
  const organizationKey = randomKey();
  const wrapped = await (async () => {
    const imported = await subtle.importKey(
      'spki',
      base64ToBytes(publicKeyB64).buffer as ArrayBuffer,
      { name: 'RSA-OAEP', hash: 'SHA-1' },
      false,
      ['encrypt']
    );
    const blob = new Uint8Array(
      await subtle.encrypt({ name: 'RSA-OAEP' }, imported, organizationKey.buffer as ArrayBuffer)
    );
    return `4.${bytesToBase64(blob)}`;
  })();

  const opened = await openOrganizationKey({
    encryptedPrivateKey,
    userEncKey: userKey.encKey,
    userMacKey: userKey.macKey,
    wrappedOrganizationKey: wrapped,
  });
  assert.deepEqual(opened, organizationKey, 'the member opens the key that was wrapped for them');
});

test('someone else cannot open it', async () => {
  const ownerPair = (await subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' },
    true,
    ['encrypt', 'decrypt']
  )) as CryptoKeyPair;
  const strangerKeys = await memberKeyPair();
  const ownerPublic = new Uint8Array(await subtle.exportKey('spki', ownerPair.publicKey));
  const strangerPrivate = new Uint8Array(await subtle.exportKey('pkcs8', strangerKeys.privateKey));

  const userKey = halves(randomKey());
  // The blob is wrapped for the owner, but the stranger's own private key is
  // what the server would hand back for them.
  const organizationKey = randomKey();
  const importedOwner = await subtle.importKey(
    'spki',
    ownerPublic.buffer as ArrayBuffer,
    { name: 'RSA-OAEP', hash: 'SHA-1' },
    false,
    ['encrypt']
  );
  const wrapped = `4.${bytesToBase64(
    new Uint8Array(await subtle.encrypt({ name: 'RSA-OAEP' }, importedOwner, organizationKey.buffer as ArrayBuffer))
  )}`;
  const strangerEncryptedPrivateKey = await encryptBw(strangerPrivate, userKey.encKey, userKey.macKey);

  await assert.rejects(
    () =>
      openOrganizationKey({
        encryptedPrivateKey: strangerEncryptedPrivateKey,
        userEncKey: userKey.encKey,
        userMacKey: userKey.macKey,
        wrappedOrganizationKey: wrapped,
      }),
    'the key wrapped for one member must not open for another'
  );
});

test('a key that is not wrapped for the member is refused instead of guessed', async () => {
  await assert.rejects(
    () =>
      openOrganizationKey({
        encryptedPrivateKey: '2.a|b|c',
        userEncKey: new Uint8Array(32),
        userMacKey: new Uint8Array(32),
        // A symmetric blob is not a wrapped organization key.
        wrappedOrganizationKey: '2.a|b|c',
      }),
    /not wrapped for this member/
  );
});

test('the whole rotation runs through the real endpoint', async () => {
  const { DatabaseSync } = await import('node:sqlite');
  const { sqliteD1 } = await import('./sqlite-d1');
  const { ensureStorageSchema } = await import('../src/services/storage-schema');
  const { StorageService } = await import('../src/services/storage');
  const { handleAuthenticatedRoute } = await import('../src/router-authenticated');

  const db = new DatabaseSync(':memory:');
  await ensureStorageSchema(sqliteD1(db));
  const env = { DB: sqliteD1(db) } as never;
  const storage = new StorageService((env as { DB: never }).DB);
  const now = '2026-11-07T00:00:00.000Z';

  // Two members. Each has an RSA key pair and a vault key.
  const owner = await memberKeyPair();
  const member = await memberKeyPair();
  const ownerVault = halves(randomKey());
  const memberVault = halves(randomKey());

  for (const [id, email] of [
    ['user-owner', 'owner@example.test'],
    ['user-member', 'member@example.test'],
  ]) {
    await storage.createUser({
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
      kdfMemory: null,
      kdfParallelism: null,
      securityStamp: 'stamp',
      role: 'user',
      status: 'active',
      verifyDevices: false,
      totpSecret: null,
      totpRecoveryCode: null,
      yubikeyKey1: null,
      yubikeyKey2: null,
      yubikeyKey3: null,
      yubikeyKey4: null,
      yubikeyKey5: null,
      yubikeyNfc: false,
      apiKey: null,
      userKeyId: null,
      createdAt: now,
      updatedAt: now,
    } as never);
  }

  // The organization as the first rotation of the project would have made it.
  const organizationKey = randomKey();
  const organizationHalves = halves(organizationKey);
  const wrapFor = async (publicKey: string, key: Uint8Array) => {
    const imported = await subtle.importKey(
      'spki',
      base64ToBytes(publicKey).buffer as ArrayBuffer,
      { name: 'RSA-OAEP', hash: 'SHA-1' },
      false,
      ['encrypt']
    );
    const blob = new Uint8Array(
      await subtle.encrypt({ name: 'RSA-OAEP' }, imported, key.buffer.slice(0, 64) as ArrayBuffer)
    );
    return `4.${bytesToBase64(blob)}`;
  };
  await env.DB.prepare(
    'INSERT INTO organizations (id, name, private_key, public_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)'
  )
    .bind('org-1', 'Acme', null, owner.publicKey, now, now)
    .run();
  for (const [membershipId, userId, type] of [
    ['ou-owner', 'user-owner', 0],
    ['ou-member', 'user-member', 2],
  ] as const) {
    await env.DB.prepare(
      'INSERT INTO organization_users (id, user_id, org_id, type, status, key, created_at, updated_at) VALUES (?, ?, ?, ?, 2, ?, ?, ?)'
    )
      .bind(
        membershipId,
        userId,
        'org-1',
        type,
        await wrapFor(membershipId === 'ou-owner' ? owner.publicKey : member.publicKey, organizationKey),
        now,
        now
      )
      .run();
  }
  await env.DB.prepare('INSERT INTO collections (id, org_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
    .bind('col-1', 'org-1', 'Shared', now, now)
    .run();
  await env.DB.prepare(
    'INSERT INTO collection_users (collection_id, org_user_id, read_only, hide_passwords, manage) VALUES (?, ?, 0, 0, 0)'
  )
    .bind('col-1', 'ou-owner')
    .run();

  // One shared item under the current organization key.
  const itemKey = randomKey();
  const itemHalves = halves(itemKey);
  const encryptedName = await encryptBw(new TextEncoder().encode('Rotated login'), itemHalves.encKey, itemHalves.macKey);
  await env.DB.prepare(
    'INSERT INTO ciphers (id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, organization_id) ' +
      'VALUES (?, ?, 1, NULL, ?, NULL, 0, ?, 0, ?, ?, ?, ?)'
  )
    .bind(
      'cipher-1',
      'user-owner',
      encryptedName,
      JSON.stringify({ login: {}, tags: [] }),
      await encryptBw(itemKey, organizationHalves.encKey, organizationHalves.macKey),
      now,
      now,
      'org-1'
    )
    .run();
  await env.DB.prepare('INSERT INTO collection_ciphers (cipher_id, collection_id) VALUES (?, ?)')
    .bind('cipher-1', 'col-1')
    .run();

  // The owner's client: open the key, rotate, send. A tiny authedFetch drives
  // the real router, so this is the client library against the real endpoint.
  const authedFetch = async (url: string, init?: RequestInit) => {
    const path = new URL(url, 'https://vault.example.test').pathname;
    const response = await handleAuthenticatedRoute(
      new Request(`https://vault.example.test${url}`, init),
      env,
      'user-owner',
      { id: 'user-owner' } as never,
      path,
      init?.method ?? 'GET'
    );
    assert.ok(response, `no route answered ${path}`);
    return response;
  };

  const result = await applyOrganizationKeyRotation({
    authedFetch,
    organization: {
      id: 'org-1',
      wrappedKey: await wrapFor(owner.publicKey, organizationKey),
    },
    encryptedPrivateKey: await encryptBw(
      new Uint8Array(await subtle.exportKey('pkcs8', owner.privateKey)),
      ownerVault.encKey,
      ownerVault.macKey
    ),
    userEncKey: ownerVault.encKey,
    userMacKey: ownerVault.macKey,
    organizationPrivateKey: null,
    members: [
      { membershipId: 'ou-owner', publicKey: owner.publicKey },
      { membershipId: 'ou-member', publicKey: member.publicKey },
    ],
    ciphers: [
      {
        id: 'cipher-1',
        key: await encryptBw(itemKey, organizationHalves.encKey, organizationHalves.macKey),
        name: encryptedName,
        notes: null,
        data: JSON.parse(
          (await env.DB.prepare('SELECT data FROM ciphers WHERE id = ?').bind('cipher-1').first<{ data: string }>())!.data
        ) as Record<string, unknown>,
      },
    ],
  });
  assert.equal(result.members, 2);
  assert.equal(result.ciphers, 1);

  // The server stored the new material.
  const storedMembership = await storage.getOrganizationUserForUser('org-1', 'user-member');
  assert.ok(storedMembership?.key);
  const storedCipher = await storage.getCipher('cipher-1');
  assert.ok(storedCipher?.key);

  // The member's own client can open the rotated key and read the item.
  const memberVaultKey = await (async () => {
    return memberVault;
  })();
  const memberOpened = await openOrganizationKey({
    encryptedPrivateKey: await encryptBw(
      new Uint8Array(await subtle.exportKey('pkcs8', member.privateKey)),
      memberVaultKey.encKey,
      memberVaultKey.macKey
    ),
    userEncKey: memberVaultKey.encKey,
    userMacKey: memberVaultKey.macKey,
    wrappedOrganizationKey: storedMembership.key,
  });
  const memberHalves = halves(memberOpened);
  const openedItemKey = await decryptBw(storedCipher.key, memberHalves.encKey, memberHalves.macKey);
  const newItemHalves = halves(openedItemKey);
  const storedRow = (await env.DB.prepare('SELECT name FROM ciphers WHERE id = ?')
    .bind('cipher-1')
    .first<{ name: string }>())!;
  assert.equal(
    new TextDecoder().decode(await decryptBw(storedRow.name, newItemHalves.encKey, newItemHalves.macKey)),
    'Rotated login',
    'the member reads the item name after the rotation'
  );

  // The key that was in place before no longer opens anything of the item.
  await assert.rejects(() => decryptBw(storedCipher.key, organizationHalves.encKey, organizationHalves.macKey));
});
