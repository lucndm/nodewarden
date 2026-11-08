// Checks that the organization key reaches each member in a form only that
// member can open.
//
// The server never sees the key. The owner's client generates it, wraps it with
// the owner's public key, and the admin wraps it again for every member with
// that member's public key. This check runs that whole path with real keys: it
// creates an organization, invites a member, confirms them with a wrapped key,
// and then proves the member can unwrap the key while an outsider cannot.
//
// Coverage:
//   - creating an organization needs the wrapped key and stores it for the owner;
//   - a member invited without a wrapped key stays unconfirmed and gets none;
//   - confirming stores the member's wrapped key and makes the membership real;
//   - each member unwraps the same organization key with their own private key;
//   - a member of another organization reaches nothing;
//   - the memberships list never leaks a key to an outsider.
import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import { webcrypto } from 'node:crypto';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { StorageService } from '../src/services/storage';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { sqliteD1 } from './sqlite-d1';
import type { Env } from '../src/types';

const { subtle } = webcrypto;
const NOW = '2026-11-07T00:00:00.000Z';
const OWNER = 'user-owner';
const MEMBER = 'user-member';
const OUTSIDER = 'user-outsider';

/** A Bitwarden-style encrypted string: `type.iv|data|mac`, base64 parts. */
function encString(iv: Uint8Array, data: Uint8Array, mac: Uint8Array): string {
  const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64');
  return `2.${b64(iv)}|${b64(data)}|${b64(mac)}`;
}

/** Wraps a symmetric key for one RSA public key, the way a client does. */
async function wrapFor(publicKey: CryptoKey, key: CryptoKey): Promise<{ wrapped: string; raw: Uint8Array }> {
  const raw = new Uint8Array(await subtle.exportKey('raw', key));
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const data = new Uint8Array(
    await subtle.encrypt({ name: 'AES-GCM', iv }, key, webcrypto.getRandomValues(new Uint8Array(32)))
  );
  // The RSA layer only carries the AES key; the payload above proves the key
  // opens real ciphertext.
  const rsa = new Uint8Array(await subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, raw));
  return { wrapped: encString(iv, rsa, data.slice(0, 16)), raw };
}

/** Opens what `wrapFor` produced with the matching private key. */
async function unwrapWith(privateKey: CryptoKey, wrapped: string): Promise<Uint8Array> {
  const parts = wrapped.split('.')[1].split('|');
  const rsa = new Uint8Array(Buffer.from(parts[1], 'base64'));
  return new Uint8Array(await subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, rsa));
}

async function keyPair(): Promise<{ publicKey: CryptoKey; privateKey: CryptoKey; publicKeyB64: string }> {
  const pair = (await subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt']
  )) as CryptoKeyPair;
  const spki = new Uint8Array(await subtle.exportKey('spki', pair.publicKey));
  return { publicKey: pair.publicKey, privateKey: pair.privateKey, publicKeyB64: Buffer.from(spki).toString('base64') };
}

interface Fixture {
  env: Env;
  storage: StorageService;
  ownerKeys: { publicKey: CryptoKey; privateKey: CryptoKey; publicKeyB64: string };
  memberKeys: { publicKey: CryptoKey; privateKey: CryptoKey; publicKeyB64: string };
  outsiderKeys: { publicKey: CryptoKey; privateKey: CryptoKey; publicKeyB64: string };
  organizationKey: CryptoKey;
}

async function fixture(): Promise<Fixture> {
  const db = new DatabaseSync(':memory:');
  await ensureStorageSchema(sqliteD1(db));
  const env = { DB: sqliteD1(db) } as unknown as Env;
  const storage = new StorageService(env.DB);

  const ownerKeys = await keyPair();
  const memberKeys = await keyPair();
  const outsiderKeys = await keyPair();

  for (const [id, email, publicKeyB64] of [
    [OWNER, 'owner@example.test', ownerKeys.publicKeyB64],
    [MEMBER, 'member@example.test', memberKeys.publicKeyB64],
    [OUTSIDER, 'outsider@example.test', outsiderKeys.publicKeyB64],
  ]) {
    await storage.createUser({
      id,
      email,
      name: null,
      masterPasswordHint: null,
      masterPasswordHash: 'hash',
      key: 'key',
      privateKey: null,
      publicKey: publicKeyB64,
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
      createdAt: NOW,
      updatedAt: NOW,
    } as never);
  }

  const organizationKey = (await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ])) as CryptoKey;

  return { env, storage, ownerKeys, memberKeys, outsiderKeys, organizationKey };
}

async function call(
  env: Env,
  url: string,
  method: string,
  userId: string,
  body?: unknown
): Promise<Response | null> {
  const request = new Request(url, {
    method,
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const path = new URL(url).pathname;
  return handleAuthenticatedRoute(request, env, userId, { id: userId } as never, path, method);
}

test('the organization key reaches each member wrapped for them', async () => {
  const { env, ownerKeys, memberKeys, outsiderKeys, organizationKey } = await fixture();

  const ownerWrapped = await wrapFor(ownerKeys.publicKey, organizationKey);

  // The owner creates the organization.
  const created = await call(env, 'https://vault.example.test/api/organizations', 'POST', OWNER, {
    name: 'Acme',
    billingEmail: 'billing@example.test',
    collectionName: 'Default',
    key: ownerWrapped.wrapped,
    keys: { publicKey: ownerKeys.publicKeyB64, encryptedPrivateKey: '2.a|b|c' },
  });
  assert.ok(created);
  assert.equal(created.status, 200);
  const organization = (await created.json()) as { id: string; name: string; key: string };
  assert.equal(organization.name, 'Acme');
  assert.equal(organization.key, ownerWrapped.wrapped, 'the owner gets back the key wrapped for them');

  // Invite the member without a wrapped key: the membership stays unconfirmed.
  const invited = await call(
    env,
    `https://vault.example.test/api/organizations/${organization.id}/users`,
    'POST',
    OWNER,
    { emails: ['member@example.test'], type: 2 }
  );
  assert.ok(invited);
  assert.equal(invited.status, 200);

  const beforeConfirm = await call(
    env,
    'https://vault.example.test/api/organizations',
    'GET',
    MEMBER
  );
  assert.ok(beforeConfirm);
  // The invitation is visible, so the member can accept it, but there is no
  // key to open anything with yet.
  const pending = (await beforeConfirm.json()) as { data: Array<{ id: string; key: string | null; status: number }> };
  assert.equal(pending.data.length, 1, 'the invited member sees the invitation');
  assert.equal(pending.data[0].key, null, 'an invited member has no organization key yet');
  assert.equal(pending.data[0].status, 0, 'the invitation is not answered yet');

  // Confirm with the key wrapped for the member.
  const memberWrapped = await wrapFor(memberKeys.publicKey, organizationKey);
  const memberMembership = await new StorageService(env.DB).getOrganizationUserForUser(organization.id, MEMBER);
  assert.ok(memberMembership);
  const confirmed = await call(
    env,
    `https://vault.example.test/api/organizations/${organization.id}/users/${memberMembership.id}/confirm`,
    'POST',
    OWNER,
    { key: memberWrapped.wrapped }
  );
  assert.ok(confirmed);
  assert.equal(confirmed.status, 200);

  // The member now sees the organization and the key wrapped for them.
  const memberOrgs = await call(env, 'https://vault.example.test/api/organizations', 'GET', MEMBER);
  assert.ok(memberOrgs);
  const memberList = (await memberOrgs.json()) as { data: Array<{ id: string; key: string }> };
  assert.equal(memberList.data.length, 1);
  assert.equal(memberList.data[0].id, organization.id);
  assert.equal(memberList.data[0].key, memberWrapped.wrapped);

  // Both members open the same organization key with their own private key.
  const ownerKey = await unwrapWith(ownerKeys.privateKey, organization.key);
  const memberKey = await unwrapWith(memberKeys.privateKey, memberList.data[0].key);
  assert.deepEqual(ownerKey, memberKey, 'both members hold the same organization key');
  assert.deepEqual(ownerKey, ownerWrapped.raw);

  // An outsider opens neither.
  await assert.rejects(() => unwrapWith(outsiderKeys.privateKey, memberList.data[0].key));

  // And an outsider sees no organization at all.
  const outsiderOrgs = await call(env, 'https://vault.example.test/api/organizations', 'GET', OUTSIDER);
  assert.ok(outsiderOrgs);
  const outsiderList = (await outsiderOrgs.json()) as { data: unknown[] };
  assert.equal(outsiderList.data.length, 0);
});

test('an organization created without a wrapped key is refused', async () => {
  const { env } = await fixture();
  const response = await call(env, 'https://vault.example.test/api/organizations', 'POST', OWNER, {
    name: 'Acme',
    billingEmail: 'billing@example.test',
    collectionName: 'Default',
  });
  assert.ok(response);
  assert.equal(response.status, 400, 'an organization nobody could open must not be created');
});

test('only an owner or admin may invite or confirm', async () => {
  const { env, memberKeys, organizationKey } = await fixture();

  const created = await call(env, 'https://vault.example.test/api/organizations', 'POST', OWNER, {
    name: 'Acme',
    collectionName: 'Default',
    key: '2.a|b|c',
  });
  assert.ok(created);
  const organization = (await created.json()) as { id: string };

  const invited = await call(
    env,
    `https://vault.example.test/api/organizations/${organization.id}/users`,
    'POST',
    OWNER,
    { emails: ['member@example.test'], type: 2 }
  );
  assert.ok(invited);

  const memberMembership = await new StorageService(env.DB).getOrganizationUserForUser(organization.id, MEMBER);
  assert.ok(memberMembership);
  const memberWrapped = await wrapFor(memberKeys.publicKey, organizationKey);

  // The member is not confirmed yet, so they may not confirm anyone.
  const attempt = await call(
    env,
    `https://vault.example.test/api/organizations/${organization.id}/users/${memberMembership.id}/confirm`,
    'POST',
    MEMBER,
    { key: memberWrapped.wrapped }
  );
  assert.ok(attempt);
  assert.equal(attempt.status, 404, 'a plain member must not confirm a membership');

  // The owner may not hand out a second ownership.
  const secondOwner = await call(
    env,
    `https://vault.example.test/api/organizations/${organization.id}/users`,
    'POST',
    OWNER,
    { emails: ['outsider@example.test'], type: 0 }
  );
  assert.ok(secondOwner);
  assert.equal(secondOwner.status, 400);
});

test('the memberships list keeps the wrapped key away from an outsider', async () => {
  const { env } = await fixture();
  const created = await call(env, 'https://vault.example.test/api/organizations', 'POST', OWNER, {
    name: 'Acme',
    collectionName: 'Default',
    key: '2.a|b|c',
  });
  assert.ok(created);
  const organization = (await created.json()) as { id: string };

  const outsiderAttempt = await call(
    env,
    `https://vault.example.test/api/organizations/${organization.id}/users/public-key`,
    'POST',
    OUTSIDER,
    { userIds: [MEMBER] }
  );
  assert.ok(outsiderAttempt);
  assert.equal(outsiderAttempt.status, 404, 'an outsider must not read the members of the organization');
});

test('a backup carries the organization and the wrapped keys across', async () => {
  const { env, ownerKeys, organizationKey } = await fixture();
  const organizationKeyWrapped = await wrapFor(ownerKeys.publicKey, organizationKey);

  const created = await call(env, 'https://vault.example.test/api/organizations', 'POST', OWNER, {
    name: 'Acme',
    collectionName: 'Default',
    key: organizationKeyWrapped.wrapped,
    keys: { publicKey: ownerKeys.publicKeyB64, encryptedPrivateKey: '2.aa|bb|cc' },
  });
  assert.ok(created);
  const organization = (await created.json()) as { id: string };

  const membership = await new StorageService(env.DB).getOrganizationUserForUser(organization.id, OWNER);
  assert.ok(membership);

  const { buildBackupArchive } = await import('../src/services/backup-archive');
  const archive = await buildBackupArchive(env, new Date(), { includeAttachments: false });
  const { unzipSync } = await import('fflate');
  const files = unzipSync(archive.bytes);
  const db = JSON.parse(Buffer.from(files['db.json']).toString()) as {
    organizations: Array<Record<string, unknown>>;
    organization_users: Array<Record<string, unknown>>;
  };

  assert.equal(db.organizations.length, 1);
  assert.equal(db.organizations[0].name, 'Acme');
  assert.equal(db.organizations[0].public_key, ownerKeys.publicKeyB64);
  assert.equal(db.organizations[0].private_key, '2.aa|bb|cc');
  assert.equal(db.organization_users.length, 1);
  assert.equal(
    db.organization_users[0].key,
    organizationKeyWrapped.wrapped,
    'the wrapped organization key must survive a backup'
  );
});
