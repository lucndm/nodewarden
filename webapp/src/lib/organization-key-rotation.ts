// Rotating an organization key, on the client.
//
// The server stores key material it cannot read, so the new key is made here
// and every blob it replaces is made here too. A rotation is what makes
// removing a member mean something: a member who left still holds the key they
// unwrapped, so the only way to keep new items away from them is to stop using
// that key.
//
// What has to be replaced:
//
//   the organization private key   re-encrypted under the new organization key
//   each member's organization key wrapped for that member with their RSA key
//   each shared item's item key    re-wrapped under the new organization key
//   each shared item's payload     re-encrypted under the item's new key
//
// The payload matters: re-wrapping an item key around the same item key would
// leave anyone who kept the old organization key able to unwrap it and read
// everything. So every item gets a fresh key and its payload is re-encrypted
// from the old one.
//
// Nothing here talks to the server or holds on to the new key: the caller
// passes the old key in, and gets the blobs to send back. The new key exists
// only for the length of the call.
import { base64ToBytes, bytesToBase64, decryptBw, encryptBw } from './crypto';

/** A member who stays in the organization, with their RSA public key (SPKI, base64). */
export interface RotationMemberInput {
  /** The membership the server stores the wrapped key on. */
  membershipId: string;
  publicKey: string;
}

/** A shared item: its key as the organization key protects it, and its payload. */
export interface RotationCipherInput {
  id: string;
  /** The item key under the old organization key, or null when the item used the organization key directly. */
  key: string | null;
  /**
   * The item's encrypted name and notes. This server keeps them in their own
   * columns, outside the payload, so a rotation that only re-encrypted the
   * payload would leave them under the old key.
   */
  name: string | null;
  notes: string | null;
  /** The stored payload; every encrypted string in it is re-encrypted. */
  data: Record<string, unknown>;
  /**
   * The item's attachments. Each attachment has a key of its own, sealed with
   * the item key, so the attachment travels with the item's new key or it
   * stops opening.
   */
  attachments?: RotationAttachmentInput[];
  /** The item's history. Every entry is sealed with the item key as well. */
  versions?: RotationVersionInput[];
}

/** An attachment: its key, sealed with the item key. */
export interface RotationAttachmentInput {
  id: string;
  key: string | null;
}

/**
 * A collection of the organization: its name as the server stores it.
 *
 * The name is sealed with the organization key, so a rotation has to seal it
 * again with the new one. A collection created before the names were
 * encrypted still carries a plain name.
 */
export interface RotationCollectionInput {
  id: string;
  name: string;
}

/** One entry of the item's history, sealed with the item key. */
export interface RotationVersionInput {
  id: string;
  key: string | null;
  name: string | null;
  notes: string | null;
  data: Record<string, unknown>;
}

export interface RotationResult {
  /** The organization private key, re-encrypted under the new organization key. */
  organizationPrivateKey: string | null;
  /** The new organization key, wrapped for each member. */
  memberKeys: Array<{ membershipId: string; key: string }>;
  /** Each collection, with its name sealed with the new organization key. */
  collections: Array<{ id: string; name: string }>;
  /**
   * The collections whose name could not be read with the old key.
   *
   * Their name is kept as it was: it was broken before the rotation, and one
   * unreadable name must not stop the rotation of the whole organization.
   */
  unreadableCollections: number;
  /** Each item with its new key and its re-encrypted name, notes and payload. */
  ciphers: Array<{
    id: string;
    key: string;
    name: string | null;
    notes: string | null;
    data: Record<string, unknown>;
    /** The attachments' keys, re-sealed under the item's new key. */
    attachments: Array<{ id: string; key: string | null }>;
    /** The history entries, re-encrypted under the item's new key. */
    versions: Array<{
      id: string;
      key: string | null;
      name: string | null;
      notes: string | null;
      data: Record<string, unknown>;
    }>;
  }>;
}

/** Bitwarden's shape for an encrypted string: a type, then base64 parts. */
const CIPHER_STRING = /^\d+\.[A-Za-z0-9+/=]+(?:\|[A-Za-z0-9+/=]+)*$/;

function looksLikeCipherString(value: string): boolean {
  return CIPHER_STRING.test(value);
}

function splitKey(raw: Uint8Array): { encKey: Uint8Array; macKey: Uint8Array } {
  if (raw.length !== 64) throw new Error('An organization key must be 64 bytes');
  return { encKey: raw.slice(0, 32), macKey: raw.slice(32) };
}

function randomKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(64));
}

function toBufferSource(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

/**
 * Wraps the organization key for one member with their RSA public key, in the
 * `4.` form the official clients expect.
 */
export async function wrapKeyForMember(organizationKey: Uint8Array, publicKeyBase64: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'spki',
    toBufferSource(base64ToBytes(publicKeyBase64)),
    { name: 'RSA-OAEP', hash: 'SHA-1' },
    false,
    ['encrypt']
  );
  const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, toBufferSource(organizationKey)));
  return `4.${bytesToBase64(wrapped)}`;
}

/**
 * Re-encrypts every encrypted string in a payload from the old item key to the
 * new one.
 *
 * A string that looks encrypted but does not decrypt under the old key stops
 * the rotation instead of being left behind: a payload half under the old key
 * and half under the new one is an item nobody can read.
 */
async function reencryptPayload(
  value: unknown,
  from: { encKey: Uint8Array; macKey: Uint8Array },
  to: { encKey: Uint8Array; macKey: Uint8Array },
  path: string
): Promise<unknown> {
  if (typeof value === 'string') {
    if (!looksLikeCipherString(value)) return value;
    let plain: Uint8Array;
    try {
      plain = await decryptBw(value, from.encKey, from.macKey);
    } catch {
      throw new Error(`Could not read the encrypted value at ${path}`);
    }
    return encryptBw(plain, to.encKey, to.macKey);
  }
  if (Array.isArray(value)) {
    return Promise.all(value.map((entry, index) => reencryptPayload(entry, from, to, `${path}[${index}]`)));
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
      out[key] = await reencryptPayload(entry, from, to, `${path}.${key}`);
    }
    return out;
  }
  return value;
}

/**
 * The key material a new organization needs.
 */
export interface NewOrganizationKeyMaterial {
  /** The organization key, wrapped for the owner in the `4.` form. */
  wrappedKey: string;
  /** The organization's own RSA public key (SPKI, base64). */
  publicKey: string;
  /** The organization's RSA private key, sealed under the organization key. */
  encryptedPrivateKey: string;
  /** The name of the first collection, encrypted with the organization key. */
  encryptedCollectionName: string;
}

/**
 * Makes the key material for a new organization.
 *
 * The server stores what it cannot read, so the keys are made here: the
 * organization gets its own RSA key pair and a 64-byte symmetric key, the
 * symmetric key is wrapped for the owner with the owner's RSA key, and the
 * organization's private key is sealed under the symmetric key.
 *
 * The name of the collection the organization starts with is sealed under the
 * same key: the official clients read a collection name as an encrypted
 * string and stop syncing when it is in plain text.
 *
 * The organization key itself never leaves this function: only its wrapped
 * form does.
 */
export async function createOrganizationKeyMaterial(input: {
  /** The owner's RSA public key (SPKI, base64). */
  ownerPublicKey: string;
  /** The plain name of the collection the organization starts with. */
  collectionName: string;
}): Promise<NewOrganizationKeyMaterial> {
  const organizationKey = randomKey();
  const keyHalves = splitKey(organizationKey);
  const pair = (await crypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' },
    true,
    ['encrypt', 'decrypt']
  )) as CryptoKeyPair;
  const publicKey = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
  const privateKey = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  return {
    wrappedKey: await wrapKeyForMember(organizationKey, input.ownerPublicKey),
    publicKey: bytesToBase64(publicKey),
    encryptedPrivateKey: await encryptBw(privateKey, keyHalves.encKey, keyHalves.macKey),
    encryptedCollectionName: await encryptBw(
      new TextEncoder().encode(input.collectionName),
      keyHalves.encKey,
      keyHalves.macKey
    ),
  };
}

/**
 * Rotates the organization key and every blob that depends on it.
 *
 * The caller unwraps the old organization key with the owner's own key first;
 * this function never sees the owner's master key or password.
 */
export async function rotateOrganizationKey(input: {
  /** The current organization key, unwrapped: 64 bytes, encryption half then MAC half. */
  oldOrganizationKey: Uint8Array;
  /** The organization private key as stored, or null when the organization has none. */
  organizationPrivateKey: string | null;
  members: RotationMemberInput[];
  ciphers: RotationCipherInput[];
  /** The collections of the organization, with the name as it is stored. */
  collections: RotationCollectionInput[];
}): Promise<RotationResult> {
  const oldKey = splitKey(input.oldOrganizationKey);
  const newOrganizationKey = randomKey();
  const newKey = splitKey(newOrganizationKey);

  // The private key is re-encrypted, not re-generated: it identifies the
  // organization, and only the key that protects it changes.
  let organizationPrivateKey: string | null = null;
  if (input.organizationPrivateKey) {
    const plain = await decryptBw(input.organizationPrivateKey, oldKey.encKey, oldKey.macKey);
    organizationPrivateKey = await encryptBw(plain, newKey.encKey, newKey.macKey);
  }

  const memberKeys: Array<{ membershipId: string; key: string }> = [];
  for (const member of input.members) {
    memberKeys.push({
      membershipId: member.membershipId,
      key: await wrapKeyForMember(newOrganizationKey, member.publicKey),
    });
  }

  // The name of a collection is sealed with the organization key, so it is
  // sealed again with the new one: a name left under the old key is a name
  // the official clients cannot read.
  const collections: RotationResult['collections'] = [];
  let unreadableCollections = 0;
  for (const collection of input.collections) {
    if (!looksLikeCipherString(collection.name)) {
      // A collection created before the names were encrypted still carries a
      // plain name, and it is sealed with the new key as well.
      collections.push({
        id: collection.id,
        name: await encryptBw(new TextEncoder().encode(collection.name), newKey.encKey, newKey.macKey),
      });
      continue;
    }
    let plain: Uint8Array;
    try {
      plain = await decryptBw(collection.name, oldKey.encKey, oldKey.macKey);
    } catch {
      // The name was already broken, before this rotation. It stays as it is:
      // one unreadable name must not stop the rotation of the organization.
      collections.push({ id: collection.id, name: collection.name });
      unreadableCollections += 1;
      continue;
    }
    collections.push({ id: collection.id, name: await encryptBw(plain, newKey.encKey, newKey.macKey) });
  }

  const ciphers: RotationResult['ciphers'] = [];
  for (const cipher of input.ciphers) {
    // An item without its own key used the organization key directly, so its
    // payload is under that key today.
    const oldItemKey = cipher.key
      ? splitKey(await decryptBw(cipher.key, oldKey.encKey, oldKey.macKey))
      : oldKey;
    const newItemKeyRaw = randomKey();
    const newItemKey = splitKey(newItemKeyRaw);
    const newCipherKey = await encryptBw(newItemKeyRaw, newKey.encKey, newKey.macKey);

    // An attachment and a history entry are sealed with the item key, so they
    // are re-sealed with the item's new key. Leaving them behind would keep
    // them readable only by whoever holds the old key.
    const attachments: Array<{ id: string; key: string | null }> = [];
    for (const attachment of cipher.attachments ?? []) {
      attachments.push({
        id: attachment.id,
        key: (await reencryptPayload(
          attachment.key,
          oldItemKey,
          newItemKey,
          `${cipher.id}.attachment.${attachment.id}.key`
        )) as string | null,
      });
    }
    const versions: RotationResult['ciphers'][number]['versions'] = [];
    for (const version of cipher.versions ?? []) {
      versions.push({
        id: version.id,
        // The history entry carries the item's wrapped key, not a payload
        // sealed with the item key, so it follows the item's new key. Its
        // name, notes and payload are sealed with the item key.
        key: newCipherKey,
        name: (await reencryptPayload(
          version.name,
          oldItemKey,
          newItemKey,
          `${cipher.id}.version.${version.id}.name`
        )) as string | null,
        notes: (await reencryptPayload(
          version.notes,
          oldItemKey,
          newItemKey,
          `${cipher.id}.version.${version.id}.notes`
        )) as string | null,
        data: (await reencryptPayload(
          version.data,
          oldItemKey,
          newItemKey,
          `${cipher.id}.version.${version.id}.data`
        )) as Record<string, unknown>,
      });
    }

    ciphers.push({
      id: cipher.id,
      key: newCipherKey,
      name: (await reencryptPayload(cipher.name, oldItemKey, newItemKey, `${cipher.id}.name`)) as string | null,
      notes: (await reencryptPayload(cipher.notes, oldItemKey, newItemKey, `${cipher.id}.notes`)) as string | null,
      data: (await reencryptPayload(cipher.data, oldItemKey, newItemKey, cipher.id)) as Record<string, unknown>,
      attachments,
      versions,
    });
  }

  return { organizationPrivateKey, memberKeys, collections, unreadableCollections, ciphers };
}

/**
 * Opens the organization key the current member holds, which is the step
 * before any rotation.
 *
 * The organization key is wrapped for the member with their RSA public key, and
 * the member's RSA private key is stored encrypted under their own vault key.
 * Opening it therefore takes two steps, and both of them are the member's own
 * key material: the server is not involved and could not help.
 */
export async function openOrganizationKey(input: {
  /** The member's RSA private key, as stored: encrypted under their vault key. */
  encryptedPrivateKey: string;
  /** The member's vault encryption and MAC halves. */
  userEncKey: Uint8Array;
  userMacKey: Uint8Array;
  /** The organization key as stored for this member: the `4.` RSA form. */
  wrappedOrganizationKey: string;
}): Promise<Uint8Array> {
  if (!input.wrappedOrganizationKey.startsWith('4.')) {
    throw new Error('The organization key is not wrapped for this member');
  }

  const pkcs8 = await decryptBw(input.encryptedPrivateKey, input.userEncKey, input.userMacKey);
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    toBufferSource(pkcs8),
    { name: 'RSA-OAEP', hash: 'SHA-1' },
    false,
    ['decrypt']
  );
  const wrapped = base64ToBytes(input.wrappedOrganizationKey.slice(2));
  const raw = new Uint8Array(
    await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, toBufferSource(wrapped))
  );
  if (raw.length !== 64) throw new Error('The organization key has an unexpected length');
  return raw;
}

/**
 * Runs a rotation end to end: open the key this member holds, make the new key
 * material, and hand it to the server.
 *
 * The caller supplies the organization, its remaining members and its shared
 * items as the server gave them. The new key exists only inside this call.
 */
export async function applyOrganizationKeyRotation(input: {
  authedFetch: (input: string, init?: RequestInit) => Promise<Response>;
  organization: { id: string; wrappedKey: string };
  /** The current member's RSA private key, encrypted under their vault key. */
  encryptedPrivateKey: string;
  userEncKey: Uint8Array;
  userMacKey: Uint8Array;
  /** The organization private key as stored, or null. */
  organizationPrivateKey: string | null;
  members: RotationMemberInput[];
  ciphers: RotationCipherInput[];
  /** The collections of the organization, with the name as it is stored. */
  collections: RotationCollectionInput[];
}): Promise<{ members: number; ciphers: number; collections: number; rotatedAt: string }> {
  const oldOrganizationKey = await openOrganizationKey({
    encryptedPrivateKey: input.encryptedPrivateKey,
    userEncKey: input.userEncKey,
    userMacKey: input.userMacKey,
    wrappedOrganizationKey: input.organization.wrappedKey,
  });

  const rotated = await rotateOrganizationKey({
    oldOrganizationKey,
    organizationPrivateKey: input.organizationPrivateKey,
    members: input.members,
    ciphers: input.ciphers,
    collections: input.collections,
  });

  const response = await input.authedFetch(
    `/api/organizations/${encodeURIComponent(input.organization.id)}/rotate-key`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        privateKey: rotated.organizationPrivateKey,
        members: rotated.memberKeys,
        // The collection names travel with the keys: this is the request that
        // replaces the key, and a name left under the old key is a name the
        // clients cannot read.
        collections: rotated.collections,
        ciphers: rotated.ciphers.map((entry) => ({
          id: entry.id,
          key: entry.key,
          name: entry.name,
          notes: entry.notes,
          data: JSON.stringify(entry.data),
          attachments: entry.attachments.map((attachment) => ({
            id: attachment.id,
            key: attachment.key,
          })),
          versions: entry.versions.map((version) => ({
            id: version.id,
            key: version.key,
            name: version.name,
            notes: version.notes,
            data: JSON.stringify(version.data),
          })),
        })),
      }),
    }
  );
  if (!response.ok) {
    throw new Error(`Rotation failed: ${response.status}`);
  }
  return (await response.json()) as { members: number; ciphers: number; collections: number; rotatedAt: string };
}
