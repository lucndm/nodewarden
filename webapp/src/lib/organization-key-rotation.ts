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
}

export interface RotationResult {
  /** The organization private key, re-encrypted under the new organization key. */
  organizationPrivateKey: string | null;
  /** The new organization key, wrapped for each member. */
  memberKeys: Array<{ membershipId: string; key: string }>;
  /** Each item with its new key and its re-encrypted name, notes and payload. */
  ciphers: Array<{
    id: string;
    key: string;
    name: string | null;
    notes: string | null;
    data: Record<string, unknown>;
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
async function wrapKeyForMember(organizationKey: Uint8Array, publicKeyBase64: string): Promise<string> {
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

  const ciphers: Array<{
    id: string;
    key: string;
    name: string | null;
    notes: string | null;
    data: Record<string, unknown>;
  }> = [];
  for (const cipher of input.ciphers) {
    // An item without its own key used the organization key directly, so its
    // payload is under that key today.
    const oldItemKey = cipher.key
      ? splitKey(await decryptBw(cipher.key, oldKey.encKey, oldKey.macKey))
      : oldKey;
    const newItemKeyRaw = randomKey();
    const newItemKey = splitKey(newItemKeyRaw);
    ciphers.push({
      id: cipher.id,
      key: await encryptBw(newItemKeyRaw, newKey.encKey, newKey.macKey),
      name: (await reencryptPayload(cipher.name, oldItemKey, newItemKey, `${cipher.id}.name`)) as string | null,
      notes: (await reencryptPayload(cipher.notes, oldItemKey, newItemKey, `${cipher.id}.notes`)) as string | null,
      data: (await reencryptPayload(cipher.data, oldItemKey, newItemKey, cipher.id)) as Record<string, unknown>,
    });
  }

  return { organizationPrivateKey, memberKeys, ciphers };
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
}): Promise<{ members: number; ciphers: number; rotatedAt: string }> {
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
  });

  const response = await input.authedFetch(
    `/api/organizations/${encodeURIComponent(input.organization.id)}/rotate-key`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        privateKey: rotated.organizationPrivateKey,
        members: rotated.memberKeys,
        ciphers: rotated.ciphers.map((entry) => ({
          id: entry.id,
          key: entry.key,
          name: entry.name,
          notes: entry.notes,
          data: JSON.stringify(entry.data),
        })),
      }),
    }
  );
  if (!response.ok) {
    throw new Error(`Rotation failed: ${response.status}`);
  }
  return (await response.json()) as { members: number; ciphers: number; rotatedAt: string };
}
