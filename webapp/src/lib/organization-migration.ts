// Moving a personal vault into an organization.
//
// The server cannot read the vault, so the move happens here: every folder
// becomes a collection, and every item is re-encrypted under the organization
// key before it is handed over. An item that is already in the organization
// is left alone, so the move can be run again after a failure without
// touching what already moved.
//
// The steps are the same as a key rotation, with one difference: the old key
// is the member's own vault key and the new key is the organization key.
import { base64ToBytes, decryptBw, encryptBw } from './crypto';
import { openOrganizationKey } from './organization-key-rotation';
import type { AuthedFetch } from './api/shared';

/** The collection the items without a folder end up in. */
export const MIGRATION_GENERAL_COLLECTION = 'General';

/** A folder as the server stores it: the name is sealed with the vault key. */
export interface MigrationFolder {
  id: string;
  name: string | null;
}

/** An item as the server stores it, with the blobs sealed with the item key. */
export interface MigrationItem {
  id: string;
  /** The item key, wrapped for the vault key; null when it used the vault key directly. */
  key: string | null;
  name: string | null;
  notes: string | null;
  /** The folder the item sits in, if any. */
  folderId: string | null;
  /** The stored payload: the fields that carry the item's own secrets. */
  fields: Record<string, unknown>;
  /** The attachments, each with a key sealed with the item key. */
  attachments: Array<{ id: string; key: string | null }>;
  /** The item's history, sealed with the item key. */
  versions: Array<{
    id: string;
    key: string | null;
    name: string | null;
    notes: string | null;
    data: Record<string, unknown>;
  }>;
}

export interface MigrationProgress {
  step: 'collections' | 'items' | 'done';
  done: number;
  total: number;
  /** What is being moved, for the progress line. */
  label: string;
}

export interface MigrationResult {
  /** The collections that were created. */
  collections: number;
  /** The items that moved. */
  items: number;
  /** What did not move, and why. */
  failed: Array<{ id: string; reason: string }>;
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

/**
 * Re-encrypts every encrypted string in a payload from one key to another.
 *
 * A string that looks encrypted but does not decrypt under the old key stops
 * the move: a payload half under the old key and half under the new one is an
 * item nobody can read.
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
 * The item's history, fetched for the items that have one.
 *
 * The history is sealed with the item key, so it has to travel with the item.
 * The list gives the ids; the full entry carries the payload that has to be
 * re-encrypted.
 */
async function loadItemHistory(
  authedFetch: AuthedFetch,
  itemId: string
): Promise<MigrationItem['versions']> {
  const listResponse = await authedFetch(`/api/ciphers/${encodeURIComponent(itemId)}/versions`);
  if (!listResponse.ok) return [];
  const list = (await listResponse.json()) as { data?: Array<{ id?: string }> };
  const ids = (list.data ?? []).map((entry) => String(entry.id || '')).filter(Boolean);
  const versions: MigrationItem['versions'] = [];
  for (const versionId of ids) {
    const response = await authedFetch(
      `/api/ciphers/${encodeURIComponent(itemId)}/versions/${encodeURIComponent(versionId)}`
    );
    if (!response.ok) continue;
    const version = (await response.json()) as {
      id?: string;
      key?: string | null;
      name?: string | null;
      notes?: string | null;
      data?: unknown;
    };
    if (!version.id) continue;
    versions.push({
      id: version.id,
      key: version.key ?? null,
      name: version.name ?? null,
      notes: version.notes ?? null,
      data: (version.data ?? {}) as Record<string, unknown>,
    });
  }
  return versions;
}

/**
 * The fields of an item that make up its payload.
 *
 * The server keeps the name, the notes and the key in columns of their own
 * and everything else in the payload, so these are the fields that travel
 * with the item when it moves.
 */
const CIPHER_COLUMN_FIELDS = new Set([
  'id',
  'userId',
  'type',
  'folderId',
  'name',
  'notes',
  'favorite',
  'reprompt',
  'key',
  'attachments',
  'createdAt',
  'creationDate',
  'updatedAt',
  'revisionDate',
  'archivedAt',
  'archivedDate',
  'deletedAt',
  'deletedDate',
  'organizationId',
  'collectionIds',
  'object',
]);

export function cipherPayloadFields(cipher: object): Record<string, unknown> {
  const fields: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(cipher)) {
    if (CIPHER_COLUMN_FIELDS.has(key)) continue;
    fields[key] = value;
  }
  return fields;
}

/**
 * Reads an item as the server stores it, so a move can be retried against
 * the current copy instead of the one it started from.
 */
async function loadItem(authedFetch: AuthedFetch, itemId: string): Promise<MigrationItem | null> {
  const response = await authedFetch(`/api/ciphers/${encodeURIComponent(itemId)}`);
  if (!response.ok) return null;
  const cipher = (await response.json()) as Record<string, unknown>;
  if (!cipher || !cipher.id) return null;
  return {
    id: String(cipher.id),
    key: typeof cipher.key === 'string' ? cipher.key : null,
    name: typeof cipher.name === 'string' ? cipher.name : null,
    notes: typeof cipher.notes === 'string' ? cipher.notes : null,
    folderId: typeof cipher.folderId === 'string' ? cipher.folderId : null,
    fields: cipherPayloadFields(cipher),
    attachments: (Array.isArray(cipher.attachments) ? cipher.attachments : [])
      .map((attachment) => ({
        id: String((attachment as Record<string, unknown>)?.id || ''),
        key: typeof (attachment as Record<string, unknown>)?.key === 'string'
          ? ((attachment as Record<string, unknown>).key as string)
          : null,
      }))
      .filter((attachment) => !!attachment.id),
    versions: [],
  };
}

/**
 * Moves one item into the organization.
 *
 * The item gets a fresh key wrapped for the organization, its payload is
 * re-encrypted with it, and its attachments and history are re-sealed.
 */
async function shareItem(
  input: { authedFetch: AuthedFetch; organization: { id: string; wrappedKey: string } },
  item: MigrationItem,
  organizationHalves: { encKey: Uint8Array; macKey: Uint8Array },
  userEnc: Uint8Array,
  userMac: Uint8Array,
  collectionIds: string[]
): Promise<{ ok: boolean; reason: string; conflict: boolean }> {
  const oldItemKey = item.key
    ? splitKey(await decryptBw(item.key, userEnc, userMac))
    : { encKey: userEnc, macKey: userMac };
  const newItemKeyRaw = randomKey();
  const newItemKey = splitKey(newItemKeyRaw);
  const newItemKeySealed = await encryptBw(newItemKeyRaw, organizationHalves.encKey, organizationHalves.macKey);

  const name = item.name
    ? ((await reencryptPayload(item.name, oldItemKey, newItemKey, `${item.id}.name`)) as string)
    : null;
  const notes = item.notes
    ? ((await reencryptPayload(item.notes, oldItemKey, newItemKey, `${item.id}.notes`)) as string)
    : null;
  const fields = (await reencryptPayload(item.fields, oldItemKey, newItemKey, item.id)) as Record<string, unknown>;
  // The tags were the personal folders; a shared item's collections are its
  // place now.
  if (Array.isArray(fields.tags)) fields.tags = [];

  // The attachments and the history are sealed with the item key too, so they
  // are re-sealed with the new one. The history carries the item's wrapped
  // key, which becomes the new one.
  const attachments = await Promise.all(
    (item.attachments ?? []).map(async (attachment) => ({
      id: attachment.id,
      key: attachment.key
        ? ((await reencryptPayload(
            attachment.key,
            oldItemKey,
            newItemKey,
            `${item.id}.attachment.${attachment.id}.key`
          )) as string)
        : null,
    }))
  );
  const history = item.versions?.length ? item.versions : await loadItemHistory(input.authedFetch, item.id);
  const versions = await Promise.all(
    history.map(async (version) => ({
      id: version.id,
      key: newItemKeySealed,
      name: version.name
        ? ((await reencryptPayload(
            version.name,
            oldItemKey,
            newItemKey,
            `${item.id}.version.${version.id}.name`
          )) as string)
        : null,
      notes: version.notes
        ? ((await reencryptPayload(
            version.notes,
            oldItemKey,
            newItemKey,
            `${item.id}.version.${version.id}.notes`
          )) as string)
        : null,
      data: (await reencryptPayload(
        version.data,
        oldItemKey,
        newItemKey,
        `${item.id}.version.${version.id}.data`
      )) as Record<string, unknown>,
    }))
  );

  const response = await input.authedFetch(`/api/ciphers/${encodeURIComponent(item.id)}/share`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      ...fields,
      id: item.id,
      name,
      notes,
      // The payload travels as the fields it is made of. The nested form the
      // official clients use is not sent, so nothing that was sealed with the
      // old key is left behind.
      data: null,
      key: newItemKeySealed,
      organizationId: input.organization.id,
      collectionIds,
      attachments,
      versions,
    }),
  });
  if (response.ok) return { ok: true, reason: '', conflict: false };
  const detail = await response.text().catch(() => '');
  return {
    ok: false,
    reason: `The item was not shared (${response.status})${detail ? `: ${detail.slice(0, 200)}` : ''}`,
    // The server refuses a write whose copy is older than the one it holds.
    conflict: response.status === 400 && /out of date/i.test(detail),
  };
}

/**
 * Moves a personal vault into an organization.
 *
 * The organization key is opened with the member's own key, the folders
 * become collections, and the items are re-encrypted and shared one by one.
 * An item that cannot be moved is reported and the move continues: a half
 * moved vault is still a readable vault.
 */
export async function migratePersonalVaultIntoOrganization(input: {
  authedFetch: AuthedFetch;
  /** The member's vault key halves, base64. */
  userEncKey: string;
  userMacKey: string;
  /** The member's RSA private key, encrypted under their vault key. */
  encryptedPrivateKey: string;
  organization: { id: string; wrappedKey: string };
  folders: MigrationFolder[];
  items: MigrationItem[];
  /** The collections the organization already has, so a second run reuses them. */
  existingCollections?: Array<{ id: string; name: string | null }>;
  onProgress?: (progress: MigrationProgress) => void;
}): Promise<MigrationResult> {
  const userEnc = base64ToBytes(input.userEncKey);
  const userMac = base64ToBytes(input.userMacKey);
  const organizationKey = await openOrganizationKey({
    encryptedPrivateKey: input.encryptedPrivateKey,
    userEncKey: userEnc,
    userMacKey: userMac,
    wrappedOrganizationKey: input.organization.wrappedKey,
  });
  const organizationHalves = splitKey(organizationKey);

  const result: MigrationResult = { collections: 0, items: 0, failed: [] };

  // The collections the organization already has, by their plain name. A
  // second run reuses them instead of making copies.
  const collectionByName = new Map<string, string>();
  for (const collection of input.existingCollections ?? []) {
    if (!collection.name) continue;
    let plain: string;
    try {
      plain = new TextDecoder().decode(
        await decryptBw(collection.name, organizationHalves.encKey, organizationHalves.macKey)
      );
    } catch {
      continue;
    }
    collectionByName.set(plain, collection.id);
  }

  const createCollection = async (plainName: string): Promise<string | null> => {
    const existing = collectionByName.get(plainName);
    if (existing) return existing;
    const sealedName = await encryptBw(
      new TextEncoder().encode(plainName),
      organizationHalves.encKey,
      organizationHalves.macKey
    );
    const response = await input.authedFetch(
      `/api/organizations/${encodeURIComponent(input.organization.id)}/collections`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: sealedName }),
      }
    );
    if (!response.ok) return null;
    const body = (await response.json()) as { id?: string };
    if (!body.id) return null;
    collectionByName.set(plainName, body.id);
    result.collections += 1;
    return body.id;
  };

  // The folders become collections.
  const collectionByFolder = new Map<string, string>();
  for (const folder of input.folders) {
    input.onProgress?.({ step: 'collections', done: result.collections, total: input.folders.length, label: folder.id });
    let plainName: string;
    try {
      plainName = folder.name ? new TextDecoder().decode(await decryptBw(folder.name, userEnc, userMac)) : '';
    } catch (error) {
      result.failed.push({
        id: folder.id,
        reason: error instanceof Error ? error.message : 'The folder name could not be read',
      });
      continue;
    }
    if (!plainName) continue;
    const collectionId = await createCollection(plainName);
    if (!collectionId) {
      result.failed.push({ id: folder.id, reason: 'The collection was not created' });
      continue;
    }
    collectionByFolder.set(folder.id, collectionId);
  }

  // The items without a folder share one collection.
  const generalCollectionId = await createCollection(MIGRATION_GENERAL_COLLECTION);

  // The items move one by one. Each one gets a fresh item key, wrapped for
  // the organization, and its payload is re-encrypted with it.
  for (const item of input.items) {
    input.onProgress?.({
      step: 'items',
      done: result.items + result.failed.length,
      total: input.items.length,
      label: item.id,
    });
    try {
      // The item's collection is the one its folder became. A folder whose
      // collection could not be made leaves its item without a place, so the
      // item goes to the general collection instead of staying behind.
      const fromFolder = item.folderId ? collectionByFolder.get(item.folderId) : undefined;
      const place = fromFolder ? [fromFolder] : generalCollectionId ? [generalCollectionId] : [];
      if (!place.length) {
        result.failed.push({ id: item.id, reason: 'No collection to put the item in' });
        continue;
      }

      const shared = await shareItem(input, item, organizationHalves, userEnc, userMac, place);
      if (shared.ok) {
        result.items += 1;
        continue;
      }
      if (shared.conflict) {
        // The item changed while the move was running. The current copy is
        // read and moved instead, so a newer edit is not overwritten with the
        // older one.
        const fresh = await loadItem(input.authedFetch, item.id);
        if (fresh) {
          const again = await shareItem(input, fresh, organizationHalves, userEnc, userMac, place);
          if (again.ok) {
            result.items += 1;
            continue;
          }
          result.failed.push({ id: item.id, reason: again.reason });
          continue;
        }
      }
      result.failed.push({ id: item.id, reason: shared.reason });
    } catch (error) {
      result.failed.push({
        id: item.id,
        reason: error instanceof Error ? error.message : 'The item could not be read',
      });
    }
  }

  input.onProgress?.({ step: 'done', done: result.items, total: input.items.length, label: '' });
  return result;
}
