// Item history (the version timeline of one vault item).
//
// The server stores every version of an item as ciphertext and never sees
// plaintext, so the browser decrypts the labels and the snapshots itself.
import { decryptSingleCipher } from './decrypt-cipher';
import type { CipherVersionEntry, CipherVersionSnapshot } from './api/vault';
import type { Cipher } from './types';

export type ItemHistoryVersionKind = 'created' | 'modified';

export interface ItemHistoryEntry {
  id: string;
  cipherId: string;
  versionNo: number;
  kind: ItemHistoryVersionKind;
  createdAt: string;
  revisionDate: string;
  name: string;
}

export interface ItemHistoryVersion extends ItemHistoryEntry {
  type: number;
  notes: string;
  username: string;
  password: string;
  totp: string;
  uris: string[];
}

export type ItemHistoryDiffKey = 'name' | 'username' | 'password' | 'website' | 'notes' | 'totp';

export interface ItemHistoryDiffEntry {
  key: ItemHistoryDiffKey;
  labelKey: string;
  current: string;
  previous: string;
}

// The fields the comparison reports, in the order they are shown.
export const ITEM_HISTORY_FIELDS: Array<{ key: ItemHistoryDiffKey; labelKey: string }> = [
  { key: 'name', labelKey: 'txt_name' },
  { key: 'username', labelKey: 'txt_username' },
  { key: 'password', labelKey: 'txt_password' },
  { key: 'website', labelKey: 'txt_website' },
  { key: 'notes', labelKey: 'txt_notes' },
  { key: 'totp', labelKey: 'txt_totp' },
];

// The label of one timeline row. The version carries the item key that was in
// effect for it, so an older version still decrypts after the key changed.
export async function decryptItemHistoryEntry(
  entry: CipherVersionEntry,
  userEnc: Uint8Array,
  userMac: Uint8Array
): Promise<ItemHistoryEntry> {
  const cipher = await decryptSingleCipher(
    { id: entry.id, type: 1, name: entry.name, key: entry.key },
    userEnc,
    userMac
  );
  return {
    id: entry.id,
    cipherId: entry.cipherId,
    versionNo: Number(entry.versionNo) || 0,
    kind: entry.kind === 'created' ? 'created' : 'modified',
    createdAt: entry.createdAt,
    revisionDate: entry.revisionDate,
    name: cipher.decName || '',
  };
}

// One stored version, decrypted. The encrypted payload holds the same shape as
// a cipher payload, so the shared cipher decryption does the whole job.
export async function decryptItemHistoryVersion(
  version: CipherVersionSnapshot,
  userEnc: Uint8Array,
  userMac: Uint8Array
): Promise<ItemHistoryVersion> {
  let payload: Record<string, unknown> = {};
  try {
    const parsed = JSON.parse(version.data || '{}');
    if (parsed && typeof parsed === 'object') payload = parsed as Record<string, unknown>;
  } catch {
    // An unreadable payload yields an empty snapshot instead of a broken item.
  }
  const cipher = await decryptSingleCipher(
    {
      ...payload,
      id: version.id,
      type: Number(version.type) || 1,
      name: version.name,
      notes: version.notes,
      key: version.key,
      reprompt: Number(version.reprompt) || 0,
    } as Cipher,
    userEnc,
    userMac
  );
  return {
    id: version.id,
    cipherId: version.cipherId,
    versionNo: Number(version.versionNo) || 0,
    kind: version.kind === 'created' ? 'created' : 'modified',
    createdAt: version.createdAt,
    revisionDate: version.revisionDate,
    name: cipher.decName || '',
    type: Number(version.type) || 1,
    notes: cipher.decNotes || '',
    username: cipher.login?.decUsername || '',
    password: cipher.login?.decPassword || '',
    totp: cipher.login?.decTotp || '',
    uris: (cipher.login?.uris || []).map((uri) => uri.decUri || '').filter(Boolean),
  };
}

// The comparable values of the item as it is right now.
export function cipherHistoryValues(cipher: Cipher): Record<ItemHistoryDiffKey, string> {
  return {
    name: cipher.decName || '',
    username: cipher.login?.decUsername || '',
    password: cipher.login?.decPassword || '',
    website: (cipher.login?.uris || []).map((uri) => uri.decUri || '').filter(Boolean).join('\n'),
    notes: cipher.decNotes || '',
    totp: cipher.login?.decTotp || '',
  };
}

// The comparable values of one stored version.
export function versionHistoryValues(version: ItemHistoryVersion): Record<ItemHistoryDiffKey, string> {
  return {
    name: version.name,
    username: version.username,
    password: version.password,
    website: version.uris.filter(Boolean).join('\n'),
    notes: version.notes,
    totp: version.totp,
  };
}

// What the stored version holds compared with the item as it is right now.
export function diffItemHistory(current: Cipher, version: ItemHistoryVersion): ItemHistoryDiffEntry[] {
  const currentValues = cipherHistoryValues(current);
  const versionValues = versionHistoryValues(version);
  return ITEM_HISTORY_FIELDS.filter((field) => currentValues[field.key] !== versionValues[field.key]).map((field) => ({
    key: field.key,
    labelKey: field.labelKey,
    current: currentValues[field.key],
    previous: versionValues[field.key],
  }));
}
