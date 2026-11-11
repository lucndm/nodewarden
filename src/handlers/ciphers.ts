import {
  Env,
  Cipher,
  CipherCard,
  CipherIdentity,
  CipherLogin,
  CipherResponse,
  CipherSecureNote,
  CipherSshKey,
  CipherBankAccount,
  CipherDriversLicense,
  CipherPassport,
  Attachment,
  PasswordHistory,
} from '../types';
import { StorageService } from '../services/storage';
import { buildCipherVersionData, isCipherContentUnchanged, isCipherWriteUnchanged } from '../services/storage-cipher-repo';
import {
  notifyUserCipherCreate,
  notifyUserCipherDelete,
  notifyUserCipherUpdate,
  notifyUserCiphersSync,
  notifyUserVaultSync,
} from '../durable/notifications-hub';
import { jsonResponse, errorResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { deleteAllAttachmentsForCipher, deleteAllAttachmentsForCiphers } from './attachments';
import { notifyOrganizationMembers } from './organizations';
import { parsePagination, encodeContinuationToken } from '../utils/pagination';
import { readActingDeviceIdentifier } from '../utils/device';
import { auditRequestMetadata, writeAuditEvent } from '../services/audit-events';
import { readNullableFullUpdateField } from './cipher-full-update';
import { isValidEncString } from '../utils/enc-string';

// CONTRACT:
// Cipher JSON is the highest-risk Bitwarden compatibility surface. Preserve
// unknown/future client fields by default, then override only server-owned
// fields. Any change to cipher response shape must be checked against /api/sync,
// attachments, import/export, and current official clients.
export interface CipherResponseOptions {
  preserveRepairableUris?: boolean;
  validFolderIds?: ReadonlySet<string>;
  /** The collections a shared item sits in; omitted for a personal item. */
  collectionIds?: string[];
}

export function shouldPreserveRepairableCipherUris(request: Request): boolean {
  return request.headers.get('X-NodeWarden-Web') === '1';
}

export function cipherResponseOptionsForRequest(request: Request): CipherResponseOptions {
  return { preserveRepairableUris: shouldPreserveRepairableCipherUris(request) };
}

function normalizeOptionalId(value: unknown): string | null {
  if (value == null) return null;
  const normalized = String(value).trim();
  return normalized ? normalized : null;
}

function normalizeResponseFolderId(folderId: unknown, validFolderIds?: ReadonlySet<string>): string | null {
  const normalized = normalizeOptionalId(folderId);
  if (!normalized) return null;
  return validFolderIds && !validFolderIds.has(normalized) ? null : normalized;
}

function readBooleanOrFallback(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

function buildCipherPermissions(passthrough: Record<string, unknown>): { delete: boolean; restore: boolean } {
  const raw = passthrough.permissions;
  const source = raw && typeof raw === 'object' && !Array.isArray(raw)
    ? raw as Record<string, unknown>
    : null;

  return {
    delete: readBooleanOrFallback(source?.delete, true),
    restore: readBooleanOrFallback(source?.restore, true),
  };
}

export function notifyVaultSyncForRequest(
  request: Request,
  env: Env,
  userId: string,
  revisionDate: string
): void {
  notifyUserVaultSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
}

function notifyCipherCreateForRequest(
  request: Request,
  env: Env,
  cipher: Cipher,
  revisionDate: string
): void {
  notifyUserCipherCreate(env, {
    userId: cipher.userId,
    cipherId: cipher.id,
    revisionDate,
    organizationId: normalizeOptionalId((cipher as any).organizationId ?? null),
    collectionIds: Array.isArray((cipher as any).collectionIds)
      ? (cipher as any).collectionIds.map((id: unknown) => String(id || '').trim()).filter(Boolean)
      : null,
    contextId: readActingDeviceIdentifier(request),
  });
}

export function notifyCipherUpdateForRequest(
  request: Request,
  env: Env,
  cipher: Cipher,
  revisionDate: string
): void {
  notifyUserCipherUpdate(env, {
    userId: cipher.userId,
    cipherId: cipher.id,
    revisionDate,
    organizationId: normalizeOptionalId((cipher as any).organizationId ?? null),
    collectionIds: Array.isArray((cipher as any).collectionIds)
      ? (cipher as any).collectionIds.map((id: unknown) => String(id || '').trim()).filter(Boolean)
      : null,
    contextId: readActingDeviceIdentifier(request),
  });
}

function notifyCipherDeleteForRequest(
  request: Request,
  env: Env,
  cipher: Cipher,
  revisionDate: string
): void {
  notifyUserCipherDelete(env, {
    userId: cipher.userId,
    cipherId: cipher.id,
    revisionDate,
    organizationId: normalizeOptionalId((cipher as any).organizationId ?? null),
    collectionIds: Array.isArray((cipher as any).collectionIds)
      ? (cipher as any).collectionIds.map((id: unknown) => String(id || '').trim()).filter(Boolean)
      : null,
    contextId: readActingDeviceIdentifier(request),
  });
}

function getAliasedProp(source: any, aliases: string[]): { present: boolean; value: any } {
  if (!source || typeof source !== 'object') return { present: false, value: undefined };
  for (const key of aliases) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      return { present: true, value: source[key] };
    }
  }
  return { present: false, value: undefined };
}

function readCipherProp<T = unknown>(source: any, aliases: string[]): { present: boolean; value: T | undefined } {
  return getAliasedProp(source, aliases) as { present: boolean; value: T | undefined };
}

/** The ids of a list of strings, without the empty ones and without repeats. */
function readIdList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const ids = value
    .filter((entry): entry is string => typeof entry === 'string')
    .map((entry) => entry.trim())
    .filter((entry) => entry !== '');
  return [...new Set(ids)];
}

function normalizeCipherTimestamp(value: unknown): string | null {
  if (value == null || value === '') return null;
  const parsed = new Date(String(value));
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString();
}

function readCipherArchivedAt(source: any, fallback: string | null = null): string | null {
  const archived = getAliasedProp(source, ['archivedAt', 'ArchivedAt', 'archivedDate', 'ArchivedDate']);
  return archived.present ? normalizeCipherTimestamp(archived.value) : fallback;
}

function readCipherRevisionDate(source: any): string | null {
  const revision = getAliasedProp(source, ['lastKnownRevisionDate', 'LastKnownRevisionDate']);
  return revision.present ? normalizeCipherTimestamp(revision.value) : null;
}

function isStaleCipherUpdate(existingUpdatedAt: string, clientRevisionDate: string | null): boolean {
  if (!clientRevisionDate) return false;
  const existingTs = Date.parse(existingUpdatedAt);
  const clientTs = Date.parse(clientRevisionDate);
  if (Number.isNaN(existingTs) || Number.isNaN(clientTs)) return false;
  return existingTs > clientTs;
}

function syncCipherComputedAliases(cipher: Cipher): Cipher {
  cipher.archivedDate = cipher.archivedAt ?? null;
  cipher.deletedDate = cipher.deletedAt ?? null;
  return cipher;
}

async function writeCipherAudit(
  storage: StorageService,
  request: Request,
  userId: string,
  action: string,
  metadata: Record<string, unknown>
): Promise<void> {
  await writeAuditEvent(storage, {
    actorUserId: userId,
    action,
    category: 'data',
    level: action.includes('delete') ? 'security' : 'info',
    targetType: 'cipher',
    targetId: typeof metadata.id === 'string' ? metadata.id : null,
    metadata: {
      ...metadata,
      ...auditRequestMetadata(request),
    },
  });
}

function optionalEncString(value: unknown): string | null {
  if (value == null || value === '') return null;
  return isValidEncString(value) ? value.trim() : null;
}

function optionalEncStringWithin(value: unknown, maxLength: number): string | null {
  const normalized = optionalEncString(value);
  if (!normalized) return null;
  return normalized.length <= maxLength ? normalized : null;
}

function shouldAcceptCipherKey(value: unknown): boolean {
  return value == null || value === '' || isValidEncString(value);
}

function normalizeCipherKeyForStorage(value: unknown): string | null {
  return optionalEncString(value);
}

function sanitizeEncryptedObject<T extends Record<string, any>>(
  source: T | null | undefined,
  encryptedKeys: readonly string[] | Record<string, number>
): T | null {
  if (!source || typeof source !== 'object') return source ?? null;
  const next: Record<string, any> = { ...source };
  const entries = Array.isArray(encryptedKeys)
    ? encryptedKeys.map((key) => [key, 10000] as const)
    : Object.entries(encryptedKeys);
  for (const [key, maxLength] of entries) {
    if (!Object.prototype.hasOwnProperty.call(next, key)) continue;
    next[key] = optionalEncStringWithin(next[key], maxLength);
  }
  return next as T;
}

const BANK_ACCOUNT_ENCRYPTED_KEYS = [
  'bankName',
  'nameOnAccount',
  'accountType',
  'accountNumber',
  'routingNumber',
  'branchNumber',
  'pin',
  'swiftCode',
  'iban',
  'bankContactPhone',
] as const;

const DRIVERS_LICENSE_ENCRYPTED_KEYS = [
  'firstName',
  'middleName',
  'lastName',
  'dateOfBirth',
  'licenseNumber',
  'issuingCountry',
  'issuingState',
  'issueDate',
  'expirationDate',
  'issuingAuthority',
  'licenseClass',
] as const;

const PASSPORT_ENCRYPTED_KEYS = [
  'surname',
  'givenName',
  'dateOfBirth',
  'sex',
  'birthPlace',
  'nationality',
  'issuingCountry',
  'passportNumber',
  'passportType',
  'nationalIdentificationNumber',
  'issuingAuthority',
  'issueDate',
  'expirationDate',
] as const;

const CIPHER_TAG_MAX_COUNT = 24;
const CIPHER_TAG_MAX_LENGTH = 64;

/**
 * Normalizes the user-defined tag list stored on a cipher: trims entries,
 * drops empties, dedupes case-insensitively, caps the list. Plaintext by
 * design (server-side metadata); official Bitwarden clients never send this
 * field and ignore it in responses.
 *
 * Ciphertext-shaped entries are dropped before the length cap: older builds
 * wrote a folder's encrypted name into this field, and a client still holding
 * that cached payload must not be able to put it back after it was repaired.
 */
export function normalizeCipherTags(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null;
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of value) {
    if (isValidEncString(raw)) continue;
    const tag = String(raw ?? '').trim().slice(0, CIPHER_TAG_MAX_LENGTH);
    if (!tag) continue;
    const dedupeKey = tag.toLocaleLowerCase();
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    out.push(tag);
    if (out.length >= CIPHER_TAG_MAX_COUNT) break;
  }
  return out.length ? out : null;
}

interface CipherTagResolution {
  kind: 'set' | 'keep' | 'folder';
  tags: string[] | null;
  folderIds: Map<string, string>;
  folderError: Response | null;
}

/**
 * Resolves the tags/folder pair for a cipher write.
 *
 * - Explicit `tags` in the payload (NodeWarden web vault) wins outright.
 * - Otherwise a present `folderId` is official-client "move to folder"
 *   semantics: the folder name becomes the first tag (or, for a null
 *   folderId, the current folder-position tag is removed).
 * - With neither field the existing tags are preserved untouched.
 *
 * When resolved, the cipher's folder_id mirrors the registry id of the first
 * tag, which is what official clients render as the cipher's folder.
 */
async function resolveCipherTags(
  storage: StorageService,
  userId: string,
  input: {
    tagsPresent: boolean;
    rawTags: unknown;
    folderId: string | null;
    folderIdPresent: boolean;
    currentTags: string[] | null;
    currentFolderId?: string | null;
  }
): Promise<CipherTagResolution> {
  let tags: string[] | null;
  if (input.tagsPresent) {
    tags = normalizeCipherTags(input.rawTags);
  } else if (input.folderIdPresent) {
    const previousFolder = input.currentFolderId ? await storage.getFolderForUser(input.currentFolderId, userId) : null;
    const pendingFolderName = previousFolder && !previousFolder.tagName && isValidEncString(previousFolder.name);
    const secondary = pendingFolderName ? input.currentTags || [] : (input.currentTags || []).slice(1);
    if (input.folderId) {
      const folder = await storage.getFolderForUser(input.folderId, userId);
      if (!folder) return { kind: 'set', tags: null, folderIds: new Map(), folderError: errorResponse('Folder not found', 404) };
      // The first tag mirrors the folder position: moving replaces it and
      // keeps the remaining (extra) tags in order.
      // Official clients send only an encrypted folder name; keep their folder
      // assignment without inventing a plaintext tag from ciphertext.
      if (!folder.tagName && isValidEncString(folder.name)) {
        return { kind: 'folder', tags: input.currentFolderId === input.folderId ? input.currentTags : normalizeCipherTags(secondary), folderIds: new Map(), folderError: null };
      }
      tags = normalizeCipherTags([folder.tagName || folder.name, ...secondary]);
    } else {
      tags = normalizeCipherTags(secondary);
    }
  } else {
    return { kind: 'keep', tags: null, folderIds: new Map(), folderError: null };
  }

  if (tags && tags.length) {
    const folderIds = await storage.ensureFoldersForTags(userId, tags);
    return { kind: 'set', tags, folderIds, folderError: null };
  }
  return { kind: 'set', tags: null, folderIds: new Map(), folderError: null };
}

function applyResolvedTagsFolder(cipher: Cipher, resolution: CipherTagResolution): void {
  cipher.tags = resolution.tags;
  const firstTag = resolution.tags && resolution.tags.length ? resolution.tags[0] : null;
  cipher.folderId = firstTag ? resolution.folderIds.get(firstTag) ?? null : null;
}

function normalizeCipherForStorage(cipher: Cipher): Cipher {
  cipher.login = normalizeCipherLoginForStorage(cipher.login);
  cipher.sshKey = normalizeCipherSshKeyForCompatibility(cipher.sshKey);
  cipher.folderId = normalizeOptionalId(cipher.folderId);
  const hasArchivedAt = Object.prototype.hasOwnProperty.call(cipher as object, 'archivedAt');
  cipher.archivedAt = hasArchivedAt
    ? normalizeCipherTimestamp(cipher.archivedAt) ?? null
    : normalizeCipherTimestamp(cipher.archivedDate) ?? null;
  return syncCipherComputedAliases(cipher);
}

export function normalizeCipherLoginForStorage(login: any): any {
  if (!login || typeof login !== 'object') return login ?? null;
  return {
    ...login,
    fido2Credentials: Array.isArray(login.fido2Credentials) ? login.fido2Credentials : null,
  };
}

export function normalizeCipherLoginForCompatibility(
  login: any,
  requiresUriChecksum: boolean = false,
  preserveRepairableUris: boolean = false
): any {
  const normalized = normalizeCipherLoginForStorage(login);
  if (!normalized || typeof normalized !== 'object') return normalized ?? null;
  const next = sanitizeEncryptedObject(normalized, {
    username: 1000,
    password: 5000,
    totp: 1000,
    uri: 10000,
  });
  if (!next) return null;
  next.uris = normalizeCipherLoginUrisForCompatibility(next.uris, {
    requiresUriChecksum,
    preserveRepairableUris,
  });
  next.fido2Credentials = normalizeFido2CredentialsForCompatibility(next.fido2Credentials);
  return next;
}

function normalizeCipherLoginUrisForCompatibility(
  uris: any,
  options: { requiresUriChecksum?: boolean; preserveRepairableUris?: boolean } = {}
): any[] | null {
  if (!Array.isArray(uris) || uris.length === 0) return null;
  const out: any[] = [];

  for (const uri of uris) {
    if (!uri || typeof uri !== 'object') continue;
    const next = sanitizeEncryptedObject(uri, ['uri', 'uriChecksum']);
    if (!next) continue;

    const hasUri = isValidEncString(next.uri);
    const hasChecksum = isValidEncString(next.uriChecksum);
    const hasMatch = next.match != null;

    if (hasUri && String(next.uri).trim().length > 10000) continue;
    if (hasChecksum && String(next.uriChecksum).trim().length > 10000) {
      next.uriChecksum = null;
    }

    if (hasUri && isValidEncString(next.uriChecksum)) {
      out.push(next);
      continue;
    }

    if (hasUri && !hasChecksum) {
      // Official Bitwarden treats UriChecksum as nullable encrypted metadata.
      // Keep the URI intact and let clients that can repair checksums do so.
      out.push({ ...next, uriChecksum: null });
      continue;
    }

    if (hasChecksum || hasMatch) {
      out.push(next);
    }
  }

  return out.length ? out : null;
}

export function validateCipherEncryptedFieldsForCompatibility(cipher: Cipher): string | null {
  if (cipher.name != null && !optionalEncStringWithin(cipher.name, 5000)) return 'Cipher name must be an encrypted string up to 5000 characters.';
  if (cipher.notes != null && !optionalEncStringWithin(cipher.notes, 50000)) return 'Cipher notes must be an encrypted string up to 50000 characters.';

  const login = cipher.login as any;
  if (login && typeof login === 'object') {
    if (login.username != null && !optionalEncStringWithin(login.username, 5000)) return 'Login username must be an encrypted string up to 5000 characters.';
    if (login.password != null && !optionalEncStringWithin(login.password, 50000)) return 'Login password must be an encrypted string up to 50000 characters.';
    if (login.totp != null && !optionalEncStringWithin(login.totp, 5000)) return 'Login TOTP must be an encrypted string up to 5000 characters.';
    if (login.uri != null && !optionalEncStringWithin(login.uri, 20000)) return 'Login URI must be an encrypted string up to 20000 characters.';

    if (Array.isArray(login.uris)) {
      for (const uri of login.uris) {
        if (!uri || typeof uri !== 'object') continue;
        if (uri.uri != null && !optionalEncStringWithin(uri.uri, 20000)) return 'Login URI must be an encrypted string up to 20000 characters.';
        if (uri.uriChecksum != null && !optionalEncStringWithin(uri.uriChecksum, 20000)) return 'Login URI checksum must be an encrypted string up to 20000 characters.';
      }
    }

    // Validate FIDO2 credentials — all encrypted-string fields, both required and optional, must be valid.
    if (Array.isArray(login.fido2Credentials)) {
      const fido2EncryptedKeys = ['credentialId', 'keyType', 'keyAlgorithm', 'keyCurve', 'keyValue', 'rpId', 'counter', 'discoverable', 'userHandle', 'userName', 'rpName', 'userDisplayName'];
      for (const cred of login.fido2Credentials) {
        if (!cred || typeof cred !== 'object') continue;
        for (const key of fido2EncryptedKeys) {
          if (cred[key] != null && !isValidEncString(cred[key])) return `FIDO2 credential ${key} must be an encrypted string.`;
        }
      }
    }
  }

  // Validate SSH key fields — all three must be encrypted strings.
  const sshKey = cipher.sshKey as any;
  if (sshKey && typeof sshKey === 'object') {
    if (sshKey.privateKey != null && !isValidEncString(sshKey.privateKey)) return 'SSH key private key must be an encrypted string.';
    if (sshKey.publicKey != null && !isValidEncString(sshKey.publicKey)) return 'SSH key public key must be an encrypted string.';
    const fingerprint = sshKey.keyFingerprint ?? sshKey.fingerprint;
    if (fingerprint != null && !isValidEncString(fingerprint)) return 'SSH key fingerprint must be an encrypted string.';
  }

  const typedEncryptedObjects: Array<[string, any, readonly string[]]> = [
    ['Bank account', (cipher as any).bankAccount, BANK_ACCOUNT_ENCRYPTED_KEYS],
    ['Drivers license', (cipher as any).driversLicense, DRIVERS_LICENSE_ENCRYPTED_KEYS],
    ['Passport', (cipher as any).passport, PASSPORT_ENCRYPTED_KEYS],
  ];
  for (const [label, source, keys] of typedEncryptedObjects) {
    if (!source || typeof source !== 'object') continue;
    for (const key of keys) {
      if (source[key] != null && !optionalEncStringWithin(source[key], 10000)) {
        return `${label} ${key} must be an encrypted string.`;
      }
    }
  }

  // Validate password history — each password must be an encrypted string.
  if (Array.isArray(cipher.passwordHistory)) {
    for (const entry of cipher.passwordHistory) {
      if (!entry || typeof entry !== 'object') continue;
      if (entry.password != null && !isValidEncString(entry.password)) return 'Password history entry must be an encrypted string.';
    }
  }

  return null;
}

function normalizeFido2CredentialsForCompatibility(credentials: any): any[] | null {
  if (!Array.isArray(credentials) || credentials.length === 0) return null;
  const requiredEncryptedKeys = [
    'credentialId',
    'keyType',
    'keyAlgorithm',
    'keyCurve',
    'keyValue',
    'rpId',
    'counter',
    'discoverable',
  ];
  const optionalEncryptedKeys = ['userHandle', 'userName', 'rpName', 'userDisplayName'];
  const out: any[] = [];

  for (const credential of credentials) {
    if (!credential || typeof credential !== 'object') continue;
    const next: Record<string, any> = { ...credential };
    let valid = true;
    for (const key of requiredEncryptedKeys) {
      if (!isValidEncString(next[key])) {
        valid = false;
        break;
      }
      next[key] = String(next[key]).trim();
    }
    if (!valid) continue;
    for (const key of optionalEncryptedKeys) {
      if (Object.prototype.hasOwnProperty.call(next, key)) {
        next[key] = optionalEncString(next[key]);
      }
    }
    out.push(next);
  }

  return out.length ? out : null;
}

// Android 2026.2.0 requires sshKey.keyFingerprint in sync payloads.
// Keep legacy alias "fingerprint" in parallel for older web payloads.
export function normalizeCipherSshKeyForCompatibility(sshKey: any): any {
  if (!sshKey || typeof sshKey !== 'object') return sshKey ?? null;

  const candidate =
    sshKey.keyFingerprint !== undefined && sshKey.keyFingerprint !== null
      ? sshKey.keyFingerprint
      : sshKey.fingerprint;

  const normalizedFingerprint =
    candidate === undefined || candidate === null
      ? ''
      : String(candidate);

  if (
    !isValidEncString(sshKey.privateKey) ||
    !isValidEncString(sshKey.publicKey) ||
    !isValidEncString(normalizedFingerprint)
  ) {
    return null;
  }

  return {
    ...sshKey,
    privateKey: String(sshKey.privateKey).trim(),
    publicKey: String(sshKey.publicKey).trim(),
    keyFingerprint: normalizedFingerprint,
    fingerprint: normalizedFingerprint,
  };
}

function normalizeCipherSecureNoteForCompatibility(secureNote: any): CipherSecureNote | null {
  if (!secureNote || typeof secureNote !== 'object') return null;
  const type = Number(secureNote?.type ?? secureNote?.Type ?? 0);
  return {
    ...secureNote,
    type: Number.isFinite(type) ? type : 0,
  };
}

// Format attachments for API response
export function formatAttachments(attachments: Attachment[]): any[] | null {
  if (attachments.length === 0) return null;
  const formatted = attachments
    .filter((a) => isValidEncString(a.fileName))
    .map(a => ({
      id: a.id,
      fileName: a.fileName.trim(),
      // Bitwarden clients decode attachment size as string in cipher payloads.
      size: String(Number(a.size) || 0),
      sizeName: a.sizeName,
      key: optionalEncString(a.key),
      url: `/api/ciphers/${a.cipherId}/attachment/${a.id}`,  // Android requires non-null url!
      object: 'attachment',
    }));
  return formatted.length ? formatted : null;
}

function formatAttachmentSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} Bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

interface IncomingAttachmentMetadata {
  id: string;
  fileName?: unknown;
  key?: unknown;
  fileSize?: unknown;
  hasFileName: boolean;
  hasKey: boolean;
  hasFileSize: boolean;
}

function readIncomingAttachmentMetadataMap(
  value: unknown,
  options: { legacyFileNameMap?: boolean } = {}
): IncomingAttachmentMetadata[] {
  if (!value || typeof value !== 'object') return [];
  const out: IncomingAttachmentMetadata[] = [];

  if (Array.isArray(value)) {
    for (const item of value) {
      if (!item || typeof item !== 'object') continue;
      const row = item as Record<string, unknown>;
      const id = String(row.id ?? row.Id ?? '').trim();
      if (!id) continue;
      const fileName = getAliasedProp(row, ['fileName', 'FileName']);
      const key = getAliasedProp(row, ['key', 'Key']);
      const fileSize = getAliasedProp(row, ['fileSize', 'FileSize', 'size', 'Size']);
      out.push({
        id,
        fileName: fileName.value,
        key: key.value,
        fileSize: fileSize.value,
        hasFileName: fileName.present,
        hasKey: key.present,
        hasFileSize: fileSize.present,
      });
    }
    return out;
  }

  for (const [rawId, rawValue] of Object.entries(value as Record<string, unknown>)) {
    const id = String(rawId || '').trim();
    if (!id) continue;

    if (options.legacyFileNameMap && (typeof rawValue === 'string' || rawValue == null)) {
      out.push({
        id,
        fileName: rawValue,
        key: undefined,
        fileSize: undefined,
        hasFileName: rawValue != null,
        hasKey: false,
        hasFileSize: false,
      });
      continue;
    }

    if (!rawValue || typeof rawValue !== 'object') continue;
    const row = rawValue as Record<string, unknown>;
    const fileName = getAliasedProp(row, ['fileName', 'FileName']);
    const key = getAliasedProp(row, ['key', 'Key']);
    const fileSize = getAliasedProp(row, ['fileSize', 'FileSize', 'size', 'Size']);
    out.push({
      id,
      fileName: fileName.value,
      key: key.value,
      fileSize: fileSize.value,
      hasFileName: fileName.present,
      hasKey: key.present,
      hasFileSize: fileSize.present,
    });
  }

  return out;
}

function readIncomingAttachmentMetadata(source: any): IncomingAttachmentMetadata[] {
  const merged = new Map<string, IncomingAttachmentMetadata>();
  const legacy = getAliasedProp(source, ['attachments', 'Attachments']);
  const current = getAliasedProp(source, ['attachments2', 'Attachments2']);

  if (legacy.present) {
    for (const item of readIncomingAttachmentMetadataMap(legacy.value, { legacyFileNameMap: true })) {
      merged.set(item.id, item);
    }
  }

  if (current.present) {
    for (const item of readIncomingAttachmentMetadataMap(current.value)) {
      const previous = merged.get(item.id);
      merged.set(item.id, {
        id: item.id,
        fileName: item.hasFileName ? item.fileName : previous?.fileName,
        key: item.hasKey ? item.key : previous?.key,
        fileSize: item.hasFileSize ? item.fileSize : previous?.fileSize,
        hasFileName: item.hasFileName || previous?.hasFileName || false,
        hasKey: item.hasKey || previous?.hasKey || false,
        hasFileSize: item.hasFileSize || previous?.hasFileSize || false,
      });
    }
  }

  return [...merged.values()];
}

async function syncIncomingAttachmentMetadata(
  storage: StorageService,
  cipherId: string,
  cipherData: any
): Promise<void> {
  const incoming = readIncomingAttachmentMetadata(cipherData);
  if (!incoming.length) return;

  const currentById = new Map((await storage.getAttachmentsByCipher(cipherId)).map((attachment) => [attachment.id, attachment]));
  for (const item of incoming) {
    const attachment = currentById.get(item.id);
    if (!attachment) continue;

    let changed = false;
    if (item.hasFileName) {
      const fileName = String(item.fileName || '').trim();
      if (isValidEncString(fileName) && fileName !== attachment.fileName) {
        attachment.fileName = fileName;
        changed = true;
      }
    }

    if (item.hasKey) {
      const key = optionalEncString(item.key);
      if (key !== attachment.key) {
        attachment.key = key;
        changed = true;
      }
    }

    if (item.hasFileSize) {
      const size = Number(item.fileSize);
      if (Number.isFinite(size) && size >= 0 && size !== Number(attachment.size || 0)) {
        attachment.size = size;
        attachment.sizeName = formatAttachmentSize(size);
        changed = true;
      }
    }

    if (changed) {
      await storage.saveAttachment(attachment);
    }
  }
}

export function applyCipherEmbeddedAttachmentMetadata(cipherData: any, attachments: Attachment[]): Attachment[] {
  const incoming = readIncomingAttachmentMetadata(cipherData);
  if (!incoming.length || !attachments.length) return attachments;

  const incomingById = new Map(incoming.map((item) => [item.id, item]));
  return attachments.map((attachment) => {
    const item = incomingById.get(attachment.id);
    if (!item) return attachment;

    const next: Attachment = { ...attachment };
    if (item.hasFileName) {
      const fileName = String(item.fileName || '').trim();
      if (isValidEncString(fileName)) {
        next.fileName = fileName;
      }
    }
    if (item.hasKey) {
      next.key = optionalEncString(item.key);
    }
    if (item.hasFileSize) {
      const size = Number(item.fileSize);
      if (Number.isFinite(size) && size >= 0) {
        next.size = size;
        next.sizeName = formatAttachmentSize(size);
      }
    }
    return next;
  });
}

function normalizeCipherFieldsForCompatibility(fields: any): any[] | null {
  if (!Array.isArray(fields) || fields.length === 0) return null;
  const out = fields
    .map((field: any) => {
      if (!field || typeof field !== 'object') return null;
      return {
        ...field,
        name: optionalEncString(field.name),
        value: optionalEncString(field.value),
        type: Number(field.type) || 0,
        linkedId: field.linkedId ?? null,
      };
    })
    .filter(Boolean);
  return out.length ? out : null;
}

function normalizePasswordHistoryForCompatibility(passwordHistory: any): PasswordHistory[] | null {
  if (!Array.isArray(passwordHistory) || passwordHistory.length === 0) return null;
  const out = passwordHistory
    .filter((entry: any) => entry && typeof entry === 'object' && isValidEncString(entry.password))
    .map((entry: any) => ({
      ...entry,
      password: String(entry.password).trim(),
      lastUsedDate: normalizeCipherTimestamp(entry.lastUsedDate) ?? new Date().toISOString(),
    }));
  return out.length ? out : null;
}

export function isCipherResponseSyncCompatible(cipher: CipherResponse): boolean {
  return isValidEncString(cipher.name);
}

// Convert internal cipher to API response format.
// Uses opaque passthrough: spreads ALL stored fields (including unknown/future ones),
// then overlays server-computed fields. This ensures new Bitwarden client fields
// survive a round-trip without code changes.
export function cipherToResponse(
  cipher: Cipher,
  attachments: Attachment[] = [],
  options: CipherResponseOptions = {}
): CipherResponse {
  // Strip internal-only fields that must not appear in the API response
  const { userId, createdAt, updatedAt, archivedAt, deletedAt, ...passthrough } = cipher;
  const responseCipherKey = optionalEncString(cipher.key);
  const normalizedLogin = normalizeCipherLoginForCompatibility(
    (passthrough as any).login ?? null,
    !!responseCipherKey,
    !!options.preserveRepairableUris
  );
  const normalizedCard = sanitizeEncryptedObject((passthrough as any).card ?? null, {
    cardholderName: 1000,
    brand: 1000,
    number: 1000,
    expMonth: 1000,
    expYear: 1000,
    code: 1000,
  });
  const normalizedIdentity = sanitizeEncryptedObject((passthrough as any).identity ?? null, [
    'title',
    'firstName',
    'middleName',
    'lastName',
    'address1',
    'address2',
    'address3',
    'city',
    'state',
    'postalCode',
    'country',
    'company',
    'email',
    'phone',
    'ssn',
    'username',
    'passportNumber',
    'licenseNumber',
  ]);
  const normalizedSshKey = normalizeCipherSshKeyForCompatibility((passthrough as any).sshKey ?? null);
  const normalizedBankAccount = sanitizeEncryptedObject(
    (passthrough as any).bankAccount ?? null,
    BANK_ACCOUNT_ENCRYPTED_KEYS
  );
  const normalizedDriversLicense = sanitizeEncryptedObject(
    (passthrough as any).driversLicense ?? null,
    DRIVERS_LICENSE_ENCRYPTED_KEYS
  );
  const normalizedPassport = sanitizeEncryptedObject(
    (passthrough as any).passport ?? null,
    PASSPORT_ENCRYPTED_KEYS
  );
  const responseType = Number(cipher.type) || 1;
  const normalizedSecureNote = responseType === 2
    ? normalizeCipherSecureNoteForCompatibility((passthrough as any).secureNote ?? null) ?? { type: 0 }
    : null;
  const responseAttachments = applyCipherEmbeddedAttachmentMetadata(cipher, attachments);
  const responsePermissions = buildCipherPermissions(passthrough);

    // A shared item names its organization and the collections it sits in; the
  // official clients use both to place and to authorise it.
  const sharedFields = options.collectionIds
    ? { organizationId: normalizeOptionalId(cipher.organizationId), collectionIds: options.collectionIds }
    : {};

return {
    // Pass through ALL stored cipher fields (known + unknown)
    ...passthrough,
    // Server-computed / enforced fields (always override)
    folderId: normalizeResponseFolderId(cipher.folderId, options.validFolderIds),
    type: responseType,
    ...sharedFields,
    organizationId: sharedFields.organizationId ?? normalizeOptionalId((passthrough as any).organizationId ?? null),
    organizationUseTotp: !!((passthrough as any).organizationUseTotp ?? false),
    creationDate: createdAt,
    revisionDate: updatedAt,
    deletedDate: deletedAt,
    archivedDate: archivedAt ?? null,
    edit: readBooleanOrFallback((passthrough as any).edit, true),
    viewPassword: readBooleanOrFallback((passthrough as any).viewPassword, true),
    permissions: responsePermissions,
    object: 'cipherDetails',
    collectionIds: Array.isArray((passthrough as any).collectionIds) ? (passthrough as any).collectionIds : [],
    attachments: formatAttachments(responseAttachments),
    name: isValidEncString(cipher.name) ? cipher.name.trim() : cipher.name,
    notes: optionalEncString(cipher.notes),
    login: normalizedLogin,
    card: normalizedCard,
    identity: normalizedIdentity,
    secureNote: normalizedSecureNote,
    fields: normalizeCipherFieldsForCompatibility((passthrough as any).fields),
    passwordHistory: normalizePasswordHistoryForCompatibility((passthrough as any).passwordHistory),
    sshKey: normalizedSshKey,
    bankAccount: responseType === 6 ? normalizedBankAccount : null,
    driversLicense: responseType === 7 ? normalizedDriversLicense : null,
    passport: responseType === 8 ? normalizedPassport : null,
    key: responseCipherKey,
    data: typeof (passthrough as any).data === 'string' ? (passthrough as any).data : null,
    encryptedFor: (passthrough as any).encryptedFor ?? null,
  };
}

// GET /api/ciphers
export async function handleGetCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const url = new URL(request.url);
  const includeDeleted = url.searchParams.get('deleted') === 'true';
  const pagination = parsePagination(url);

  let filteredCiphers: Cipher[];
  let continuationToken: string | null = null;
  if (pagination) {
    const pageRows = await storage.getCiphersPage(
      userId,
      includeDeleted,
      pagination.limit + 1,
      pagination.offset
    );
    const hasNext = pageRows.length > pagination.limit;
    filteredCiphers = hasNext ? pageRows.slice(0, pagination.limit) : pageRows;
    continuationToken = hasNext ? encodeContinuationToken(pagination.offset + filteredCiphers.length) : null;
  } else {
    // The list shows the items the member may read: their own, plus the shared
    // ones they reach through a collection.
    const ciphers = await storage.getVisibleCiphers(userId);
    filteredCiphers = includeDeleted
      ? ciphers
      : ciphers.filter(c => !c.deletedAt);
  }

  const attachmentsByCipher = await storage.getAttachmentsByCipherIds(
    filteredCiphers.map((cipher) => cipher.id)
  );
  const validFolderIds = new Set((await storage.getAllFolders(userId)).map((folder) => folder.id));
  const collectionIdsByCipher = await storage.getCollectionIdsByCipherIds(
    filteredCiphers.filter((cipher) => !!cipher.organizationId).map((cipher) => cipher.id)
  );

  // Build responses only for the current page to keep pagination cheap.
  const responseOptions = { ...cipherResponseOptionsForRequest(request), validFolderIds };
  const cipherResponses: CipherResponse[] = [];
  for (const cipher of filteredCiphers) {
    const attachments = attachmentsByCipher.get(cipher.id) || [];
    const collectionIds = cipher.organizationId ? collectionIdsByCipher.get(cipher.id) : undefined;
    cipherResponses.push(
      cipherToResponse(cipher, attachments, collectionIds ? { ...responseOptions, collectionIds } : responseOptions)
    );
  }

  return jsonResponse({
    data: cipherResponses,
    object: 'list',
    continuationToken: continuationToken,
  });
}

// GET /api/ciphers/:id
export async function handleGetCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  // getCipherForUser already answers "may this member read it": their own item,
  // or a shared one they reach through a collection.
  const cipher = await storage.getCipherForUser(id, userId);

  if (!cipher) {
    return errorResponse('Cipher not found', 404);
  }

  const attachments = await storage.getAttachmentsByCipher(cipher.id);
  const responseOptions = cipherResponseOptionsForRequest(request);
  const collectionIds = cipher.organizationId
    ? await storage.getCollectionIdsForCipher(cipher.id)
    : undefined;
  return jsonResponse(
    cipherToResponse(
      cipher,
      attachments,
      collectionIds ? { ...responseOptions, collectionIds } : responseOptions
    )
  );
}

async function verifyFolderOwnership(storage: StorageService, folderId: string | null | undefined, userId: string): Promise<boolean> {
  if (!folderId) return true;
  const folder = await storage.getFolderForUser(folderId, userId);
  return !!folder;
}

// POST /api/ciphers
export async function handleCreateCipher(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  // Handle nested cipher object (from some clients)
  // Android client sends PascalCase "Cipher" for organization ciphers
  const cipherData = body.Cipher || body.cipher || body;
  const createFolderId = readCipherProp<string | null>(cipherData, ['folderId', 'FolderId']);
  const createKey = readCipherProp<string | null>(cipherData, ['key', 'Key']);
  const createLogin = readCipherProp<CipherLogin | null>(cipherData, ['login', 'Login']);
  const createCard = readCipherProp<CipherCard | null>(cipherData, ['card', 'Card']);
  const createIdentity = readCipherProp<CipherIdentity | null>(cipherData, ['identity', 'Identity']);
  const createSecureNote = readCipherProp<CipherSecureNote | null>(cipherData, ['secureNote', 'SecureNote']);
  const createSshKey = readCipherProp<CipherSshKey | null>(cipherData, ['sshKey', 'SshKey']);
  const createBankAccount = readCipherProp<CipherBankAccount | null>(cipherData, ['bankAccount', 'BankAccount']);
  const createDriversLicense = readCipherProp<CipherDriversLicense | null>(cipherData, ['driversLicense', 'DriversLicense']);
  const createPassport = readCipherProp<CipherPassport | null>(cipherData, ['passport', 'Passport']);
  const createPasswordHistory = readCipherProp<PasswordHistory[] | null>(cipherData, ['passwordHistory', 'PasswordHistory']);

  if (createKey.present && !shouldAcceptCipherKey(createKey.value)) {
    return errorResponse('Cipher key encryption is not supported by this server. Resync the client and try again.', 400);
  }

  // The official clients name the account they encrypted the item for. An item
  // encrypted for someone else could not be opened by the account storing it,
  // so it is refused, as Vaultwarden does. The web vault does not send the field.
  const encryptedFor = readCipherProp<string | null>(cipherData, ['encryptedFor', 'EncryptedFor']);
  if (encryptedFor.present && encryptedFor.value != null && encryptedFor.value !== userId) {
    return errorResponse('Invalid user cipher', 422);
  }

  const now = new Date().toISOString();
  // Opaque passthrough: spread ALL client fields to preserve unknown/future ones,
  // then override only server-controlled fields.
  const cipher: Cipher = {
    ...cipherData,
    // Server-controlled fields (always override client values)
    id: generateUUID(),
    userId: userId,
    type: Number(cipherData.type) || 1,
    favorite: !!cipherData.favorite,
    reprompt: cipherData.reprompt || 0,
    createdAt: now,
    updatedAt: now,
    archivedAt: readCipherArchivedAt(cipherData, null),
    deletedAt: null,
  };
  cipher.folderId = createFolderId.present ? normalizeOptionalId(createFolderId.value) : normalizeOptionalId(cipher.folderId);
  cipher.key = normalizeCipherKeyForStorage(createKey.present ? createKey.value : cipher.key);
  cipher.login = createLogin.present ? (createLogin.value ?? null) : (cipher.login ?? null);
  cipher.card = createCard.present ? (createCard.value ?? null) : (cipher.card ?? null);
  cipher.identity = createIdentity.present ? (createIdentity.value ?? null) : (cipher.identity ?? null);
  cipher.secureNote = createSecureNote.present ? (createSecureNote.value ?? null) : (cipher.secureNote ?? null);
  cipher.sshKey = createSshKey.present ? (createSshKey.value ?? null) : (cipher.sshKey ?? null);
  cipher.bankAccount = createBankAccount.present ? (createBankAccount.value ?? null) : ((cipher as any).bankAccount ?? null);
  cipher.driversLicense = createDriversLicense.present ? (createDriversLicense.value ?? null) : ((cipher as any).driversLicense ?? null);
  cipher.passport = createPassport.present ? (createPassport.value ?? null) : ((cipher as any).passport ?? null);
  cipher.passwordHistory = createPasswordHistory.present ? (createPasswordHistory.value ?? null) : (cipher.passwordHistory ?? null);
  const createFields = getAliasedProp(cipherData, ['fields', 'Fields']);
  cipher.fields = createFields.present ? (createFields.value ?? null) : (cipher.fields ?? null);
  const createResolution = await resolveCipherTags(storage, userId, {
    tagsPresent: Object.prototype.hasOwnProperty.call(cipherData, 'tags')
      || Object.prototype.hasOwnProperty.call(cipherData, 'Tags'),
    rawTags: cipherData.tags ?? cipherData.Tags,
    folderId: normalizeOptionalId(createFolderId.present ? createFolderId.value : cipher.folderId),
    folderIdPresent: true,
    currentTags: null,
  });
  if (createResolution.folderError) return createResolution.folderError;
  if (createResolution.kind === 'set') {
    applyResolvedTagsFolder(cipher, createResolution);
  }
  // An item in an organization is shared: it belongs to the organization, sits
  // in collections, and only a member who may write those collections can put
  // it there. The item key travels encrypted under the organization key, which
  // the server cannot read.
  const incomingOrganizationId = normalizeOptionalId(
    readCipherProp<string | null>(cipherData, ['organizationId', 'OrganizationId']).value
  );
  // The official clients post `{ cipher: {...}, collectionIds: [...] }` to
  // /ciphers/create: the collections sit beside the cipher. The web vault puts
  // them inside it.
  const besideCollectionIds = readCipherProp<string[] | null>(body, ['collectionIds', 'CollectionIds']);
  const incomingCollectionIds = besideCollectionIds.present && cipherData !== body
    ? besideCollectionIds
    : readCipherProp<string[] | null>(cipherData, ['collectionIds', 'CollectionIds']);
  if (incomingOrganizationId) {
    const collectionIds = Array.isArray(incomingCollectionIds.value)
      ? [...new Set(incomingCollectionIds.value.filter((value): value is string => typeof value === 'string'))]
      : [];
    if (!collectionIds.length) {
      return errorResponse('A shared item must be placed in at least one collection', 400);
    }
    const organizationCollections = await storage.getOrganizationCollectionIds(incomingOrganizationId, collectionIds);
    if (organizationCollections.size !== collectionIds.length) {
      return errorResponse('Collection not found', 404);
    }
    const rights = await storage.getCollectionRightsForCollections(userId, collectionIds);
    for (const collectionId of collectionIds) {
      const entry = rights.get(collectionId);
      if (!entry || entry.readOnly || entry.hidePasswords) {
        return errorResponse('You may not write to that collection', 403);
      }
    }
    cipher.organizationId = incomingOrganizationId;
    cipher.collectionIds = collectionIds;
  }

  normalizeCipherForStorage(cipher);
  const compatibilityError = validateCipherEncryptedFieldsForCompatibility(cipher);
  if (compatibilityError) return errorResponse(compatibilityError, 400);

  await storage.saveCipher(cipher);
  if (cipher.organizationId) {
    await storage.setCipherCollections(cipher.id, cipher.collectionIds ?? []);
  }
  const revisionDate = await storage.updateRevisionDate(userId);
  notifyVaultSyncForRequest(request, env, userId, revisionDate);
  notifyCipherCreateForRequest(request, env, cipher, revisionDate);
  const responseOptions = cipherResponseOptionsForRequest(request);

  return jsonResponse(
    cipherToResponse(cipher, [], { ...responseOptions, collectionIds: cipher.collectionIds ?? [] }),
    200
  );
}

// PUT /api/ciphers/:id
export async function handleUpdateCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const existingCipher = await storage.getCipherForUser(id, userId);

  if (!existingCipher) {
    return errorResponse('Cipher not found', 404);
  }

  // A personal item belongs to the account that owns it. A shared item belongs
  // to the organization, and any member who may write it may change it.
  const writeAccess = await storage.getCipherWriteAccess(existingCipher, userId);
  if (writeAccess === null) {
    return errorResponse('Cipher not found', 404);
  }
  if (!writeAccess) {
    return errorResponse('You may not change this item', 403);
  }

  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  // Handle nested cipher object
  // Android client sends PascalCase "Cipher" for organization ciphers
  const cipherData = body.Cipher || body.cipher || body;
  const incomingFolderId = readCipherProp<string | null>(cipherData, ['folderId', 'FolderId']);
  const incomingKey = readCipherProp<string | null>(cipherData, ['key', 'Key']);
  const incomingLogin = readCipherProp<CipherLogin | null>(cipherData, ['login', 'Login']);
  const incomingCard = readCipherProp<CipherCard | null>(cipherData, ['card', 'Card']);
  const incomingIdentity = readCipherProp<CipherIdentity | null>(cipherData, ['identity', 'Identity']);
  const incomingSecureNote = readCipherProp<CipherSecureNote | null>(cipherData, ['secureNote', 'SecureNote']);
  const incomingSshKey = readCipherProp<CipherSshKey | null>(cipherData, ['sshKey', 'SshKey']);
  const incomingBankAccount = readCipherProp<CipherBankAccount | null>(cipherData, ['bankAccount', 'BankAccount']);
  const incomingDriversLicense = readCipherProp<CipherDriversLicense | null>(cipherData, ['driversLicense', 'DriversLicense']);
  const incomingPassport = readCipherProp<CipherPassport | null>(cipherData, ['passport', 'Passport']);
  const incomingPasswordHistory = readCipherProp<PasswordHistory[] | null>(cipherData, ['passwordHistory', 'PasswordHistory']);
  const incomingRevisionDate = readCipherRevisionDate(cipherData);
  const preserveRevisionDate =
    shouldPreserveRepairableCipherUris(request)
    && (body.preserveRevisionDate === true || cipherData.preserveRevisionDate === true);

  if (incomingKey.present && !shouldAcceptCipherKey(incomingKey.value)) {
    return errorResponse('Cipher key encryption is not supported by this server. Resync the client and try again.', 400);
  }

  if (isStaleCipherUpdate(existingCipher.updatedAt, incomingRevisionDate)) {
    return errorResponse('The client copy of this cipher is out of date. Resync the client and try again.', 400);
  }

  const nextType = Number(cipherData.type) || existingCipher.type;

  // Opaque passthrough: merge existing stored data with ALL incoming client fields.
  // Unknown/future fields from the client are preserved; server-controlled fields are protected.
  const {
    preserveRevisionDate: _preserveRevisionDate,
    PreserveRevisionDate: _pascalPreserveRevisionDate,
    lastKnownRevisionDate: _lastKnownRevisionDate,
    LastKnownRevisionDate: _pascalLastKnownRevisionDate,
    ...cipherDataWithoutFlags
  } = cipherData;
  const cipher: Cipher = {
    ...existingCipher,   // start with all existing stored data (including unknowns)
    ...cipherDataWithoutFlags, // overlay all client data (including new/unknown fields)
    // Server-controlled fields (never from client)
    id: existingCipher.id,
    userId: existingCipher.userId,
    type: nextType,
    favorite: cipherData.favorite ?? existingCipher.favorite,
    reprompt: cipherData.reprompt ?? existingCipher.reprompt,
    createdAt: existingCipher.createdAt,
    updatedAt: preserveRevisionDate ? existingCipher.updatedAt : new Date(Math.max(Date.now(), Date.parse(existingCipher.updatedAt) + 1)).toISOString(),
    archivedAt: readCipherArchivedAt(cipherData, existingCipher.archivedAt ?? null),
    deletedAt: existingCipher.deletedAt,
    // Moving an item between organizations is not an edit: the official server
    // refuses it too, and the item key is wrapped for the old organization.
    organizationId: existingCipher.organizationId ?? null,
  };
  if (incomingFolderId.present) {
    cipher.folderId = normalizeOptionalId(incomingFolderId.value);
  }
  if (incomingKey.present) {
    const normalizedIncomingKey = normalizeCipherKeyForStorage(incomingKey.value);
    cipher.key = normalizedIncomingKey || normalizeCipherKeyForStorage(existingCipher.key);
  } else {
    cipher.key = normalizeCipherKeyForStorage(existingCipher.key);
  }
  cipher.login = nextType === 1 ? (incomingLogin.present ? (incomingLogin.value ?? null) : (existingCipher.login ?? null)) : null;
  cipher.secureNote = nextType === 2 ? (incomingSecureNote.present ? (incomingSecureNote.value ?? null) : (existingCipher.secureNote ?? null)) : null;
  cipher.card = nextType === 3 ? (incomingCard.present ? (incomingCard.value ?? null) : (existingCipher.card ?? null)) : null;
  cipher.identity = nextType === 4 ? (incomingIdentity.present ? (incomingIdentity.value ?? null) : (existingCipher.identity ?? null)) : null;
  cipher.sshKey = nextType === 5 ? (incomingSshKey.present ? (incomingSshKey.value ?? null) : (existingCipher.sshKey ?? null)) : null;
  cipher.bankAccount = nextType === 6 ? (incomingBankAccount.present ? (incomingBankAccount.value ?? null) : ((existingCipher as any).bankAccount ?? null)) : null;
  cipher.driversLicense = nextType === 7 ? (incomingDriversLicense.present ? (incomingDriversLicense.value ?? null) : ((existingCipher as any).driversLicense ?? null)) : null;
  cipher.passport = nextType === 8 ? (incomingPassport.present ? (incomingPassport.value ?? null) : ((existingCipher as any).passport ?? null)) : null;
  if (incomingPasswordHistory.present) {
    cipher.passwordHistory = incomingPasswordHistory.value ?? null;
  }

  // Nullable fields use replacement semantics on this full-update endpoint.
  // Some clients omit cleared values, so merge fallback must not resurrect them.
  cipher.notes = readNullableFullUpdateField<string>(cipherData, ['notes', 'Notes']);
  cipher.fields = readNullableFullUpdateField<Cipher['fields']>(cipherData, ['fields', 'Fields']);
  // Tags/folder resolution: explicit tags (web vault) win; otherwise folderId
  // is official-client move-to-folder semantics on the first tag; with
  // neither field the stored tags and folder survive untouched.
  const updateTagsPresent = Object.prototype.hasOwnProperty.call(cipherData, 'tags')
    || Object.prototype.hasOwnProperty.call(cipherData, 'Tags');
  const updateFolderIdPresent = incomingFolderId.present
    || Object.prototype.hasOwnProperty.call(cipherData, 'folderId')
    || Object.prototype.hasOwnProperty.call(cipherData, 'FolderId');
  const updateFolderId = incomingFolderId.present
    ? normalizeOptionalId(incomingFolderId.value)
    : normalizeOptionalId(cipher.folderId);
  const updateResolution = await resolveCipherTags(storage, userId, {
    tagsPresent: updateTagsPresent,
    rawTags: cipherData.tags ?? cipherData.Tags,
    folderId: updateFolderId,
    folderIdPresent: updateFolderIdPresent,
    currentTags: Array.isArray(existingCipher.tags) ? existingCipher.tags : null,
    currentFolderId: existingCipher.folderId,
  });
  if (updateResolution.folderError) return updateResolution.folderError;
  if (updateResolution.kind === 'set') {
    applyResolvedTagsFolder(cipher, updateResolution);
  }
  if (updateResolution.kind === 'folder') cipher.tags = updateResolution.tags;
  normalizeCipherForStorage(cipher);
  const compatibilityError = validateCipherEncryptedFieldsForCompatibility(cipher);
  if (compatibilityError) return errorResponse(compatibilityError, 400);

  // Prevent referencing a folder owned by another user. The tags model mirrors
  // the folder position in the first tag, so this also guards tag-derived ids.
  if (cipher.folderId) {
    const folderOk = await verifyFolderOwnership(storage, cipher.folderId, userId);
    if (!folderOk) return errorResponse('Folder not found', 404);
  }

  // A shared item may be moved between collections by a member who may write
  // them. The collections must belong to the item's own organization.
  const incomingCollectionIds = readCipherProp<string[] | null>(cipherData, [
    'collectionIds',
    'CollectionIds',
  ]);
  let collectionsChanged = false;
  if (existingCipher.organizationId) {
    const currentCollectionIds = await storage.getCollectionIdsForCipher(existingCipher.id);
    cipher.collectionIds = currentCollectionIds;
    if (incomingCollectionIds.present) {
      const requested = Array.isArray(incomingCollectionIds.value)
        ? [...new Set(incomingCollectionIds.value.filter((value): value is string => typeof value === 'string'))]
        : [];
      if (!requested.length) {
        return errorResponse('A shared item must stay in at least one collection', 400);
      }
      const organizationCollections = await storage.getOrganizationCollectionIds(
        existingCipher.organizationId,
        requested
      );
      if (organizationCollections.size !== requested.length) {
        return errorResponse('Collection not found', 404);
      }
      const rights = await storage.getCollectionRightsForCollections(userId, requested);
      for (const collectionId of requested) {
        const entry = rights.get(collectionId);
        if (!entry || entry.readOnly) {
          return errorResponse('You may not write to that collection', 403);
        }
      }
      const before = [...currentCollectionIds].sort().join(',');
      const after = [...requested].sort().join(',');
      collectionsChanged = before !== after;
      cipher.collectionIds = requested;
    }
  }

  // A save that changes nothing must not bump the revision and must not notify
  // the other clients. Attachment metadata lives outside the cipher row, so a
  // payload that touches it always takes the write path.
  const changesAttachmentMetadata = readIncomingAttachmentMetadata(cipherData).some(
    (item) => item.hasFileName || item.hasKey || item.hasFileSize
  );
  if (!changesAttachmentMetadata && !collectionsChanged && isCipherWriteUnchanged(cipher, existingCipher)) {
    const attachments = await storage.getAttachmentsByCipher(existingCipher.id);
    return jsonResponse(
      cipherToResponse(existingCipher, attachments, cipherResponseOptionsForRequest(request))
    );
  }

  // Optimistic concurrency: reject a stale client copy instead of overwriting a
  // newer save (or resurrecting a row deleted between our read and this write).
  // A write that changes what the item holds leaves the previous state behind
  // as a version, written in the same batch under the same revision check.
  const contentChanged = !isCipherContentUnchanged(cipher, existingCipher);
  const revisionDate = new Date().toISOString();
  const version = contentChanged
    ? {
        id: generateUUID(),
        cipherId: existingCipher.id,
        userId,
        kind: existingCipher.updatedAt === existingCipher.createdAt ? ('created' as const) : ('modified' as const),
        revisionDate,
        createdAt: existingCipher.updatedAt,
        type: Number(existingCipher.type) || 1,
        name: existingCipher.name ?? null,
        notes: existingCipher.notes ?? null,
        key: existingCipher.key ?? null,
        reprompt: existingCipher.reprompt ?? 0,
        data: buildCipherVersionData(existingCipher),
        appliedUpdatedAt: cipher.updatedAt,
      }
    : null;
  if (!(await storage.updateCipherIfUnchanged(cipher, existingCipher.updatedAt, version))) {
    return errorResponse('The client copy of this cipher is out of date. Resync the client and try again.', 400);
  }
  if (version) await storage.pruneCipherVersions(cipher.id);
  if (collectionsChanged && cipher.collectionIds) {
    await storage.setCipherCollections(cipher.id, cipher.collectionIds);
  }
  // Rejected updates must not modify attachment metadata either.
  await syncIncomingAttachmentMetadata(storage, cipher.id, cipherData);
  const revision = await storage.updateRevisionDate(userId, revisionDate);
  notifyVaultSyncForRequest(request, env, userId, revision);
  notifyCipherUpdateForRequest(request, env, cipher, revision);
  const attachments = await storage.getAttachmentsByCipher(cipher.id);
  const responseOptions = cipherResponseOptionsForRequest(request);
  const responseCollectionIds = cipher.organizationId
    ? await storage.getCollectionIdsForCipher(cipher.id)
    : undefined;

  return jsonResponse(
    cipherToResponse(
      cipher,
      attachments,
      responseCollectionIds ? { ...responseOptions, collectionIds: responseCollectionIds } : responseOptions
    )
  );
}

// PUT /api/ciphers/:id/share
//
// The official clients share a personal item by re-encrypting it under the
// organization key on their side and sending the whole item back with the
// organization and the collections it should join. The server never sees the
// key; it checks that the member may write those collections and stores the
// item where it was told.
export async function handleShareCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const existingCipher = await storage.getCipherForUser(id, userId);
  if (!existingCipher) return errorResponse('Cipher not found', 404);
  // Only the item's own owner shares it: a shared item already belongs to an
  // organization, and moving one between organizations would leave its key
  // wrapped for the old one.
  if (existingCipher.organizationId) {
    return errorResponse('This item already belongs to an organization', 400);
  }

  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }
  const cipherData = body.Cipher || body.cipher || body;

  // The official clients put the organization inside the cipher, and the
  // collections beside it. Both are accepted where they arrive.
  const organizationId = normalizeOptionalId(
    readCipherProp<string | null>(body, ['organizationId', 'OrganizationId']).value
    ?? readCipherProp<string | null>(cipherData, ['organizationId', 'OrganizationId']).value
  );
  if (!organizationId) return errorResponse('organizationId is required', 400);

  // The official clients send `{ cipher: {...}, collectionIds: [...] }`: the
  // collections sit beside the cipher, not inside it. A body without them
  // shares the item and leaves it in no collection, which is what the newer
  // clients do before they assign one.
  const incomingCollectionIds = readCipherProp<string[] | null>(body, ['collectionIds', 'CollectionIds']);
  const nestedCollectionIds = readCipherProp<string[] | null>(cipherData, ['collectionIds', 'CollectionIds']);
  const rawCollectionIds = incomingCollectionIds.present
    ? incomingCollectionIds.value
    : nestedCollectionIds.value;
  const requested = Array.isArray(rawCollectionIds)
    ? [...new Set(rawCollectionIds.filter((value): value is string => typeof value === 'string'))]
    : [];
  if (requested.length) {
    const organizationCollections = await storage.getOrganizationCollectionIds(organizationId, requested);
    if (organizationCollections.size !== requested.length) {
      return errorResponse('Collection not found', 404);
    }
    const rights = await storage.getCollectionRightsForCollections(userId, requested);
    for (const collectionId of requested) {
      const entry = rights.get(collectionId);
      if (!entry || entry.readOnly || entry.hidePasswords) {
        return errorResponse('You may not write to that collection', 403);
      }
    }
  }

  const incomingKey = readCipherProp<string | null>(cipherData, ['key', 'Key']);
  if (incomingKey.present && !shouldAcceptCipherKey(incomingKey.value)) {
    return errorResponse('Cipher key encryption is not supported by this server. Resync the client and try again.', 400);
  }

  const {
    preserveRevisionDate: _preserveRevisionDate,
    PreserveRevisionDate: _pascalPreserveRevisionDate,
    lastKnownRevisionDate: _lastKnownRevisionDate,
    LastKnownRevisionDate: _pascalLastKnownRevisionDate,
    organizationId: _organizationId,
    OrganizationId: _pascalOrganizationId,
    collectionIds: _collectionIds,
    CollectionIds: _pascalCollectionIds,
    ...sharedFields
  } = cipherData;
  const cipher: Cipher = {
    ...existingCipher,
    ...sharedFields,
    id: existingCipher.id,
    userId: existingCipher.userId,
    createdAt: existingCipher.createdAt,
    // A shared item has no personal folder and no personal tags: both belong
    // to the member's own vault, not to the organization.
    folderId: null,
    tags: [],
    organizationId,
    collectionIds: requested,
    updatedAt: new Date(Math.max(Date.now(), Date.parse(existingCipher.updatedAt) + 1)).toISOString(),
  };
  if (incomingKey.present) {
    cipher.key = normalizeCipherKeyForStorage(incomingKey.value) || normalizeCipherKeyForStorage(existingCipher.key);
  } else {
    cipher.key = normalizeCipherKeyForStorage(existingCipher.key);
  }
  normalizeCipherForStorage(cipher);
  const compatibilityError = validateCipherEncryptedFieldsForCompatibility(cipher);
  if (compatibilityError) return errorResponse(compatibilityError, 400);

  // The attachments and the history are sealed with the item key. Sharing an
  // item gives it a new key, so they are re-sealed with it in the same write.
  const resealedAttachments = Array.isArray(body.attachments)
    ? body.attachments
        .map((entry: any) => ({
          id: String(entry?.id || '').trim(),
          key: String(entry?.key || '').trim().slice(0, 4096) || null,
        }))
        .filter((entry: { id: string }) => !!entry.id)
    : [];
  const resealedVersions = Array.isArray(body.versions)
    ? body.versions
        .map((entry: any) => ({
          id: String(entry?.id || '').trim(),
          key: String(entry?.key || '').trim().slice(0, 4096) || null,
          name: typeof entry?.name === 'string' ? entry.name : null,
          notes: typeof entry?.notes === 'string' ? entry.notes : null,
          data: typeof entry?.data === 'string' ? entry.data : JSON.stringify(entry?.data ?? {}),
        }))
        .filter((entry: { id: string }) => !!entry.id)
    : [];

  if (!(await storage.updateCipherIfUnchanged(cipher, existingCipher.updatedAt, null, {
    attachments: resealedAttachments,
    versions: resealedVersions,
  }))) {
    return errorResponse('The client copy of this cipher is out of date. Resync the client and try again.', 400);
  }
  await storage.setCipherCollections(cipher.id, requested);
  const revision = await storage.updateRevisionDate(userId);
  notifyVaultSyncForRequest(request, env, userId, revision);
  notifyCipherUpdateForRequest(request, env, cipher, revision);

  return jsonResponse(
    cipherToResponse(cipher, await storage.getAttachmentsByCipher(cipher.id), {
      ...cipherResponseOptionsForRequest(request),
      collectionIds: requested,
    })
  );
}

// PUT /api/ciphers/share
//
// The official clients move several items into an organization at once, each
// re-encrypted with the organization key: `{ ciphers: [...], collectionIds }`.
// Every item goes through the same checks as a single share. The request is
// checked as a whole first, so a malformed one changes nothing; as upstream,
// an item that fails later stops the run.
export async function handleBulkShareCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }
  const ciphers = readCipherProp<any[] | null>(body, ['ciphers', 'Ciphers']).value;
  const collectionIds = readCipherProp<string[] | null>(body, ['collectionIds', 'CollectionIds']).value;
  if (!Array.isArray(ciphers) || !ciphers.length) {
    return errorResponse('You must select at least one cipher.', 400);
  }
  if (!Array.isArray(collectionIds) || !collectionIds.length) {
    return errorResponse('You must select at least one collection.', 400);
  }
  for (const cipher of ciphers) {
    if (!normalizeOptionalId(readCipherProp<string | null>(cipher, ['id', 'Id']).value)) {
      return errorResponse('Request missing ids field', 400);
    }
    if (!normalizeOptionalId(readCipherProp<string | null>(cipher, ['organizationId', 'OrganizationId']).value)) {
      return errorResponse('Cipher OrganizationId is required.', 400);
    }
  }

  const shared: unknown[] = [];
  for (const cipher of ciphers) {
    const id = normalizeOptionalId(readCipherProp<string | null>(cipher, ['id', 'Id']).value) as string;
    const single = new Request(request.url, {
      method: 'PUT',
      headers: request.headers,
      body: JSON.stringify({ cipher, collectionIds }),
    });
    const response = await handleShareCipher(single, env, userId, id);
    if (!response.ok) return response;
    shared.push(await response.json());
  }
  return jsonResponse({ data: shared, object: 'list', continuationToken: null });
}

// PUT /api/ciphers/:id/collections_v2
//
// The newer clients assign the collections of an organization item here,
// after sharing it. The member has to be allowed to write them.
export async function handleSetCipherCollections(
  request: Request,
  env: Env,
  userId: string,
  id: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const cipher = await storage.getCipherForUser(id, userId);
  if (!cipher) return errorResponse('Cipher not found', 404);
  if (!cipher.organizationId) return errorResponse('This item does not belong to an organization', 400);

  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }
  const incoming = readCipherProp<string[] | null>(body, ['collectionIds', 'CollectionIds']);
  const requested = Array.isArray(incoming.value)
    ? [...new Set(incoming.value.filter((value): value is string => typeof value === 'string'))]
    : [];
  if (!requested.length) {
    return errorResponse('A shared item must stay in at least one collection', 400);
  }
  const organizationCollections = await storage.getOrganizationCollectionIds(cipher.organizationId, requested);
  if (organizationCollections.size !== requested.length) {
    return errorResponse('Collection not found', 404);
  }
  const rights = await storage.getCollectionRightsForCollections(userId, requested);
  for (const collectionId of requested) {
    const entry = rights.get(collectionId);
    if (!entry || entry.readOnly || entry.hidePasswords) {
      return errorResponse('You may not write to that collection', 403);
    }
  }

  await storage.setCipherCollections(cipher.id, requested);
  const revision = await storage.updateRevisionDate(userId);
  notifyVaultSyncForRequest(request, env, userId, revision);

  return new Response(null, { status: 204 });
}

// POST /api/ciphers/bulk-collections
//
// The "Assign to collections" dialog of the web vault, the extension and the
// desktop app calls this route to put several items of an organization into
// collections at once. It calls it twice when a collection is taken away:
// once to add the collections that stay, once to remove the one that goes.
//
// An item the member may not write is skipped, and an item of an
// organization always stays in at least one collection, so the whole request
// is refused when it would leave one behind.
export async function handleBulkUpdateCipherCollections(
  request: Request,
  env: Env,
  userId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const rawOrganizationId = readCipherProp<unknown>(body, ['organizationId', 'OrganizationId']).value;
  const organizationId = typeof rawOrganizationId === 'string' ? normalizeOptionalId(rawOrganizationId) : null;
  if (!organizationId) return errorResponse('organizationId is required', 400);

  const cipherIds = readIdList(readCipherProp<string[] | null>(body, ['cipherIds', 'CipherIds']).value);
  const collectionIds = readIdList(readCipherProp<string[] | null>(body, ['collectionIds', 'CollectionIds']).value);
  if (!collectionIds.length) return errorResponse('At least one collection is required', 400);
  if (!cipherIds.length) return errorResponse('At least one item is required', 400);

  const removeCollections =
    readCipherProp<boolean | null>(body, ['removeCollections', 'RemoveCollections']).value === true;

  // Only a confirmed member of the organization may assign its collections.
  const membership = await storage.getOrganizationUserForUser(organizationId, userId);
  if (!membership || membership.status !== 2) return errorResponse('Organization not found', 404);

  const organizationCollections = await storage.getOrganizationCollectionIds(organizationId, collectionIds);
  if (organizationCollections.size !== collectionIds.length) {
    return errorResponse('Collection not found', 404);
  }
  const rights = await storage.getCollectionRightsForCollections(userId, collectionIds);
  for (const collectionId of collectionIds) {
    const entry = rights.get(collectionId);
    if (!entry || entry.readOnly || entry.hidePasswords) {
      return errorResponse('You may not write to that collection', 403);
    }
  }

  // Only the items of this organization the member may change: an item of
  // another organization, a personal item, and an item the member may only
  // read are skipped, as the official server does.
  const writable = await storage.filterWritableCipherIds(cipherIds, userId);
  const organizations = await storage.getOrganizationIdByCipherIds(writable);
  const targetIds = writable.filter((id) => organizations.get(id) === organizationId);
  if (!targetIds.length) return new Response(null, { status: 204 });

  const current = await storage.getCollectionIdsByCipherIds(targetIds);
  const requested = new Set(collectionIds);
  const added: Array<[string, string]> = [];
  const removed: Array<[string, string]> = [];
  for (const cipherId of targetIds) {
    const links = current.get(cipherId) ?? [];
    const held = new Set(links);
    for (const collectionId of collectionIds) {
      if (removeCollections) {
        if (held.has(collectionId)) removed.push([cipherId, collectionId]);
      } else if (!held.has(collectionId)) {
        added.push([cipherId, collectionId]);
      }
    }
    // An item of an organization always sits in a collection, so taking the
    // last one away is refused before anything is written.
    if (removeCollections && links.some((collectionId) => requested.has(collectionId))) {
      const left = links.filter((collectionId) => !requested.has(collectionId));
      if (!left.length) {
        return errorResponse('A shared item must stay in at least one collection', 400);
      }
    }
  }

  if (added.length || removed.length) {
    await storage.updateCollectionCipherLinks(added, removed);
    // The collections of the organization decide what every member may see,
    // so the members have to sync.
    await notifyOrganizationMembers(request, env, storage, organizationId, new Date().toISOString());
  }

  return new Response(null, { status: 204 });
}

// DELETE /api/ciphers/:id
export async function handleDeleteCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const cipher = await storage.getCipherForUser(id, userId);

  if (!cipher) {
    return errorResponse('Cipher not found', 404);
  }
  // A personal item belongs to the account that owns it; a shared item belongs
  // to the organization, and any member who may write it may act on it.
  const access = await storage.getCipherWriteAccess(cipher, userId);
  if (access === null) {
    return errorResponse('Cipher not found', 404);
  }
  if (!access) {
    return errorResponse('You may not change this item', 403);
  }

  // Soft delete
  cipher.deletedAt = new Date().toISOString();
  cipher.updatedAt = cipher.deletedAt;
  syncCipherComputedAliases(cipher);
  await storage.saveCipher(cipher);
  const revisionDate = await storage.updateRevisionDate(userId);
  notifyVaultSyncForRequest(request, env, userId, revisionDate);
  notifyCipherDeleteForRequest(request, env, cipher, revisionDate);
  await writeCipherAudit(storage, request, userId, 'cipher.delete.soft', {
    id: cipher.id,
    type: cipher.type,
    folderId: cipher.folderId ?? null,
  });

  return jsonResponse(
    cipherToResponse(cipher, [], cipherResponseOptionsForRequest(request))
  );
}

// DELETE /api/ciphers/:id (compat mode)
// Bitwarden clients may call DELETE on a trashed item to purge it permanently.
// For compatibility:
// - If item is active -> soft delete.
// - If item is already soft-deleted -> hard delete.
export async function handleDeleteCipherCompat(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const cipher = await storage.getCipherForUser(id, userId);

  if (!cipher) {
    return errorResponse('Cipher not found', 404);
  }
  // A personal item belongs to the account that owns it; a shared item belongs
  // to the organization, and any member who may write it may act on it.
  const access = await storage.getCipherWriteAccess(cipher, userId);
  if (access === null) {
    return errorResponse('Cipher not found', 404);
  }
  if (!access) {
    return errorResponse('You may not change this item', 403);
  }

  if (cipher.deletedAt) {
    await deleteAllAttachmentsForCipher(env, id);
    await storage.deleteCipher(id, userId);
    const revisionDate = await storage.updateRevisionDate(userId);
    notifyVaultSyncForRequest(request, env, userId, revisionDate);
    notifyCipherDeleteForRequest(request, env, cipher, revisionDate);
    await writeCipherAudit(storage, request, userId, 'cipher.delete.permanent', {
      id,
      type: cipher.type,
      folderId: cipher.folderId ?? null,
      compat: true,
    });
    return new Response(null, { status: 204 });
  }

  return handleDeleteCipher(request, env, userId, id);
}

// DELETE /api/ciphers/:id (permanent)
export async function handlePermanentDeleteCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const cipher = await storage.getCipherForUser(id, userId);

  if (!cipher) {
    return errorResponse('Cipher not found', 404);
  }
  // A personal item belongs to the account that owns it; a shared item belongs
  // to the organization, and any member who may write it may act on it.
  const access = await storage.getCipherWriteAccess(cipher, userId);
  if (access === null) {
    return errorResponse('Cipher not found', 404);
  }
  if (!access) {
    return errorResponse('You may not change this item', 403);
  }

  // Destroying a shared item for everyone takes manage rights on its
  // collection: an editor may change or move it, not erase it.
  if (cipher.organizationId) {
    const manageable = await storage.filterWritableCipherIds([cipher.id], userId, 4);
    if (!manageable.length) {
      return errorResponse('You may not delete this item for everyone', 403);
    }
  }

  // Delete all attachments first
  await deleteAllAttachmentsForCipher(env, id);

  await storage.deleteCipher(id, userId);
  const revisionDate = await storage.updateRevisionDate(userId);
  notifyVaultSyncForRequest(request, env, userId, revisionDate);
  notifyCipherDeleteForRequest(request, env, cipher, revisionDate);
  await writeCipherAudit(storage, request, userId, 'cipher.delete.permanent', {
    id,
    type: cipher.type,
    folderId: cipher.folderId ?? null,
  });

  return new Response(null, { status: 204 });
}

// PUT /api/ciphers/:id/restore
export async function handleRestoreCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const cipher = await storage.getCipherForUser(id, userId);

  if (!cipher) {
    return errorResponse('Cipher not found', 404);
  }
  // A personal item belongs to the account that owns it; a shared item belongs
  // to the organization, and any member who may write it may act on it.
  const access = await storage.getCipherWriteAccess(cipher, userId);
  if (access === null) {
    return errorResponse('Cipher not found', 404);
  }
  if (!access) {
    return errorResponse('You may not change this item', 403);
  }

  cipher.deletedAt = null;
  cipher.updatedAt = new Date().toISOString();
  syncCipherComputedAliases(cipher);
  await storage.saveCipher(cipher);
  const revisionDate = await storage.updateRevisionDate(userId);
  notifyVaultSyncForRequest(request, env, userId, revisionDate);
  notifyCipherUpdateForRequest(request, env, cipher, revisionDate);

  return jsonResponse(
    cipherToResponse(cipher, [], cipherResponseOptionsForRequest(request))
  );
}

// PUT /api/ciphers/:id/partial - Update only favorite/folderId
export async function handlePartialUpdateCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const cipher = await storage.getCipherForUser(id, userId);

  if (!cipher) {
    return errorResponse('Cipher not found', 404);
  }
  // A personal item belongs to the account that owns it; a shared item belongs
  // to the organization, and any member who may write it may act on it.
  const access = await storage.getCipherWriteAccess(cipher, userId);
  if (access === null) {
    return errorResponse('Cipher not found', 404);
  }
  if (!access) {
    return errorResponse('You may not change this item', 403);
  }

  let body: { folderId?: string | null; favorite?: boolean };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (body.folderId !== undefined) {
    const folderId = normalizeOptionalId(body.folderId);
    const resolution = await resolveCipherTags(storage, userId, {
      tagsPresent: false, rawTags: null, folderId, folderIdPresent: true,
      currentTags: cipher.tags || null, currentFolderId: cipher.folderId,
    });
    if (resolution.folderError) return resolution.folderError;
    if (resolution.kind === 'set') applyResolvedTagsFolder(cipher, resolution);
    if (resolution.kind === 'folder') cipher.tags = resolution.tags;
    if (resolution.kind === 'folder') cipher.folderId = folderId;
  }
  if (body.favorite !== undefined) {
    cipher.favorite = body.favorite;
  }
  cipher.updatedAt = new Date().toISOString();
  syncCipherComputedAliases(cipher);

  await storage.saveCipher(cipher);
  const revisionDate = await storage.updateRevisionDate(userId);
  notifyVaultSyncForRequest(request, env, userId, revisionDate);
  notifyCipherUpdateForRequest(request, env, cipher, revisionDate);

  return jsonResponse(
    cipherToResponse(cipher, [], cipherResponseOptionsForRequest(request))
  );
}

// POST/PUT /api/ciphers/move - Bulk move to folder
export async function handleBulkMoveCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { ids?: string[]; folderId?: string | null };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (!body.ids || !Array.isArray(body.ids)) {
    return errorResponse('ids array is required', 400);
  }

  const folderId = normalizeOptionalId(body.folderId);
  if (folderId) {
    const folderOk = await verifyFolderOwnership(storage, folderId, userId);
    if (!folderOk) return errorResponse('Folder not found', 404);
  }

  // A bulk action only touches the items the member may change: an item they
  // may only read, or cannot reach at all, is not theirs to move.
  const ids = await storage.filterWritableCipherIds(body.ids, userId);
  if (!ids.length) return new Response(null, { status: 204 });

  const { revisionDate, conflict } = await storage.bulkMoveCiphers(ids, folderId, userId);
  if (revisionDate) notifyVaultSyncForRequest(request, env, userId, revisionDate);
  if (conflict) return errorResponse('Cipher changed during bulk move. Resync and try again.', 409);

  return new Response(null, { status: 204 });
}

async function buildCipherListResponse(
  request: Request,
  storage: StorageService,
  userId: string,
  ids: string[]
): Promise<Response> {
  // Read each item through the permission check instead of trusting the ids
  // the client sent: an item the member may not reach is simply not returned.
  // A repeated id is one item, so it is listed once.
  const unique = Array.from(new Set(ids));
  const loaded = await Promise.all(unique.map((id) => storage.getCipherForUser(id, userId)));
  const ciphers = loaded.filter((cipher): cipher is NonNullable<typeof cipher> => !!cipher);
  const attachmentsByCipher = await storage.getAttachmentsByCipherIds(ciphers.map((cipher) => cipher.id));

  return jsonResponse({
    data: ciphers.map((cipher) =>
      cipherToResponse(cipher, attachmentsByCipher.get(cipher.id) || [], cipherResponseOptionsForRequest(request))
    ),
    object: 'list',
    continuationToken: null,
  });
}

function parseCipherIdList(body: { ids?: unknown }): string[] | null {
  if (!Array.isArray(body.ids)) return null;
  return Array.from(new Set(body.ids.map((id) => String(id || '').trim()).filter(Boolean)));
}

// PUT/POST /api/ciphers/:id/archive
export async function handleArchiveCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const cipher = await storage.getCipherForUser(id, userId);

  if (!cipher) {
    return errorResponse('Cipher not found', 404);
  }
  // A personal item belongs to the account that owns it; a shared item belongs
  // to the organization, and any member who may write it may act on it.
  const access = await storage.getCipherWriteAccess(cipher, userId);
  if (access === null) {
    return errorResponse('Cipher not found', 404);
  }
  if (!access) {
    return errorResponse('You may not change this item', 403);
  }
  if (cipher.deletedAt) {
    return errorResponse('Cannot archive a deleted cipher', 400);
  }

  cipher.archivedAt = new Date().toISOString();
  cipher.updatedAt = cipher.archivedAt;
  normalizeCipherForStorage(cipher);
  await storage.saveCipher(cipher);
  const revisionDate = await storage.updateRevisionDate(userId);
  notifyVaultSyncForRequest(request, env, userId, revisionDate);
  notifyCipherUpdateForRequest(request, env, cipher, revisionDate);

  const attachments = await storage.getAttachmentsByCipher(cipher.id);
  return jsonResponse(
    cipherToResponse(cipher, attachments, cipherResponseOptionsForRequest(request))
  );
}

// PUT/POST /api/ciphers/:id/unarchive
export async function handleUnarchiveCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const cipher = await storage.getCipherForUser(id, userId);

  if (!cipher) {
    return errorResponse('Cipher not found', 404);
  }
  // A personal item belongs to the account that owns it; a shared item belongs
  // to the organization, and any member who may write it may act on it.
  const access = await storage.getCipherWriteAccess(cipher, userId);
  if (access === null) {
    return errorResponse('Cipher not found', 404);
  }
  if (!access) {
    return errorResponse('You may not change this item', 403);
  }

  cipher.archivedAt = null;
  cipher.updatedAt = new Date().toISOString();
  normalizeCipherForStorage(cipher);
  await storage.saveCipher(cipher);
  const revisionDate = await storage.updateRevisionDate(userId);
  notifyVaultSyncForRequest(request, env, userId, revisionDate);

  const attachments = await storage.getAttachmentsByCipher(cipher.id);
  return jsonResponse(
    cipherToResponse(cipher, attachments, cipherResponseOptionsForRequest(request))
  );
}

// PUT/POST /api/ciphers/archive
export async function handleBulkArchiveCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { ids?: unknown };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const ids = parseCipherIdList(body);
  if (!ids) {
    return errorResponse('ids array is required', 400);
  }

  const allowedIds = await storage.filterWritableCipherIds(ids, userId);
  const revisionDate = await storage.bulkArchiveCiphers(allowedIds, userId);
  if (revisionDate) {
    notifyVaultSyncForRequest(request, env, userId, revisionDate);
    notifyUserCiphersSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
  }

  return buildCipherListResponse(request, storage, userId, ids);
}

// PUT/POST /api/ciphers/unarchive
export async function handleBulkUnarchiveCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { ids?: unknown };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const ids = parseCipherIdList(body);
  if (!ids) {
    return errorResponse('ids array is required', 400);
  }

  const allowedIds = await storage.filterWritableCipherIds(ids, userId);
  const revisionDate = await storage.bulkUnarchiveCiphers(allowedIds, userId);
  if (revisionDate) {
    notifyVaultSyncForRequest(request, env, userId, revisionDate);
    notifyUserCiphersSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
  }

  return buildCipherListResponse(request, storage, userId, ids);
}

// POST /api/ciphers/delete - Bulk soft delete
export async function handleBulkDeleteCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { ids?: string[] };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (!body.ids || !Array.isArray(body.ids)) {
    return errorResponse('ids array is required', 400);
  }

  const ids = await storage.filterWritableCipherIds(body.ids, userId);
  if (!ids.length) return new Response(null, { status: 204 });

  const revisionDate = await storage.bulkSoftDeleteCiphers(ids, userId);
  if (revisionDate) {
    notifyVaultSyncForRequest(request, env, userId, revisionDate);
    notifyUserCiphersSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
    await writeCipherAudit(storage, request, userId, 'cipher.delete.soft.bulk', {
      count: body.ids.length,
    });
  }

  return new Response(null, { status: 204 });
}

// PUT /api/ciphers/restore (POST retained for older NodeWarden clients)
export async function handleBulkRestoreCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { ids?: string[] };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (!body.ids || !Array.isArray(body.ids)) {
    return errorResponse('ids array is required', 400);
  }

  const ids = await storage.filterWritableCipherIds(body.ids, userId);
  // Nothing to restore is still answered with the same shape as a restore
  // that did something, so a client does not have to special-case it.
  if (!ids.length) return buildCipherListResponse(request, storage, userId, []);

  const revisionDate = await storage.bulkRestoreCiphers(ids, userId);
  if (revisionDate) {
    notifyVaultSyncForRequest(request, env, userId, revisionDate);
    notifyUserCiphersSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
  }

  return buildCipherListResponse(request, storage, userId, body.ids);
}

// POST /api/ciphers/delete-permanent - Bulk permanent delete
export async function handleBulkPermanentDeleteCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { ids?: string[] };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (!body.ids || !Array.isArray(body.ids)) {
    return errorResponse('ids array is required', 400);
  }

  const ids = Array.from(new Set(body.ids.map((id) => String(id || '').trim()).filter(Boolean)));
  if (!ids.length) {
    return new Response(null, { status: 204 });
  }

  // Permanent deletion of a shared item takes manage rights on its collection,
  // not merely the right to edit it: an editor can move an item but must not
  // be able to destroy it for everyone.
  const ownedIds = await storage.filterWritableCipherIds(ids, userId, 4);
  if (!ownedIds.length) {
    return new Response(null, { status: 204 });
  }

  await deleteAllAttachmentsForCiphers(env, ownedIds);

  const revisionDate = await storage.bulkDeleteCiphers(ownedIds, userId);
  if (revisionDate) {
    notifyVaultSyncForRequest(request, env, userId, revisionDate);
    notifyUserCiphersSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
    await writeCipherAudit(storage, request, userId, 'cipher.delete.permanent.bulk', {
      count: ownedIds.length,
      requestedCount: ids.length,
    });
  }

  return new Response(null, { status: 204 });
}

// --- Password scan exclusions ---
//
// A scan sends a hash prefix of a password to a breach database. The user may
// not want that for one item, so the exclusion is kept beside the item: it is
// a setting of the account, not a property of the item, and other clients
// and exports never see it.

export const SCAN_SCOPES = ['password-health'] as const;

function readScanScope(request: Request, body?: unknown): { ok: true; scope: string } | { ok: false; response: Response } {
  const url = new URL(request.url);
  const raw =
    (typeof body === 'object' && body !== null ? (body as { scope?: unknown }).scope : undefined) ??
    url.searchParams.get('scope') ??
    'password-health';
  const scope = String(raw || '').trim();
  if (!SCAN_SCOPES.includes(scope as (typeof SCAN_SCOPES)[number])) {
    return {
      ok: false,
      response: errorResponse('Unknown scan scope', 400),
    };
  }
  return { ok: true, scope };
}

// GET /api/security/scan-exclusions
export async function handleGetScanExclusions(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const scope = readScanScope(request);
  if (!scope.ok) return scope.response;
  const exclusions = await storage.getScanExclusions(userId, scope.scope);
  return jsonResponse({ data: exclusions, object: 'list' });
}

// PUT /api/security/scan-exclusions/:cipherId
export async function handleSetScanExclusion(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  let body: unknown = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }
  const scope = readScanScope(request, body);
  if (!scope.ok) return scope.response;
  // The item has to be one this account may read: an exclusion for an item
  // nobody can reach would only hide the fact that the item is missing.
  const cipher = await storage.getCipherForUser(cipherId, userId);
  if (!cipher) {
    return errorResponse('Cipher not found', 404);
  }
  const exclusion = await storage.excludeCipherFromScan(userId, cipherId, scope.scope);
  await writeAuditEvent(storage, {
    actorUserId: userId,
    action: 'security.scan.exclude',
    category: 'security',
    level: 'info',
    targetType: 'cipher',
    targetId: cipherId,
    metadata: { scope: scope.scope, ...auditRequestMetadata(request) },
  });
  return jsonResponse(exclusion);
}

// DELETE /api/security/scan-exclusions/:cipherId
export async function handleDeleteScanExclusion(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const scope = readScanScope(request);
  if (!scope.ok) return scope.response;
  await storage.includeCipherInScan(userId, cipherId, scope.scope);
  await writeAuditEvent(storage, {
    actorUserId: userId,
    action: 'security.scan.include',
    category: 'security',
    level: 'info',
    targetType: 'cipher',
    targetId: cipherId,
    metadata: { scope: scope.scope, ...auditRequestMetadata(request) },
  });
  return new Response(null, { status: 204 });
}

// GET /api/ciphers/usage
// Password-copy counters for the current owner, keyed by cipher id. Ciphers
// that were never copied are omitted.
export async function handleGetCipherUsage(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  return jsonResponse(await storage.getCipherUsage(userId));
}

// POST /api/ciphers/:id/usage
// Records one successful password copy. Only an owned, non-deleted,
// non-archived login cipher can be counted. Recording a copy never changes the
// cipher revision date, its updated_at or the sync notifications.
export async function handleRecordCipherUsage(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const usage = await storage.incrementCipherUsage(id, userId);
  if (!usage) {
    return errorResponse('Cipher not found', 404);
  }
  return jsonResponse(usage);
}
