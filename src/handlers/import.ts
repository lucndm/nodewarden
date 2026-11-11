import { Env, Cipher, Folder, CipherType } from '../types';
import { notifyUserVaultSync } from '../durable/notifications-hub';
import { StorageService } from '../services/storage';
import { errorResponse, jsonResponse } from '../utils/response';
import { readActingDeviceIdentifier } from '../utils/device';
import { generateUUID } from '../utils/uuid';
import { LIMITS } from '../config/limits';
import { isValidEncString } from '../utils/enc-string';
import { COLLECTION_NAME_NOT_ENCRYPTED } from './organizations';
import { normalizeCipherLoginForStorage, normalizeCipherSshKeyForCompatibility, validateCipherEncryptedFieldsForCompatibility } from './ciphers';

// Bitwarden client import request format
interface CiphersImportRequest {
  ciphers: Array<{
    id?: string | null;
    type: number;
    name?: string | null;
    notes?: string | null;
    favorite?: boolean;
    reprompt?: number;
    sshKey?: any | null;
    bankAccount?: any | null;
    driversLicense?: any | null;
    passport?: any | null;
    key?: string | null;
    login?: {
      uris?: Array<{ uri: string | null; uriChecksum?: string | null; match?: number | null }> | null;
      username?: string | null;
      password?: string | null;
      totp?: string | null;
      autofillOnPageLoad?: boolean | null;
      uri?: string | null;
      passwordRevisionDate?: string | null;
      [key: string]: any;
    } | null;
    card?: {
      cardholderName?: string | null;
      brand?: string | null;
      number?: string | null;
      expMonth?: string | null;
      expYear?: string | null;
      code?: string | null;
    } | null;
    identity?: {
      title?: string | null;
      firstName?: string | null;
      middleName?: string | null;
      lastName?: string | null;
      address1?: string | null;
      address2?: string | null;
      address3?: string | null;
      city?: string | null;
      state?: string | null;
      postalCode?: string | null;
      country?: string | null;
      company?: string | null;
      email?: string | null;
      phone?: string | null;
      ssn?: string | null;
      username?: string | null;
      passportNumber?: string | null;
      licenseNumber?: string | null;
    } | null;
    secureNote?: { type: number } | null;
    fields?: Array<{
      name?: string | null;
      value?: string | null;
      type: number;
      linkedId?: number | null;
    }> | null;
    passwordHistory?: Array<{
      password: string;
      lastUsedDate: string;
    }> | null;
    [key: string]: any;
  }>;
  folders: Array<{
    name: string;
    tagName?: string;
  }>;
  folderRelationships: Array<{
    key: number;   // cipher index
    value: number; // folder index
  }>;
}

function bindNull(v: any): any {
  return v === undefined ? null : v;
}

function readAliasedImportProp<T = unknown>(source: any, aliases: string[]): T | undefined {
  if (!source || typeof source !== 'object') return undefined;
  for (const key of aliases) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      return source[key] as T;
    }
  }
  return undefined;
}

function normalizeOptionalId(value: unknown): string | null {
  if (value == null) return null;
  const normalized = String(value).trim();
  return normalized ? normalized : null;
}

async function runBatchInChunks(db: D1Database, statements: D1PreparedStatement[], chunkSize: number): Promise<void> {
  for (let i = 0; i < statements.length; i += chunkSize) {
    const chunk = statements.slice(i, i + chunkSize);
    await db.batch(chunk);
  }
}

// POST /api/ciphers/import - Bitwarden client import endpoint
/**
 * One imported item as it is stored: the official import request carries the
 * item's encrypted fields as a client would create them; this fills the
 * shape NodeWarden stores and leaves the encrypted values untouched.
 */
export function buildImportedCipher(
  c: CiphersImportRequest['ciphers'][number],
  userId: string,
  folderId: string | null,
  now: string
): Cipher {
  const login = readAliasedImportProp<any | null>(c, ['login', 'Login']);
  const card = readAliasedImportProp<any | null>(c, ['card', 'Card']);
  const identity = readAliasedImportProp<any | null>(c, ['identity', 'Identity']);
  const secureNote = readAliasedImportProp<any | null>(c, ['secureNote', 'SecureNote']);
  const sshKey = readAliasedImportProp<any | null>(c, ['sshKey', 'SshKey']);
  const bankAccount = readAliasedImportProp<any | null>(c, ['bankAccount', 'BankAccount']);
  const driversLicense = readAliasedImportProp<any | null>(c, ['driversLicense', 'DriversLicense']);
  const passport = readAliasedImportProp<any | null>(c, ['passport', 'Passport']);
  const fields = readAliasedImportProp<any[] | null>(c, ['fields', 'Fields']);
  const passwordHistory = readAliasedImportProp<any[] | null>(c, ['passwordHistory', 'PasswordHistory']);
  const key = readAliasedImportProp<string | null>(c, ['key', 'Key']);

  const cipher: Cipher = {
    ...c,
    id: generateUUID(),
    userId: userId,
    type: c.type as CipherType,
    folderId: folderId,
    name: c.name ?? 'Untitled',
    notes: c.notes ?? null,
    favorite: c.favorite ?? false,
    login: login ? {
      ...login,
      username: login.username ?? null,
      password: login.password ?? null,
      uris: login.uris?.map((u: any) => ({
        ...u,
        uri: u.uri ?? null,
        uriChecksum: u.uriChecksum ?? null,
        match: u.match ?? null,
      })) || null,
      totp: login.totp ?? null,
      autofillOnPageLoad: login.autofillOnPageLoad ?? null,
      fido2Credentials: Array.isArray(login.fido2Credentials) ? login.fido2Credentials : null,
      uri: login.uri ?? null,
      passwordRevisionDate: login.passwordRevisionDate ?? null,
    } : null,
    card: card ? {
      ...card,
      cardholderName: card.cardholderName ?? null,
      brand: card.brand ?? null,
      number: card.number ?? null,
      expMonth: card.expMonth ?? null,
      expYear: card.expYear ?? null,
      code: card.code ?? null,
    } : null,
    identity: identity ? {
      ...identity,
      title: identity.title ?? null,
      firstName: identity.firstName ?? null,
      middleName: identity.middleName ?? null,
      lastName: identity.lastName ?? null,
      address1: identity.address1 ?? null,
      address2: identity.address2 ?? null,
      address3: identity.address3 ?? null,
      city: identity.city ?? null,
      state: identity.state ?? null,
      postalCode: identity.postalCode ?? null,
      country: identity.country ?? null,
      company: identity.company ?? null,
      email: identity.email ?? null,
      phone: identity.phone ?? null,
      ssn: identity.ssn ?? null,
      username: identity.username ?? null,
      passportNumber: identity.passportNumber ?? null,
      licenseNumber: identity.licenseNumber ?? null,
    } : null,
    secureNote: secureNote ?? null,
    fields: fields?.map((f: any) => ({
      ...f,
      name: f.name ?? null,
      value: f.value ?? null,
      type: f.type,
      linkedId: f.linkedId ?? null,
    })) || null,
    passwordHistory: passwordHistory ?? null,
    reprompt: c.reprompt ?? 0,
    sshKey: normalizeCipherSshKeyForCompatibility(sshKey ?? null),
    bankAccount: bankAccount ?? null,
    driversLicense: driversLicense ?? null,
    passport: passport ?? null,
    key: key ?? null,
    createdAt: now,
    updatedAt: now,
    archivedAt: null,
    deletedAt: null,
  };
  cipher.login = normalizeCipherLoginForStorage(cipher.login);
  return cipher;
}

/** The write of one imported item, organization included, for a batch. */
export function cipherInsertStatement(db: D1Database, cipher: Cipher): D1PreparedStatement {
  const data = JSON.stringify(cipher);
  return db
    .prepare(
      'INSERT INTO ciphers(id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, archived_at, deleted_at, organization_id) ' +
      'VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(id) DO UPDATE SET ' +
      'user_id=excluded.user_id, type=excluded.type, folder_id=excluded.folder_id, name=excluded.name, notes=excluded.notes, favorite=excluded.favorite, data=excluded.data, reprompt=excluded.reprompt, key=excluded.key, updated_at=excluded.updated_at, archived_at=excluded.archived_at, deleted_at=excluded.deleted_at, organization_id=excluded.organization_id'
    )
    .bind(
      cipher.id,
      cipher.userId,
      Number(cipher.type) || 1,
      bindNull(cipher.folderId),
      bindNull(cipher.name),
      bindNull(cipher.notes),
      cipher.favorite ? 1 : 0,
      data,
      bindNull(cipher.reprompt ?? 0),
      bindNull(cipher.key),
      cipher.createdAt,
      cipher.updatedAt,
      bindNull(cipher.archivedAt),
      bindNull(cipher.deletedAt),
      bindNull(cipher.organizationId ?? null)
    );
}

export async function handleCiphersImport(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const url = new URL(request.url);
  const returnCipherMap = url.searchParams.get('returnCipherMap') === '1';

  let importData: CiphersImportRequest;
  try {
    importData = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const folders = Array.isArray(importData.folders) ? importData.folders : [];
  const ciphers = Array.isArray(importData.ciphers) ? importData.ciphers : [];
  const folderRelationships = Array.isArray(importData.folderRelationships) ? importData.folderRelationships : [];

  if (folders.length + ciphers.length > LIMITS.performance.importItemLimit) {
    return errorResponse(`Import exceeds maximum of ${LIMITS.performance.importItemLimit} items`, 400);
  }

  const now = new Date().toISOString();
  const batchChunkSize = LIMITS.performance.bulkMoveChunkSize;

  // Create folders and build index -> id mapping
  const folderIdMap = new Map<number, string>();
  const folderRows: Folder[] = [];
  
  for (let i = 0; i < folders.length; i++) {
    const importedFolder = folders[i] && typeof folders[i] === 'object' ? folders[i] : null;
    const folderId = generateUUID();
    folderIdMap.set(i, folderId);

    const folder: Folder = {
      id: folderId,
      userId: userId,
      name: typeof importedFolder?.name === 'string' && importedFolder.name ? importedFolder.name : 'Folder',
      tagName: typeof importedFolder?.tagName === 'string' ? importedFolder.tagName.trim().slice(0, 64) || null : null,
      createdAt: now,
      updatedAt: now,
    };

    folderRows.push(folder);
  }

  if (folderRows.length > 0) {
    const folderStatements = folderRows.map(folder =>
      env.DB
        .prepare(
          'INSERT INTO folders(id, user_id, name, tag_name, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?) ' +
          'ON CONFLICT(id) DO UPDATE SET user_id=excluded.user_id, name=excluded.name, tag_name=excluded.tag_name, updated_at=excluded.updated_at'
        )
        .bind(folder.id, folder.userId, folder.name, folder.tagName ?? null, folder.createdAt, folder.updatedAt)
    );
    await runBatchInChunks(env.DB, folderStatements, batchChunkSize);
  }

  // Build cipher index -> folder id mapping from relationships
  const cipherFolderMap = new Map<number, string>();
  for (const rel of folderRelationships) {
    if (!rel || typeof rel !== 'object') continue;
    const folderId = folderIdMap.get(rel.value);
    if (folderId) {
      cipherFolderMap.set(rel.key, folderId);
    }
  }
  const existingFolderIds = new Set((await storage.getAllFolders(userId)).map((folder) => folder.id));

  // Create ciphers
  const cipherRows: Cipher[] = [];
  const cipherMapRows: Array<{ index: number; sourceId: string | null; id: string }> = [];
  for (let i = 0; i < ciphers.length; i++) {
    const c = ciphers[i] && typeof ciphers[i] === 'object' ? ciphers[i] : {} as CiphersImportRequest['ciphers'][number];
    const importedFolderId = normalizeOptionalId(readAliasedImportProp<string | null>(c, ['folderId', 'FolderId']));
    const folderId = cipherFolderMap.get(i) || (importedFolderId && existingFolderIds.has(importedFolderId) ? importedFolderId : null);
    const sourceIdRaw = String(c?.id ?? '').trim();
    const sourceId = sourceIdRaw || null;
    const cipher = buildImportedCipher(c, userId, folderId, now);
    const compatibilityError = validateCipherEncryptedFieldsForCompatibility(cipher);
    if (compatibilityError) {
      return errorResponse(`Cipher ${i + 1}: ${compatibilityError}`, 400);
    }

    cipherRows.push(cipher);
    cipherMapRows.push({ index: i, sourceId, id: cipher.id });
  }

  if (cipherRows.length > 0) {
    const cipherStatements = cipherRows.map((cipher) => cipherInsertStatement(env.DB, cipher));
    await runBatchInChunks(env.DB, cipherStatements, batchChunkSize);
  }

  // Update revision date
  const revisionDate = await storage.updateRevisionDate(userId);
  notifyUserVaultSync(env, userId, revisionDate, readActingDeviceIdentifier(request));

  if (returnCipherMap) {
    return jsonResponse({
      object: 'import-result',
      cipherMap: cipherMapRows,
    });
  }

  return new Response(null, { status: 200 });
}

interface OrganizationImportRequest extends CiphersImportRequest {
  collections?: Array<{ id?: string | null; name?: string | null; externalId?: string | null }>;
  collectionRelationships?: Array<{ key: number; value: number }>;
}

// Owner (0) and admin (1) manage every collection of the organization.
const ORGANIZATION_ADMIN_MAX_TYPE = 1;
const MEMBERSHIP_CONFIRMED = 2;

/**
 * POST /api/ciphers/import-organization?organizationId=
 *
 * The official web vault's import into an organization:
 * `{ ciphers, collections, collectionRelationships }`, every name already
 * encrypted with the organization key. As in vaultwarden, the caller has to
 * be a confirmed member; an existing collection needs write rights on it, and
 * only an owner or admin creates new ones. Every item goes into the
 * organization, never into a personal folder.
 *
 * A shared item in NodeWarden always sits in at least one collection, so an
 * item the request leaves without one is refused rather than left unassigned.
 * The whole request is checked before anything is written.
 */
export async function handleOrganizationCiphersImport(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const organizationId = normalizeOptionalId(
    new URL(request.url).searchParams.get('organizationId') ?? new URL(request.url).searchParams.get('OrganizationId')
  );
  if (!organizationId) return errorResponse('organizationId is required', 400);

  const membership = await storage.getOrganizationUserForUser(organizationId, userId);
  if (!membership) return errorResponse('Organization not found', 404);
  if (membership.status !== MEMBERSHIP_CONFIRMED) {
    return errorResponse('You need to be a Member of the Organization to call this endpoint', 403);
  }
  const isAdmin = membership.type <= ORGANIZATION_ADMIN_MAX_TYPE;

  let importData: OrganizationImportRequest;
  try {
    importData = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }
  const ciphers = Array.isArray(importData.ciphers) ? importData.ciphers : [];
  const collections = Array.isArray(importData.collections) ? importData.collections : [];
  const relationships = Array.isArray(importData.collectionRelationships) ? importData.collectionRelationships : [];
  if (collections.length + ciphers.length > LIMITS.performance.importItemLimit) {
    return errorResponse(`Import exceeds maximum of ${LIMITS.performance.importItemLimit} items`, 400);
  }

  const now = new Date().toISOString();

  // The collections, by their index in the request: an existing one by id, or
  // a new one the caller is allowed to create.
  const requestedIds = collections
    .map((collection) => normalizeOptionalId(collection?.id))
    .filter((id): id is string => !!id);
  const existingIds = requestedIds.length
    ? await storage.getOrganizationCollectionIds(organizationId, requestedIds)
    : new Set<string>();
  const rights = !isAdmin && existingIds.size
    ? await storage.getCollectionRightsForCollections(userId, [...existingIds])
    : new Map();
  const collectionIdByIndex: string[] = [];
  const newCollections: Array<{ id: string; name: string }> = [];
  for (let i = 0; i < collections.length; i++) {
    const requested = normalizeOptionalId(collections[i]?.id);
    if (requested && existingIds.has(requested)) {
      const entry = rights.get(requested);
      if (!isAdmin && (!entry || entry.readOnly || entry.hidePasswords)) {
        return errorResponse("The current user isn't allowed to manage this collection", 403);
      }
      collectionIdByIndex.push(requested);
      continue;
    }
    if (!isAdmin) return errorResponse("The current user isn't allowed to create new collections", 403);
    const name = String(collections[i]?.name || '').trim();
    if (!name) return errorResponse(`Collection ${i + 1}: a name is required`, 400);
    if (!isValidEncString(name)) return errorResponse(COLLECTION_NAME_NOT_ENCRYPTED, 400);
    const id = generateUUID();
    newCollections.push({ id, name });
    collectionIdByIndex.push(id);
  }

  // Which collections each item goes into.
  const collectionsByCipher = new Map<number, Set<string>>();
  for (const relation of relationships) {
    const cipherIndex = Number(relation?.key);
    const collectionId = collectionIdByIndex[Number(relation?.value)];
    if (!Number.isInteger(cipherIndex) || cipherIndex < 0 || cipherIndex >= ciphers.length || !collectionId) {
      return errorResponse('Invalid collection relationship', 400);
    }
    if (!collectionsByCipher.has(cipherIndex)) collectionsByCipher.set(cipherIndex, new Set());
    collectionsByCipher.get(cipherIndex)!.add(collectionId);
  }

  const cipherRows: Cipher[] = [];
  for (let i = 0; i < ciphers.length; i++) {
    const assigned = collectionsByCipher.get(i);
    if (!assigned || !assigned.size) {
      return errorResponse(`Cipher ${i + 1}: a shared item must be placed in at least one collection`, 400);
    }
    const c = ciphers[i] && typeof ciphers[i] === 'object' ? ciphers[i] : ({} as CiphersImportRequest['ciphers'][number]);
    // The target organization replaces whatever the client put in the item,
    // and a shared item has no personal folder.
    const cipher = buildImportedCipher(c, userId, null, now);
    cipher.organizationId = organizationId;
    cipher.collectionIds = [...assigned];
    const compatibilityError = validateCipherEncryptedFieldsForCompatibility(cipher);
    if (compatibilityError) return errorResponse(`Cipher ${i + 1}: ${compatibilityError}`, 400);
    cipherRows.push(cipher);
  }

  const statements: D1PreparedStatement[] = [
    ...newCollections.map((collection) =>
      env.DB
        .prepare('INSERT INTO collections (id, org_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
        .bind(collection.id, organizationId, collection.name, now, now)
    ),
    ...cipherRows.map((cipher) => cipherInsertStatement(env.DB, cipher)),
    ...cipherRows.flatMap((cipher) =>
      (cipher.collectionIds ?? []).map((collectionId: string) =>
        env.DB.prepare('INSERT INTO collection_ciphers (cipher_id, collection_id) VALUES (?, ?)').bind(cipher.id, collectionId)
      )
    ),
  ];
  await runBatchInChunks(env.DB, statements, LIMITS.performance.bulkMoveChunkSize);

  const revisionDate = await storage.updateRevisionDate(userId);
  notifyUserVaultSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
  return new Response(null, { status: 200 });
}
