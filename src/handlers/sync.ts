import { Env, SyncResponse, CipherResponse, FolderResponse, ProfileResponse } from '../types';
import { StorageService } from '../services/storage';
import { errorResponse } from '../utils/response';
import { cipherToResponse, isCipherResponseSyncCompatible, shouldPreserveRepairableCipherUris } from './ciphers';
import { sendToResponse } from './sends';
import { LIMITS } from '../config/limits';
import {
  buildUserDecryptionCompat,
  buildUserDecryptionOptions,
} from '../utils/user-decryption';
import { buildDomainsResponse } from '../services/domain-rules';
import { buildWebAuthnPrfOption } from '../utils/account-passkeys';
import { buildProfileResponse } from '../utils/profile-response';

// CONTRACT:
// /api/sync reuses cipherToResponse() as the single cipher response shaper.
// Filtering invalid cipher responses here protects clients from stored rows that
// would otherwise make official apps fail after an HTTP 200 sync.
// Keep this aligned with src/handlers/ciphers.ts when adding new vault fields.
function buildSyncCacheRequest(
  request: Request,
  userId: string,
  revisionDate: string,
  accountPasskeyCacheTag: string,
  excludeDomains: boolean,
  excludeSends: boolean,
  preserveRepairableUris: boolean
): Request {
  const url = new URL(request.url);
  const cacheUrl = new URL(
    `/__nodewarden/cache/sync/${encodeURIComponent(userId)}/${encodeURIComponent(revisionDate)}/${encodeURIComponent(accountPasskeyCacheTag)}/${excludeDomains ? '1' : '0'}/${excludeSends ? '1' : '0'}/${preserveRepairableUris ? '1' : '0'}`,
    url.origin
  );
  return new Request(cacheUrl.toString(), { method: 'GET' });
}

async function readSyncCache(cacheRequest: Request): Promise<Response | null> {
  const hit = await caches.default.match(cacheRequest);
  if (!hit) return null;
  return new Response(hit.body, hit);
}

async function writeSyncCache(cacheRequest: Request, response: Response): Promise<void> {
  await caches.default.put(cacheRequest, response.clone());
}

// GET /api/sync
export async function handleSync(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const url = new URL(request.url);
  const excludeDomainsParam = url.searchParams.get('excludeDomains');
  const excludeDomains = excludeDomainsParam !== null && /^(1|true|yes)$/i.test(excludeDomainsParam);
  const excludeSendsParam = url.searchParams.get('excludeSends');
  const excludeSends = excludeSendsParam !== null && /^(1|true|yes)$/i.test(excludeSendsParam);
  const preserveRepairableUris = shouldPreserveRepairableCipherUris(request);

  const user = await storage.getUserById(userId);
  if (!user) {
    return errorResponse('User not found', 404);
  }

  // Legacy/imported ciphers that only carry folder_id get their tag backfill
  // here; the folders table keeps its rows and ids, so official clients see
  // no folder churn. Idempotent and cheap once migrated. The rewrite changes
  // cipher payloads, so the account revision has to move: the sync cache is
  // keyed by it and would otherwise keep serving the pre-repair bodies.
  if (await storage.migrateFolderCiphersToTags(userId)) {
    await storage.updateRevisionDate(userId);
  }

  const [revisionDate, accountPasskeys] = await Promise.all([
    storage.getRevisionDate(userId),
    storage.getAccountPasskeyCredentialsByUserId(userId),
  ]);
  const accountPasskeyCacheTag = accountPasskeys
    .map((credential) => [
      credential.id,
      credential.updatedAt,
      credential.supportsPrf ? '1' : '0',
      credential.encryptedUserKey && credential.encryptedPublicKey && credential.encryptedPrivateKey ? '1' : '0',
    ].join(':'))
    .join(',');
  const cacheRequest = buildSyncCacheRequest(request, userId, revisionDate, accountPasskeyCacheTag, excludeDomains, excludeSends, preserveRepairableUris);
  const cachedResponse = await readSyncCache(cacheRequest);
  if (cachedResponse) {
    return cachedResponse;
  }

  const [ciphers, folders, sends, attachmentsByCipher, domainSettings, collections, organizations, memberships] = await Promise.all([
    storage.getVisibleCiphers(userId),
    storage.getAllFolders(userId),
    excludeSends ? Promise.resolve([]) : storage.getAllSends(userId),
    storage.getAttachmentsByUserId(userId),
    excludeDomains ? Promise.resolve(null) : storage.getUserDomainSettings(userId),
    storage.getCollectionsForUser(userId),
    storage.getOrganizationsForUser(userId),
    storage.getOrganizationUsersForUser(userId),
  ]);
  const webAuthnPrfOptions = accountPasskeys
    .map(buildWebAuthnPrfOption)
    .filter((option): option is NonNullable<typeof option> => !!option);
  const userDecryptionOptions = buildUserDecryptionOptions(user, webAuthnPrfOptions[0] || null);
  const validFolderIds = new Set(folders.map((folder) => folder.id));

  // The organization key travels wrapped for the member asking: the server
  // never holds it in a readable form. An invited member has no wrapped key
  // yet and gets none.
  const membershipByOrg = new Map(
    memberships.filter((membership) => membership.status === 2).map((membership) => [membership.orgId, membership])
  );
  const organizationResponses = organizations.map((organization) => ({
    id: organization.id,
    name: organization.name,
    key: membershipByOrg.get(organization.id)?.key ?? null,
    keyRotationRequired: organization.keyRotationRequired,
    status: 2,
    type: membershipByOrg.get(organization.id)?.type ?? 2,
    enabled: true,
    usePolicies: false,
    useGroups: false,
    useDirectory: false,
    useEvents: false,
    useTotp: true,
    use2fa: true,
    useApi: true,
    usersGetPremium: true,
    object: 'profileOrganization',
  }));

  const profile: ProfileResponse = buildProfileResponse(user, env, {
    // The official Bitwarden SDK parses profile.masterPasswordHint from the
    // /api/sync payload as an EncString; stored plaintext hints ("myhint12")
    // make it throw "EncString error, Invalid length". Suppress here; the
    // dedicated /api/accounts/profile endpoint still returns the stored value
    // so the bundled web vault can prefill the Settings form.
    suppressNonEncStringHint: true,
    organizations: organizationResponses,
  });

  // A shared item names the collections it sits in, so the client can place it
  // and read its rights without a second request per item.
  const collectionIdsByCipher = await storage.getCollectionIdsByCipherIds(
    ciphers.filter((cipher) => !!cipher.organizationId).map((cipher) => cipher.id)
  );

  const cipherResponses: CipherResponse[] = [];
  for (const cipher of ciphers) {
    // The items the member may not read were already left out by the query
    // that reads the vault, so the interface hiding an item is never the only
    // thing keeping it from the client.
    const response = cipherToResponse(cipher, attachmentsByCipher.get(cipher.id) || [], {
      preserveRepairableUris,
      validFolderIds,
      collectionIds: cipher.organizationId ? (collectionIdsByCipher.get(cipher.id) ?? []) : undefined,
    });
    if (isCipherResponseSyncCompatible(response)) {
      cipherResponses.push(response);
    }
  }

  const folderResponses: FolderResponse[] = [];
  for (const folder of folders) {
    folderResponses.push({
      id: folder.id,
      name: folder.name,
      tagName: folder.tagName ?? null,
      revisionDate: folder.updatedAt,
      creationDate: folder.createdAt,
      object: 'folder',
    });
  }

  const sendResponses = sends.map(sendToResponse);
  const collectionRights = await storage.getCollectionRights(userId);
  const rightsByCollection = new Map(collectionRights.map((rights) => [rights.collectionId, rights]));
  const collectionResponses = collections.map((collection) => {
    const rights = rightsByCollection.get(collection.id);
    return {
      id: collection.id,
      organizationId: collection.orgId,
      name: collection.name,
      externalId: null,
      type: 0,
      readOnly: rights?.readOnly ?? true,
      hidePasswords: rights?.hidePasswords ?? true,
      manage: rights?.manage ?? false,
      object: 'collectionDetails',
    };
  });
  const syncResponse: SyncResponse = {
    profile,
    folders: folderResponses,
    collections: collectionResponses,
    ciphers: cipherResponses,
    domains: excludeDomains
      ? null
      : buildDomainsResponse(
          domainSettings?.equivalentDomains || [],
          domainSettings?.customEquivalentDomains || [],
          domainSettings?.excludedGlobalEquivalentDomains || [],
          { omitExcludedGlobals: true }
        ),
    policies: [],
    policiesNew: [],
    sends: sendResponses,
    UserDecryption: {
      MasterPasswordUnlock: userDecryptionOptions.MasterPasswordUnlock,
      TrustedDeviceOption: null,
      KeyConnectorOption: null,
      WebAuthnPrfOption: webAuthnPrfOptions[0] || null,
      WebAuthnPrfOptions: webAuthnPrfOptions,
      V2UpgradeToken: null,
      UserKeyId: user.userKeyId ?? null,
      Object: 'userDecryption',
    },
    UserDecryptionOptions: userDecryptionOptions,
    userDecryption: buildUserDecryptionCompat(user) as SyncResponse['userDecryption'],
    object: 'sync',
  };

  const response = new Response(JSON.stringify(syncResponse), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': `private, max-age=${Math.max(1, Math.floor(LIMITS.cache.syncResponseTtlMs / 1000))}`,
    },
  });
  await writeSyncCache(cacheRequest, response);
  return response;
}
