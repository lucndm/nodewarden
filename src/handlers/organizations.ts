// Creating an organization and handing its key to each member.
//
// The server never sees the organization key. The owner's client generates it,
// wraps it with the owner's public key, and sends that wrapped form together
// with the organization's RSA key pair (private key already encrypted under the
// organization key). An admin later wraps the same key for a new member with
// that member's public key and sends the blob; the server stores it and hands
// it back on sync.
//
// So the server stores blobs it cannot read, and every member receives the
// organization key in a form only their own private key opens. A member who has
// no wrapped key yet (invited, not confirmed) gets nothing.
import { StorageService } from '../services/storage';
import { notifyVaultSyncForRequest } from './ciphers';
import { errorResponse, jsonResponse } from '../utils/response';
import type { Env } from '../types';

const OWNER_TYPE = 0;
const USER_TYPE = 2;
const STATUS_INVITED = 0;
const STATUS_ACCEPTED = 1;
const STATUS_CONFIRMED = 2;
const STATUS_REVOKED = -1;

// A rotation is a bounded write. These caps keep one call from pushing an
// arbitrarily large body into the database; the client batches instead.
const ROTATION_KEY_MAX = 4096;
const ROTATION_FIELD_MAX = 4096;
const ROTATION_NOTES_MAX = 65_536;
const ROTATION_DATA_MAX = 65_536;
const ROTATION_MAX_CIPHERS = 200;
const ROTATION_MAX_MEMBERS = 200;
const ROTATION_MAX_TOTAL_BYTES = 8 * 1024 * 1024;

interface CreateOrganizationBody {
  name?: unknown;
  billingEmail?: unknown;
  collectionName?: unknown;
  /** The organization key, wrapped with the owner's public key. */
  key?: unknown;
  keys?: { encryptedPrivateKey?: unknown; publicKey?: unknown } | null;
}

function text(value: unknown, max = 256): string {
  return typeof value === 'string' ? value.slice(0, max) : '';
}

// POST /api/organizations
export async function handleCreateOrganization(
  request: Request,
  env: Env,
  userId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: CreateOrganizationBody;
  try {
    body = (await request.json()) as CreateOrganizationBody;
  } catch {
    return errorResponse('Invalid JSON body', 400);
  }

  const name = text(body.name).trim();
  if (!name) return errorResponse('Organization name is required', 400);

  // Without a wrapped key the members could never open a shared item, so an
  // organization created without one would be a shell.
  const wrappedOrganizationKey = text(body.key, 4096).trim();
  if (!wrappedOrganizationKey) {
    return errorResponse('The wrapped organization key is required', 400);
  }

  const publicKey = text(body.keys?.publicKey, 4096).trim();
  const encryptedPrivateKey = text(body.keys?.encryptedPrivateKey, 8192).trim();

  const now = new Date().toISOString();
  const orgId = crypto.randomUUID();
  const membershipId = crypto.randomUUID();
  const collectionId = crypto.randomUUID();
  const collectionName = text(body.collectionName).trim() || 'Default';

  await storage.createOrganizationWithOwner({
    id: orgId,
    name,
    privateKey: encryptedPrivateKey || null,
    publicKey: publicKey || null,
    ownerUserId: userId,
    ownerMembershipId: membershipId,
    wrappedOrganizationKey,
    collectionId,
    collectionName,
    now,
  });

  // A new organization changes what the member's vault holds, so the revision
  // moves: the official clients skip a sync whose revision matches, and would
  // otherwise not see the organization until something else changed.
  const organizationRevision = await storage.updateRevisionDate(userId, now);
  notifyVaultSyncForRequest(request, env, userId, organizationRevision);

  return jsonResponse(
    {
      id: orgId,
      name,
      billingEmail: text(body.billingEmail),
      key: wrappedOrganizationKey,
      status: STATUS_CONFIRMED,
      type: OWNER_TYPE,
      keyRotationRequired: false,
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
    },
    200
  );
}

interface InviteMemberBody {
  emails?: unknown;
  type?: unknown;
  /** The organization key wrapped for each invited member, keyed by email. */
  keys?: unknown;
}

// POST /api/organizations/:orgId/users
//
// An owner or admin adds a member. The wrapped key for that member is optional
// here: it can only be produced once the member's public key is known, so the
// usual flow is invite, then confirm with the wrapped key.
export async function handleInviteOrganizationUser(
  request: Request,
  env: Env,
  userId: string,
  orgId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);

  const requester = await storage.getOrganizationUserForUser(orgId, userId);
  if (!requester || requester.status !== STATUS_CONFIRMED || requester.type > 1) {
    return errorResponse('Organization not found', 404);
  }

  let body: InviteMemberBody;
  try {
    body = (await request.json()) as InviteMemberBody;
  } catch {
    return errorResponse('Invalid JSON body', 400);
  }

  const emails = Array.isArray(body.emails)
    ? body.emails.map((value) => text(value, 320).trim().toLowerCase()).filter(Boolean)
    : [];
  if (!emails.length) return errorResponse('At least one email is required', 400);

  const type = body.type === OWNER_TYPE || body.type === 1 ? Number(body.type) : USER_TYPE;
  if (type === OWNER_TYPE) {
    return errorResponse('An organization has one owner', 400);
  }

  const wrappedKeys =
    body.keys && typeof body.keys === 'object' ? (body.keys as Record<string, unknown>) : {};
  const now = new Date().toISOString();
  const added: string[] = [];

  for (const email of emails) {
    const user = await storage.getUser(email);
    if (!user) continue;
    const existing = await storage.getOrganizationUserForUser(orgId, user.id);
    if (existing) continue;

    const wrappedKey = text(wrappedKeys[email], 4096).trim();
    await storage.addOrganizationUser({
      id: crypto.randomUUID(),
      userId: user.id,
      orgId,
      type,
      // A member whose key was wrapped in the same request is already
      // confirmed; a member without one stays invited.
      status: wrappedKey ? STATUS_CONFIRMED : STATUS_INVITED,
      now,
    });
    if (wrappedKey) {
      const membership = await storage.getOrganizationUserForUser(orgId, user.id);
      if (membership) {
        await storage.confirmOrganizationUser({
          membershipId: membership.id,
          orgId,
          wrappedOrganizationKey: wrappedKey,
          now,
        });
      }
    }
    added.push(user.id);
  }

  return jsonResponse({ object: 'list', data: added.map((id) => ({ id })), continuationToken: null }, 200);
}

interface ConfirmMemberBody {
  key?: unknown;
}

// POST /api/organizations/:orgId/users/:membershipId/confirm
//
// An admin wraps the organization key for the confirmed member and sends it.
// The server stores the blob and confirms the membership.
export async function handleConfirmOrganizationUser(
  request: Request,
  env: Env,
  userId: string,
  orgId: string,
  membershipId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);

  const requester = await storage.getOrganizationUserForUser(orgId, userId);
  if (!requester || requester.status !== STATUS_CONFIRMED || requester.type > 1) {
    return errorResponse('Organization not found', 404);
  }

  let body: ConfirmMemberBody;
  try {
    body = (await request.json()) as ConfirmMemberBody;
  } catch {
    return errorResponse('Invalid JSON body', 400);
  }

  const wrappedOrganizationKey = text(body.key, 4096).trim();
  if (!wrappedOrganizationKey) {
    return errorResponse('The wrapped organization key is required', 400);
  }

  const confirmed = await storage.confirmOrganizationUser({
    membershipId,
    orgId,
    wrappedOrganizationKey,
    now: new Date().toISOString(),
  });
  if (!confirmed) return errorResponse('Organization member not found', 404);

  return jsonResponse({ id: membershipId, status: STATUS_CONFIRMED, object: 'organizationUser' }, 200);
}

/** The public key of the member, so an admin's client can wrap the org key. */
export async function handleGetMemberPublicKeys(
  request: Request,
  env: Env,
  userId: string,
  orgId: string,
  userIds: string[]
): Promise<Response> {
  const storage = new StorageService(env.DB);
  // Only an owner or an admin needs the member list, and only they may read it:
  // handing it to every member would let one enumerate the organization.
  const requester = await storage.getOrganizationUserForUser(orgId, userId);
  if (!requester || requester.status !== STATUS_CONFIRMED || requester.type > 1) {
    return errorResponse('Organization not found', 404);
  }
  const keys = await storage.getMemberPublicKeys(userIds);
  return jsonResponse(
    {
      object: 'list',
      data: [...keys.entries()].map(([id, publicKey]) => ({
        id,
        userId: id,
        publicKey: publicKey ?? null,
        object: 'organizationUserPublicKey',
      })),
      continuationToken: null,
    },
    200
  );
}

// POST /api/organizations/:orgId/accept
//
// The invited member accepts the invitation. Accepting does not hand over the
// organization key: that is wrapped with the member's own RSA key, so the
// owner still has to do it. What accepting says is that the member wants in.
export async function handleAcceptOrganization(
  request: Request,
  env: Env,
  userId: string,
  orgId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const membership = await storage.getOrganizationUserForUser(orgId, userId);
  if (!membership) return errorResponse('Organization not found', 404);
  if (membership.status === STATUS_CONFIRMED) {
    return errorResponse('This membership is already confirmed', 400);
  }
  if (membership.status === STATUS_REVOKED) {
    return errorResponse('This invitation was withdrawn', 400);
  }

  const accepted = await storage.acceptOrganizationUser({
    membershipId: membership.id,
    orgId,
    now: new Date().toISOString(),
  });
  if (!accepted) return errorResponse('This invitation was withdrawn', 400);
  return jsonResponse({ id: membership.id, status: STATUS_ACCEPTED, object: 'organizationUser' }, 200);
}

/**
 * GET /api/organizations/:orgId/users
 *
 * The members of the organization, with the role they hold and the rights
 * they hold on each collection.
 *
 * Only an owner or an admin may read it: it is the list of who can reach the
 * organization's items.
 */
export async function handleGetOrganizationUsers(
  request: Request,
  env: Env,
  userId: string,
  orgId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  if (!(await requireOrgAdmin(storage, orgId, userId))) {
    return errorResponse('Organization not found', 404);
  }

  const memberships = await storage.getOrganizationUsers(orgId);
  const emails = await storage.getMemberEmails(memberships.map((membership) => membership.userId));
  const users: Array<Record<string, unknown>> = [];
  for (const membership of memberships) {
    const assignments = await storage.getMembershipCollections(membership.id);
    users.push({
      id: membership.id,
      userId: membership.userId,
      email: emails.get(membership.userId) ?? null,
      type: membership.type,
      status: membership.status,
      collections: assignments.map((entry) => ({
        id: entry.collectionId,
        readOnly: entry.readOnly,
        hidePasswords: entry.hidePasswords,
        manage: entry.manage,
      })),
      object: 'organizationUserDetails',
    });
  }

  return jsonResponse({ object: 'list', data: users, continuationToken: null }, 200);
}

/**
 * GET /api/organizations/:orgId/rotation-data
 *
 * Everything a key rotation needs, in one read: the organization's encrypted
 * private key, the members who keep their access, and the items the rotation
 * has to re-encrypt.
 *
 * Only the owner gets this. The rotation itself is the owner's job, and the
 * private key would be handed out with it.
 */
export async function handleGetOrganizationRotationData(
  request: Request,
  env: Env,
  userId: string,
  orgId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const requester = await storage.getOrganizationUserForUser(orgId, userId);
  if (!requester || requester.status !== STATUS_CONFIRMED || requester.type !== OWNER_TYPE) {
    return errorResponse('Organization not found', 404);
  }

  const organizations = await storage.getOrganizationsForUser(userId);
  const organization = organizations.find((entry) => entry.id === orgId);
  if (!organization) return errorResponse('Organization not found', 404);

  // Only members who stay keep their access, and only they need the new key.
  // Only the confirmed members keep their access, so only they get the new
  // key. An invited member has none yet.
  const memberships = (await storage.getOrganizationUsers(orgId)).filter(
    (membership) => membership.status === STATUS_CONFIRMED
  );
  const publicKeys = await storage.getMemberPublicKeys(memberships.map((membership) => membership.userId));
  const members = memberships.map((membership) => ({
    membershipId: membership.id,
    userId: membership.userId,
    publicKey: publicKeys.get(membership.userId) ?? null,
  }));

  const ciphers = await storage.getOrganizationCiphersForRotation(orgId);

  return jsonResponse(
    {
      object: 'organizationRotationData',
      organization: {
        id: organization.id,
        name: organization.name,
        privateKey: organization.privateKey,
      },
      members,
      ciphers: ciphers.map((cipher) => ({
        id: cipher.id,
        key: cipher.key,
        name: cipher.name,
        notes: cipher.notes,
        data: cipher.data,
      })),
    },
    200
  );
}

export async function handleUnsupportedOrganizationAction(): Promise<Response> {
  return errorResponse('Not implemented', 501);
}

function listResponse(data: unknown[]): Response {
  return jsonResponse({ data, object: 'list', continuationToken: null });
}

// GET /api/organizations
export async function handleGetOrganizations(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const [organizations, memberships] = await Promise.all([
    storage.getOrganizationsForUser(userId),
    storage.getOrganizationUsersForUser(userId),
  ]);
  // The organization key travels wrapped for the member asking: an invited
  // member has no wrapped key yet and gets none.
  // An invited member is not a member yet, but they have to see the
  // invitation, and they see no key until the owner hands it over.
  const membershipByOrg = new Map(memberships.map((membership) => [membership.orgId, membership]));
  return listResponse(
    organizations.map((organization) => {
      const membership = membershipByOrg.get(organization.id);
      const confirmed = membership?.status === STATUS_CONFIRMED;
      return {
      id: organization.id,
      name: organization.name,
      key: confirmed ? membership?.key ?? null : null,
      status: membership?.status ?? STATUS_INVITED,
      type: membership?.type ?? USER_TYPE,
      // A member left while holding the key: the owner has to rotate before
      // their removal actually keeps anything away from them.
      keyRotationRequired: organization.keyRotationRequired,
      keyRotatedAt: organization.keyRotatedAt,
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
      };
    })
  );
}

// GET /api/collections
export async function handleGetCollections(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const [collections, rights] = await Promise.all([
    storage.getCollectionsForUser(userId),
    storage.getCollectionRights(userId),
  ]);
  const rightsByCollection = new Map(rights.map((entry) => [entry.collectionId, entry]));
  return listResponse(
    collections.map((collection) => {
      // A collection the member reaches always has rights. The fallback cannot
      // grant anything: it reports the most restrictive reading.
      const entry = rightsByCollection.get(collection.id);
      return {
        id: collection.id,
        organizationId: collection.orgId,
        name: collection.name,
        externalId: null,
        type: 0,
        readOnly: entry?.readOnly ?? true,
        hidePasswords: entry?.hidePasswords ?? true,
        manage: entry?.manage ?? false,
        object: 'collectionDetails',
      };
    })
  );
}

/** The membership of an owner or admin, or null when the caller has no say. */
async function requireOrgAdmin(storage: StorageService, orgId: string, userId: string) {
  const membership = await storage.getOrganizationUserForUser(orgId, userId);
  if (!membership || membership.status !== STATUS_CONFIRMED || membership.type > 1) return null;
  return membership;
}

// POST /api/organizations/:orgId/collections
export async function handleCreateCollection(
  request: Request,
  env: Env,
  userId: string,
  orgId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  if (!(await requireOrgAdmin(storage, orgId, userId))) {
    return errorResponse('Organization not found', 404);
  }

  let body: { name?: unknown };
  try {
    body = (await request.json()) as { name?: unknown };
  } catch {
    return errorResponse('Invalid JSON body', 400);
  }
  const name = text(body.name).trim();
  if (!name) return errorResponse('Collection name is required', 400);

  const collectionId = crypto.randomUUID();
  const now = new Date().toISOString();
  await storage.createCollection({ id: collectionId, orgId, name, now });
  // A collection is something the members' clients have to sync.
  for (const membership of await storage.getOrganizationUsers(orgId)) {
    if (membership.status !== STATUS_CONFIRMED) continue;
    const revision = await storage.updateRevisionDate(membership.userId, now);
    notifyVaultSyncForRequest(request, env, membership.userId, revision);
  }
  return jsonResponse(
    {
      id: collectionId,
      organizationId: orgId,
      name,
      externalId: null,
      type: 0,
      readOnly: false,
      hidePasswords: false,
      manage: true,
      object: 'collectionDetails',
    },
    200
  );
}

// GET /api/organizations/:orgId/collections
//
// The collections of one organization that this member may reach, with the
// rights they hold on each. The official clients ask for this before they let
// a member put an item into a collection.
export async function handleGetOrganizationCollections(
  request: Request,
  env: Env,
  userId: string,
  orgId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const membership = await storage.getOrganizationUserForUser(orgId, userId);
  if (!membership || membership.status !== STATUS_CONFIRMED) {
    return errorResponse('Organization not found', 404);
  }

  const [collections, rights] = await Promise.all([
    storage.getCollectionsForUser(userId),
    storage.getCollectionRights(userId),
  ]);
  const rightsByCollection = new Map(rights.map((entry) => [entry.collectionId, entry]));
  return listResponse(
    collections
      .filter((collection) => collection.orgId === orgId)
      .map((collection) => {
        const entry = rightsByCollection.get(collection.id);
        return {
          id: collection.id,
          organizationId: collection.orgId,
          name: collection.name,
          externalId: null,
          type: 0,
          // The fallback grants nothing: a collection whose rights did not
          // arrive is reported as the most restrictive reading.
          readOnly: entry?.readOnly ?? true,
          hidePasswords: entry?.hidePasswords ?? true,
          manage: entry?.manage ?? false,
          object: 'collectionDetails',
        };
      })
  );
}

interface MemberRightsBody {
  type?: unknown;
  collections?: unknown;
}

// PUT /api/organizations/:orgId/users/:membershipId
//
// The owner or an admin sets the role of a member and the rights that member
// holds on each collection. The assignments replace the previous ones.
export async function handleUpdateOrganizationUser(
  request: Request,
  env: Env,
  userId: string,
  orgId: string,
  membershipId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const requester = await requireOrgAdmin(storage, orgId, userId);
  if (!requester) {
    return errorResponse('Organization not found', 404);
  }

  const members = await storage.getOrganizationMembershipIds(orgId);
  if (!members.has(membershipId)) return errorResponse('Organization member not found', 404);

  let body: MemberRightsBody;
  try {
    body = (await request.json()) as MemberRightsBody;
  } catch {
    return errorResponse('Invalid JSON body', 400);
  }

  const now = new Date().toISOString();

  if (body.type !== undefined) {
    const type = Number(body.type);
    if (![0, 1, 2].includes(type)) return errorResponse('Invalid role', 400);
    // Nobody becomes an owner through this route, and the owner of the
    // organization does not change here.
    if (type === 0) return errorResponse('An organization has one owner', 400);
    // Only the owner hands out a role: an admin who could promote members
    // would be able to hand their own powers on.
    if (requester.type !== OWNER_TYPE) return errorResponse('Only the owner changes roles', 403);
    const target = (await storage.getOrganizationUsers(orgId)).find((entry) => entry.id === membershipId);
    if (target?.type === 0) return errorResponse('The owner role does not change here', 400);
    await storage.setOrganizationUserType(orgId, membershipId, type);
  }

  if (body.collections !== undefined) {
    if (!Array.isArray(body.collections)) return errorResponse('collections must be an array', 400);
    const requested = body.collections
      .map((entry) => entry as { id?: unknown; readOnly?: unknown; hidePasswords?: unknown; manage?: unknown })
      .filter((entry) => typeof entry?.id === 'string' && (entry.id as string).trim())
      .map((entry) => ({
        collectionId: String(entry.id).trim(),
        readOnly: entry.readOnly === true,
        hidePasswords: entry.hidePasswords === true,
        manage: entry.manage === true,
      }));

    const ids = requested.map((entry) => entry.collectionId);
    const owned = await storage.getOrganizationCollectionIds(orgId, ids);
    if (owned.size !== new Set(ids).size) return errorResponse('Collection not found', 404);

    await storage.replaceMembershipCollections(membershipId, requested);
  }

  const updated = (await storage.getOrganizationUsers(orgId)).find((entry) => entry.id === membershipId);
  const assignments = await storage.getMembershipCollections(membershipId);
  return jsonResponse(
    {
      id: membershipId,
      organizationId: orgId,
      userId: updated?.userId ?? null,
      type: updated?.type ?? USER_TYPE,
      status: updated?.status ?? STATUS_CONFIRMED,
      collections: assignments.map((entry) => ({
        id: entry.collectionId,
        readOnly: entry.readOnly,
        hidePasswords: entry.hidePasswords,
        manage: entry.manage,
      })),
      object: 'organizationUserDetails',
      updatedAt: now,
    },
    200
  );
}

// DELETE /api/organizations/:orgId/users/:membershipId
//
// Removing a member takes their rights away at once: the queries that resolve
// access join the membership, so every collection they reached stops counting.
// It cannot take back the organization key they already unwrapped.
export async function handleRemoveOrganizationUser(
  request: Request,
  env: Env,
  userId: string,
  orgId: string,
  membershipId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const requester = await requireOrgAdmin(storage, orgId, userId);
  if (!requester) return errorResponse('Organization not found', 404);

  const target = (await storage.getOrganizationUsers(orgId)).find((entry) => entry.id === membershipId);
  if (!target) return errorResponse('Organization member not found', 404);
  if (target.type === 0) return errorResponse('The owner cannot be removed', 400);
  // An admin may remove a member; removing another admin is the owner's call,
  // so two admins cannot strip each other out of the organization.
  if (target.type === 1 && requester.type !== OWNER_TYPE) {
    return errorResponse('Only the owner removes an admin', 400);
  }
  if (target.userId === userId) return errorResponse('Remove yourself from another owner account', 400);

  const removed = await storage.removeOrganizationUser(orgId, membershipId);
  if (!removed) return errorResponse('Organization member not found', 404);
  // 204 keeps the shape the clients expect; the organization now reports
  // keyRotationRequired, which is what tells the owner the removal is not done
  // until the key is replaced.
  return new Response(null, { status: 204 });
}

interface RotateKeyBody {
  privateKey?: unknown;
  members?: unknown;
  ciphers?: unknown;
}

// POST /api/organizations/:orgId/rotate-key
//
// The owner's client generates a new organization key, wraps it for every
// remaining member, and re-wraps the item key of every shared item under it.
// The server stores the new blobs; it cannot read any of them, and it cannot
// rotate anything on its own.
//
// Rotating is what makes a removal mean something: without it, a member who
// left still holds the key they unwrapped and can open the items they kept.
export async function handleRotateOrganizationKey(
  request: Request,
  env: Env,
  userId: string,
  orgId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);

  // Only the owner rotates: an admin rotating could lock the owner out.
  const requester = await storage.getOrganizationUserForUser(orgId, userId);
  if (!requester || requester.status !== STATUS_CONFIRMED || requester.type !== OWNER_TYPE) {
    return errorResponse('Organization not found', 404);
  }

  let body: RotateKeyBody;
  try {
    body = (await request.json()) as RotateKeyBody;
  } catch {
    return errorResponse('Invalid JSON body', 400);
  }

  const members = Array.isArray(body.members)
    ? body.members
        .map((entry) => entry as { membershipId?: unknown; key?: unknown })
        .map((entry) => ({
          membershipId: text(entry?.membershipId).trim(),
          key: text(entry?.key, 4096).trim(),
        }))
        .filter((entry) => entry.membershipId && entry.key)
    : [];
  // Rotation fields are rejected when they are too long, never truncated: a
  // shortened ciphertext is a broken item, and the client would never know.
  let rotationFieldTooLong = false;
  const strict = (value: unknown, max: number): string => {
    const raw = typeof value === 'string' ? value : '';
    if (raw.length > max) rotationFieldTooLong = true;
    return raw;
  };
  const ciphers = Array.isArray(body.ciphers)
    ? body.ciphers
        .map((entry) => entry as { id?: unknown; key?: unknown; name?: unknown; notes?: unknown; data?: unknown })
        .map((entry) => ({
          cipherId: text(entry?.id).trim(),
          key: strict(entry?.key, ROTATION_KEY_MAX).trim() || null,
          // The name and the notes live in their own columns, so they travel
          // beside the payload and are re-encrypted with it.
          name: entry?.name === undefined ? undefined : strict(entry.name, ROTATION_FIELD_MAX) || null,
          notes: entry?.notes === undefined ? undefined : strict(entry.notes, ROTATION_NOTES_MAX) || null,
          data: strict(entry?.data, ROTATION_DATA_MAX),
        }))
        .filter((entry) => entry.cipherId && entry.data)
    : [];
  const membersTooLong = Array.isArray(body.members)
    ? body.members.some((entry) => {
        const key = (entry as { key?: unknown })?.key;
        return typeof key === 'string' && key.length > ROTATION_KEY_MAX;
      })
    : false;
  if (rotationFieldTooLong || membersTooLong) {
    return errorResponse('The rotated key material is too long', 413);
  }
  const privateKey = body.privateKey === undefined ? undefined : text(body.privateKey, 8192) || null;

  if (!members.length && !ciphers.length && privateKey === undefined) {
    return errorResponse('Nothing to rotate', 400);
  }

  // A rotation is one bounded write. Without a ceiling an owner could use it to
  // push an arbitrarily large body into the database in a single call; the
  // client sends the organization in batches instead.
  if (ciphers.length > ROTATION_MAX_CIPHERS || members.length > ROTATION_MAX_MEMBERS) {
    return errorResponse('Rotate fewer items at a time', 413);
  }
  const totalBytes = ciphers.reduce(
    (sum, entry) => sum + entry.data.length + (entry.name?.length ?? 0) + (entry.notes?.length ?? 0) + (entry.key?.length ?? 0),
    members.reduce((sum, entry) => sum + entry.key.length, 0) + (privateKey?.length ?? 0)
  );
  if (totalBytes > ROTATION_MAX_TOTAL_BYTES) {
    return errorResponse('Rotate fewer items at a time', 413);
  }

  // Every membership must belong to this organization, and every item must be
  // one of its own: a rotation naming anything else is refused whole.
  const organizationMembers = await storage.getOrganizationMembershipIds(orgId);
  for (const member of members) {
    if (!organizationMembers.has(member.membershipId)) {
      return errorResponse('Organization member not found', 404);
    }
  }
  if (ciphers.length) {
    const organizationCollections = await storage.getOrganizationCollectionIds(orgId, []);
    void organizationCollections;
    const ranks = await storage.getCipherRankByCipherForUser(userId);
    for (const cipher of ciphers) {
      const cipherRecord = await storage.getCipher(cipher.cipherId);
      if (!cipherRecord || cipherRecord.organizationId !== orgId) {
        return errorResponse('Cipher not found', 404);
      }
      void ranks;
    }
  }

  const now = new Date().toISOString();
  await storage.rotateOrganizationKey({
    orgId,
    privateKey,
    memberKeys: members,
    cipherKeys: ciphers,
    now,
  });

  // Every member has to fetch the new blobs, so their revision moves.
  const memberships = await storage.getOrganizationUsers(orgId);
  let revisionDate: string | null = null;
  for (const membership of memberships) {
    const revision = await storage.updateRevisionDate(membership.userId, now);
    if (revision) revisionDate = revision;
  }
  if (revisionDate) notifyVaultSyncForRequest(request, env, userId, revisionDate);

  return jsonResponse(
    {
      object: 'organizationKeyRotation',
      rotatedAt: now,
      members: members.length,
      ciphers: ciphers.length,
    },
    200
  );
}
