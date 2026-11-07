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
import { errorResponse, jsonResponse } from '../utils/response';
import type { Env } from '../types';

const OWNER_TYPE = 0;
const USER_TYPE = 2;
const STATUS_INVITED = 0;
const STATUS_CONFIRMED = 2;

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

  return jsonResponse(
    {
      id: orgId,
      name,
      billingEmail: text(body.billingEmail),
      key: wrappedOrganizationKey,
      status: STATUS_CONFIRMED,
      type: OWNER_TYPE,
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
  const requester = await storage.getOrganizationUserForUser(orgId, userId);
  if (!requester || requester.status !== STATUS_CONFIRMED) {
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
  const membershipByOrg = new Map(
    memberships.filter((membership) => membership.status === STATUS_CONFIRMED).map((membership) => [membership.orgId, membership])
  );
  return listResponse(
    organizations.map((organization) => ({
      id: organization.id,
      name: organization.name,
      key: membershipByOrg.get(organization.id)?.key ?? null,
      status: STATUS_CONFIRMED,
      type: membershipByOrg.get(organization.id)?.type ?? USER_TYPE,
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
    }))
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
  await storage.createCollection({ id: collectionId, orgId, name, now: new Date().toISOString() });
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
  if (!(await requireOrgAdmin(storage, orgId, userId))) {
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
  if (target.userId === userId) return errorResponse('Remove yourself from another owner account', 400);

  const removed = await storage.removeOrganizationUser(orgId, membershipId);
  if (!removed) return errorResponse('Organization member not found', 404);
  return new Response(null, { status: 204 });
}
