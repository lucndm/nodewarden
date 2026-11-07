// The organizations, collections and groups of the Bitwarden sharing model,
// and the rights a member holds on them.
//
// An organization holds collections. A member joins an organization and
// reaches a collection either directly (a collection assignment) or through a
// group. An item belongs to an organization and sits in one or more
// collections.
//
// The rights a member holds on a collection are read_only, hide_passwords and
// manage. How they combine for an item is decided in
// src/services/collection-access.ts, which follows the official server.
import { resolveItemAccess, type CollectionGrant, type ItemAccess } from './collection-access';

export interface Organization {
  id: string;
  name: string;
  /** The organization's RSA private key, encrypted with the organization key. */
  privateKey: string | null;
  /** The organization's RSA public key. */
  publicKey: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface OrganizationUser {
  id: string;
  userId: string;
  orgId: string;
  /** 0 owner, 1 admin, 2 user. */
  type: number;
  /** -1 revoked, 0 invited, 1 accepted, 2 confirmed. */
  status: number;
  /**
   * The organization's symmetric key, wrapped with this member's public key.
   * Null until an admin confirms the membership and wraps the key for them.
   */
  key: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface Collection {
  id: string;
  orgId: string;
  name: string;
  createdAt: string;
  updatedAt: string;
}

export interface Group {
  id: string;
  orgId: string;
  name: string;
  createdAt: string;
  updatedAt: string;
}

/** The rights a member holds on one collection. */
export interface CollectionRights {
  collectionId: string;
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
  /** True when the rights come from a direct collection assignment. */
  direct: boolean;
}

interface GrantRow {
  collection_id: string;
  read_only: number | null;
  hide_passwords: number | null;
  manage: number | null;
  direct: number | null;
}

/**
 * The grants a member holds on the collections an item sits in.
 *
 * The direct assignments and the group assignments are read separately, the
 * way the official server reads them: a direct assignment hides the group
 * grants for the same collection, so the group can neither widen nor narrow
 * it.
 */
export async function getItemGrants(
  db: D1Database,
  cipherId: string,
  userId: string
): Promise<CollectionGrant[]> {
  const rows = await db
    .prepare(
      'SELECT CC.collection_id AS collection_id, ' +
      'CU.read_only AS read_only, CU.hide_passwords AS hide_passwords, CU.manage AS manage, 1 AS direct ' +
      'FROM collection_ciphers CC ' +
      'INNER JOIN collections C ON C.id = CC.collection_id ' +
      'INNER JOIN organization_users OU ON OU.org_id = C.org_id AND OU.user_id = ? AND OU.status = 2 ' +
      'INNER JOIN collection_users CU ON CU.collection_id = CC.collection_id AND CU.org_user_id = OU.id ' +
      'WHERE CC.cipher_id = ? ' +
      'UNION ALL ' +
      'SELECT CC.collection_id AS collection_id, ' +
      'CG.read_only AS read_only, CG.hide_passwords AS hide_passwords, CG.manage AS manage, 0 AS direct ' +
      'FROM collection_ciphers CC ' +
      'INNER JOIN collections C ON C.id = CC.collection_id ' +
      'INNER JOIN organization_users OU ON OU.org_id = C.org_id AND OU.user_id = ? AND OU.status = 2 ' +
      'INNER JOIN collection_groups CG ON CG.collection_id = CC.collection_id ' +
      'INNER JOIN group_users GU ON GU.group_id = CG.group_id AND GU.org_user_id = OU.id ' +
      'WHERE CC.cipher_id = ? ' +
      'AND NOT EXISTS (SELECT 1 FROM collection_users CU2 ' +
      'WHERE CU2.collection_id = CG.collection_id AND CU2.org_user_id = OU.id)'
    )
    .bind(userId, cipherId, userId, cipherId)
    .all<GrantRow>();

  return (rows.results || []).map((row) => ({
    collectionId: row.collection_id,
    readOnly: !!row.read_only,
    hidePasswords: !!row.hide_passwords,
    manage: !!row.manage,
    direct: !!row.direct,
  }));
}

/** The rights a member holds on an item, or null when the item is out of reach. */
export async function getItemAccess(
  db: D1Database,
  cipherId: string,
  userId: string
): Promise<ItemAccess | null> {
  return resolveItemAccess(await getItemGrants(db, cipherId, userId));
}

/** The collections a member may see, with the rights they hold on each. */
export async function getCollectionRights(
  db: D1Database,
  userId: string
): Promise<CollectionRights[]> {
  const rows = await db
    .prepare(
      'SELECT C.id AS collection_id, ' +
      'COALESCE(CU.read_only, CG.read_only, 0) AS read_only, ' +
      'COALESCE(CU.hide_passwords, CG.hide_passwords, 0) AS hide_passwords, ' +
      'COALESCE(CU.manage, CG.manage, 0) AS manage, ' +
      'CASE WHEN CU.collection_id IS NOT NULL THEN 1 ELSE 0 END AS direct ' +
      'FROM collections C ' +
      'INNER JOIN organization_users OU ON OU.org_id = C.org_id AND OU.user_id = ? AND OU.status = 2 ' +
      'LEFT JOIN collection_users CU ON CU.collection_id = C.id AND CU.org_user_id = OU.id ' +
      'LEFT JOIN group_users GU ON GU.org_user_id = OU.id ' +
      'LEFT JOIN collection_groups CG ON CG.collection_id = C.id AND CG.group_id = GU.group_id ' +
      'WHERE CU.collection_id IS NOT NULL OR CG.collection_id IS NOT NULL'
    )
    .bind(userId)
    .all<GrantRow>();

  // A collection can come back twice, once per group. The direct assignment
  // wins, and between two group grants the better one wins.
  const byCollection = new Map<string, CollectionRights>();
  for (const row of rows.results || []) {
    const rights: CollectionRights = {
      collectionId: row.collection_id,
      readOnly: !!row.read_only,
      hidePasswords: !!row.hide_passwords,
      manage: !!row.manage,
      direct: !!row.direct,
    };
    const existing = byCollection.get(rights.collectionId);
    if (!existing || (rights.direct && !existing.direct)) {
      byCollection.set(rights.collectionId, rights);
    }
  }
  return [...byCollection.values()];
}

/** The organizations a member belongs to. */
export async function getOrganizationsForUser(db: D1Database, userId: string): Promise<Organization[]> {
  const res = await db
    .prepare(
      'SELECT O.id AS id, O.name AS name, O.private_key AS private_key, O.public_key AS public_key, ' +
      'O.created_at AS created_at, O.updated_at AS updated_at ' +
      'FROM organizations O ' +
      'INNER JOIN organization_users OU ON OU.org_id = O.id AND OU.user_id = ? AND OU.status = 2 ' +
      'ORDER BY O.name ASC'
    )
    .bind(userId)
    .all<{
      id: string;
      name: string;
      private_key: string | null;
      public_key: string | null;
      created_at: string;
      updated_at: string;
    }>();
  return (res.results || []).map((row) => ({
    id: row.id,
    name: row.name,
    privateKey: row.private_key,
    publicKey: row.public_key,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }));
}

/** The collections a member may see. */
export async function getCollectionsForUser(db: D1Database, userId: string): Promise<Collection[]> {
  const res = await db
    .prepare(
      'SELECT DISTINCT C.id AS id, C.org_id AS org_id, C.name AS name, C.created_at AS created_at, C.updated_at AS updated_at ' +
      'FROM collections C ' +
      'INNER JOIN organization_users OU ON OU.org_id = C.org_id AND OU.user_id = ? AND OU.status = 2 ' +
      'LEFT JOIN collection_users CU ON CU.collection_id = C.id AND CU.org_user_id = OU.id ' +
      'LEFT JOIN group_users GU ON GU.org_user_id = OU.id ' +
      'LEFT JOIN collection_groups CG ON CG.collection_id = C.id AND CG.group_id = GU.group_id ' +
      'WHERE CU.collection_id IS NOT NULL OR CG.collection_id IS NOT NULL ' +
      'ORDER BY C.name ASC'
    )
    .bind(userId)
    .all<{ id: string; org_id: string; name: string; created_at: string; updated_at: string }>();
  return (res.results || []).map((row) => ({
    id: row.id,
    orgId: row.org_id,
    name: row.name,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }));
}

/** The organization memberships of a member. */
export async function getOrganizationUsersForUser(
  db: D1Database,
  userId: string
): Promise<OrganizationUser[]> {
  const res = await db
    .prepare(
      'SELECT id, user_id, org_id, type, status, key, created_at, updated_at FROM organization_users ' +
      'WHERE user_id = ? ORDER BY created_at ASC'
    )
    .bind(userId)
    .all<{
      id: string;
      user_id: string;
      org_id: string;
      type: number;
      status: number;
      key: string | null;
      created_at: string;
      updated_at: string;
    }>();
  return (res.results || []).map((row) => ({
    id: row.id,
    userId: row.user_id,
    orgId: row.org_id,
    type: row.type,
    status: row.status,
    key: row.key,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }));
}

/** The groups a member is in. */
export async function getGroupsForUser(db: D1Database, userId: string): Promise<Group[]> {
  const res = await db
    .prepare(
      'SELECT DISTINCT G.id AS id, G.org_id AS org_id, G.name AS name, G.created_at AS created_at, G.updated_at AS updated_at ' +
      'FROM groups G ' +
      'INNER JOIN group_users GU ON GU.group_id = G.id ' +
      'INNER JOIN organization_users OU ON OU.id = GU.org_user_id AND OU.user_id = ? AND OU.status = 2 ' +
      'ORDER BY G.name ASC'
    )
    .bind(userId)
    .all<{ id: string; org_id: string; name: string; created_at: string; updated_at: string }>();
  return (res.results || []).map((row) => ({
    id: row.id,
    orgId: row.org_id,
    name: row.name,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }));
}

/**
 * The items a member may see in the organizations they belong to.
 *
 * This is the filter that keeps an item out of the sync response when the
 * member has no rights on it. It belongs here, in the query, and not in the
 * interface: an item the member may not read must not leave the server at
 * all.
 */
export async function getSharedCipherIdsForUser(
  db: D1Database,
  userId: string
): Promise<Set<string>> {
  const res = await db
    .prepare(
      'SELECT DISTINCT CC.cipher_id AS cipher_id ' +
      'FROM collection_ciphers CC ' +
      'INNER JOIN collections C ON C.id = CC.collection_id ' +
      'INNER JOIN organization_users OU ON OU.org_id = C.org_id AND OU.user_id = ? AND OU.status = 2 ' +
      'LEFT JOIN collection_users CU ON CU.collection_id = C.id AND CU.org_user_id = OU.id ' +
      'LEFT JOIN group_users GU ON GU.org_user_id = OU.id ' +
      'LEFT JOIN collection_groups CG ON CG.collection_id = C.id AND CG.group_id = GU.group_id ' +
      'WHERE CU.collection_id IS NOT NULL OR CG.collection_id IS NOT NULL'
    )
    .bind(userId)
    .all<{ cipher_id: string }>();
  return new Set((res.results || []).map((row) => row.cipher_id));
}

/**
 * The items a member may see: the ones they own, plus the ones they reach
 * through a collection of an organization they belong to.
 *
 * An owned item has no organization; a shared item has one and is reached
 * through a collection. The two are read apart, the way the official server
 * reads them, so an item in an organization is never handed out because the
 * member happens to have created it.
 */
export async function getVisibleCipherIdsForUser(
  db: D1Database,
  userId: string
): Promise<Set<string>> {
  const shared = await getSharedCipherIdsForUser(db, userId);
  const owned = await db
    .prepare('SELECT id FROM ciphers WHERE user_id = ? AND organization_id IS NULL')
    .bind(userId)
    .all<{ id: string }>();
  const ids = new Set<string>(shared);
  for (const row of owned.results || []) ids.add(row.id);
  return ids;
}

/**
 * Creates an organization, its owner membership and a first collection in one
 * batch.
 *
 * The organization key is wrapped by the owner's client before it gets here:
 * the server stores the wrapped form and can never read the key itself. The
 * owner also sends the organization's RSA key pair, with the private key
 * already encrypted under the organization key.
 */
export async function createOrganizationWithOwner(
  db: D1Database,
  input: {
    id: string;
    name: string;
    privateKey: string | null;
    publicKey: string | null;
    ownerUserId: string;
    ownerMembershipId: string;
    /** The organization key, wrapped with the owner's public key. */
    wrappedOrganizationKey: string | null;
    collectionId: string;
    collectionName: string;
    now: string;
  }
): Promise<void> {
  await db.batch([
    db
      .prepare(
        'INSERT INTO organizations (id, name, private_key, public_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)'
      )
      .bind(input.id, input.name, input.privateKey, input.publicKey, input.now, input.now),
    db
      .prepare(
        'INSERT INTO organization_users (id, user_id, org_id, type, status, key, created_at, updated_at) ' +
          'VALUES (?, ?, ?, 0, 2, ?, ?, ?)'
      )
      .bind(input.ownerMembershipId, input.ownerUserId, input.id, input.wrappedOrganizationKey, input.now, input.now),
    db
      .prepare('INSERT INTO collections (id, org_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
      .bind(input.collectionId, input.id, input.collectionName, input.now, input.now),
  ]);
}

/** Adds a member to an organization, without the organization key yet. */
export async function addOrganizationUser(
  db: D1Database,
  input: {
    id: string;
    userId: string;
    orgId: string;
    type: number;
    /** 0 invited, 2 confirmed. A membership confirmed here still needs its key. */
    status: number;
    now: string;
  }
): Promise<void> {
  await db
    .prepare(
      'INSERT INTO organization_users (id, user_id, org_id, type, status, key, created_at, updated_at) ' +
        'VALUES (?, ?, ?, ?, ?, NULL, ?, ?)'
    )
    .bind(input.id, input.userId, input.orgId, input.type, input.status, input.now, input.now)
    .run();
}

/**
 * Stores the organization key wrapped for one member, and confirms the
 * membership.
 *
 * The wrapped key comes from an admin's client, which knows the organization
 * key and the member's public key. The server stores the blob: it can neither
 * read the key nor wrap it for anyone.
 */
export async function confirmOrganizationUser(
  db: D1Database,
  input: { membershipId: string; orgId: string; wrappedOrganizationKey: string; now: string }
): Promise<boolean> {
  const result = await db
    .prepare(
      'UPDATE organization_users SET key = ?, status = 2, updated_at = ? WHERE id = ? AND org_id = ?'
    )
    .bind(input.wrappedOrganizationKey, input.now, input.membershipId, input.orgId)
    .run();
  return (result.meta.changes ?? 0) === 1;
}

/** The memberships of one organization. */
export async function getOrganizationUsers(
  db: D1Database,
  orgId: string
): Promise<OrganizationUser[]> {
  const res = await db
    .prepare(
      'SELECT id, user_id, org_id, type, status, key, created_at, updated_at FROM organization_users ' +
        'WHERE org_id = ? ORDER BY created_at ASC'
    )
    .bind(orgId)
    .all<{
      id: string;
      user_id: string;
      org_id: string;
      type: number;
      status: number;
      key: string | null;
      created_at: string;
      updated_at: string;
    }>();
  return (res.results || []).map((row) => ({
    id: row.id,
    userId: row.user_id,
    orgId: row.org_id,
    type: row.type,
    status: row.status,
    key: row.key,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }));
}

/** The membership of one member in one organization, or null. */
export async function getOrganizationUserForUser(
  db: D1Database,
  orgId: string,
  userId: string
): Promise<OrganizationUser | null> {
  const row = await db
    .prepare(
      'SELECT id, user_id, org_id, type, status, key, created_at, updated_at FROM organization_users ' +
        'WHERE org_id = ? AND user_id = ?'
    )
    .bind(orgId, userId)
    .first<{
      id: string;
      user_id: string;
      org_id: string;
      type: number;
      status: number;
      key: string | null;
      created_at: string;
      updated_at: string;
    }>();
  if (!row) return null;
  return {
    id: row.id,
    userId: row.user_id,
    orgId: row.org_id,
    type: row.type,
    status: row.status,
    key: row.key,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/** The organization key wrapped for one member, or null before confirmation. */
export async function getWrappedOrganizationKey(
  db: D1Database,
  orgId: string,
  userId: string
): Promise<string | null> {
  const membership = await getOrganizationUserForUser(db, orgId, userId);
  if (!membership || membership.status !== 2) return null;
  return membership.key ?? null;
}

/** The public keys of the members an admin wants to wrap the key for. */
export async function getMemberPublicKeys(
  db: D1Database,
  userIds: string[]
): Promise<Map<string, string | null>> {
  const keys = new Map<string, string | null>();
  if (!userIds.length) return keys;
  const placeholders = userIds.map(() => '?').join(',');
  const res = await db
    .prepare(`SELECT id, public_key FROM users WHERE id IN (${placeholders})`)
    .bind(...userIds)
    .all<{ id: string; public_key: string | null }>();
  for (const row of res.results || []) keys.set(row.id, row.public_key ?? null);
  return keys;
}
