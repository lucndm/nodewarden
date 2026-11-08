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
  /**
   * True when a member left and the key they still hold has to be replaced
   * before the removal means anything.
   */
  keyRotationRequired: boolean;
  /** When the key was last rotated. */
  keyRotatedAt: string | null;
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
      // An owner or admin of the organization reaches every collection of it,
      // which is what the official server does when the organization allows
      // admin access to all collection items.
      'SELECT CC.collection_id AS collection_id, 0 AS read_only, 0 AS hide_passwords, 1 AS manage, 1 AS direct ' +
      'FROM collection_ciphers CC ' +
      'INNER JOIN collections C ON C.id = CC.collection_id ' +
      'INNER JOIN organization_users OU ON OU.org_id = C.org_id AND OU.user_id = ? AND OU.status = 2 AND OU.type <= 1 ' +
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
    .bind(userId, cipherId, userId, cipherId, userId, cipherId)
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
      // An owner or admin of the organization manages every collection of it,
      // whatever the assignment says.
      'CASE WHEN OU.type <= 1 THEN 0 ELSE COALESCE(CU.read_only, CG.read_only, 0) END AS read_only, ' +
      'CASE WHEN OU.type <= 1 THEN 0 ELSE COALESCE(CU.hide_passwords, CG.hide_passwords, 0) END AS hide_passwords, ' +
      'CASE WHEN OU.type <= 1 THEN 1 ELSE COALESCE(CU.manage, CG.manage, 0) END AS manage, ' +
      'CASE WHEN CU.collection_id IS NOT NULL THEN 1 ELSE 0 END AS direct ' +
      'FROM collections C ' +
      'INNER JOIN organization_users OU ON OU.org_id = C.org_id AND OU.user_id = ? AND OU.status = 2 ' +
      'LEFT JOIN collection_users CU ON CU.collection_id = C.id AND CU.org_user_id = OU.id ' +
      'LEFT JOIN group_users GU ON GU.org_user_id = OU.id ' +
      'LEFT JOIN collection_groups CG ON CG.collection_id = C.id AND CG.group_id = GU.group_id ' +
      'WHERE CU.collection_id IS NOT NULL OR CG.collection_id IS NOT NULL OR OU.type <= 1'
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
      'O.key_rotation_required AS key_rotation_required, O.key_rotated_at AS key_rotated_at, ' +
      'O.created_at AS created_at, O.updated_at AS updated_at ' +
      'FROM organizations O ' +
      // A revoked member is gone; an invited one is not a member yet, but
      // they have to see the invitation.
      'INNER JOIN organization_users OU ON OU.org_id = O.id AND OU.user_id = ? AND OU.status != -1 ' +
      'ORDER BY O.name ASC'
    )
    .bind(userId)
    .all<{
      id: string;
      name: string;
      private_key: string | null;
      public_key: string | null;
      key_rotation_required: number | null;
      key_rotated_at: string | null;
      created_at: string;
      updated_at: string;
    }>();
  return (res.results || []).map((row) => ({
    id: row.id,
    name: row.name,
    privateKey: row.private_key,
    publicKey: row.public_key,
    keyRotationRequired: !!row.key_rotation_required,
    keyRotatedAt: row.key_rotated_at,
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
      'WHERE CU.collection_id IS NOT NULL OR CG.collection_id IS NOT NULL OR OU.type <= 1 ' +
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
      'WHERE CU.collection_id IS NOT NULL OR CG.collection_id IS NOT NULL OR OU.type <= 1'
    )
    .bind(userId)
    .all<{ cipher_id: string }>();
  return new Set((res.results || []).map((row) => row.cipher_id));
}

/**
 * The groups of one organization, with the members and the collections each
 * one carries.
 *
 * A group is a shortcut: it hands a set of collections to a set of members in
 * one go, instead of one member at a time.
 */
export async function getOrganizationGroups(
  db: D1Database,
  orgId: string
): Promise<Array<Group & { members: string[]; collections: CollectionAssignment[] }>> {
  const groups = await db
    .prepare('SELECT id, org_id, name, created_at, updated_at FROM groups WHERE org_id = ? ORDER BY name ASC')
    .bind(orgId)
    .all<{ id: string; org_id: string; name: string; created_at: string; updated_at: string }>();

  const result: Array<Group & { members: string[]; collections: CollectionAssignment[] }> = [];
  for (const row of groups.results || []) {
    const members = await db
      .prepare('SELECT org_user_id FROM group_users WHERE group_id = ? ORDER BY org_user_id ASC')
      .bind(row.id)
      .all<{ org_user_id: string }>();
    const collections = await db
      .prepare(
        'SELECT collection_id, read_only, hide_passwords, manage FROM collection_groups WHERE group_id = ? ORDER BY collection_id ASC'
      )
      .bind(row.id)
      .all<{ collection_id: string; read_only: number; hide_passwords: number; manage: number }>();
    result.push({
      id: row.id,
      orgId: row.org_id,
      name: row.name,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      members: (members.results || []).map((entry) => entry.org_user_id),
      collections: (collections.results || []).map((entry) => ({
        collectionId: entry.collection_id,
        readOnly: !!entry.read_only,
        hidePasswords: !!entry.hide_passwords,
        manage: !!entry.manage,
      })),
    });
  }
  return result;
}

/** Creates a group, and puts the members and collections into it. */
export async function createOrganizationGroup(
  db: D1Database,
  input: {
    id: string;
    orgId: string;
    name: string;
    members: string[];
    collections: CollectionAssignment[];
    now: string;
  }
): Promise<void> {
  const statements: D1PreparedStatement[] = [
    db
      .prepare('INSERT INTO groups (id, org_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
      .bind(input.id, input.orgId, input.name, input.now, input.now),
  ];
  for (const memberId of input.members) {
    statements.push(
      db.prepare('INSERT OR IGNORE INTO group_users (group_id, org_user_id) VALUES (?, ?)').bind(input.id, memberId)
    );
  }
  for (const assignment of input.collections) {
    statements.push(
      db
        .prepare(
          'INSERT OR REPLACE INTO collection_groups (collection_id, group_id, read_only, hide_passwords, manage) VALUES (?, ?, ?, ?, ?)'
        )
        .bind(
          assignment.collectionId,
          input.id,
          assignment.readOnly ? 1 : 0,
          assignment.hidePasswords ? 1 : 0,
          assignment.manage ? 1 : 0
        )
    );
  }
  await db.batch(statements);
}

/**
 * Replaces the members and the collections of a group.
 *
 * The assignments replace the previous ones, the way the rights of a member
 * do: what is not listed any more is not there.
 */
export async function replaceOrganizationGroup(
  db: D1Database,
  input: {
    groupId: string;
    members: string[];
    collections: CollectionAssignment[];
    now: string;
  }
): Promise<void> {
  const statements: D1PreparedStatement[] = [
    db.prepare('DELETE FROM group_users WHERE group_id = ?').bind(input.groupId),
    db.prepare('DELETE FROM collection_groups WHERE group_id = ?').bind(input.groupId),
    db.prepare('UPDATE groups SET updated_at = ? WHERE id = ?').bind(input.now, input.groupId),
  ];
  for (const memberId of input.members) {
    statements.push(
      db.prepare('INSERT OR IGNORE INTO group_users (group_id, org_user_id) VALUES (?, ?)').bind(input.groupId, memberId)
    );
  }
  for (const assignment of input.collections) {
    statements.push(
      db
        .prepare(
          'INSERT OR REPLACE INTO collection_groups (collection_id, group_id, read_only, hide_passwords, manage) VALUES (?, ?, ?, ?, ?)'
        )
        .bind(
          assignment.collectionId,
          input.groupId,
          assignment.readOnly ? 1 : 0,
          assignment.hidePasswords ? 1 : 0,
          assignment.manage ? 1 : 0
        )
    );
  }
  await db.batch(statements);
}

/** Removes a group. Its members and collections go with it. */
export async function deleteOrganizationGroup(db: D1Database, groupId: string): Promise<boolean> {
  const result = await db.prepare('DELETE FROM groups WHERE id = ?').bind(groupId).run();
  return (result.meta.changes ?? 0) === 1;
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

/**
 * The member accepts the invitation: the membership goes from invited to
 * accepted, and the owner can then hand over the organization key.
 *
 * Only the invited member accepts, and only once: a membership that is
 * already confirmed or revoked does not change.
 */
export async function acceptOrganizationUser(
  db: D1Database,
  input: { membershipId: string; orgId: string; now: string }
): Promise<boolean> {
  const result = await db
    .prepare(
      'UPDATE organization_users SET status = 1, updated_at = ? ' +
        'WHERE id = ? AND org_id = ? AND status = 0'
    )
    .bind(input.now, input.membershipId, input.orgId)
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

/**
 * The items of one organization, with the raw stored payload.
 *
 * A rotation needs the payload exactly as it is stored: the client re-encrypts
 * every encrypted string in it and sends it back, so a payload that was
 * reshaped on the way out would come back reshaped and the item would stop
 * matching what the other clients expect.
 */
export async function getOrganizationCiphersForRotation(
  db: D1Database,
  orgId: string
): Promise<
  Array<{
    id: string;
    key: string | null;
    name: string | null;
    notes: string | null;
    data: unknown;
    /** The item's attachments; each has a key sealed with the item key. */
    attachments: Array<{ id: string; key: string | null }>;
    /** The item's history; every entry is sealed with the item key. */
    versions: Array<{
      id: string;
      key: string | null;
      name: string | null;
      notes: string | null;
      data: unknown;
    }>;
  }>
> {
  const res = await db
    .prepare('SELECT id, key, name, notes, data FROM ciphers WHERE organization_id = ?')
    .bind(orgId)
    .all<{ id: string; key: string | null; name: string | null; notes: string | null; data: string }>();
  const ciphers = (res.results || []).map((row) => {
    let data: unknown = {};
    try {
      data = JSON.parse(row.data) as unknown;
    } catch {
      data = {};
    }
    return { id: row.id, key: row.key, name: row.name, notes: row.notes, data };
  });

  // An attachment's key and a history entry are sealed with the item key, so
  // the rotation has to carry them too: re-sealing only the item would leave
  // them readable only under the old key.
  const attachmentsByCipher = new Map<string, Array<{ id: string; key: string | null }>>();
  const attachmentRows = await db
    .prepare(
      'SELECT a.id AS id, a.cipher_id AS cipher_id, a.key AS key FROM attachments a ' +
        'JOIN ciphers c ON c.id = a.cipher_id WHERE c.organization_id = ?'
    )
    .bind(orgId)
    .all<{ id: string; cipher_id: string; key: string | null }>();
  for (const row of attachmentRows.results || []) {
    const list = attachmentsByCipher.get(row.cipher_id) ?? [];
    list.push({ id: row.id, key: row.key });
    attachmentsByCipher.set(row.cipher_id, list);
  }

  const versionsByCipher = new Map<
    string,
    Array<{ id: string; key: string | null; name: string | null; notes: string | null; data: unknown }>
  >();
  const versionRows = await db
    .prepare(
      'SELECT v.id AS id, v.cipher_id AS cipher_id, v.key AS key, v.name AS name, v.notes AS notes, v.data AS data ' +
        'FROM cipher_versions v JOIN ciphers c ON c.id = v.cipher_id WHERE c.organization_id = ?'
    )
    .bind(orgId)
    .all<{
      id: string;
      cipher_id: string;
      key: string | null;
      name: string | null;
      notes: string | null;
      data: string;
    }>();
  for (const row of versionRows.results || []) {
    let data: unknown = {};
    try {
      data = JSON.parse(row.data) as unknown;
    } catch {
      data = {};
    }
    const list = versionsByCipher.get(row.cipher_id) ?? [];
    list.push({ id: row.id, key: row.key, name: row.name, notes: row.notes, data });
    versionsByCipher.set(row.cipher_id, list);
  }

  return ciphers.map((cipher) => ({
    ...cipher,
    attachments: attachmentsByCipher.get(cipher.id) ?? [],
    versions: versionsByCipher.get(cipher.id) ?? [],
  }));
}

/**
 * The email addresses of these members, keyed by user id.
 *
 * A member list is worthless without the addresses: the member is identified
 * by who they are, not by an id.
 */
export async function getMemberEmails(
  db: D1Database,
  userIds: string[]
): Promise<Map<string, string>> {
  const emails = new Map<string, string>();
  if (!userIds.length) return emails;
  const placeholders = userIds.map(() => '?').join(',');
  const res = await db
    .prepare(`SELECT id, email FROM users WHERE id IN (${placeholders})`)
    .bind(...userIds)
    .all<{ id: string; email: string }>();
  for (const row of res.results || []) emails.set(row.id, row.email);
  return emails;
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

/** The collections each of these items sits in, keyed by item id. */
export async function getCollectionIdsByCipherIds(
  db: D1Database,
  cipherIds: string[]
): Promise<Map<string, string[]>> {
  const byCipher = new Map<string, string[]>();
  if (!cipherIds.length) return byCipher;
  const placeholders = cipherIds.map(() => '?').join(',');
  const res = await db
    .prepare(
      `SELECT cipher_id, collection_id FROM collection_ciphers WHERE cipher_id IN (${placeholders}) ` +
        'ORDER BY collection_id ASC'
    )
    .bind(...cipherIds)
    .all<{ cipher_id: string; collection_id: string }>();
  for (const row of res.results || []) {
    const list = byCipher.get(row.cipher_id) ?? [];
    list.push(row.collection_id);
    byCipher.set(row.cipher_id, list);
  }
  return byCipher;
}

/** The collections of one item. */
export async function getCollectionIdsForCipher(db: D1Database, cipherId: string): Promise<string[]> {
  const map = await getCollectionIdsByCipherIds(db, [cipherId]);
  return map.get(cipherId) ?? [];
}

/**
 * Replaces the collections of an item.
 *
 * The caller has already checked that the member may change the item and that
 * every collection belongs to the item's organization.
 */
export async function setCipherCollections(
  db: D1Database,
  cipherId: string,
  collectionIds: string[]
): Promise<void> {
  const statements: D1PreparedStatement[] = [
    db.prepare('DELETE FROM collection_ciphers WHERE cipher_id = ?').bind(cipherId),
  ];
  for (const collectionId of collectionIds) {
    statements.push(
      db
        .prepare('INSERT INTO collection_ciphers (cipher_id, collection_id) VALUES (?, ?)')
        .bind(cipherId, collectionId)
    );
  }
  await db.batch(statements);
}

/** The collections of one organization that these ids name. */
export async function getOrganizationCollectionIds(
  db: D1Database,
  orgId: string,
  collectionIds: string[]
): Promise<Set<string>> {
  const found = new Set<string>();
  if (!collectionIds.length) return found;
  const placeholders = collectionIds.map(() => '?').join(',');
  const res = await db
    .prepare(`SELECT id FROM collections WHERE org_id = ? AND id IN (${placeholders})`)
    .bind(orgId, ...collectionIds)
    .all<{ id: string }>();
  for (const row of res.results || []) found.add(row.id);
  return found;
}

/** The collection rights a member holds on these collections, keyed by id. */
export async function getCollectionRightsForCollections(
  db: D1Database,
  userId: string,
  collectionIds: string[]
): Promise<Map<string, CollectionRights>> {
  const rights = new Map<string, CollectionRights>();
  if (!collectionIds.length) return rights;
  const placeholders = collectionIds.map(() => '?').join(',');
  const rows = await db
    .prepare(
      'SELECT C.id AS collection_id, ' +
        'CASE WHEN OU.type <= 1 THEN 0 ELSE COALESCE(CU.read_only, CG.read_only, 0) END AS read_only, ' +
        'CASE WHEN OU.type <= 1 THEN 0 ELSE COALESCE(CU.hide_passwords, CG.hide_passwords, 0) END AS hide_passwords, ' +
        'CASE WHEN OU.type <= 1 THEN 1 ELSE COALESCE(CU.manage, CG.manage, 0) END AS manage, ' +
        'CASE WHEN CU.collection_id IS NOT NULL THEN 1 ELSE 0 END AS direct ' +
        'FROM collections C ' +
        'INNER JOIN organization_users OU ON OU.org_id = C.org_id AND OU.user_id = ? AND OU.status = 2 ' +
        'LEFT JOIN collection_users CU ON CU.collection_id = C.id AND CU.org_user_id = OU.id ' +
        'LEFT JOIN group_users GU ON GU.org_user_id = OU.id ' +
        'LEFT JOIN collection_groups CG ON CG.collection_id = C.id AND CG.group_id = GU.group_id ' +
        `WHERE C.id IN (${placeholders}) AND (CU.collection_id IS NOT NULL OR CG.collection_id IS NOT NULL OR OU.type <= 1)`
    )
    .bind(userId, ...collectionIds)
    .all<GrantRow>();
  for (const row of rows.results || []) {
    const entry: CollectionRights = {
      collectionId: row.collection_id,
      readOnly: !!row.read_only,
      hidePasswords: !!row.hide_passwords,
      manage: !!row.manage,
      direct: !!row.direct,
    };
    const existing = rights.get(entry.collectionId);
    if (!existing || (entry.direct && !existing.direct)) rights.set(entry.collectionId, entry);
  }
  return rights;
}

/**
 * The right level a member holds on each item they can reach in an
 * organization, keyed by item id.
 *
 * The level is the rank the official server uses: manage 4, edit 2, view
 * password 1. An owner or admin of the organization reaches every collection
 * of it, so their items rank 7.
 */
export async function getCipherRankByCipherForUser(
  db: D1Database,
  userId: string,
  cipherIds?: string[]
): Promise<Map<string, number>> {
  const ranks = new Map<string, number>();
  const scope = cipherIds && cipherIds.length
    ? ` AND CC.cipher_id IN (${cipherIds.map(() => '?').join(',')})`
    : '';
  const scopeBinds = cipherIds && cipherIds.length ? cipherIds : [];
  const res = await db
    .prepare(
      'SELECT CC.cipher_id AS cipher_id, ' +
        'MAX(CASE WHEN manage = 1 THEN 4 ELSE 0 END ' +
        '+ CASE WHEN read_only = 0 THEN 2 ELSE 0 END ' +
        '+ CASE WHEN hide_passwords = 0 THEN 1 ELSE 0 END) AS rank ' +
        'FROM (' +
        'SELECT CC.cipher_id AS cipher_id, CU.read_only AS read_only, CU.hide_passwords AS hide_passwords, CU.manage AS manage ' +
        'FROM collection_ciphers CC ' +
        'INNER JOIN collections C ON C.id = CC.collection_id ' +
        'INNER JOIN organization_users OU ON OU.org_id = C.org_id AND OU.user_id = ? AND OU.status = 2 ' +
        'INNER JOIN collection_users CU ON CU.collection_id = CC.collection_id AND CU.org_user_id = OU.id ' +
        `WHERE 1 = 1 ${scope} ` +
        'UNION ALL ' +
        'SELECT CC.cipher_id AS cipher_id, CG.read_only AS read_only, CG.hide_passwords AS hide_passwords, CG.manage AS manage ' +
        'FROM collection_ciphers CC ' +
        'INNER JOIN collections C ON C.id = CC.collection_id ' +
        'INNER JOIN organization_users OU ON OU.org_id = C.org_id AND OU.user_id = ? AND OU.status = 2 ' +
        'INNER JOIN collection_groups CG ON CG.collection_id = CC.collection_id ' +
        'INNER JOIN group_users GU ON GU.group_id = CG.group_id AND GU.org_user_id = OU.id ' +
        'WHERE NOT EXISTS (SELECT 1 FROM collection_users CU2 ' +
        `WHERE CU2.collection_id = CG.collection_id AND CU2.org_user_id = OU.id) ${scope} ` +
        'UNION ALL ' +
        'SELECT CC.cipher_id AS cipher_id, 0 AS read_only, 0 AS hide_passwords, 1 AS manage ' +
        'FROM collection_ciphers CC ' +
        'INNER JOIN collections C ON C.id = CC.collection_id ' +
        'INNER JOIN organization_users OU ON OU.org_id = C.org_id AND OU.user_id = ? AND OU.status = 2 AND OU.type <= 1 ' +
        `WHERE 1 = 1 ${scope} ` +
        ') AS CC GROUP BY CC.cipher_id'
    )
    .bind(userId, ...scopeBinds, userId, ...scopeBinds, userId, ...scopeBinds)
    .all<{ cipher_id: string; rank: number }>();
  for (const row of res.results || []) ranks.set(row.cipher_id, Number(row.rank) || 0);
  return ranks;
}

/**
 * The ids of the items the member may change: their own, plus the shared ones
 * whose rights allow writing.
 *
 * A bulk action must filter its ids through here before touching anything: an
 * item the member may only read, or cannot reach at all, is not theirs to
 * move, archive or delete.
 */
export async function filterWritableCipherIds(
  db: D1Database,
  userId: string,
  cipherIds: string[],
  minimumRank = 2
): Promise<string[]> {
  if (!cipherIds.length) return [];
  const unique = [...new Set(cipherIds)];
  const placeholders = unique.map(() => '?').join(',');
  const owned = await db
    .prepare(
      `SELECT id FROM ciphers WHERE user_id = ? AND organization_id IS NULL AND id IN (${placeholders})`
    )
    .bind(userId, ...unique)
    .all<{ id: string }>();
  const allowed = new Set((owned.results || []).map((row) => row.id));

  // Only the items this call is about: a bulk action on a few items must not
  // walk every item of the organization.
  const ranks = await getCipherRankByCipherForUser(db, userId, unique);
  for (const id of unique) {
    if (allowed.has(id)) continue;
    const rank = ranks.get(id);
    if (rank !== undefined && rank >= minimumRank) allowed.add(id);
  }
  return unique.filter((id) => allowed.has(id));
}

export interface CollectionAssignment {
  collectionId: string;
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
}

/** Creates a collection in an organization. */
export async function createCollection(
  db: D1Database,
  input: { id: string; orgId: string; name: string; now: string }
): Promise<void> {
  await db
    .prepare('INSERT INTO collections (id, org_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
    .bind(input.id, input.orgId, input.name, input.now, input.now)
    .run();
}

/**
 * Replaces the collection assignments of one membership.
 *
 * The caller has already checked that every collection belongs to the
 * organization and that this member may hand out rights on it.
 */
export async function replaceMembershipCollections(
  db: D1Database,
  membershipId: string,
  assignments: CollectionAssignment[]
): Promise<void> {
  const statements: D1PreparedStatement[] = [
    db.prepare('DELETE FROM collection_users WHERE org_user_id = ?').bind(membershipId),
  ];
  for (const assignment of assignments) {
    statements.push(
      db
        .prepare(
          'INSERT INTO collection_users (collection_id, org_user_id, read_only, hide_passwords, manage) VALUES (?, ?, ?, ?, ?)'
        )
        .bind(
          assignment.collectionId,
          membershipId,
          assignment.readOnly ? 1 : 0,
          assignment.hidePasswords ? 1 : 0,
          assignment.manage ? 1 : 0
        )
    );
  }
  await db.batch(statements);
}

/**
 * Removes a member from an organization.
 *
 * Their collection assignments and group memberships go with them, so every
 * query that asks for rights stops returning anything for that member. What
 * this cannot do is take back the organization key they already unwrapped:
 * anything they downloaded while they were a member stays readable to them.
 */
export async function removeOrganizationUser(
  db: D1Database,
  orgId: string,
  membershipId: string
): Promise<boolean> {
  const existing = await db
    .prepare('SELECT id FROM organization_users WHERE id = ? AND org_id = ?')
    .bind(membershipId, orgId)
    .first<{ id: string }>();
  if (!existing) return false;
  await db.batch([
    db.prepare('DELETE FROM collection_users WHERE org_user_id = ?').bind(membershipId),
    db.prepare('DELETE FROM group_users WHERE org_user_id = ?').bind(membershipId),
    db.prepare('DELETE FROM organization_users WHERE id = ? AND org_id = ?').bind(membershipId, orgId),
    // The member keeps the organization key they already unwrapped, so the
    // removal is only half done: record that the key has to be replaced.
    db.prepare('UPDATE organizations SET key_rotation_required = 1, updated_at = ? WHERE id = ?').bind(
      new Date().toISOString(),
      orgId
    ),
  ]);
  return true;
}

/** Updates the role of a membership. */
export async function setOrganizationUserType(
  db: D1Database,
  orgId: string,
  membershipId: string,
  type: number,
  now: string
): Promise<boolean> {
  const result = await db
    .prepare('UPDATE organization_users SET type = ?, updated_at = ? WHERE id = ? AND org_id = ?')
    .bind(type, now, membershipId, orgId)
    .run();
  return (result.meta.changes ?? 0) === 1;
}

/** The membership ids of one organization, for the admin views. */
export async function getOrganizationMembershipIds(
  db: D1Database,
  orgId: string
): Promise<Set<string>> {
  const res = await db
    .prepare('SELECT id FROM organization_users WHERE org_id = ?')
    .bind(orgId)
    .all<{ id: string }>();
  return new Set((res.results || []).map((row) => row.id));
}

/** The collection assignments of one membership. */
export async function getMembershipCollections(
  db: D1Database,
  membershipId: string
): Promise<CollectionAssignment[]> {
  const res = await db
    .prepare(
      'SELECT collection_id, read_only, hide_passwords, manage FROM collection_users WHERE org_user_id = ? ' +
        'ORDER BY collection_id ASC'
    )
    .bind(membershipId)
    .all<{ collection_id: string; read_only: number; hide_passwords: number; manage: number }>();
  return (res.results || []).map((row) => ({
    collectionId: row.collection_id,
    readOnly: !!row.read_only,
    hidePasswords: !!row.hide_passwords,
    manage: !!row.manage,
  }));
}

export interface OrganizationKeyRotation {
  orgId: string;
  /** The organization private key, re-encrypted under the new key. */
  privateKey?: string | null;
  /** The new organization key, wrapped for each remaining member. */
  memberKeys: Array<{ membershipId: string; key: string }>;
  /** Each shared item, with its item key re-wrapped under the new key. */
  cipherKeys: Array<{ cipherId: string; key: string | null; name?: string | null; notes?: string | null; data: string }>;
  /** Each attachment's key, re-sealed under its item's new key. */
  attachmentKeys?: Array<{ attachmentId: string; cipherId: string; key: string | null }>;
  /** Each history entry, re-encrypted under its item's new key. */
  versions?: Array<{
    versionId: string;
    cipherId: string;
    key: string | null;
    name?: string | null;
    notes?: string | null;
    data: string;
  }>;
  now: string;
}

/**
 * Applies a key rotation: the organization private key, the key wrapped for
 * every remaining member and the item key of every shared item.
 *
 * The client does all of the cryptography; the server only stores the new
 * blobs, and it stores them in one batch so a half-applied rotation cannot
 * leave a member or an item behind. Every member's revision moves afterwards,
 * which is what makes their client fetch the new blobs instead of the old ones
 * it cached.
 */
export async function rotateOrganizationKey(
  db: D1Database,
  rotation: OrganizationKeyRotation
): Promise<void> {
  const statements: D1PreparedStatement[] = [];
  if (rotation.privateKey !== undefined) {
    statements.push(
      db
        .prepare('UPDATE organizations SET private_key = ?, updated_at = ? WHERE id = ?')
        .bind(rotation.privateKey, rotation.now, rotation.orgId)
    );
  }
  for (const member of rotation.memberKeys) {
    statements.push(
      db
        .prepare('UPDATE organization_users SET key = ?, updated_at = ? WHERE id = ? AND org_id = ?')
        .bind(member.key, rotation.now, member.membershipId, rotation.orgId)
    );
  }
  for (const cipher of rotation.cipherKeys) {
    statements.push(
      db
        .prepare(
          'UPDATE ciphers SET key = ?, data = ?, ' +
            // The name and the notes are columns, so a rotation has to replace
            // them too or the item stays readable under the old key.
            'name = COALESCE(?, name), notes = COALESCE(?, notes), ' +
            'updated_at = ? WHERE id = ? AND organization_id = ?'
        )
        .bind(
          cipher.key,
          cipher.data,
          cipher.name ?? null,
          cipher.notes ?? null,
          rotation.now,
          cipher.cipherId,
          rotation.orgId
        )
    );
  }
  // The attachments and the history are sealed with the item key, so they are
  // replaced in the same batch: a rotation that changed the item key but left
  // them behind would make them readable only under the old key.
  for (const attachment of rotation.attachmentKeys ?? []) {
    statements.push(
      db
        .prepare('UPDATE attachments SET key = ? WHERE id = ? AND cipher_id = ?')
        .bind(attachment.key, attachment.attachmentId, attachment.cipherId)
    );
  }
  for (const version of rotation.versions ?? []) {
    statements.push(
      db
        .prepare(
          'UPDATE cipher_versions SET key = COALESCE(?, key), name = COALESCE(?, name), ' +
            'notes = COALESCE(?, notes), data = ? WHERE id = ? AND cipher_id = ?'
        )
        .bind(
          version.key,
          version.name ?? null,
          version.notes ?? null,
          version.data,
          version.versionId,
          version.cipherId
        )
    );
  }

  // A rotation is what makes a removal count, so it clears the marker.
  statements.push(
    db
      .prepare('UPDATE organizations SET key_rotation_required = 0, key_rotated_at = ?, updated_at = ? WHERE id = ?')
      .bind(rotation.now, rotation.now, rotation.orgId)
  );
  await db.batch(statements);
}
