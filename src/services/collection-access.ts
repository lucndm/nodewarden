// Who may see and change a shared item, in the Bitwarden model.
//
// An item lives in an organization and is linked to one or more collections.
// A member reaches a collection either directly (a collection assignment) or
// through a group. Each of those routes carries three flags:
//
//   readOnly       the member may read the item but not change it
//   hidePasswords  the member may read the item but not its password
//   manage         the member may change the item and its collection rights
//
// The official Bitwarden clients take the rights of an item from the server
// as three booleans, so the server has to combine the grants of a member the
// same way the official server does. That combination is by rank, not by
// counting:
//
//   Manage        4
//   Edit         2   (the grant is not read-only)
//   ViewPassword 1   (the grant does not hide passwords)
//
// A grant is worth the sum of the parts it allows, and the item takes the
// highest grant the member can reach. So manage overrules everything, edit
// overrules viewing the password, and a member who reaches the item through
// any single collection with edit rights may edit it.
//
// A direct collection assignment wins over a group assignment for the same
// collection: the group is a shortcut to a collection, not a way to widen
// rights the member was already given or withheld directly. A member in two
// groups that both grant the same collection keeps the better of the two.
//
// An item the member cannot reach at all is not visible, so the resolver
// reports no access rather than a set of flags.
//
// This mirrors the official server, in
// src/Sql/dbo/Vault/Stored Procedures/Cipher/CipherDetails_ReadByUserId.sql
// (the /sync path) and GetCipherPermissionsForUserQuery (the organization
// path).
export interface CollectionAccessFlags {
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
}

/** The rights a member has on one collection. */
export interface CollectionGrant extends CollectionAccessFlags {
  collectionId: string;
  /** True when the grant comes from a direct collection assignment. */
  direct: boolean;
}

/**
 * The rights a member has on an item, or null when the item is out of reach.
 */
export interface ItemAccess extends CollectionAccessFlags {
  /** The collection the rights came from, or null when no grant applies. */
  viaCollection: string | null;
}

/**
 * The worth of a grant: manage counts most, then the right to edit, then the
 * right to see the password.
 */
function grantRank(grant: CollectionGrant): number {
  return (grant.manage ? 4 : 0) + (grant.readOnly ? 0 : 2) + (grant.hidePasswords ? 0 : 1);
}

/**
 * Combines the grants a member holds on the collections an item sits in.
 *
 * A grant that came directly to the member replaces every group grant for the
 * same collection, so the group can neither widen nor narrow it.
 */
export function resolveItemAccess(grants: CollectionGrant[]): ItemAccess | null {
  if (!grants.length) return null;

  // The best grant per collection. A direct grant replaces the group grants
  // for that collection; between group grants the better one wins.
  const byCollection = new Map<string, CollectionGrant>();
  for (const grant of grants) {
    const existing = byCollection.get(grant.collectionId);
    if (!existing) {
      byCollection.set(grant.collectionId, grant);
      continue;
    }
    if (existing.direct) continue;
    if (grant.direct || grantRank(grant) > grantRank(existing)) {
      byCollection.set(grant.collectionId, grant);
    }
  }

  // The item takes the highest grant the member can reach.
  let best: CollectionGrant | null = null;
  let bestRank = -1;
  for (const grant of byCollection.values()) {
    const rank = grantRank(grant);
    if (rank > bestRank) {
      best = grant;
      bestRank = rank;
    }
  }
  if (!best) return null;

  return {
    readOnly: best.readOnly,
    hidePasswords: best.hidePasswords,
    manage: best.manage,
    viaCollection: best.collectionId,
  };
}

/** Whether the member may change the item. */
export function canWriteItem(access: ItemAccess | null): boolean {
  if (!access) return false;
  return !access.readOnly || access.manage;
}

/**
 * Whether the member may change the item and the rights of the collection it
 * sits in. Passwords that are hidden block this, so that hiding a password
 * cannot be undone by editing the item.
 */
export function canEditCollection(access: ItemAccess | null): boolean {
  if (!access) return false;
  return (!access.readOnly && !access.hidePasswords) || access.manage;
}

/** Whether the member may see the item at all. */
export function canReadItem(access: ItemAccess | null): boolean {
  return access !== null;
}
