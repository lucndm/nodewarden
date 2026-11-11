// The names of the collections an older web vault created.
//
// The web vault used to create the first collection of an organization with a
// plain name, and the official clients (the Android app among them) read a
// collection name as an encrypted string: they stop syncing an organization
// whose collection names are in plain text.
//
// So the owner of an organization, or one of its admins, seals the plain names
// with the organization key and renames the collections with them. The name
// that was there is kept: only its form changes, from text the clients
// refuse to read to a cipher string they can.
//
// The repair runs in the background and reports nothing to the member: a
// collection that cannot be renamed is left as it is.
import { looksLikeCipherString } from './app-support';
import { encryptBw } from './crypto';
import { renameCollection } from './api/organizations';
import type { AuthedFetch } from './api/shared';
import type { VaultCollection, VaultOrganization } from './api/organizations';

// The membership of a confirmed owner or admin of the organization.
const ORGANIZATION_OWNER = 0;
const ORGANIZATION_ADMIN = 1;
const ORGANIZATION_CONFIRMED = 2;

export interface RepairCandidatesInput {
  /** The collections as the server returned them, not decrypted. */
  collections: VaultCollection[];
  organizations: VaultOrganization[];
  organizationKeys: Map<string, { encKey: Uint8Array; macKey: Uint8Array }>;
}

/**
 * The collections whose name has to be sealed: the ones that carry a plain
 * name, in an organization this member owns or administers, and whose
 * organization key is open.
 */
export function plainCollectionCandidates(input: RepairCandidatesInput): VaultCollection[] {
  const organizationsById = new Map(input.organizations.map((organization) => [organization.id, organization]));
  return input.collections.filter((collection) => {
    const name = String(collection.name || '').trim();
    if (!name || looksLikeCipherString(name)) return false;

    const organization = organizationsById.get(collection.organizationId);
    if (!organization) return false;
    if (organization.status !== ORGANIZATION_CONFIRMED) return false;
    if (organization.type !== ORGANIZATION_OWNER && organization.type !== ORGANIZATION_ADMIN) return false;

    return input.organizationKeys.has(collection.organizationId);
  });
}

export async function sealPlainCollectionNames(input: {
  authedFetch: AuthedFetch;
  collections: VaultCollection[];
  organizations: VaultOrganization[];
  organizationKeys: Map<string, { encKey: Uint8Array; macKey: Uint8Array }>;
}): Promise<number> {
  let renamed = 0;

  for (const collection of plainCollectionCandidates(input)) {
    const name = String(collection.name || '').trim();
    const key = input.organizationKeys.get(collection.organizationId);
    if (!key) continue;
    try {
      const sealed = await encryptBw(new TextEncoder().encode(name), key.encKey, key.macKey);
      await renameCollection(input.authedFetch, collection.organizationId, collection.id, sealed);
      renamed += 1;
    } catch {
      // A collection the server refuses is left as it is, and the next one is
      // still tried.
    }
  }

  return renamed;
}
