// The organizations and collections a member belongs to.
//
// The official clients ask for these lists on their own as well as through
// /sync, and they read the rights of each collection from the response. The
// lists are read from the same storage the sync filter uses, so a collection
// the member cannot reach never appears here either.
import { StorageService } from '../services/storage';
import { errorResponse, jsonResponse } from '../utils/response';
import type { Env } from '../types';

function listResponse(data: unknown[]): Response {
  return jsonResponse({ data, object: 'list', continuationToken: null });
}

// GET /api/organizations
export async function handleGetOrganizations(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const organizations = await storage.getOrganizationsForUser(userId);
  return listResponse(
    organizations.map((organization) => ({
      id: organization.id,
      name: organization.name,
      key: organization.key ?? null,
      status: 2,
      type: 2,
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

// POST /api/collections and everything else under it stays unimplemented: the
// organization has to be created and its key distributed first, and a route
// that answers "created" without doing that would be a lie.
export async function handleUnsupportedCollectionRoute(): Promise<Response> {
  return errorResponse('Not implemented', 501);
}
