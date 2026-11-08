// The organizations and collections the current member belongs to.
//
// These change far less often than the vault itself, so they are read on their
// own instead of riding along with every sync. The rights travel with each
// collection: the interface needs them to tell a collection the member may
// write from one they may only read.
import { parseJson, type AuthedFetch } from './shared';
import { t } from '../i18n';

export interface VaultOrganization {
  id: string;
  name: string;
  /** The organization key, wrapped for the current member. */
  key: string | null;
  status: number;
  type: number;
  /** A member left while holding the key: the owner has to rotate it. */
  keyRotationRequired: boolean;
}

export interface VaultCollection {
  id: string;
  organizationId: string;
  name: string;
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
}

function normalizeOrganization(raw: Record<string, unknown>): VaultOrganization | null {
  const id = String(raw?.id || '').trim();
  const name = String(raw?.name || '').trim();
  if (!id || !name) return null;
  return {
    id,
    name,
    key: typeof raw.key === 'string' && raw.key.trim() ? raw.key : null,
    status: Number(raw.status) || 0,
    // The owner is type 0, and a plain `|| 2` would turn the owner into an
    // ordinary member.
    type: raw.type === undefined || raw.type === null ? 2 : Number(raw.type),
    keyRotationRequired: raw?.keyRotationRequired === true,
  };
}

function normalizeCollection(raw: Record<string, unknown>): VaultCollection | null {
  const id = String(raw?.id || '').trim();
  const organizationId = String(raw?.organizationId || '').trim();
  const name = String(raw?.name || '').trim();
  if (!id || !organizationId || !name) return null;
  return {
    id,
    organizationId,
    name,
    // Missing flags read as the most restrictive value: a collection whose
    // rights did not arrive must not look writable.
    readOnly: raw?.readOnly !== false,
    hidePasswords: raw?.hidePasswords !== false,
    manage: raw?.manage === true,
  };
}

export async function getOrganizations(authedFetch: AuthedFetch): Promise<VaultOrganization[]> {
  const resp = await authedFetch('/api/organizations');
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_organization_load_failed')));
  const body = await parseJson<{ data?: unknown }>(resp);
  const rows = Array.isArray(body?.data) ? (body.data as Record<string, unknown>[]) : [];
  return rows
    .map(normalizeOrganization)
    .filter((entry): entry is VaultOrganization => !!entry)
    .sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * Everything a key rotation needs, in one read.
 *
 * The server never sees the key itself: it hands back the encrypted private
 * key, the members who keep their access, and the items as they are stored,
 * so the client can re-encrypt them and send the result back.
 */
export interface OrganizationRotationData {
  organization: { id: string; name: string; privateKey: string | null };
  members: Array<{ membershipId: string; userId: string; publicKey: string | null }>;
  ciphers: Array<{
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
  }>;
}

export async function getOrganizationRotationData(
  authedFetch: AuthedFetch,
  organizationId: string
): Promise<OrganizationRotationData> {
  const resp = await authedFetch(`/api/organizations/${encodeURIComponent(organizationId)}/rotation-data`);
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_organization_load_failed')));
  const body = await parseJson<Record<string, unknown>>(resp);
  const organization = (body?.organization ?? {}) as Record<string, unknown>;
  const rows = Array.isArray(body?.members) ? (body.members as Record<string, unknown>[]) : [];
  const ciphers = Array.isArray(body?.ciphers) ? (body.ciphers as Record<string, unknown>[]) : [];
  return {
    organization: {
      id: String(organization.id || ''),
      name: String(organization.name || ''),
      privateKey: typeof organization.privateKey === 'string' ? organization.privateKey : null,
    },
    members: rows.map((entry) => ({
      membershipId: String(entry.membershipId || ''),
      userId: String(entry.userId || ''),
      publicKey: typeof entry.publicKey === 'string' && entry.publicKey.trim() ? entry.publicKey : null,
    })),
    ciphers: ciphers.map((entry) => ({
      id: String(entry.id || ''),
      key: typeof entry.key === 'string' ? entry.key : null,
      name: typeof entry.name === 'string' ? entry.name : null,
      notes: typeof entry.notes === 'string' ? entry.notes : null,
      data: entry.data,
      attachments: Array.isArray(entry.attachments)
        ? (entry.attachments as Record<string, unknown>[]).map((attachment) => ({
            id: String(attachment.id || ''),
            key: typeof attachment.key === 'string' ? attachment.key : null,
          }))
        : [],
      versions: Array.isArray(entry.versions)
        ? (entry.versions as Record<string, unknown>[]).map((version) => ({
            id: String(version.id || ''),
            key: typeof version.key === 'string' ? version.key : null,
            name: typeof version.name === 'string' ? version.name : null,
            notes: typeof version.notes === 'string' ? version.notes : null,
            data: version.data,
          }))
        : [],
    })),
  };
}

/**
 * Accepts the invitation to an organization.
 *
 * Accepting says the member wants in. The organization key is wrapped with
 * the member's own RSA key, so the owner hands that over separately.
 */
export async function acceptOrganizationInvitation(
  authedFetch: AuthedFetch,
  organizationId: string
): Promise<void> {
  const resp = await authedFetch(`/api/organizations/${encodeURIComponent(organizationId)}/accept`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_accept_invitation_failed')));
}

/**
 * A group of an organization.
 *
 * A group is a shortcut: it hands a set of collections to a set of members in
 * one go, instead of one member at a time.
 */
export interface OrganizationGroup {
  id: string;
  name: string;
  /** The memberships the group carries. */
  members: string[];
  collections: Array<{ id: string; readOnly: boolean; hidePasswords: boolean; manage: boolean }>;
}

export async function getOrganizationGroups(
  authedFetch: AuthedFetch,
  organizationId: string
): Promise<OrganizationGroup[]> {
  const resp = await authedFetch(`/api/organizations/${encodeURIComponent(organizationId)}/groups`);
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_organization_load_failed')));
  const body = await parseJson<{ data?: unknown }>(resp);
  const rows = Array.isArray(body?.data) ? (body.data as Record<string, unknown>[]) : [];
  return rows.map((entry) => ({
    id: String(entry.id || ''),
    name: String(entry.name || ''),
    members: Array.isArray(entry.members)
      ? (entry.members as unknown[]).filter((value): value is string => typeof value === 'string')
      : [],
    collections: (Array.isArray(entry.collections) ? (entry.collections as Record<string, unknown>[]) : []).map(
      (assignment) => ({
        id: String(assignment.id || ''),
        readOnly: assignment.readOnly === true,
        hidePasswords: assignment.hidePasswords === true,
        manage: assignment.manage === true,
      })
    ),
  }));
}

export async function createOrganizationGroup(
  authedFetch: AuthedFetch,
  organizationId: string,
  group: { name: string; members: string[]; collections: Array<{ id: string }> }
): Promise<void> {
  const resp = await authedFetch(`/api/organizations/${encodeURIComponent(organizationId)}/groups`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(group),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_group_save_failed')));
}

export async function deleteOrganizationGroup(
  authedFetch: AuthedFetch,
  organizationId: string,
  groupId: string
): Promise<void> {
  const resp = await authedFetch(
    `/api/organizations/${encodeURIComponent(organizationId)}/groups/${encodeURIComponent(groupId)}`,
    { method: 'DELETE' }
  );
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_group_save_failed')));
}

/** A member of an organization, with the rights they hold on each collection. */
export interface OrganizationMember {
  id: string;
  userId: string;
  email: string | null;
  /** 0 owner, 1 admin, 2 user. */
  type: number;
  /** 0 invited, 2 confirmed. */
  status: number;
  collections: Array<{ id: string; readOnly: boolean; hidePasswords: boolean; manage: boolean }>;
}

/** The policy that decides what the members may do with Send. */
export const SEND_CONTROLS_POLICY = 21;

export interface OrganizationPolicyState {
  type: number;
  enabled: boolean;
  data: Record<string, unknown>;
}

export async function getOrganizationPolicies(
  authedFetch: AuthedFetch,
  organizationId: string
): Promise<OrganizationPolicyState[]> {
  const resp = await authedFetch(`/api/organizations/${encodeURIComponent(organizationId)}/policies`);
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_organization_load_failed')));
  const body = await parseJson<{ data?: unknown }>(resp);
  const rows = Array.isArray(body?.data) ? (body.data as Record<string, unknown>[]) : [];
  return rows.map((entry) => ({
    type: Number(entry.type || 0),
    enabled: entry.enabled === true,
    data: entry.data && typeof entry.data === 'object' ? (entry.data as Record<string, unknown>) : {},
  }));
}

export async function setOrganizationPolicy(
  authedFetch: AuthedFetch,
  organizationId: string,
  type: number,
  enabled: boolean,
  data: Record<string, unknown>
): Promise<void> {
  const resp = await authedFetch(
    `/api/organizations/${encodeURIComponent(organizationId)}/policies/${type}`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled, data }),
    }
  );
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_policy_save_failed')));
}

export async function getOrganizationMembers(
  authedFetch: AuthedFetch,
  organizationId: string
): Promise<OrganizationMember[]> {
  const resp = await authedFetch(`/api/organizations/${encodeURIComponent(organizationId)}/users`);
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_organization_load_failed')));
  const body = await parseJson<{ data?: unknown }>(resp);
  const rows = Array.isArray(body?.data) ? (body.data as Record<string, unknown>[]) : [];
  return rows.map((entry) => ({
    id: String(entry.id || ''),
    userId: String(entry.userId || ''),
    email: typeof entry.email === 'string' ? entry.email : null,
    type: Number(entry.type) || 0,
    status: Number(entry.status) || 0,
    collections: (Array.isArray(entry.collections) ? (entry.collections as Record<string, unknown>[]) : []).map(
      (assignment) => ({
        id: String(assignment.id || ''),
        readOnly: assignment.readOnly === true,
        hidePasswords: assignment.hidePasswords === true,
        manage: assignment.manage === true,
      })
    ),
  }));
}

/**
 * Invites a member by email.
 *
 * The invite alone is not enough: the organization key has to be wrapped for
 * the member's RSA key, and a member without a public key cannot be given
 * one yet. The caller does that wrapping and confirms the membership.
 */
export async function inviteOrganizationMember(
  authedFetch: AuthedFetch,
  organizationId: string,
  email: string,
  type = 2
): Promise<string[]> {
  const resp = await authedFetch(`/api/organizations/${encodeURIComponent(organizationId)}/users`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ emails: [email], type }),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_invite_member_failed')));
  const body = await parseJson<{ data?: unknown }>(resp);
  const rows = Array.isArray(body?.data) ? (body.data as Record<string, unknown>[]) : [];
  return rows.map((entry) => String(entry.id || '')).filter(Boolean);
}

/** The public keys of these members, so the organization key can be wrapped for them. */
export async function getMemberPublicKeys(
  authedFetch: AuthedFetch,
  organizationId: string,
  userIds: string[]
): Promise<Map<string, string | null>> {
  const resp = await authedFetch(`/api/organizations/${encodeURIComponent(organizationId)}/users/public-key`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userIds }),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_organization_load_failed')));
  const body = await parseJson<{ data?: unknown }>(resp);
  const rows = Array.isArray(body?.data) ? (body.data as Record<string, unknown>[]) : [];
  const keys = new Map<string, string | null>();
  for (const entry of rows) {
    keys.set(String(entry.userId || entry.id || ''), typeof entry.publicKey === 'string' ? entry.publicKey : null);
  }
  return keys;
}

/** Hands the member their organization key, wrapped for their own RSA key. */
export async function confirmOrganizationMember(
  authedFetch: AuthedFetch,
  organizationId: string,
  membershipId: string,
  wrappedKey: string
): Promise<void> {
  const resp = await authedFetch(
    `/api/organizations/${encodeURIComponent(organizationId)}/users/${encodeURIComponent(membershipId)}/confirm`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: wrappedKey }),
    }
  );
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_invite_member_failed')));
}

/** Sets the member's role and the rights they hold on each collection. */
export async function updateOrganizationMember(
  authedFetch: AuthedFetch,
  organizationId: string,
  membershipId: string,
  patch: {
    type?: number;
    collections?: Array<{ id: string; readOnly: boolean; hidePasswords: boolean; manage: boolean }>;
  }
): Promise<void> {
  const resp = await authedFetch(
    `/api/organizations/${encodeURIComponent(organizationId)}/users/${encodeURIComponent(membershipId)}`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(patch),
    }
  );
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_update_member_failed')));
}

/** Removes the member. The key they hold has to be replaced afterwards. */
export async function removeOrganizationMember(
  authedFetch: AuthedFetch,
  organizationId: string,
  membershipId: string
): Promise<void> {
  const resp = await authedFetch(
    `/api/organizations/${encodeURIComponent(organizationId)}/users/${encodeURIComponent(membershipId)}`,
    { method: 'DELETE' }
  );
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_remove_member_failed')));
}

export async function getCollections(authedFetch: AuthedFetch): Promise<VaultCollection[]> {
  const resp = await authedFetch('/api/collections');
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_collection_load_failed')));
  const body = await parseJson<{ data?: unknown }>(resp);
  const rows = Array.isArray(body?.data) ? (body.data as Record<string, unknown>[]) : [];
  return rows
    .map(normalizeCollection)
    .filter((entry): entry is VaultCollection => !!entry)
    .sort((a, b) => a.name.localeCompare(b.name));
}

async function parseErrorMessage(resp: Response, fallback: string): Promise<string> {
  try {
    const body = (await resp.json()) as { error_description?: string; error?: string; message?: string };
    return body?.error_description || body?.message || body?.error || fallback;
  } catch {
    return fallback;
  }
}
