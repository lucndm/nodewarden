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
    type: Number(raw.type) || 2,
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
