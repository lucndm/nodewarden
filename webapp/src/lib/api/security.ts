// The items this account does not want checked by the password scan.
//
// A scan sends a hash prefix of a password to a breach database. Some items
// the user does not want that for, so the exclusion is kept by the server
// beside the item: it is a setting of the account, not a property of the
// item, and other clients and exports never see it.
//
// The request carries no secret: only the cipher id travels.

import type { AuthedFetch } from '@/lib/api/shared';
import { parseErrorMessage, parseJson } from '@/lib/api/shared';

export interface ScanExclusion {
  cipherId: string;
  scope: string;
  createdAt: string;
}

export const PASSWORD_HEALTH_SCOPE = 'password-health';

/** GET /api/security/scan-exclusions */
export async function getScanExclusions(
  authedFetch: AuthedFetch,
  scope: string = PASSWORD_HEALTH_SCOPE
): Promise<ScanExclusion[]> {
  const resp = await authedFetch(`/api/security/scan-exclusions?scope=${encodeURIComponent(scope)}`);
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Load scan exclusions failed'));
  const body = await parseJson<{ data?: unknown }>(resp);
  const rows = Array.isArray(body?.data) ? (body.data as Record<string, unknown>[]) : [];
  return rows.map((row) => ({
    cipherId: String(row.cipherId || ''),
    scope: String(row.scope || scope),
    createdAt: String(row.createdAt || ''),
  }));
}

/** PUT /api/security/scan-exclusions/:cipherId */
export async function excludeCipherFromScan(
  authedFetch: AuthedFetch,
  cipherId: string,
  scope: string = PASSWORD_HEALTH_SCOPE
): Promise<void> {
  const resp = await authedFetch(`/api/security/scan-exclusions/${encodeURIComponent(cipherId)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scope }),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Exclude from the check failed'));
}

/** DELETE /api/security/scan-exclusions/:cipherId */
export async function includeCipherInScan(
  authedFetch: AuthedFetch,
  cipherId: string,
  scope: string = PASSWORD_HEALTH_SCOPE
): Promise<void> {
  const resp = await authedFetch(
    `/api/security/scan-exclusions/${encodeURIComponent(cipherId)}?scope=${encodeURIComponent(scope)}`,
    { method: 'DELETE' }
  );
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Include in the check failed'));
}
