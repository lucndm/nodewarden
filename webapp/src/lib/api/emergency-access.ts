// Emergency access.
//
// One account lets another person in when they cannot get in themselves. The
// grantor hands over a key wrapped for the grantee, so the server holds a key
// it cannot open.
//
// The request carries the wrapped key, never a key the server could open and
// never a master password.

import type { AuthedFetch } from '@/lib/api/shared';
import { parseErrorMessage, parseJson } from '@/lib/api/shared';

export interface EmergencyAccessGranteeDetails {
  id: string;
  status: number;
  type: number;
  waitTimeDays: number;
  granteeId: string | null;
  email: string | null;
  name: string | null;
}

export interface EmergencyAccessGrantorDetails {
  id: string;
  status: number;
  type: number;
  waitTimeDays: number;
  grantorId: string;
  email: string | null;
  name: string | null;
}

function readRows(body: { data?: unknown } | null): Record<string, unknown>[] {
  return Array.isArray(body?.data) ? (body.data as Record<string, unknown>[]) : [];
}

/** GET /api/emergency-access/trusted — the grants this account gave. */
export async function getTrustedEmergencyAccess(
  authedFetch: AuthedFetch
): Promise<EmergencyAccessGranteeDetails[]> {
  const resp = await authedFetch('/api/emergency-access/trusted');
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Load emergency access failed'));
  const body = await parseJson<{ data?: unknown }>(resp);
  return readRows(body).map((row) => ({
    id: String(row.id || ''),
    status: Number(row.status) || 0,
    type: Number(row.type) || 0,
    waitTimeDays: Number(row.waitTimeDays) || 0,
    granteeId: row.granteeId ? String(row.granteeId) : null,
    email: row.email ? String(row.email) : null,
    name: row.name ? String(row.name) : null,
  }));
}

/** GET /api/emergency-access/granted — the grants this account was given. */
export async function getGrantedEmergencyAccess(
  authedFetch: AuthedFetch
): Promise<EmergencyAccessGrantorDetails[]> {
  const resp = await authedFetch('/api/emergency-access/granted');
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Load emergency access failed'));
  const body = await parseJson<{ data?: unknown }>(resp);
  return readRows(body).map((row) => ({
    id: String(row.id || ''),
    status: Number(row.status) || 0,
    type: Number(row.type) || 0,
    waitTimeDays: Number(row.waitTimeDays) || 0,
    grantorId: String(row.grantorId || ''),
    email: row.email ? String(row.email) : null,
    name: row.name ? String(row.name) : null,
  }));
}

/** POST /api/emergency-access/invite */
export async function inviteEmergencyAccess(
  authedFetch: AuthedFetch,
  input: { email: string; type: number; waitTimeDays: number; encryptedUserKey: string }
): Promise<void> {
  const resp = await authedFetch('/api/emergency-access/invite', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Invite failed'));
}

/** PUT /api/emergency-access/:id/accept */
export async function acceptEmergencyAccess(authedFetch: AuthedFetch, id: string): Promise<void> {
  const resp = await authedFetch(`/api/emergency-access/${encodeURIComponent(id)}/accept`, { method: 'PUT' });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Accept failed'));
}

/** POST /api/emergency-access/:id/initiate — the grantee starts the wait. */
export async function initiateEmergencyAccess(authedFetch: AuthedFetch, id: string): Promise<void> {
  const resp = await authedFetch(`/api/emergency-access/${encodeURIComponent(id)}/initiate`, { method: 'POST' });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Start the wait failed'));
}

/** POST /api/emergency-access/:id/approve — the grantor approves the recovery. */
export async function approveEmergencyAccess(authedFetch: AuthedFetch, id: string): Promise<void> {
  const resp = await authedFetch(`/api/emergency-access/${encodeURIComponent(id)}/approve`, { method: 'POST' });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Approve failed'));
}

/** PUT /api/emergency-access/:id/reject */
export async function rejectEmergencyAccess(authedFetch: AuthedFetch, id: string): Promise<void> {
  const resp = await authedFetch(`/api/emergency-access/${encodeURIComponent(id)}/reject`, { method: 'PUT' });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Reject failed'));
}

/** DELETE /api/emergency-access/:id */
export async function withdrawEmergencyAccess(authedFetch: AuthedFetch, id: string): Promise<void> {
  const resp = await authedFetch(`/api/emergency-access/${encodeURIComponent(id)}`, { method: 'DELETE' });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Withdraw failed'));
}
