// Organization policies: what an organization decides for its members.
//
// A policy is stored the way the official clients expect to read it: the type
// is the number Bitwarden uses, `enabled` says whether it applies, and `data`
// is the policy's own JSON. Keeping that shape means a client that already
// understands policies picks ours up without a translation layer - and the
// server enforces the same policy for clients that do not look at all.
import type { D1Database } from '@cloudflare/workers-types';

/** The policy that decides what members may do with Send. */
export const SEND_CONTROLS_POLICY = 21;

export interface OrganizationPolicy {
  id: string;
  orgId: string;
  type: number;
  enabled: boolean;
  /** The policy's own JSON, exactly as it was stored. */
  data: string;
  revisionDate: string;
}

interface PolicyRow {
  id: string;
  org_id: string;
  type: number;
  enabled: number;
  data: string | null;
  revision_date: string;
}

function policyFromRow(row: PolicyRow): OrganizationPolicy {
  return {
    id: row.id,
    orgId: row.org_id,
    type: Number(row.type),
    enabled: Number(row.enabled) === 1,
    data: typeof row.data === 'string' && row.data ? row.data : '{}',
    revisionDate: row.revision_date,
  };
}

/** Whether the policy data says that Send is off for the members. */
export function sendControlsDisableSend(data: string | null | undefined): boolean {
  if (!data) return false;
  try {
    const parsed = JSON.parse(data) as { DisableSend?: unknown; disableSend?: unknown };
    return parsed?.DisableSend === true || parsed?.disableSend === true;
  } catch {
    return false;
  }
}

export async function listOrganizationPolicies(db: D1Database, orgId: string): Promise<OrganizationPolicy[]> {
  const rows = await db
    .prepare('SELECT id, org_id, type, enabled, data, revision_date FROM organization_policies WHERE org_id = ? ORDER BY type ASC')
    .bind(orgId)
    .all<PolicyRow>();
  return (rows.results || []).map(policyFromRow);
}

export async function getOrganizationPolicy(
  db: D1Database,
  orgId: string,
  type: number
): Promise<OrganizationPolicy | null> {
  const row = await db
    .prepare('SELECT id, org_id, type, enabled, data, revision_date FROM organization_policies WHERE org_id = ? AND type = ? LIMIT 1')
    .bind(orgId, type)
    .first<PolicyRow>();
  return row ? policyFromRow(row) : null;
}

export async function saveOrganizationPolicy(
  db: D1Database,
  input: { id: string; orgId: string; type: number; enabled: boolean; data: string; revisionDate: string }
): Promise<OrganizationPolicy> {
  await db
    .prepare(
      'INSERT INTO organization_policies(id, org_id, type, enabled, data, revision_date) VALUES (?, ?, ?, ?, ?, ?) ' +
        'ON CONFLICT(org_id, type) DO UPDATE SET enabled = excluded.enabled, data = excluded.data, revision_date = excluded.revision_date'
    )
    .bind(input.id, input.orgId, input.type, input.enabled ? 1 : 0, input.data, input.revisionDate)
    .run();
  const saved = await getOrganizationPolicy(db, input.orgId, input.type);
  if (!saved) throw new Error('the policy was not saved');
  return saved;
}

/**
 * The policies of the organizations the user is in, for the client to read.
 * An invitation that was not answered yet carries no policy: a policy binds
 * the members of the organization, not the people who may join it.
 */
export async function listPoliciesForUser(db: D1Database, userId: string): Promise<OrganizationPolicy[]> {
  const rows = await db
    .prepare(
      'SELECT p.id, p.org_id, p.type, p.enabled, p.data, p.revision_date ' +
        'FROM organization_policies p ' +
        'JOIN organization_users u ON u.org_id = p.org_id ' +
        'WHERE u.user_id = ? AND u.status >= 1 ' +
        'ORDER BY p.org_id ASC, p.type ASC'
    )
    .bind(userId)
    .all<PolicyRow>();
  return (rows.results || []).map(policyFromRow);
}

/** Whether any organization of the user turns Send off for its members. */
export async function userHasSendDisabled(db: D1Database, userId: string): Promise<boolean> {
  const rows = await db
    .prepare(
      'SELECT p.data FROM organization_policies p ' +
        'JOIN organization_users u ON u.org_id = p.org_id ' +
        'WHERE u.user_id = ? AND u.status >= 1 AND p.type = ? AND p.enabled = 1'
    )
    .bind(userId, SEND_CONTROLS_POLICY)
    .all<{ data: string | null }>();
  return (rows.results || []).some((row) => sendControlsDisableSend(row.data));
}
