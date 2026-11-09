// Organization policies: the endpoints that read and set them.
//
// A policy is an organization's decision for its members ("nobody in this
// organization may use Send"). The list a client reads keeps the shape the
// official clients already understand, so they can show the policy and grey
// out what it forbids; the server refuses the action itself as well, because
// a client that never looks at policies must not be able to ignore one.
import type { Env } from '../types';
import { StorageService } from '../services/storage';
import { jsonResponse, errorResponse } from '../utils/response';
import { writeAuditEvent, auditRequestMetadata } from '../services/audit-events';
import { SEND_CONTROLS_POLICY, type OrganizationPolicy } from '../services/storage-policy-repo';

const STATUS_CONFIRMED = 2;
const ADMIN_TYPE = 1;

/** The policies this server knows how to enforce. */
const ENFORCED_POLICIES = new Set<number>([SEND_CONTROLS_POLICY]);

export function policyResponse(policy: OrganizationPolicy): Record<string, unknown> {
  let data: unknown = {};
  try {
    data = JSON.parse(policy.data || '{}');
  } catch {
    data = {};
  }
  return {
    object: 'policy',
    id: policy.id,
    organizationId: policy.orgId,
    type: policy.type,
    enabled: policy.enabled,
    data,
    revisionDate: policy.revisionDate,
  };
}

/** GET /api/policies — the policies of the organizations the user is in. */
export async function handleGetUserPolicies(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const policies = await storage.listPoliciesForUser(userId);
  return jsonResponse({
    data: policies.map(policyResponse),
    object: 'list',
    continuationToken: null,
  });
}

async function requireOrganizationAdmin(
  storage: StorageService,
  orgId: string,
  userId: string
): Promise<Response | null> {
  const requester = await storage.getOrganizationUserForUser(orgId, userId);
  if (!requester || requester.status !== STATUS_CONFIRMED || requester.type > ADMIN_TYPE) {
    return errorResponse('Forbidden', 403);
  }
  return null;
}

/** GET /api/organizations/:orgId/policies — the organization's decisions. */
export async function handleGetOrganizationPolicies(
  request: Request,
  env: Env,
  userId: string,
  orgId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const forbidden = await requireOrganizationAdmin(storage, orgId, userId);
  if (forbidden) return forbidden;
  const policies = await storage.listOrganizationPolicies(orgId);
  return jsonResponse({ data: policies.map(policyResponse), object: 'list', continuationToken: null });
}

function readPolicyData(raw: unknown): string | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const data = raw as Record<string, unknown>;
  if ('DisableSend' in data && typeof data.DisableSend !== 'boolean') return null;
  return JSON.stringify(data);
}

/** PUT /api/organizations/:orgId/policies/:type — turn one policy on or off. */
export async function handleSetOrganizationPolicy(
  request: Request,
  env: Env,
  userId: string,
  orgId: string,
  type: number
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const forbidden = await requireOrganizationAdmin(storage, orgId, userId);
  if (forbidden) return forbidden;

  if (!ENFORCED_POLICIES.has(type)) {
    // Storing a policy nothing enforces would be a promise the server does
    // not keep, so an unknown type is refused instead.
    return errorResponse('This policy is not supported by this server', 400);
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }
  const input = (body || {}) as { enabled?: unknown; data?: unknown };
  if (typeof input.enabled !== 'boolean') {
    return errorResponse('enabled is required', 400);
  }
  const data = readPolicyData(input.data ?? {});
  if (data === null) {
    return errorResponse('data is not a valid policy body', 400);
  }

  const existing = await storage.getOrganizationPolicy(orgId, type);
  const saved = await storage.saveOrganizationPolicy({
    id: existing?.id || crypto.randomUUID(),
    orgId,
    type,
    enabled: input.enabled,
    data,
    revisionDate: new Date().toISOString(),
  });

  await writeAuditEvent(storage, {
    actorUserId: userId,
    action: 'organization.policy.update',
    category: 'security',
    level: 'info',
    targetType: 'organization',
    targetId: orgId,
    metadata: { type, enabled: saved.enabled, ...auditRequestMetadata(request) },
  });

  return jsonResponse(policyResponse(saved));
}
