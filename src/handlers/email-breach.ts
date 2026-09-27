import type { Env } from '../types';
import { StorageService } from '../services/storage';
import { errorResponse, jsonResponse } from '../utils/response';
import {
  checkEmailBreaches,
  shouldRefreshBreachCache,
  type EmailBreachInfo,
  type EmailBreachStatus,
} from '../services/email-breach-monitor';
import { getEmailBreachCache, upsertEmailBreachCache } from '../services/storage-email-breach-repo';

interface EmailBreachesResponseBody {
  object: 'emailBreaches';
  enabled: boolean;
  status: EmailBreachStatus | null;
  checkedAt: string | null;
  breaches: EmailBreachInfo[];
}

/**
 * GET /api/security/email-breaches (authenticated)
 *
 * Reports known data breaches affecting the account email. The result comes
 * from the daily cron sweep; if this account's cache is stale (or missing),
 * an on-demand check runs inline so the user does not have to wait up to a
 * full sweep cycle.
 */
export async function handleGetEmailBreaches(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);
  const email = user.email.trim().toLowerCase();
  if (!email) return errorResponse('Account email is not configured', 409);

  let cached = await getEmailBreachCache(env.DB, email);
  if (!cached || shouldRefreshBreachCache(cached.checkedAt)) {
    const outcome = await checkEmailBreaches(env, email);
    if (outcome.status === 'ok' || outcome.status === 'invalid_key') {
      const checkedAt = new Date().toISOString();
      await upsertEmailBreachCache(env.DB, email, outcome.status, JSON.stringify(outcome.breaches), checkedAt);
      cached = { emailNorm: email, checkedAt, status: outcome.status, breachesJson: JSON.stringify(outcome.breaches) };
    }
  }

  if (!cached) {
    // Transient failure with no previous verdict to fall back on.
    const body: EmailBreachesResponseBody = { object: 'emailBreaches', enabled: true, status: 'error', checkedAt: null, breaches: [] };
    return jsonResponse(body);
  }

  let breaches: EmailBreachInfo[] = [];
  try {
    const parsed = JSON.parse(cached.breachesJson);
    if (Array.isArray(parsed)) breaches = parsed as EmailBreachInfo[];
  } catch {
    breaches = [];
  }
  const body: EmailBreachesResponseBody = {
    object: 'emailBreaches',
    enabled: true,
    status: cached.status as EmailBreachStatus,
    checkedAt: cached.checkedAt,
    breaches,
  };
  return jsonResponse(body);
}
