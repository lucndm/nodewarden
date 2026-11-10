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

interface EmailBreachVerdict {
  status: EmailBreachStatus;
  checkedAt: string;
  breaches: EmailBreachInfo[];
}

/**
 * The breaches of one address. The result comes from the daily cron sweep;
 * if the cache is stale (or missing), an on-demand check runs inline so the
 * user does not have to wait up to a full sweep cycle. Null when the check
 * failed and there is no previous verdict to fall back on.
 */
async function loadEmailBreaches(env: Env, email: string): Promise<EmailBreachVerdict | null> {
  let cached = await getEmailBreachCache(env.DB, email);
  if (!cached || shouldRefreshBreachCache(cached.checkedAt)) {
    const outcome = await checkEmailBreaches(env, email);
    if (outcome.status === 'ok' || outcome.status === 'invalid_key') {
      const checkedAt = new Date().toISOString();
      await upsertEmailBreachCache(env.DB, email, outcome.status, JSON.stringify(outcome.breaches), checkedAt);
      cached = { emailNorm: email, checkedAt, status: outcome.status, breachesJson: JSON.stringify(outcome.breaches) };
    }
  }
  if (!cached) return null;

  let breaches: EmailBreachInfo[] = [];
  try {
    const parsed = JSON.parse(cached.breachesJson);
    if (Array.isArray(parsed)) breaches = parsed as EmailBreachInfo[];
  } catch {
    breaches = [];
  }
  return { status: cached.status as EmailBreachStatus, checkedAt: cached.checkedAt, breaches };
}

/**
 * GET /api/security/email-breaches (authenticated)
 *
 * Reports known data breaches affecting the account email.
 */
export async function handleGetEmailBreaches(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);
  const email = user.email.trim().toLowerCase();
  if (!email) return errorResponse('Account email is not configured', 409);

  const verdict = await loadEmailBreaches(env, email);
  if (!verdict) {
    // Transient failure with no previous verdict to fall back on.
    const body: EmailBreachesResponseBody = { object: 'emailBreaches', enabled: true, status: 'error', checkedAt: null, breaches: [] };
    return jsonResponse(body);
  }
  const body: EmailBreachesResponseBody = {
    object: 'emailBreaches',
    enabled: true,
    status: verdict.status,
    checkedAt: verdict.checkedAt,
    breaches: verdict.breaches,
  };
  return jsonResponse(body);
}

/**
 * GET /api/hibp/breach?username= (authenticated)
 *
 * The official web vault's "Data breach report", read as a list of
 * BreachAccountResponse. Only the account's own address is checked: the
 * report would otherwise let every account on the server look up anybody's
 * address through the server's breach provider.
 */
export async function handleGetHibpBreach(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);
  const email = user.email.trim().toLowerCase();
  const username = (new URL(request.url).searchParams.get('username') || '').trim().toLowerCase();
  if (!username) return errorResponse('A username is required.', 400);
  if (username !== email) {
    return errorResponse('Only the email address of this account can be checked.', 400);
  }

  const verdict = await loadEmailBreaches(env, email);
  if (!verdict || verdict.status !== 'ok') {
    return errorResponse('The breach check is not available right now.', 503);
  }
  return jsonResponse(
    verdict.breaches.map((breach) => ({
      name: breach.name,
      title: breach.title,
      domain: breach.domain,
      breachDate: breach.breachDate,
      addedDate: breach.breachDate,
      modifiedDate: breach.breachDate,
      pwnCount: breach.pwnCount,
      description: '',
      dataClasses: breach.dataClasses,
      isVerified: breach.verified,
      isFabricated: false,
      isSensitive: false,
      isRetired: false,
      isSpamList: false,
      logoPath: '',
    }))
  );
}
