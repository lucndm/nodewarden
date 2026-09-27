import type { Env } from '../types';
import {
  getEmailBreachCache,
  listActiveUserEmails,
  upsertEmailBreachCache,
} from './storage-email-breach-repo';

// Email breach monitoring via the Have I Been Pwned v3 API.
//
// The account email is checked against known data breaches. Results are cached
// per account (email_breach_cache) and refreshed at most once per day: a
// cron-driven sweep checks a few stale accounts per run, and the authenticated
// endpoint performs an on-demand check only when its cache is stale.
// The API requires a paid HIBP subscription key (env.HIBP_API_KEY); without it
// the feature reports enabled=false and nothing is sent anywhere.

const HIBP_BREACHED_ACCOUNT_URL = 'https://haveibeenpwned.com/api/v3/breachedaccount';
const HIBP_USER_AGENT = 'NodeWarden-Password-Manager';
// Re-check each account at most once per day. HIBP breach data changes slowly
// and the subscription is rate limited, so aggressive polling adds nothing.
export const EMAIL_BREACH_REFRESH_INTERVAL_MS = 24 * 60 * 60 * 1000;
// Bound per cron run: cron fires every 5 minutes, so a handful of accounts is
// fully refreshed within minutes of becoming stale even at this pace.
const SWEEP_MAX_CHECKS_PER_RUN = 3;

export type EmailBreachStatus = 'ok' | 'invalid_key' | 'rate_limited' | 'error';

export interface EmailBreachInfo {
  name: string;
  title: string;
  domain: string;
  breachDate: string;
  pwnCount: number;
  dataClasses: string[];
  verified: boolean;
}

export interface EmailBreachCheckOutcome {
  status: EmailBreachStatus;
  breaches: EmailBreachInfo[];
}

interface HibpBreachPayload {
  Name?: string;
  Title?: string;
  Domain?: string;
  BreachDate?: string;
  PwnCount?: number;
  DataClasses?: unknown;
  IsVerified?: boolean;
}

export function getHibpApiKey(env: Env): string {
  return String(env.HIBP_API_KEY || '').trim();
}

export function isEmailBreachMonitoringEnabled(env: Env): boolean {
  return getHibpApiKey(env).length > 0;
}

export function shouldRefreshBreachCache(checkedAt: string | null | undefined, now: number = Date.now()): boolean {
  const checked = Date.parse(String(checkedAt || ''));
  if (!Number.isFinite(checked)) return true;
  return now - checked >= EMAIL_BREACH_REFRESH_INTERVAL_MS;
}

function mapBreach(entry: HibpBreachPayload): EmailBreachInfo | null {
  const name = String(entry?.Name || entry?.Title || '').trim();
  if (!name) return null;
  const dataClasses = Array.isArray(entry.DataClasses)
    ? entry.DataClasses.map((item) => String(item)).filter(Boolean)
    : [];
  return {
    name,
    title: String(entry?.Title || name),
    domain: String(entry?.Domain || ''),
    breachDate: String(entry?.BreachDate || ''),
    pwnCount: Number.isFinite(entry?.PwnCount) ? Number(entry.PwnCount) : 0,
    dataClasses,
    verified: entry?.IsVerified !== false,
  };
}

/** Maps an HIBP breachedaccount HTTP response to a check outcome. */
export function mapHibpResponse(status: number, body: unknown): EmailBreachCheckOutcome {
  if (status === 200) {
    const entries = Array.isArray(body) ? (body as HibpBreachPayload[]) : [];
    const breaches = entries
      .map(mapBreach)
      .filter((entry): entry is EmailBreachInfo => entry !== null)
      .sort((a, b) => b.breachDate.localeCompare(a.breachDate) || b.pwnCount - a.pwnCount);
    return { status: 'ok', breaches };
  }
  // 404 means the account is not known to any breach in the corpus.
  if (status === 404) return { status: 'ok', breaches: [] };
  if (status === 401 || status === 403) return { status: 'invalid_key', breaches: [] };
  if (status === 429) return { status: 'rate_limited', breaches: [] };
  return { status: 'error', breaches: [] };
}

export async function checkEmailBreaches(env: Env, email: string): Promise<EmailBreachCheckOutcome> {
  const apiKey = getHibpApiKey(env);
  if (!apiKey) return { status: 'error', breaches: [] };

  let response: Response;
  try {
    response = await fetch(
      `${HIBP_BREACHED_ACCOUNT_URL}/${encodeURIComponent(email)}?includeUnverified=true&truncateResponse=false`,
      {
        headers: {
          'HIBP-API-Key': apiKey,
          'User-Agent': HIBP_USER_AGENT,
        },
      }
    );
  } catch {
    return { status: 'error', breaches: [] };
  }

  let body: unknown = null;
  if (response.status === 200 || response.status === 404) {
    body = await response.json().catch(() => null);
  }
  return mapHibpResponse(response.status, body);
}

async function refreshEmailBreachCache(env: Env, email: string): Promise<EmailBreachCheckOutcome> {
  const outcome = await checkEmailBreaches(env, email);
  // Only definitive results overwrite the cache: transient failures
  // (network, rate limit) keep the previous verdict so a temporary HIBP
  // outage does not blank out the user's report.
  if (outcome.status === 'ok' || outcome.status === 'invalid_key') {
    await upsertEmailBreachCache(env.DB, email, outcome.status, JSON.stringify(outcome.breaches), new Date().toISOString());
  }
  return outcome;
}

/**
 * Cron sweep: refresh the oldest stale account caches. Cheap by design —
 * a handful of D1 reads and at most SWEEP_MAX_CHECKS_PER_RUN outbound calls.
 */
export async function sweepEmailBreachCaches(env: Env, now: number = Date.now()): Promise<void> {
  if (!isEmailBreachMonitoringEnabled(env)) return;

  const emails = await listActiveUserEmails(env.DB);
  let checked = 0;
  for (const email of emails) {
    if (checked >= SWEEP_MAX_CHECKS_PER_RUN) return;
    const cached = await getEmailBreachCache(env.DB, email);
    if (cached && !shouldRefreshBreachCache(cached.checkedAt, now)) continue;
    const outcome = await checkEmailBreaches(env, email);
    if (outcome.status === 'ok' || outcome.status === 'invalid_key') {
      await upsertEmailBreachCache(env.DB, email, outcome.status, JSON.stringify(outcome.breaches), new Date().toISOString());
      checked++;
      continue;
    }
    // Rate limited or HIBP unreachable: stop this run entirely, the next cron
    // tick retries — hammering a misbehaving upstream helps nobody.
    return;
  }
}
