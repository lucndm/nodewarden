import type { Env } from '../types';
import {
  getEmailBreachCache,
  listActiveUserEmails,
  upsertEmailBreachCache,
} from './storage-email-breach-repo';

// Email breach monitoring against public breach databases.
//
// Two interchangeable upstream providers:
//  - "hibp": Have I Been Pwned v3 API. More complete, requires a paid
//    subscription key (env.HIBP_API_KEY).
//  - "xon":  XposedOrNot public API. Free, no key — the default provider.
//
// Results are cached per account (email_breach_cache) and refreshed at most
// once per day: a cron-driven sweep checks a few stale accounts per run, and
// the authenticated endpoint performs an on-demand check only when its cache
// is stale. Passwords are never sent anywhere — only the account email.

const HIBP_BREACHED_ACCOUNT_URL = 'https://haveibeenpwned.com/api/v3/breachedaccount';
const HIBP_USER_AGENT = 'NodeWarden-Password-Manager';
const XON_CHECK_URL = 'https://api.xposedornot.com/v1/check-email';
const XON_CATALOG_URL = 'https://api.xposedornot.com/v1/breaches';
// Re-check each account at most once per day. Breach corpora change slowly and
// the upstreams are rate limited, so aggressive polling adds nothing.
export const EMAIL_BREACH_REFRESH_INTERVAL_MS = 24 * 60 * 60 * 1000;
// Bound per cron run: cron fires every 5 minutes, so a handful of accounts is
// fully refreshed within minutes of becoming stale even at this pace.
const SWEEP_MAX_CHECKS_PER_RUN = 3;

export type EmailBreachStatus = 'ok' | 'invalid_key' | 'rate_limited' | 'error';
export type BreachProvider = 'hibp' | 'xon';

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

export function getBreachProvider(env: Env): BreachProvider {
  return String(env.HIBP_API_KEY || '').trim() ? 'hibp' : 'xon';
}

export function shouldRefreshBreachCache(checkedAt: string | null | undefined, now: number = Date.now()): boolean {
  const checked = Date.parse(String(checkedAt || ''));
  if (!Number.isFinite(checked)) return true;
  return now - checked >= EMAIL_BREACH_REFRESH_INTERVAL_MS;
}

function mapBreach(entry: { name: string; title?: string; domain?: string; breachDate?: string; pwnCount?: number; dataClasses?: unknown; verified?: boolean }): EmailBreachInfo | null {
  const name = String(entry?.name || entry?.title || '').trim();
  if (!name) return null;
  const dataClasses = Array.isArray(entry.dataClasses)
    ? entry.dataClasses.map((item) => String(item)).filter(Boolean)
    : [];
  return {
    name,
    title: String(entry?.title || name),
    domain: String(entry?.domain || ''),
    breachDate: String(entry?.breachDate || ''),
    pwnCount: Number.isFinite(entry?.pwnCount) ? Number(entry.pwnCount) : 0,
    dataClasses,
    verified: entry?.verified !== false,
  };
}

/** Maps an HIBP breachedaccount HTTP response to a check outcome. */
export function mapHibpResponse(status: number, body: unknown): EmailBreachCheckOutcome {
  if (status === 200) {
    const entries = Array.isArray(body) ? (body as Array<Record<string, unknown>>) : [];
    const breaches = entries
      .map((entry) =>
        mapBreach({
          name: String(entry?.Name || ''),
          title: entry?.Title === undefined ? undefined : String(entry?.Title),
          domain: entry?.Domain === undefined ? undefined : String(entry?.Domain),
          breachDate: entry?.BreachDate === undefined ? undefined : String(entry?.BreachDate),
          pwnCount: entry?.PwnCount as number | undefined,
          dataClasses: entry?.DataClasses,
          verified: entry?.IsVerified as boolean | undefined,
        })
      )
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

// --- XposedOrNot (free, no key) ---

interface XonCatalogEntry {
  breachDate: string;
  domain: string;
  pwnCount: number;
  dataClasses: string[];
  verified: boolean;
}

let xonCatalog: { loadedAt: number; byName: Map<string, XonCatalogEntry> } | null = null;

async function getXonCatalog(now: number = Date.now()): Promise<Map<string, XonCatalogEntry>> {
  if (xonCatalog && now - xonCatalog.loadedAt < EMAIL_BREACH_REFRESH_INTERVAL_MS) {
    return xonCatalog.byName;
  }
  const byName = new Map<string, XonCatalogEntry>();
  try {
    const response = await fetch(XON_CATALOG_URL);
    if (response.ok) {
      const body = (await response.json()) as {
        exposedBreaches?: Array<Record<string, unknown>>;
      };
      for (const entry of body.exposedBreaches || []) {
        const name = String(entry.breachID || '').trim();
        if (!name) continue;
        byName.set(name, {
          breachDate: String(entry.breachedDate || '').slice(0, 10),
          domain: String(entry.domain || ''),
          pwnCount: Number(entry.exposedRecords) || 0,
          dataClasses: Array.isArray(entry.exposedData) ? entry.exposedData.map((item) => String(item)) : [],
          verified: entry.verified !== false,
        });
      }
    }
  } catch {
    // Catalog is optional enrichment: checks still work with name-only results.
  }
  xonCatalog = { loadedAt: now, byName };
  return byName;
}

/** Flattens the XposedOrNot check-email payload ("breaches" is arrays of names). */
export function mapXonCheckResponse(
  body: { Error?: string; breaches?: unknown } | null,
  catalog: Map<string, XonCatalogEntry>
): EmailBreachCheckOutcome {
  if (body && typeof body === 'object' && body.Error) return { status: 'ok', breaches: [] };
  const groups = Array.isArray(body?.breaches) ? (body?.breaches as unknown[]) : [];
  const names = new Set<string>();
  for (const group of groups) {
    if (!Array.isArray(group)) continue;
    for (const name of group) {
      const normalized = String(name || '').trim();
      if (normalized) names.add(normalized);
    }
  }
  const breaches: EmailBreachInfo[] = [];
  for (const name of names) {
    const meta = catalog.get(name);
    const mapped = mapBreach({
      name,
      breachDate: meta?.breachDate,
      domain: meta?.domain,
      pwnCount: meta?.pwnCount,
      dataClasses: meta?.dataClasses,
      verified: meta?.verified,
    });
    if (mapped) breaches.push(mapped);
  }
  breaches.sort((a, b) => b.breachDate.localeCompare(a.breachDate) || b.pwnCount - a.pwnCount);
  return { status: 'ok', breaches };
}

async function checkEmailBreachesXon(email: string): Promise<EmailBreachCheckOutcome> {
  let response: Response;
  try {
    response = await fetch(`${XON_CHECK_URL}/${encodeURIComponent(email)}`);
  } catch {
    return { status: 'error', breaches: [] };
  }
  if (response.status === 429) return { status: 'rate_limited', breaches: [] };
  if (!response.ok) return { status: 'error', breaches: [] };
  const body = (await response.json().catch(() => null)) as { Error?: string; breaches?: unknown } | null;
  const names = mapXonCheckResponse(body, await getXonCatalog());
  return names;
}

async function checkEmailBreachesHibp(env: Env, email: string): Promise<EmailBreachCheckOutcome> {
  const apiKey = String(env.HIBP_API_KEY || '').trim();
  let response: Response;
  try {
    response = await fetch(
      `${HIBP_BREACHED_ACCOUNT_URL}/${encodeURIComponent(email)}?includeUnverified=true&truncateResponse=false`,
      {
        headers: {
          'HIBP-API-Key': apiKey,
          'User-Agent': 'NodeWarden-Password-Manager',
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

export async function checkEmailBreaches(env: Env, email: string): Promise<EmailBreachCheckOutcome> {
  if (getBreachProvider(env) === 'hibp') return checkEmailBreachesHibp(env, email);
  return checkEmailBreachesXon(email);
}

async function refreshEmailBreachCache(env: Env, email: string): Promise<EmailBreachCheckOutcome> {
  const outcome = await checkEmailBreaches(env, email);
  // Only definitive results overwrite the cache: transient failures
  // (network, rate limit) keep the previous verdict so a temporary upstream
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
    // Rate limited or upstream unreachable: stop this run entirely, the next
    // cron tick retries — hammering a misbehaving upstream helps nobody.
    return;
  }
}
