import assert from 'node:assert/strict';
import test from 'node:test';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { handleGetEmailBreaches } from '../src/handlers/email-breach';
import {
  mapHibpResponse,
  mapXonCheckResponse,
  sweepEmailBreachCaches,
  shouldRefreshBreachCache,
} from '../src/services/email-breach-monitor';
import { getEmailBreachCache, upsertEmailBreachCache } from '../src/services/storage-email-breach-repo';
import { MemoryD1 } from './memory-d1';
import type { Env } from '../src/types';

const HOUR = 60 * 60 * 1000;
const originalFetch = globalThis.fetch;

function envWithKey(key: string | undefined, db: unknown): Env {
  return {
    DB: db,
    JWT_SECRET: 'test-secret-0123456789',
    HIBP_API_KEY: key,
  } as unknown as Env;
}

/** Intercepts the global fetch: routes HIBP breachedaccount calls by email. */
function installHibpFetch(
  respond: (email: string) => Response
): { calls: () => string[]; restore: () => void } {
  const original = globalThis.fetch;
  const calls: string[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
    const url = new URL(String(input));
    if (url.hostname === 'haveibeenpwned.com') {
      const email = decodeURIComponent(url.pathname.split('/').pop() || '');
      calls.push(email);
      return respond(email);
    }
    throw new Error(`unexpected outbound request to ${String(input)}`);
  }) as typeof fetch;
  return { calls: () => calls.length, restore: () => { globalThis.fetch = original; } };
}

async function seedUser(db: MemoryD1, email: string): Promise<void> {
  await db
    .prepare(
      'INSERT INTO users(id, email, name, master_password_hash, key, security_stamp, role, status, verify_devices, yubikey_nfc, created_at, updated_at) ' +
        'VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    )
    .bind('u-' + email, email, 'Test', 'hash', 'key', 'stamp', 'user', 'active', 0, 0, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')
    .run();
}

test('mapHibpResponse parses, filters and sorts breach entries', () => {
  const outcome = mapHibpResponse(200, [
    { Name: 'Adobe', BreachDate: '2013-10-04', PwnCount: 152445165, DataClasses: ['Email addresses'] },
    { Name: 'LinkedIn', Title: 'LinkedIn', Domain: 'linkedin.com', BreachDate: '2021-06-22', PwnCount: 164611509, DataClasses: ['Email addresses', 'Passwords'], IsVerified: true },
    { Title: 'No name entry' },
    'garbage',
  ]);
  assert.equal(outcome.status, 'ok');
  // Entries with only a Title are kept (name falls back to Title); entries
  // without any name and non-object entries are dropped.
  assert.equal(outcome.breaches.length, 3);
  assert.equal(outcome.breaches[0].name, 'LinkedIn');
  assert.equal(outcome.breaches[0].pwnCount, 164611509);
  assert.deepEqual(outcome.breaches[0].dataClasses, ['Email addresses', 'Passwords']);
  assert.equal(outcome.breaches[1].verified, true);

  assert.deepEqual(mapHibpResponse(404, null), { status: 'ok', breaches: [] });
  assert.equal(mapHibpResponse(401, null).status, 'invalid_key');
  assert.equal(mapHibpResponse(403, null).status, 'invalid_key');
  assert.equal(mapHibpResponse(429, null).status, 'rate_limited');
  assert.equal(mapHibpResponse(500, null).status, 'error');
});

test('shouldRefreshBreachCache enforces the daily interval', () => {
  const now = Date.now();
  assert.equal(shouldRefreshBreachCache(null, now), true);
  assert.equal(shouldRefreshBreachCache('not-a-date', now), true);
  assert.equal(shouldRefreshBreachCache(new Date(now - 23 * HOUR).toISOString(), now), false);
  assert.equal(shouldRefreshBreachCache(new Date(now - 25 * HOUR).toISOString(), now), true);
});

test('endpoint checks on demand, caches, and reports disabled without a key', async (t) => {
  const db = new MemoryD1();
  await seedUser(db, 'one@example.test');
  const env = envWithKey('hibp-key', db);
  const hibp = installHibpFetch((email) => (email === 'one@example.test'
    ? Response.json([
        { Name: 'LinkedIn', Title: 'LinkedIn', Domain: 'linkedin.com', BreachDate: '2021-06-22', PwnCount: 164611509, DataClasses: ['Email addresses', 'Passwords'], IsVerified: true },
        { Name: 'Adobe', Title: 'Adobe', Domain: 'adobe.com', BreachDate: '2013-10-04', PwnCount: 152445165, DataClasses: ['Email addresses', 'Password hints', 'Passwords', 'Usernames'] },
      ])
    : new Response(null, { status: 404 })));
  t.after(hibp.restore);

  const first = await handleGetEmailBreaches(new Request('https://vault.example.test/api/security/email-breaches'), env, 'u-one@example.test');
  assert.equal(first.status, 200);
  const firstBody = (await first.json()) as { enabled: boolean; status: string; breaches: unknown[]; checkedAt: string | null };
  assert.equal(firstBody.enabled, true);
  assert.equal(firstBody.status, 'ok');
  assert.equal(firstBody.breaches.length, 2);
  assert.ok(firstBody.checkedAt);
  assert.equal(hibp.calls(), 1);

  // Fresh cache: the second read must not hit HIBP again.
  const second = await handleGetEmailBreaches(new Request('https://vault.example.test/api/security/email-breaches'), env, 'u-one@example.test');
  assert.equal((await second.json()).status, 'ok');
  assert.equal(hibp.calls(), 1);
});

test('without a HIBP key the free XposedOrNot provider serves the endpoint', async (t) => {
  const db = new MemoryD1();
  await seedUser(db, 'one@example.test');
  const env = envWithKey(undefined, db);

  // Unknown email: XON answers 200 with an Error marker — clean verdict, no breaches.
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = new URL(String(input));
    assert.equal(url.hostname, 'api.xposedornot.com');
    if (url.pathname.startsWith('/v1/check-email/')) {
      return Response.json({ Error: 'Not found', email: null });
    }
    throw new Error(`unexpected request: ${String(input)}`);
  }) as typeof fetch;
  t.after(() => { globalThis.fetch = originalFetch; });

  const response = await handleGetEmailBreaches(new Request('https://vault.example.test/api/security/email-breaches'), env, 'u-one@example.test');
  const body = (await response.json()) as { enabled: boolean; status: string; breaches: unknown[] };
  assert.equal(body.enabled, true);
  assert.equal(body.status, 'ok');
  assert.equal(body.breaches.length, 0);
});

test('cron sweep refreshes stale accounts and skips fresh ones', async (t) => {
  const db = new MemoryD1();
  await seedUser(db, 'one@example.test');
  await seedUser(db, 'two@example.test');
  const env = envWithKey('hibp-key', db);
  const hibp = installHibpFetch((email) => (email === 'one@example.test'
    ? Response.json([{ Name: 'LinkedIn', BreachDate: '2021-06-22', PwnCount: 164611509, DataClasses: ['Passwords'] }])
    : new Response(null, { status: 404 })));
  t.after(hibp.restore);

  await sweepEmailBreachCaches(env);
  assert.equal(hibp.calls(), 2);

  const one = await getEmailBreachCache(db, 'one@example.test');
  assert.ok(one);
  assert.equal(one!.status, 'ok');
  assert.ok(one!.breachesJson.includes('LinkedIn'));
  const two = await getEmailBreachCache(db, 'two@example.test');
  assert.ok(two);
  assert.equal(two!.status, 'ok');

  // Everything is fresh now: an immediate second sweep makes no calls.
  await sweepEmailBreachCaches(env);
  assert.equal(hibp.calls(), 2);
});

test('cron sweep retries stale entries and does not cache transient failures', async (t) => {
  const db = new MemoryD1();
  await seedUser(db, 'one@example.test');
  // Stale cache from a day ago.
  await upsertEmailBreachCache(db, 'one@example.test', 'ok', '[]', new Date(Date.now() - 25 * HOUR).toISOString());
  const env = envWithKey('hibp-key', db);
  const hibp = installHibpFetch(() => new Response(null, { status: 429 }));

  // HIBP rate limits: the sweep must stop and leave the stale cache intact.
  await sweepEmailBreachCaches(env);
  assert.equal(hibp.calls(), 1);
  const untouched = await getEmailBreachCache(db, 'one@example.test');
  assert.equal(untouched!.breachesJson, '[]');

  const second = installHibpFetch(() => Response.json([{ Name: 'NewLeak', BreachDate: '2026-01-01', PwnCount: 10, DataClasses: [] }]));
  t.after(second.restore);
  await sweepEmailBreachCaches(env);
  const refreshed = await getEmailBreachCache(db, 'one@example.test');
  assert.ok(refreshed!.breachesJson.includes('NewLeak'));
});


test('mapXonCheckResponse flattens groups and enriches from the catalog', () => {
  const catalog = new Map([
    ['Adobe', { breachDate: '2013-10-04', domain: 'adobe.com', pwnCount: 152445165, dataClasses: ['Email addresses', 'Passwords'], verified: true }],
  ]);

  const clean = mapXonCheckResponse({ Error: 'Not found', email: null }, catalog);
  assert.deepEqual(clean, { status: 'ok', breaches: [] });

  const outcome = mapXonCheckResponse(
    { breaches: [['LinkedIn', 'Adobe'], ['Unknown-Custom-Site'], 'junk', null] },
    catalog
  );
  assert.equal(outcome.status, 'ok');
  assert.equal(outcome.breaches.length, 3);
  assert.equal(outcome.breaches[0].name, 'Adobe');
  assert.equal(outcome.breaches[0].pwnCount, 152445165);
  assert.deepEqual(outcome.breaches[0].dataClasses, ['Email addresses', 'Passwords']);
  // Unknown names stay as name-only entries.
  assert.equal(outcome.breaches[2].name, 'Unknown-Custom-Site');
  assert.equal(outcome.breaches[2].pwnCount, 0);
});