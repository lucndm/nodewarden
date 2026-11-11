import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import test, { mock } from 'node:test';

import { handleNotificationsHub, handleNotificationsNegotiate } from '../src/handlers/notifications';
import type { Env } from '../src/types';
import { createJWT } from '../src/utils/jwt';

// The Durable Object module imports the Workers runtime, which only resolves
// on Cloudflare: the tests give it the same stub the other offline tests use.
// A static import would load that module before the stub is registered, so it
// is loaded once the hook below is in place.
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === 'cloudflare:workers') {
      const source = 'export class DurableObject {} export function waitUntil(p) { p.catch(() => {}); }';
      return { url: 'data:text/javascript,' + encodeURIComponent(source), shortCircuit: true };
    }
    return nextResolve(specifier, context);
  },
});

const { isAcceptableTicketExpiry } = await import('../src/durable/notifications-hub');

const secret = 'notification-security-test-secret-32-bytes';
const userId = 'd75020e1-2de4-46e8-b8f1-475d127b51f2';
const securityStamp = 'security-stamp';

function createTestEnv(options: { refuseTickets?: boolean } = {}) {
  const connectionTokens = new Map<string, { userId: string; deviceIdentifier: string | null; expiresAt: number }>();
  const forwardedHubUrls: string[] = [];
  const durableObjectNames: string[] = [];
  const userRow = {
    id: userId,
    email: 'user@example.test',
    name: 'Test User',
    master_password_hint: null,
    master_password_hash: 'hash',
    key: 'key',
    private_key: null,
    public_key: null,
    kdf_type: 0,
    kdf_iterations: 600000,
    kdf_memory: null,
    kdf_parallelism: null,
    security_stamp: securityStamp,
    role: 'user',
    status: 'active',
    verify_devices: 0,
    totp_secret: null,
    totp_recovery_code: null,
    yubikey_key1: null,
    yubikey_key2: null,
    yubikey_key3: null,
    yubikey_key4: null,
    yubikey_key5: null,
    yubikey_nfc: 0,
    api_key: null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  const db = {
    prepare() {
      return {
        bind() {
          return this;
        },
        async first() {
          return userRow;
        },
      };
    },
  } as unknown as D1Database;

  const stub = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const request = new Request(input, init);
      const url = new URL(request.url);
      if (url.pathname === '/internal/ws-token') {
        const body = await request.json() as {
          token: string;
          userId: string;
          deviceIdentifier: string | null;
          expiresAt: number;
        };
        if (options.refuseTickets) return new Response('Invalid websocket connection token', { status: 400 });
        connectionTokens.set(body.token, body);
        return new Response(null, { status: 204 });
      }
      if (url.pathname === '/internal/ws-token/consume') {
        const { token } = await request.json() as { token: string };
        const connection = connectionTokens.get(token);
        connectionTokens.delete(token);
        if (!connection || connection.expiresAt <= Date.now()) return new Response(null, { status: 401 });
        return Response.json(connection);
      }
      forwardedHubUrls.push(request.url);
      return new Response(null, { status: 204 });
    },
  };

  const env = {
    DB: db,
    JWT_SECRET: secret,
    NOTIFICATIONS_HUB: {
      idFromName(name: string) {
        durableObjectNames.push(name);
        return name;
      },
      get() {
        return stub;
      },
    },
  } as unknown as Env;

  return { env, connectionTokens, durableObjectNames, forwardedHubUrls };
}

async function validAccessToken(): Promise<string> {
  return createJWT({
    sub: userId,
    email: 'user@example.test',
    name: 'Test User',
    sstamp: securityStamp,
  }, secret);
}

test('the official clients authenticate the websocket with access_token in the query', async () => {
  const { env, forwardedHubUrls } = createTestEnv();
  const token = await validAccessToken();
  const response = await handleNotificationsHub(new Request(
    `https://vault.example.test/notifications/hub?access_token=${encodeURIComponent(token)}`,
    { headers: { Upgrade: 'websocket' } }
  ), env);

  assert.equal(response.status, 204);
  const forwarded = new URL(forwardedHubUrls[0]);
  assert.equal(forwarded.searchParams.get('nw_uid'), userId);
  // The token does not travel on to the Durable Object.
  assert.equal(forwarded.searchParams.has('access_token'), false);
});

test('a forged or stale access_token in the query is refused', async () => {
  const { env, forwardedHubUrls } = createTestEnv();
  const forged = await createJWT({ sub: userId, email: 'user@example.test', name: 'Test User', sstamp: securityStamp }, 'not-the-server-secret-0123456789abcdef');
  const stale = await createJWT({ sub: userId, email: 'user@example.test', name: 'Test User', sstamp: 'an-old-stamp' }, secret);
  for (const token of [forged, stale, 'not-a-jwt']) {
    const response = await handleNotificationsHub(new Request(
      `https://vault.example.test/notifications/hub?access_token=${encodeURIComponent(token)}`,
      { headers: { Upgrade: 'websocket' } }
    ), env);
    assert.equal(response.status, 401);
  }
  assert.deepEqual(forwardedHubUrls, []);
});

test('Authorization bearer token still authenticates notifications', async () => {
  const { env, forwardedHubUrls } = createTestEnv();
  const token = await validAccessToken();
  const response = await handleNotificationsHub(new Request(
    'https://vault.example.test/notifications/hub',
    { headers: { Authorization: `Bearer ${token}`, Upgrade: 'websocket' } }
  ), env);

  assert.equal(response.status, 204);
  assert.equal(new URL(forwardedHubUrls[0]).searchParams.get('nw_uid'), userId);
});

test('negotiate issues a short-lived one-time websocket connection token', async () => {
  const { env, connectionTokens, forwardedHubUrls } = createTestEnv();
  const accessToken = await validAccessToken();
  const negotiate = await handleNotificationsNegotiate(new Request(
    'https://vault.example.test/notifications/hub/negotiate',
    { method: 'POST', headers: { Authorization: `Bearer ${accessToken}` } }
  ), env);
  const body = await negotiate.json() as { connectionToken: string };
  const stored = connectionTokens.get(body.connectionToken);

  assert.equal(negotiate.status, 200);
  assert.ok(stored);
  assert.ok(stored.expiresAt > Date.now());
  assert.ok(stored.expiresAt <= Date.now() + 60_000);

  const request = () => new Request(
    `https://vault.example.test/notifications/hub?id=${encodeURIComponent(body.connectionToken)}`,
    { headers: { Upgrade: 'websocket' } }
  );
  assert.equal((await handleNotificationsHub(request(), env)).status, 204);
  assert.equal((await handleNotificationsHub(request(), env)).status, 401);
  assert.equal(forwardedHubUrls.length, 1);
});

test('a non-upgrade request does not consume a websocket connection token', async () => {
  const { env, connectionTokens } = createTestEnv();
  const accessToken = await validAccessToken();
  const negotiate = await handleNotificationsNegotiate(new Request(
    'https://vault.example.test/notifications/hub/negotiate',
    { method: 'POST', headers: { Authorization: `Bearer ${accessToken}` } }
  ), env);
  const { connectionToken } = await negotiate.json() as { connectionToken: string };
  const url = `https://vault.example.test/notifications/hub?id=${encodeURIComponent(connectionToken)}`;

  assert.equal((await handleNotificationsHub(new Request(url), env)).status, 426);
  assert.ok(connectionTokens.has(connectionToken));
  assert.equal((await handleNotificationsHub(new Request(url, { headers: { Upgrade: 'websocket' } }), env)).status, 204);
});

test('a forged ticket cannot select or activate a Durable Object', async () => {
  const { env, durableObjectNames } = createTestEnv();
  const response = await handleNotificationsHub(new Request(
    'https://vault.example.test/notifications/hub?id=attacker-controlled.invalid-signature',
    { headers: { Upgrade: 'websocket' } }
  ), env);

  assert.equal(response.status, 401);
  assert.deepEqual(durableObjectNames, []);
});

test('a ticket the hub clock runs behind on is still accepted', () => {
  const now = Date.now();

  assert.equal(isAcceptableTicketExpiry(now + 60_000, now), true);
  assert.equal(isAcceptableTicketExpiry(now + 90_000, now), true, 'the two clocks are a little apart');
  assert.equal(isAcceptableTicketExpiry(now + 121_000, now), false, 'past the skew the hub tolerates');
  assert.equal(isAcceptableTicketExpiry(now, now), false, 'a ticket that is already over');
  assert.equal(isAcceptableTicketExpiry(now - 1, now), false);
});

test('a hub that refuses the ticket answers negotiate with 503', async () => {
  const { env } = createTestEnv({ refuseTickets: true });
  const accessToken = await validAccessToken();
  const warnings: string[] = [];
  const warn = mock.method(console, 'warn', (...args: unknown[]) => {
    warnings.push(args.map((arg) => String(arg)).join(' '));
  });

  try {
    const response = await handleNotificationsNegotiate(new Request(
      'https://vault.example.test/notifications/hub/negotiate',
      {
        method: 'POST',
        headers: { Authorization: `Bearer ${accessToken}`, 'User-Agent': 'Bitwarden/2026.9.0' },
      }
    ), env);
    assert.equal(response.status, 503);
    assert.equal(response.headers.get('Retry-After'), '5');
  } finally {
    warn.mock.restore();
  }

  assert.equal(warnings.length, 1, 'the refusal is logged once');
  assert.ok(warnings[0].includes('notifications.negotiate.refused'));
  assert.ok(warnings[0].includes('Bitwarden/2026.9.0'), 'the client that retries shows up in the log');
  assert.equal(warnings[0].includes(accessToken), false, 'the access token stays out of the log');
});
