// Regression guard for the public password-hint lookup endpoint.
//
// Background: POST /api/accounts/password-hint was an unauthenticated route
// that returned the plaintext masterPasswordHint of any registered account
// when probed with a known email. Same-origin + 1 req/min/IP guards were
// insufficient because the rate limit was per-IP (shared across NAT, VPN,
// corporate networks), so a single attacker could enumerate the entire
// userbase. The endpoint and its rate-limit knobs were removed; this test
// pins the removal so it cannot be silently reintroduced.
import assert from 'node:assert/strict';
import test from 'node:test';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { handlePublicRoute } from '../src/router-public';
import { handleRequest } from '../src/router';
import { LIMITS } from '../src/config/limits';
import * as accountsModule from '../src/handlers/accounts';
import { MemoryD1 } from './memory-d1';
import type { Env } from '../src/types';

const VAULT_ORIGIN = 'https://vault.example.test';
const ENDPOINT_PATH = '/api/accounts/password-hint';

function buildEnv(): Env {
  return {
    DB: new MemoryD1(),
    JWT_SECRET: 'regression-test-secret-32-bytes-min!',
  } as unknown as Env;
}

function buildPasswordHintRequest(): Request {
  return new Request(`${VAULT_ORIGIN}${ENDPOINT_PATH}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Origin': VAULT_ORIGIN,
    },
    body: JSON.stringify({ email: 'victim@example.test' }),
  });
}

test('public router no longer routes /api/accounts/password-hint', async () => {
  const response = await handlePublicRoute(
    buildPasswordHintRequest(),
    buildEnv(),
    ENDPOINT_PATH,
    'POST',
    async () => null,
  );
  assert.equal(response, null, 'public router must not recognise the removed path');
});

test('top-level router never discloses a hint for /api/accounts/password-hint', async () => {
  // The endpoint is gone. The production behavior for an unauthenticated
  // probe is 401 (no bearer token) — the public router returns null for the
  // removed path and the request falls through to the auth check. Both 401
  // and 404 are acceptable; the only unacceptable outcome is 200 with the
  // historical response shape, because that is the user-enumeration leak.
  const response = await handleRequest(buildPasswordHintRequest(), buildEnv());
  assert.notEqual(response.status, 200, 'removed endpoint must not return 200');
  const body = await response.text();
  assert.ok(
    !body.includes('masterPasswordHint') && !body.includes('passwordHint'),
    `response body must not leak the historical response shape; got status=${response.status} body=${body}`,
  );
});

test('handler export handleGetPasswordHint is gone', () => {
  assert.equal(
    typeof (accountsModule as unknown as { handleGetPasswordHint?: unknown }).handleGetPasswordHint,
    'undefined',
    'handleGetPasswordHint must not be re-exported from handlers/accounts',
  );
});

test('LIMITS no longer exposes passwordHint rate knobs', () => {
  const rateLimit = LIMITS.rateLimit as unknown as Record<string, unknown>;
  assert.equal(
    typeof rateLimit.passwordHintRequestsPerMinute,
    'undefined',
    'passwordHintRequestsPerMinute must be removed',
  );
  assert.equal(
    typeof rateLimit.passwordHintRequestsPerHour,
    'undefined',
    'passwordHintRequestsPerHour must be removed',
  );
});
