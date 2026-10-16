// Official Bitwarden Android 2026.9.1 calls GET /api/account/billing/vnext/subscription
// after every vault unlock. The pre-existing 404 left a retrofit2.HttpException in
// the user's flight recorder; NodeWarden has no Stripe integration so we serve a
// minimal-but-valid BitwardenSubscriptionResponseJson instead and let the SDK
// stay on its "active" happy path.
import assert from 'node:assert/strict';
import test from 'node:test';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { MemoryD1 } from './memory-d1';
import type { Env } from '../src/types';

const USER_ID = '00000000-0000-4000-8000-000000000042';

function env(): Env {
  return { DB: new MemoryD1() } as unknown as Env;
}

function buildRequest(): Request {
  return new Request('https://vault.example.test/api/account/billing/vnext/subscription', {
    method: 'GET',
  });
}

test('returns 200 with a valid BitwardenSubscriptionResponseJson shape', async () => {
  const response = await handleAuthenticatedRoute(
    buildRequest(),
    env(),
    USER_ID,
    { id: USER_ID } as never,
    '/api/account/billing/vnext/subscription',
    'GET'
  );
  assert.ok(response, 'route must be handled');
  assert.equal(response.status, 200);
  const body = (await response.json()) as Record<string, unknown>;

  // Mirror BitwardenSubscriptionResponseJson fields exactly.
  assert.equal(body.status, 'active');
  const cart = body.cart as Record<string, unknown>;
  assert.ok(cart, 'cart required');
  assert.ok(cart.passwordManager, 'cart.passwordManager required');
  const seats = (cart.passwordManager as Record<string, unknown>).seats as Record<string, unknown>;
  assert.ok(seats, 'cart.passwordManager.seats required');
  assert.equal(typeof seats.quantity, 'number');
  assert.equal(typeof seats.cost, 'number');
  assert.equal(cart.cadence, 'annually');
  assert.equal(typeof cart.estimatedTax, 'number');
  assert.equal(body.storage, null);
  assert.equal(body.cancelAt, null);
  assert.equal(body.canceled, null);
  assert.equal(body.nextCharge, null);
  assert.equal(body.suspension, null);
  assert.equal(body.gracePeriod, null);
});

test('non-GET methods on this route are not silently handled', async () => {
  // We deliberately do not accept POST/PUT/DELETE — only GET is implemented.
  const response = await handleAuthenticatedRoute(
    new Request('https://vault.example.test/api/account/billing/vnext/subscription', {
      method: 'POST',
    }),
    env(),
    USER_ID,
    { id: USER_ID } as never,
    '/api/account/billing/vnext/subscription',
    'POST'
  );
  // Router returns null for unhandled methods → caller falls through to 404,
  // matching the upstream behavior for unsupported billing verbs.
  assert.equal(response, null);
});