// Contract test for the public SSO verified-domains route.
//
// Background: the SSO page of the official clients (web vault, extension,
// desktop) calls POST /api/organizations/domain/sso/verified without a login
// to ask which organizations claimed the domain of the email being typed
// (OrgDomainApiService.getVerifiedOrgDomainsByEmail; Android uses
// UnauthenticatedOrganizationApi). NodeWarden had no route for it, so the
// request fell through to the router that requires a login, answered 401, and
// the clients showed an error on the SSO screen. The route answers 200 with an
// empty list, the same as the official server does when no organization
// claimed the domain; the client then lets the user type the identifier.
import assert from 'node:assert/strict';
import test from 'node:test';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { handleRequest } from '../src/router';
import { MemoryD1 } from './memory-d1';
import type { Env } from '../src/types';

const VAULT_ORIGIN = 'https://vault.example.test';
const ENDPOINT_PATH = '/api/organizations/domain/sso/verified';
const EMPTY_LIST = { data: [], object: 'list', continuationToken: null };

function buildEnv(): Env {
  return {
    DB: new MemoryD1(),
    JWT_SECRET: 'regression-test-secret-32-bytes-min!',
  } as unknown as Env;
}

function buildVerifiedRequest(body?: string, method: string = 'POST'): Request {
  return new Request(`${VAULT_ORIGIN}${ENDPOINT_PATH}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      'CF-Connecting-IP': '203.0.113.9',
      Origin: VAULT_ORIGIN,
    },
    body: method === 'GET' ? undefined : (body ?? ''),
  });
}

test('the verified domains route answers without a login', async () => {
  const response = await handleRequest(
    buildVerifiedRequest(JSON.stringify({ email: 'someone@minhluc.info' })),
    buildEnv(),
  );
  assert.equal(response.status, 200, await response.clone().text());
  assert.deepEqual(await response.json(), EMPTY_LIST);
});

test('the verified domains route ignores the body it never reads', async () => {
  for (const body of ['', '{not json']) {
    const response = await handleRequest(buildVerifiedRequest(body), buildEnv());
    assert.equal(response.status, 200, `body ${JSON.stringify(body)}: ${await response.clone().text()}`);
    assert.deepEqual(await response.json(), EMPTY_LIST);
  }
});

test('the verified domains route only answers POST', async () => {
  const response = await handleRequest(buildVerifiedRequest(undefined, 'GET'), buildEnv());
  assert.notEqual(response.status, 200, 'a GET must not reach the verified domains route');
});
