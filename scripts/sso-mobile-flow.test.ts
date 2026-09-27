// End-to-end handler test for the official Bitwarden mobile SSO login flow.
//
// Flow under test (src/handlers/identity.ts):
//   1. GET  /api/sso/prevalidate?domainHint=...   (mobile sends domainHint)
//   2. GET  /identity/connect/authorize           (client_id=mobile, PKCE S256,
//                                                  redirect_uri=bitwarden:// or loopback)
//   3. GET  /auth/sso/callback                    (IdP redirects back; server verifies the
//                                                  RS256 id_token against the IdP JWKS, then
//                                                  hands the client a short-lived code through
//                                                  its redirect URI)
//   4. POST /identity/connect/token               (grant_type=authorization_code; server checks
//                                                  PKCE + single-use, then issues vault tokens)
//
// The IdP (Zitadel-style OIDC provider) is faked in-process: discovery document,
// JWKS backed by a real RSA key pair, and a token endpoint that enforces client
// Basic auth. D1 is faked by a tiny in-memory SQL shim (MemoryD1) that supports
// the statements this flow executes.
import assert from 'node:assert/strict';
import test from 'node:test';

import { installTestGlobals } from './test-env';
installTestGlobals();

// tsx on Node 18 executes this file in a context without the WebCrypto global
// that the worker runtime (and src/) relies on — see scripts/test-env.ts.


import {
  handleSsoPrevalidate,
  handleSsoAuthorize,
  handleSsoCallback,
  handleToken,
} from '../src/handlers/identity';
import { handlePublicRoute } from '../src/router-public';
import { createPkcePair } from '../src/lib/oidc';
import { StorageService } from '../src/services/storage';
import { verifyJWT } from '../src/utils/jwt';
import type { Env, User } from '../src/types';

// In-memory D1 shim lives in scripts/memory-d1.ts (shared with other tests).
import { MemoryD1 } from './memory-d1';

// ---------------------------------------------------------------------------
// Fake OIDC identity provider
// ---------------------------------------------------------------------------

interface TokenPostRecord {
  authorization: string | null;
  body: Record<string, string>;
}

function base64UrlEncodeJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8')
    .toString('base64')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '');
}

class FakeIdp {
  static readonly issuer = 'https://idp.example.test';
  static readonly clientId = 'nodewarden-sso-test';
  static readonly clientSecret = 'sso-client-secret-for-tests';
  static readonly idpCode = 'idp-authorization-code-0123456789abcdef';

  readonly discoveryGets: string[] = [];
  readonly jwksGets: string[] = [];
  readonly tokenPosts: TokenPostRecord[] = [];

  // A real IdP binds the authorize-time nonce to its code and embeds it in the
  // id_token. Tests register the authorize redirect (visitAuthorize) so the
  // token endpoint can mint the id_token with the correct nonce claim.
  private pendingNonce: string | null = null;

  // id_token claims served by the fake token endpoint; tests may adjust these
  // to exercise negative paths.
  subject = 'idp-subject-4f2b8c1a';
  email = 'user@example.test';
  private readonly kid = 'test-signing-key';
  // One key pair per process: oidc.ts caches the JWKS per issuer for an hour,
  // so every FakeIdp instance must sign with the same key the cache holds.
  private static keyPair: CryptoKeyPair | null = null;

  private async keys(): Promise<CryptoKeyPair> {
    if (!FakeIdp.keyPair) {
      // modulusLength/publicExponent are required by Node's WebCrypto (the
      // Workers runtime is more lenient) and accepted by the spec.
      FakeIdp.keyPair = (await crypto.subtle.generateKey(
        {
          name: 'RSASSA-PKCS1-v1_5',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256',
        },
        true,
        ['sign', 'verify']
      )) as CryptoKeyPair;
    }
    return FakeIdp.keyPair;
  }

  private async publicJwk(): Promise<JsonWebKey & { kid: string }> {
    const { publicKey } = await this.keys();
    const jwk = (await crypto.subtle.exportKey('jwk', publicKey)) as JsonWebKey & { kid: string };
    delete jwk.key_ops;
    delete (jwk as { ext?: boolean }).ext;
    return { ...jwk, kid: this.kid };
  }

  async mintIdToken(claims: {
    nonce: string;
    sub: string;
    email: string;
    aud?: string;
    iss?: string;
    expirySeconds?: number;
  }): Promise<string> {
    const { privateKey } = await this.keys();
    const header = { alg: 'RS256', kid: this.kid };
    const payload = {
      iss: claims.iss ?? FakeIdp.issuer,
      aud: claims.aud ?? FakeIdp.clientId,
      sub: claims.sub,
      email: claims.email,
      email_verified: true,
      name: claims.email.split('@')[0],
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (claims.expirySeconds ?? 300),
      nonce: claims.nonce,
    };
    const signingInput = `${base64UrlEncodeJson(header)}.${base64UrlEncodeJson(payload)}`;
    const signature = await crypto.subtle.sign(
      'RSASSA-PKCS1-v1_5',
      privateKey,
      new TextEncoder().encode(signingInput)
    );
    const signatureSegment = Buffer.from(signature)
      .toString('base64')
      .replaceAll('+', '-')
      .replaceAll('/', '_')
      .replaceAll('=', '');
    return `${signingInput}.${signatureSegment}`;
  }

  visitAuthorize(authorizeUrl: URL): void {
    this.pendingNonce = authorizeUrl.searchParams.get('nonce');
  }

  install(): () => void {
    const originalFetch = globalThis.fetch;
    const idp = this;
    const stub = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const request = new Request(input, init);
      if (new URL(request.url).origin === new URL(FakeIdp.issuer).origin) {
        return idp.handle(request);
      }
      throw new Error(`FakeIdp: unexpected outbound request to ${request.url}`);
    };
    globalThis.fetch = stub as typeof fetch;
    return () => {
      globalThis.fetch = originalFetch;
    };
  }

  private async handle(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === '/.well-known/openid-configuration') {
      this.discoveryGets.push(request.url);
      return Response.json({
        issuer: FakeIdp.issuer,
        authorization_endpoint: `${FakeIdp.issuer}/oauth2/v1/authorize`,
        token_endpoint: `${FakeIdp.issuer}/oauth2/v1/token`,
        jwks_uri: `${FakeIdp.issuer}/oauth2/v1/keys`,
      });
    }
    if (url.pathname === '/oauth2/v1/keys') {
      this.jwksGets.push(request.url);
      return Response.json({ keys: [await this.publicJwk()] });
    }
    if (url.pathname === '/oauth2/v1/token' && request.method === 'POST') {
      const body = Object.fromEntries(new URLSearchParams(await request.text()).entries());
      this.tokenPosts.push({ authorization: request.headers.get('Authorization'), body });
      const expectedAuth = `Basic ${btoa(`${FakeIdp.clientId}:${FakeIdp.clientSecret}`)}`;
      if (request.headers.get('Authorization') !== expectedAuth) {
        return Response.json({ error: 'invalid_client' }, { status: 401 });
      }
      if (body.grant_type !== 'authorization_code' || body.code !== FakeIdp.idpCode) {
        return Response.json({ error: 'invalid_grant' }, { status: 400 });
      }
      return Response.json({
        id_token: await this.mintIdToken({ nonce: this.pendingNonce ?? '', sub: this.subject, email: this.email }),
        access_token: 'idp-access-token',
        refresh_token: 'idp-refresh-token',
        token_type: 'Bearer',
      });
    }
    return Response.json({ error: 'not_found' }, { status: 404 });
  }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const JWT_SECRET = 'sso-mobile-flow-test-secret-0123456789';
const VAULT_ORIGIN = 'https://vault.example.test';
const DEEPLINK_REDIRECT = 'bitwarden://sso-callback';

interface ClientRequest {
  clientId?: string;
  redirectUri?: string;
  codeChallengeMethod?: string;
  email?: string;
}

interface TestContext {
  env: Env;
  storage: StorageService;
  idp: FakeIdp;
  restoreFetch: () => void;
  user: User;
}

function buildUser(overrides: Partial<User> = {}): User {
  const now = new Date().toISOString();
  return {
    id: overrides.id ?? '0f7d2a10-1111-4111-8111-111111111111',
    email: overrides.email ?? 'user@example.test',
    name: 'SSO Test User',
    masterPasswordHint: null,
    masterPasswordHash: 'stored-master-password-hash',
    key: 'encrypted-user-key',
    privateKey: 'encrypted-private-key',
    publicKey: 'public-key',
    kdfType: 0,
    kdfIterations: 600000,
    kdfMemory: null,
    kdfParallelism: null,
    securityStamp: 'security-stamp-sso',
    role: 'user',
    status: 'active',
    verifyDevices: false,
    totpSecret: null,
    totpRecoveryCode: null,
    yubikeyKey1: null,
    yubikeyKey2: null,
    yubikeyKey3: null,
    yubikeyKey4: null,
    yubikeyKey5: null,
    yubikeyNfc: false,
    apiKey: null,
    ssoSubject: 'idp-subject-4f2b8c1a',
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
}

async function setup(overrides: { user?: Partial<User> } = {}): Promise<TestContext> {
  const db = new MemoryD1();
  const idp = new FakeIdp();
  const restoreFetch = idp.install();

  const env = {
    DB: db as unknown as D1Database,
    JWT_SECRET: JWT_SECRET,
    OIDC_ISSUER: FakeIdp.issuer,
    OIDC_CLIENT_ID: FakeIdp.clientId,
    OIDC_CLIENT_SECRET: FakeIdp.clientSecret,
  } as unknown as Env;

  const storage = new StorageService(env.DB);
  const user = buildUser(overrides.user);
  await storage.saveUser(user);

  return { env, storage, idp, restoreFetch, user };
}

function getStateCookie(response: Response): { raw: string; sealed: string } | null {
  const cookies = typeof response.headers.getSetCookie === 'function'
    ? response.headers.getSetCookie()
    : [response.headers.get('Set-Cookie') ?? ''].filter(Boolean);
  const entry = cookies.find((cookie) => cookie.startsWith('nw_sso_state='));
  if (!entry) return null;
  const raw = entry.slice('nw_sso_state='.length).split(';')[0];
  return { raw, sealed: decodeURIComponent(raw) };
}

async function startMobileAuthorize(
  env: Env,
  pair: { verifier: string; challenge: string },
  request: ClientRequest = {}
): Promise<Response> {
  const params = new URLSearchParams({
    client_id: request.clientId ?? 'mobile',
    redirect_uri: request.redirectUri ?? DEEPLINK_REDIRECT,
    state: 'client-state-123',
    code_challenge: pair.challenge,
    code_challenge_method: request.codeChallengeMethod ?? 'S256',
    ...(request.email === undefined ? {} : { email: request.email }),
  });
  return handleSsoAuthorize(
    new Request(`${VAULT_ORIGIN}/identity/connect/authorize?${params.toString()}`),
    env
  );
}

interface AuthorizeCallbackResult {
  authorize: Response;
  callback: Response;
  location: URL;
}

/** Runs steps 2-3 (authorize + IdP callback) and returns the client-facing code redirect. */
async function runAuthorizeAndCallback(
  idp: FakeIdp,
  env: Env,
  pair: { verifier: string; challenge: string },
  request: ClientRequest = {}
): Promise<AuthorizeCallbackResult> {
  const authorize = await startMobileAuthorize(env, pair, request);
  assert.equal(authorize.status, 302, 'authorize must redirect to the IdP');

  const authorizeUrl = new URL(authorize.headers.get('Location')!);
  // The user agent would now hit the IdP authorization endpoint; the IdP
  // binds the nonce to the authorization code it is about to issue.
  idp.visitAuthorize(authorizeUrl);
  const cookie = getStateCookie(authorize);
  assert.ok(cookie, 'authorize must set the SSO state cookie');

  const callback = await handleSsoCallback(
    new Request(
      `${VAULT_ORIGIN}/auth/sso/callback?code=${FakeIdp.idpCode}&state=${authorizeUrl.searchParams.get('state')}`,
      { headers: { Cookie: `nw_sso_state=${cookie.raw}` } }
    ),
    env
  );
  const location = new URL(callback.headers.get('Location') ?? 'about:blank', VAULT_ORIGIN);
  return { authorize, callback, location };
}

async function exchangeCode(
  env: Env,
  code: string,
  pair: { verifier: string; challenge: string },
  overrides: Record<string, string> = {}
): Promise<Response> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: 'mobile',
    code,
    code_verifier: pair.verifier,
    redirect_uri: DEEPLINK_REDIRECT,
    deviceIdentifier: 'mobile-device-identifier-abc',
    deviceName: 'Pixel Test Device',
    deviceType: '0',
    ...overrides,
  });
  return handleToken(
    new Request(`${VAULT_ORIGIN}/identity/connect/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'CF-Connecting-IP': '203.0.113.10',
      },
      body: body.toString(),
    }),
    env
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test('prevalidate announces SSO availability for the mobile domainHint parameter', async (t) => {
  const ctx = await setup();
  t.after(() => ctx.restoreFetch());
  const { env } = ctx;

  const get = await handleSsoPrevalidate(
    new Request(`${VAULT_ORIGIN}/api/sso/prevalidate?domainHint=my-organization`),
    env
  );
  assert.equal(get.status, 200);
  const getBody = (await get.json()) as { ssoAvailable: boolean; token: string };
  assert.equal(getBody.ssoAvailable, true);
  assert.ok(getBody.token.length > 0);

  const post = await handleSsoPrevalidate(
    new Request(`${VAULT_ORIGIN}/api/sso/prevalidate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domainHint: 'my-organization' }),
    }),
    env
  );
  assert.equal(post.status, 200);
  const postBody = (await post.json()) as { ssoAvailable: boolean };
  assert.equal(postBody.ssoAvailable, true);
});

test('authorize rejects invalid client requests but accepts the mobile loopback redirect', async (t) => {
  const ctx = await setup();
  t.after(() => ctx.restoreFetch());
  const pair = await createPkcePair();

  const unknownClient = await startMobileAuthorize(ctx.env, pair, { clientId: 'workspace' });
  assert.equal(unknownClient.status, 400);

  const plainPkce = await startMobileAuthorize(ctx.env, pair, { codeChallengeMethod: 'plain' });
  assert.equal(plainPkce.status, 400);

  const foreignRedirect = await startMobileAuthorize(ctx.env, pair, {
    redirectUri: 'https://evil.example.test/callback',
  });
  assert.equal(foreignRedirect.status, 400);

  const loopback = await startMobileAuthorize(ctx.env, pair, {
    redirectUri: 'http://127.0.0.1:8080/callback',
  });
  assert.equal(loopback.status, 302);
  const loopbackAuthorizeUrl = new URL(loopback.headers.get('Location')!);
  assert.equal(loopbackAuthorizeUrl.pathname, '/oauth2/v1/authorize');
  assert.equal(loopbackAuthorizeUrl.searchParams.get('code_challenge_method'), 'S256');
});

test('backslash redirect_uri variants are rejected (open-redirect regression)', async (t) => {
  const ctx = await setup();
  t.after(() => ctx.restoreFetch());
  const pair = await createPkcePair();

  // NW-SSO-REDIRECT-1: "/\evil.com" starts with a single slash so it used to
  // pass the relative-shape check, then folded off-origin at the callback,
  // leaking the freshly minted code to an attacker host.
  for (const redirectUri of ['/%5Cevil.example.test/cb', '/%2Fevil.example.test', '\\\\evil.example.test']) {
    const response = await startMobileAuthorize(ctx.env, pair, {
      redirectUri: decodeURIComponent(redirectUri),
    });
    assert.equal(response.status, 400, `redirect_uri ${redirectUri} must be rejected`);
  }

  // Legitimate relative and same-origin redirects keep working.
  const relative = await startMobileAuthorize(ctx.env, pair, { redirectUri: '/sso-connector.html' });
  assert.equal(relative.status, 302);
  const sameOrigin = await startMobileAuthorize(ctx.env, pair, {
    redirectUri: 'https://vault.example.test/sso-connector.html',
  });
  assert.equal(sameOrigin.status, 302);
});

test('callback sink refuses off-origin redirect even for a sealed backslash URI', async (t) => {
  const ctx = await setup();
  t.after(() => ctx.restoreFetch());
  const pair = await createPkcePair();

  // Defense-in-depth: hand-craft a validly sealed client_sso state whose
  // clientRedirectUri is the backslash variant, as if an older build had
  // accepted it at authorize. The callback must refuse to redirect off-origin.
  const nonce = 'sink-test-nonce';
  const statePayload = {
    state: 'sink-test-state',
    verifier: pair.verifier,
    nonce,
    exp: Date.now() + 60_000,
    purpose: 'client_sso' as const,
    clientId: 'mobile',
    clientState: 'client-state-123',
    clientRedirectUri: '/\\evil.example.test/cb',
    clientCodeChallenge: pair.challenge,
    clientCodeChallengeMethod: 'S256',
  };
  const body = Buffer.from(JSON.stringify(statePayload), 'utf8')
    .toString('base64')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '');
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body));
  const sealed = `${body}.${Buffer.from(signature).toString('base64').replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')}`;

  ctx.idp.visitAuthorize(new URL(`https://idp.example.test/authorize?nonce=${nonce}`));
  const callback = await handleSsoCallback(
    new Request(`${VAULT_ORIGIN}/auth/sso/callback?code=${FakeIdp.idpCode}&state=${statePayload.state}`, {
      headers: { Cookie: `nw_sso_state=${encodeURIComponent(sealed)}` },
    }),
    ctx.env
  );
  assert.equal(callback.status, 302);
  const location = callback.headers.get('Location')!;
  assert.ok(!/evil\.example\.test/.test(location), `must not redirect off-origin: ${location}`);
  assert.ok(
    location.startsWith('/?sso_error='),
    `must fall back to the relative web error redirect: ${location}`
  );
});

test('full mobile SSO login: authorize → IdP callback → deeplink code → token exchange', async (t) => {
  const ctx = await setup();
  t.after(() => ctx.restoreFetch());
  const pair = await createPkcePair();

  const { authorize, callback, location } = await runAuthorizeAndCallback(ctx.idp, ctx.env, pair);

  // Authorize redirect targets the IdP authorization endpoint. The server acts
  // as the OIDC client here, so the URL carries the server's own PKCE pair;
  // the client's challenge is sealed into the state (proven by the token
  // exchange's verifier check further down).
  const authorizeUrl = new URL(authorize.headers.get('Location')!);
  assert.equal(authorizeUrl.origin, new URL(FakeIdp.issuer).origin);
  assert.equal(authorizeUrl.searchParams.get('client_id'), FakeIdp.clientId);
  assert.equal(authorizeUrl.searchParams.get('redirect_uri'), `${VAULT_ORIGIN}/auth/sso/callback`);
  assert.equal(authorizeUrl.searchParams.get('response_type'), 'code');
  assert.ok(authorizeUrl.searchParams.get('nonce'));
  assert.ok(/^[A-Za-z0-9_-]{43}$/.test(authorizeUrl.searchParams.get('code_challenge') ?? ''));
  assert.equal(authorizeUrl.searchParams.get('code_challenge_method'), 'S256');

  // Callback hands the code back to the mobile app via its deeplink.
  assert.equal(callback.status, 302, 'callback must redirect');
  assert.equal(`${location.protocol}//${location.host}${location.pathname}`, DEEPLINK_REDIRECT);
  assert.equal(location.searchParams.get('state'), 'client-state-123');
  assert.equal(location.searchParams.get('scope'), 'api offline_access');
  assert.equal(location.searchParams.get('iss'), VAULT_ORIGIN);
  const serverCode = location.searchParams.get('code') ?? '';
  assert.ok(/^[A-Za-z0-9_-]{40,}$/.test(serverCode), 'code must be a fresh base64url value');

  // The server consumed its state cookie.
  const cleared = getStateCookie(callback);
  assert.ok(cleared && cleared.sealed === '', 'callback must clear the SSO state cookie');

  // The IdP token exchange used client Basic auth and the server redirect_uri.
  assert.equal(ctx.idp.tokenPosts.length, 1);
  const tokenPost = ctx.idp.tokenPosts[0];
  assert.equal(tokenPost.authorization, `Basic ${btoa(`${FakeIdp.clientId}:${FakeIdp.clientSecret}`)}`);
  assert.equal(tokenPost.body.grant_type, 'authorization_code');
  assert.equal(tokenPost.body.code, FakeIdp.idpCode);
  assert.equal(tokenPost.body.redirect_uri, `${VAULT_ORIGIN}/auth/sso/callback`);
  assert.ok(tokenPost.body.code_verifier, 'server must send its PKCE verifier to the IdP');

  // Mobile app exchanges the deeplink code for vault tokens.
  const token = await exchangeCode(ctx.env, serverCode, pair);
  assert.equal(token.status, 200);
  const payload = (await token.json()) as Record<string, unknown>;
  assert.equal(payload.token_type, 'Bearer');
  assert.equal(payload.scope, 'api offline_access');
  assert.ok(payload.refresh_token, 'mobile grant must receive a refresh token');
  assert.equal(payload.Key, ctx.user.key);
  assert.equal(payload.PrivateKey, ctx.user.privateKey);
  assert.equal(payload.Kdf, 0);
  assert.equal(payload.KdfIterations, 600000);

  // Access token is a bound JWT for this user + device.
  const access = await verifyJWT(payload.access_token as string, JWT_SECRET);
  assert.ok(access);
  assert.equal(access!.sub, ctx.user.id);
  assert.equal(access!.did, 'mobile-device-identifier-abc');

  // Refresh token is persisted for the mobile client type and device.
  const record = await ctx.storage.getRefreshTokenRecord(payload.refresh_token as string);
  assert.ok(record);
  assert.equal(record!.userId, ctx.user.id);
  assert.equal(record!.deviceIdentifier, 'mobile-device-identifier-abc');
  assert.equal(record!.clientType, 'mobile');

  // Device is registered with a session stamp that matches the access token.
  const device = await ctx.storage.getDevice(ctx.user.id, 'mobile-device-identifier-abc');
  assert.ok(device);
  assert.ok(device!.sessionStamp);
  assert.equal(access!.dstamp, device!.sessionStamp);
});

test('authorization codes are single-use: replay is rejected with invalid_grant', async (t) => {
  const ctx = await setup();
  t.after(() => ctx.restoreFetch());
  const pair = await createPkcePair();

  const { location } = await runAuthorizeAndCallback(ctx.idp, ctx.env, pair);
  const code = location.searchParams.get('code')!;

  const first = await exchangeCode(ctx.env, code, pair);
  assert.equal(first.status, 200);

  const replay = await exchangeCode(ctx.env, code, pair);
  assert.equal(replay.status, 400);
  const replayBody = (await replay.json()) as { error: string };
  assert.equal(replayBody.error, 'invalid_grant');
});

test('PKCE verifier mismatch and redirect_uri mismatch are rejected', async (t) => {
  const ctx = await setup();
  t.after(() => ctx.restoreFetch());
  const pair = await createPkcePair();
  const wrongPair = await createPkcePair();

  const { location } = await runAuthorizeAndCallback(ctx.idp, ctx.env, pair);
  const code = location.searchParams.get('code')!;

  const badVerifier = await exchangeCode(ctx.env, code, wrongPair);
  assert.equal(badVerifier.status, 400);
  assert.equal(((await badVerifier.json()) as { error: string }).error, 'invalid_grant');

  const badRedirect = await exchangeCode(ctx.env, code, pair, { redirect_uri: 'bitwarden://other' });
  assert.equal(badRedirect.status, 400);
  assert.equal(((await badRedirect.json()) as { error: string }).error, 'invalid_grant');
});

test('unlinked IdP subject is denied through the client code channel', async (t) => {
  const ctx = await setup({
    user: { id: '0f7d2a10-2222-4222-8222-222222222222', ssoSubject: null },
  });
  t.after(() => ctx.restoreFetch());
  const pair = await createPkcePair();

  const { location } = await runAuthorizeAndCallback(ctx.idp, ctx.env, pair);
  assert.equal(`${location.protocol}//${location.host}${location.pathname}`, DEEPLINK_REDIRECT);
  // Official clients only read code/state: failure is signalled as code=clientState,
  // which the token endpoint then rejects.
  assert.equal(location.searchParams.get('code'), 'client-state-123');
  assert.equal(location.searchParams.get('state'), 'client-state-123');
});

test('IdP email mismatch with the linked account is denied', async (t) => {
  const ctx = await setup();
  t.after(() => ctx.restoreFetch());
  const pair = await createPkcePair();

  const { location } = await runAuthorizeAndCallback(ctx.idp, ctx.env, pair, {
    email: 'someone-else@example.test',
  });
  assert.equal(`${location.protocol}//${location.host}${location.pathname}`, DEEPLINK_REDIRECT);
  assert.equal(location.searchParams.get('code'), 'client-state-123');
});

test('password grant stays closed for SSO-linked accounts (mobile fallback protection)', async (t) => {
  const ctx = await setup();
  t.after(() => ctx.restoreFetch());

  const body = new URLSearchParams({
    grant_type: 'password',
    username: ctx.user.email,
    password: 'any-master-password-hash',
    client_id: 'mobile',
    deviceIdentifier: 'mobile-device-identifier-abc',
    deviceName: 'Pixel Test Device',
  });
  const response = await handleToken(
    new Request(`${VAULT_ORIGIN}/identity/connect/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'CF-Connecting-IP': '203.0.113.10',
      },
      body: body.toString(),
    }),
    ctx.env
  );
  assert.equal(response.status, 400);
  const payload = (await response.json()) as { error: string };
  assert.equal(payload.error, 'sso_required');
});

test('router serves SSO prevalidate on every official client path', async (t) => {
  const ctx = await setup();
  t.after(() => ctx.restoreFetch());

  // Regression: the official Android/iOS apps call the IdentityServer path
  // (/identity/sso/prevalidate). A missing alias used to fall through to the
  // authenticated API fallback and answered 401 before login.
  const limiter = async () => null;
  const ssoPaths = ['/identity/sso/prevalidate', '/api/sso/prevalidate', '/sso/prevalidate'];
  for (const path of ssoPaths) {
    const response = await handlePublicRoute(
      new Request(`${VAULT_ORIGIN}${path}?domainHint=minhluc`),
      ctx.env,
      path,
      'GET',
      limiter
    );
    assert.ok(response, `${path} must be routed`);
    assert.equal(response.status, 200, `${path} must answer 200`);
    const body = (await response.json()) as { ssoAvailable: boolean; object: string };
    assert.equal(body.ssoAvailable, true, `${path} must report SSO availability`);
    assert.equal(body.object, 'ssoPrevalidate');
  }

  // POST with a JSON body (the variant some clients send) works on all aliases.
  for (const path of ssoPaths) {
    const response = await handlePublicRoute(
      new Request(`${VAULT_ORIGIN}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domainHint: 'minhluc' }),
      }),
      ctx.env,
      path,
      'POST',
      limiter
    );
    assert.ok(response, `${path} POST must be routed`);
    assert.equal(response.status, 200, `${path} POST must answer 200`);
  }

  // Unrouted /identity paths still fall through to the authenticated router.
  const fallthrough = await handlePublicRoute(
    new Request(`${VAULT_ORIGIN}/identity/sso/unknown`),
    ctx.env,
    '/identity/sso/unknown',
    'GET',
    limiter
  );
  assert.equal(fallthrough, null);
});
