import type { Env } from '../types';

// Minimal OIDC relying-party helpers for the Zitadel SSO login flow.
// Scope: authorization code + PKCE (S256), RS256 id_token verification via
// the issuer JWKS. No external dependencies — Web Crypto only.

export interface OidcConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
}

export interface OidcDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
}

export interface OidcIdTokenClaims {
  sub: string;
  email: string;
  emailVerified: boolean;
  name: string | null;
}

/** Returns the OIDC config when all three env values are present, else null. */
export function getOidcConfig(env: Env): OidcConfig | null {
  const issuer = String(env.OIDC_ISSUER || '').trim().replace(/\/+$/, '');
  const clientId = String(env.OIDC_CLIENT_ID || '').trim();
  const clientSecret = String(env.OIDC_CLIENT_SECRET || '').trim();
  if (!issuer || !clientId || !clientSecret) return null;
  return { issuer, clientId, clientSecret };
}

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

const discoveryCache = new Map<string, CacheEntry<OidcDiscovery>>();
const jwksCache = new Map<string, CacheEntry<JsonWebKey[]>>();
const CACHE_TTL_MS = 60 * 60 * 1000;

export async function discoverOidc(issuer: string): Promise<OidcDiscovery> {
  const cached = discoveryCache.get(issuer);
  if (cached && cached.expiresAt > Date.now()) return cached.value;

  const response = await fetch(`${issuer}/.well-known/openid-configuration`, {
    headers: { Accept: 'application/json' },
  });
  if (!response.ok) {
    throw new Error(`OIDC discovery failed (${response.status})`);
  }
  const body = (await response.json()) as Partial<OidcDiscovery>;
  if (!body.authorization_endpoint || !body.token_endpoint || !body.jwks_uri) {
    throw new Error('OIDC discovery document is incomplete');
  }
  const value: OidcDiscovery = {
    issuer: String(body.issuer || issuer),
    authorization_endpoint: body.authorization_endpoint,
    token_endpoint: body.token_endpoint,
    jwks_uri: body.jwks_uri,
  };
  discoveryCache.set(issuer, { value, expiresAt: Date.now() + CACHE_TTL_MS });
  return value;
}

async function fetchJwks(jwksUri: string): Promise<JsonWebKey[]> {
  const cached = jwksCache.get(jwksUri);
  if (cached && cached.expiresAt > Date.now()) return cached.value;

  const response = await fetch(jwksUri, { headers: { Accept: 'application/json' } });
  if (!response.ok) throw new Error(`JWKS fetch failed (${response.status})`);
  const body = (await response.json()) as { keys?: JsonWebKey[] };
  const keys = Array.isArray(body.keys) ? body.keys : [];
  jwksCache.set(jwksUri, { value: keys, expiresAt: Date.now() + CACHE_TTL_MS });
  return keys;
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

function base64UrlDecode(value: string): Uint8Array {
  const padded = value.replaceAll('-', '+').replaceAll('_', '/');
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function decodeJsonSegment<T>(segment: string): T {
  return JSON.parse(new TextDecoder().decode(base64UrlDecode(segment))) as T;
}

export interface PkcePair {
  verifier: string;
  challenge: string;
}

export async function createPkcePair(): Promise<PkcePair> {
  const verifier = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return { verifier, challenge: base64UrlEncode(new Uint8Array(digest)) };
}

export function buildAuthorizeUrl(
  config: OidcConfig,
  discovery: OidcDiscovery,
  params: { redirectUri: string; state: string; nonce: string; challenge: string }
): string {
  const url = new URL(discovery.authorization_endpoint);
  url.searchParams.set('client_id', config.clientId);
  url.searchParams.set('redirect_uri', params.redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'openid email profile');
  url.searchParams.set('state', params.state);
  url.searchParams.set('nonce', params.nonce);
  url.searchParams.set('code_challenge', params.challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  return url.toString();
}

export interface OidcTokenResponse {
  id_token: string;
  access_token?: string;
  refresh_token?: string;
}

export async function exchangeAuthorizationCode(
  config: OidcConfig,
  discovery: OidcDiscovery,
  params: { code: string; redirectUri: string; verifier: string }
): Promise<OidcTokenResponse> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: params.code,
    redirect_uri: params.redirectUri,
    code_verifier: params.verifier,
  });
  const response = await fetch(discovery.token_endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
      Authorization: `Basic ${btoa(`${config.clientId}:${config.clientSecret}`)}`,
    },
    body: body.toString(),
  });
  const payload = (await response.json().catch(() => ({}))) as Partial<OidcTokenResponse> & { error?: string };
  if (!response.ok || !payload.id_token) {
    throw new Error(payload.error || `OIDC token exchange failed (${response.status})`);
  }
  return payload as OidcTokenResponse;
}

/**
 * Verifies an id_token: RS256 signature against the issuer JWKS, plus
 * issuer/audience/expiry/nonce checks. Throws on any failure.
 */
export async function verifyIdToken(
  config: OidcConfig,
  discovery: OidcDiscovery,
  idToken: string,
  expectedNonce: string
): Promise<OidcIdTokenClaims> {
  const segments = idToken.split('.');
  if (segments.length !== 3) throw new Error('Malformed id_token');
  const [headerSegment, payloadSegment, signatureSegment] = segments;

  const header = decodeJsonSegment<{ alg?: string; kid?: string }>(headerSegment);
  if (header.alg !== 'RS256' || !header.kid) {
    throw new Error(`Unsupported id_token algorithm: ${header.alg ?? 'none'}`);
  }

  const keys = await fetchJwks(discovery.jwks_uri);
  const jwk = keys.find((key) => (key as JsonWebKey & { kid?: string }).kid === header.kid);
  if (!jwk) throw new Error('id_token signing key not found in JWKS');

  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );
  const valid = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    key,
    base64UrlDecode(signatureSegment),
    new TextEncoder().encode(`${headerSegment}.${payloadSegment}`)
  );
  if (!valid) throw new Error('id_token signature verification failed');

  const claims = decodeJsonSegment<{
    iss?: string;
    aud?: string | string[];
    exp?: number;
    nonce?: string;
    sub?: string;
    email?: string;
    email_verified?: boolean;
    name?: string;
    preferred_username?: string;
  }>(payloadSegment);

  if (claims.iss !== discovery.issuer && claims.iss !== config.issuer) {
    throw new Error('id_token issuer mismatch');
  }
  const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audience.includes(config.clientId)) {
    throw new Error('id_token audience mismatch');
  }
  if (!claims.exp || claims.exp * 1000 <= Date.now()) {
    throw new Error('id_token expired');
  }
  if (claims.nonce !== expectedNonce) {
    throw new Error('id_token nonce mismatch');
  }
  if (!claims.sub) throw new Error('id_token is missing sub');
  if (!claims.email) throw new Error('id_token is missing email');
  if (claims.email_verified !== true) {
    throw new Error('id_token email is not verified');
  }

  return {
    sub: claims.sub,
    email: claims.email.toLowerCase().trim(),
    emailVerified: true,
    name: claims.name || claims.preferred_username || null,
  };
}
