import type { Env } from './types';

const BACKEND_PATH_PREFIXES = [
  '/api',
  '/identity',
  '/icons',
  '/fill-assist',
  '/notifications',
  '/.well-known',
  // Zitadel/OIDC SSO routes must reach the worker (not the SPA asset fallback).
  '/auth/sso',
  // Bitwarden client SSO protocol entry point.
  '/identity/connect/authorize',
  // Root-level aliases used by the official mobile apps (Retrofit paths with
  // a leading slash resolve against the host root, not the /identity prefix).
  '/sso',
  '/connect',
  '/accounts',
  // Compatibility aliases retained for older Bitwarden clients.
  '/devices',
  '/auth-requests',
  '/webauthn',
] as const;

const BACKEND_EXACT_PATHS = new Set([
  '/v1/assetlinks:check',
  '/web-bootstrap',
  '/config',
  '/accounts/kdf',
  '/settings/domains',
]);

export function isBackendRequestPath(pathname: string): boolean {
  const path = pathname.toLowerCase();
  if (BACKEND_EXACT_PATHS.has(path)) return true;

  return BACKEND_PATH_PREFIXES.some((prefix) => (
    path === prefix || path.startsWith(`${prefix}/`)
  ));
}

export function isWebVaultHidden(env: Env): boolean {
  return String(env.HIDE_WEB_VAULT || '').trim() === '1';
}

export function webVaultNotFoundResponse(request: Request): Response {
  const body = request.method === 'HEAD' ? null : 'Not Found';
  return new Response(body, {
    status: 404,
    headers: {
      'Cache-Control': 'no-store, max-age=0',
      'Content-Type': 'text/plain; charset=utf-8',
      'X-Robots-Tag': 'noindex, nofollow, noarchive, nosnippet',
    },
  });
}
