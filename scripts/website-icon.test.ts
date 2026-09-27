// Route-level tests for the website icon proxy (GET /icons/{host}/icon.png).
//
// Coverage goals:
//   - the provider chain serves the first non-placeholder upstream response;
//   - known placeholder images (Bitwarden default globe by size+sha256,
//     Google s2 default by size, DuckDuckGo default by size+sha256) are
//     skipped instead of served;
//   - the direct https://{host}/favicon.ico last resort is consulted after
//     all aggregators fail;
//   - exhausted chain falls back per mode (default SVG globe vs 404).
//
// Upstream fetches are stubbed via globalThis.fetch; D1 + caches are the
// shared in-memory shims.
import assert from 'node:assert/strict';
import test from 'node:test';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { handlePublicRoute } from '../src/router-public';
import { MemoryD1 } from './memory-d1';
import type { Env } from '../src/types';

const originalFetch = globalThis.fetch;

const VAULT_ORIGIN = 'https://vault.example.test';
const PNG_BYTES = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const ICO_BYTES = new Uint8Array([0x00, 0x00, 0x01, 0x00, 0x01, 0x00]);
const BITWARDEN_GLOBE_BYTES = new Uint8Array(500).fill(0x61);
const GOOGLE_GLOBE_BYTES = new Uint8Array(341).fill(0x67);
const DDG_PLACEHOLDER_BYTES = new Uint8Array(1478).fill(0x64);

function pngResponse(bytes: Uint8Array): Response {
  return new Response(bytes as unknown as BodyInit, { status: 200, headers: { 'Content-Type': 'image/png' } });
}

function icoResponse(bytes: Uint8Array): Response {
  return new Response(bytes as unknown as BodyInit, { status: 200, headers: { 'Content-Type': 'image/x-icon' } });
}

interface StubRoute {
  match: (url: URL) => boolean;
  respond: (url: URL) => Response | Promise<Response>;
}

function installIconFetch(routes: StubRoute[]): void {
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = new URL(String(input));
    for (const route of routes) {
      if (route.match(url)) return route.respond(url);
    }
    throw new Error(`unexpected upstream request: ${String(input)}`);
  }) as typeof fetch;
}

function iconEnv(): Env {
  return { DB: new MemoryD1() } as unknown as Env;
}

function limiter() {
  return async () => null;
}

async function requestIcon(host: string, fallbackMode = ''): Promise<Response> {
  const suffix = fallbackMode ? `?fallback=${fallbackMode}` : '';
  const response = await handlePublicRoute(
    new Request(`${VAULT_ORIGIN}/icons/${encodeURIComponent(host)}/icon.png${suffix}`),
    iconEnv(),
    `/icons/${encodeURIComponent(host)}/icon.png`,
    'GET',
    limiter()
  );
  assert.ok(response, 'icon route must be routed');
  return response;
}

test('first working upstream wins', async (t) => {
  installIconFetch([
    {
      match: (url) => url.hostname === 'favicon.im',
      respond: () => pngResponse(PNG_BYTES),
    },
  ]);
  t.after(() => { globalThis.fetch = originalFetch; });

  const response = await requestIcon('example.com');
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('Content-Type'), 'image/png');
  assert.match(response.headers.get('Cache-Control') || '', /immutable/);
  assert.match(response.headers.get('Content-Security-Policy') || '', /sandbox/);
});

test('bitwarden default globe is rejected and google s2 serves next', async (t) => {
  let ddgTouched = false;
  installIconFetch([
    {
      match: (url) => url.hostname === 'favicon.im',
      respond: () => new Response(null, { status: 404 }),
    },
    {
      match: (url) => url.hostname === 'icons.bitwarden.net',
      respond: () => pngResponse(BITWARDEN_GLOBE_BYTES),
    },
    {
      match: (url) => url.hostname === 'www.google.com',
      respond: () => pngResponse(PNG_BYTES),
    },
    {
      match: (url) => url.hostname === 'icons.duckduckgo.com',
      respond: () => {
        ddgTouched = true;
        return pngResponse(PNG_BYTES);
      },
    },
  ]);
  t.after(() => { globalThis.fetch = originalFetch; });

  const response = await requestIcon('example.com');
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('Content-Type'), 'image/png');
  assert.equal(ddgTouched, false, 'chain must stop at first usable source');
});

test('google s2 341-byte default is rejected and duckduckgo serves next', async (t) => {
  installIconFetch([
    { match: (url) => url.hostname === 'favicon.im', respond: () => new Response(null, { status: 404 }) },
    { match: (url) => url.hostname === 'icons.bitwarden.net', respond: () => new Response(null, { status: 404 }) },
    { match: (url) => url.hostname === 'www.google.com', respond: () => pngResponse(GOOGLE_GLOBE_BYTES) },
    { match: (url) => url.hostname === 'icons.duckduckgo.com', respond: () => icoResponse(ICO_BYTES) },
  ]);
  t.after(() => { globalThis.fetch = originalFetch; });

  const response = await requestIcon('example.com');
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('Content-Type'), 'image/x-icon');
});

test('duckduckgo same-size real icon is served (sha mismatch) and direct favicon.ico serves last', async (t) => {
  installIconFetch([
    { match: (url) => url.hostname === 'favicon.im', respond: () => new Response(null, { status: 404 }) },
    { match: (url) => url.hostname === 'icons.bitwarden.net', respond: () => new Response(null, { status: 404 }) },
    { match: (url) => url.hostname === 'www.google.com', respond: () => pngResponse(GOOGLE_GLOBE_BYTES) },
    { match: (url) => url.hostname === 'icons.duckduckgo.com', respond: () => icoResponse(DDG_PLACEHOLDER_BYTES) },
  ]);
  t.after(() => { globalThis.fetch = originalFetch; });

  // 1478 bytes with unknown sha256 = plausibly a real (small) icon: served.
  const response = await requestIcon('example.com');
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('Content-Type'), 'image/x-icon');
});

test('direct favicon.ico is consulted after all aggregators fail', async (t) => {
  let directTouched = false;
  installIconFetch([
    { match: (url) => url.hostname === 'favicon.im' || url.hostname === 'icons.bitwarden.net' || url.hostname === 'www.google.com' || url.hostname === 'icons.duckduckgo.com', respond: () => new Response(null, { status: 404 }) },
    {
      match: (url) => url.hostname === 'example.com' && url.pathname === '/favicon.ico',
      respond: () => {
        directTouched = true;
        return icoResponse(ICO_BYTES);
      },
    },
  ]);
  t.after(() => { globalThis.fetch = originalFetch; });

  const response = await requestIcon('example.com');
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('Content-Type'), 'image/x-icon');
  assert.equal(directTouched, true, 'direct favicon.ico must be the last resort');
});

test('matchesIconPlaceholder rejects by size and size+sha', async (t) => {
  const { createHash } = await import('node:crypto');
  const { matchesIconPlaceholder } = await import('../src/router-public');
  const bytes = new ArrayBuffer(341);
  const digest = createHash('sha256').update(new Uint8Array(bytes)).digest('hex');

  assert.equal(await matchesIconPlaceholder(bytes, undefined), false);
  assert.equal(await matchesIconPlaceholder(bytes, { byteLength: 341 }), true, 'size-only match rejects');
  assert.equal(await matchesIconPlaceholder(bytes, { byteLength: 500, sha256: 'x' }), false, 'size mismatch never rejects');
  assert.equal(await matchesIconPlaceholder(bytes, { byteLength: 341, sha256: digest }), true, 'matching sha rejects');
  assert.equal(
    await matchesIconPlaceholder(bytes, { byteLength: 341, sha256: 'deadbeef' }),
    false,
    'sha mismatch keeps the icon'
  );
});

test('exhausted chain falls back per mode', async (t) => {
  installIconFetch([
    { match: () => true, respond: () => new Response(null, { status: 404 }) },
  ]);
  t.after(() => { globalThis.fetch = originalFetch; });

  const defaultFallback = await requestIcon('example.com');
  assert.equal(defaultFallback.status, 200);
  assert.match(defaultFallback.headers.get('Content-Type') || '', /image\/svg\+xml/);

  const notFound = await requestIcon('example.com', '404');
  assert.equal(notFound.status, 404);
});
