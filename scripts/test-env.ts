import { webcrypto } from 'node:crypto';

const rateLimitCacheStore = new Map<string, string>();

/**
 * Installs worker-runtime globals that tsx/Node lacks: WebCrypto (src/ uses it
 * everywhere) and the Cache API backing RateLimitService's fixed-window limiter.
 * Call once at the top of each test file, before any handler runs.
 */
export function installTestGlobals(): void {
  const globals = globalThis as unknown as { crypto?: unknown; caches?: unknown };
  if (!globals.crypto) {
    globals.crypto = webcrypto as unknown as Crypto;
  }
  if (!globals.caches) {
    globals.caches = {
      open: async () => ({
        match: async (request: Request) => {
          const value = rateLimitCacheStore.get(request.url);
          return value === undefined ? undefined : new Response(value);
        },
        put: async (request: Request, response: Response) => {
          rateLimitCacheStore.set(request.url, await response.text());
        },
      }),
    };
  }
}
