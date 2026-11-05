// A write must never be submitted twice. NodeWarden generates the id for
// created items, so a retried POST /api/ciphers stores a second row instead of
// repeating the same one. Only idempotent methods may be sent again.
//
// The retry decision is two-layered:
//   - 429 means the server rejected the request before doing any work, so it is
//     safe to send again for writes as well.
//   - a 5xx may mean the write already landed, and a thrown fetch may mean the
//     request reached the server at all: both are only repeated for idempotent
//     methods.
import assert from 'node:assert/strict';
import test from 'node:test';

import { installTestGlobals } from './test-env';
installTestGlobals();

import {
  createAuthedFetch,
  isIdempotentMethod,
  isRetryableResponse,
} from '../webapp/src/lib/api/auth';
import type { SessionState } from '../webapp/src/lib/types';

const SESSION: SessionState = {
  accessToken: 'test-token',
  email: 'tester@example.com',
  authMode: 'token',
};

type FetchCall = { url: string; method: string };

async function withFetch(
  handler: (call: FetchCall, attempt: number) => Promise<Response> | Response,
  run: (calls: FetchCall[]) => Promise<void>
): Promise<void> {
  const originalFetch = globalThis.fetch;
  const originalWindow = (globalThis as Record<string, unknown>).window;
  const calls: FetchCall[] = [];
  (globalThis as Record<string, unknown>).window = {
    // Run the backoff immediately: the delay itself is not under test.
    setTimeout: (fn: () => void) => {
      fn();
      return 0;
    },
  };
  globalThis.fetch = (async (input: string, init: RequestInit = {}) => {
    const call = { url: String(input), method: String(init.method || 'GET').toUpperCase() };
    calls.push(call);
    return handler(call, calls.length);
  }) as unknown as typeof fetch;
  try {
    await run(calls);
  } finally {
    globalThis.fetch = originalFetch;
    (globalThis as Record<string, unknown>).window = originalWindow;
  }
}

function status(code: number): Response {
  return new Response('body', { status: code });
}

test('only GET, HEAD and OPTIONS are treated as idempotent', () => {
  assert.equal(isIdempotentMethod('GET'), true);
  assert.equal(isIdempotentMethod('head'), true);
  assert.equal(isIdempotentMethod('OPTIONS'), true);
  assert.equal(isIdempotentMethod(undefined), true);
  assert.equal(isIdempotentMethod('POST'), false);
  assert.equal(isIdempotentMethod('PUT'), false);
  assert.equal(isIdempotentMethod('PATCH'), false);
  assert.equal(isIdempotentMethod('DELETE'), false);
});

test('429 is retryable for writes, a 5xx only for idempotent methods', () => {
  assert.equal(isRetryableResponse('POST', 429), true);
  assert.equal(isRetryableResponse('DELETE', 429), true);
  assert.equal(isRetryableResponse('GET', 429), true);
  assert.equal(isRetryableResponse('GET', 500), true);
  assert.equal(isRetryableResponse('GET', 503), true);
  assert.equal(isRetryableResponse('POST', 500), false);
  assert.equal(isRetryableResponse('PUT', 502), false);
  assert.equal(isRetryableResponse('GET', 400), false);
  assert.equal(isRetryableResponse('GET', 404), false);
  assert.equal(isRetryableResponse('GET', 200), false);
});

test('a write that fails with a server error is sent exactly once', async () => {
  await withFetch(
    () => status(500),
    async (calls) => {
      const authedFetch = createAuthedFetch(() => SESSION, () => {});
      const response = await authedFetch('/api/ciphers', {
        method: 'POST',
        body: JSON.stringify({ name: 'x' }),
      });
      assert.equal(response.status, 500);
      assert.equal(calls.length, 1);
    }
  );
});

test('a write whose connection drops is never sent again', async () => {
  await withFetch(
    () => {
      throw new TypeError('network error');
    },
    async (calls) => {
      const authedFetch = createAuthedFetch(() => SESSION, () => {});
      await assert.rejects(
        authedFetch('/api/ciphers', { method: 'POST', body: JSON.stringify({ name: 'x' }) }),
        /network error/
      );
      assert.equal(calls.length, 1);
    }
  );
});

test('a rate limited write is retried, because the server did no work', async () => {
  await withFetch(
    () => status(429),
    async (calls) => {
      const authedFetch = createAuthedFetch(() => SESSION, () => {});
      const response = await authedFetch('/api/ciphers', {
        method: 'POST',
        body: JSON.stringify({ name: 'x' }),
      });
      assert.equal(response.status, 429);
      assert.equal(calls.length, 3);
    }
  );
});

test('an idempotent read is retried on a server error', async () => {
  await withFetch(
    () => status(500),
    async (calls) => {
      const authedFetch = createAuthedFetch(() => SESSION, () => {});
      const response = await authedFetch('/api/sync');
      assert.equal(response.status, 500);
      assert.equal(calls.length, 3);
    }
  );
});

test('an idempotent read is retried when the connection drops', async () => {
  await withFetch(
    () => {
      throw new TypeError('network error');
    },
    async (calls) => {
      const authedFetch = createAuthedFetch(() => SESSION, () => {});
      await assert.rejects(authedFetch('/api/sync'), /network error/);
      assert.equal(calls.length, 3);
    }
  );
});
