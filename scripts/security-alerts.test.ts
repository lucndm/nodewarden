/// <reference types="node" />
/// <reference types="@cloudflare/workers-types" />
import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync, type SQLInputValue } from 'node:sqlite';
import { sendSecurityAlert } from '../src/services/security-alerts';
import type { Env } from '../src/types';

function database(): D1Database {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec('CREATE TABLE rate_limit_buckets(bucket_key TEXT PRIMARY KEY, count INTEGER NOT NULL, expires_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)');
  return {
    prepare(sql: string) {
      let values: SQLInputValue[] = [];
      const statement = {
        bind(...bound: SQLInputValue[]) { values = bound; return statement; },
        async run() { return { meta: { changes: Number(sqlite.prepare(sql).run(...values).changes) } }; },
        async first() { return sqlite.prepare(sql).get(...values) ?? null; },
      };
      return statement;
    },
  } as unknown as D1Database;
}

const token = '123456789:fake-secret-token';
const chatId = '123456';
const account = '00000000-0000-4000-8000-000000000001';
const request = new Request('https://vault.example.test/identity/connect/token?secret=never-send', {
  headers: { 'CF-Connecting-IP': '198.51.100.2', 'User-Agent': 'private-device', Authorization: 'Bearer private-token' },
});
function env(): Env {
  return { DB: database(), TELEGRAM_BOT_TOKEN: token, TELEGRAM_CHAT_ID: chatId } as Env;
}

test('disabled alerts require both secrets and never touch storage or network', async () => {
  const original = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => { calls++; return Response.json({ ok: true }); };
  try {
    for (const config of [{}, { TELEGRAM_BOT_TOKEN: token }, { TELEGRAM_CHAT_ID: chatId }]) {
      await sendSecurityAlert(config as Env, request, { kind: 'new_device', accountId: account });
      assert.equal(calls, 0);
    }
  } finally { globalThis.fetch = original; }
});

test('persistent cooldown prevents concurrent duplicates and separates alert kinds', async () => {
  const config = env();
  const original = globalThis.fetch;
  const bodies: Array<{ text: string }> = [];
  globalThis.fetch = async (_input, init) => {
    bodies.push(JSON.parse(String(init?.body)));
    return Response.json({ ok: true });
  };
  try {
    await Promise.all(Array.from({ length: 10 }, () => sendSecurityAlert(config, request, { kind: 'new_device', accountId: account, method: 'password' })));
    assert.equal(bodies.length, 1);
    await sendSecurityAlert({ ...config }, request, { kind: 'new_device', accountId: account });
    assert.equal(bodies.length, 1, 'a fresh Env instance still uses persisted cooldown');
    await sendSecurityAlert(config, request, { kind: 'login_lockout', accountId: account });
    assert.equal(bodies.length, 2);
    assert.match(bodies[0].text, /unrecognized client session/);
    assert.match(bodies[1].text, /temporary login lockout/);
    assert.match(bodies[0].text, /Account: 00000000/);
    for (const body of bodies) {
      for (const secret of [token, chatId, account, '198.51.100.2', 'private-device', 'private-token', 'never-send']) {
        assert.ok(!body.text.includes(secret), `payload must omit ${secret}`);
      }
    }
  } finally { globalThis.fetch = original; }
});

test('global delivery budget bounds floods spanning many accounts', async () => {
  const config = env();
  const original = globalThis.fetch;
  let deliveries = 0;
  globalThis.fetch = async () => { deliveries++; return Response.json({ ok: true }); };
  try {
    await Promise.all(Array.from({ length: 25 }, (_, i) => sendSecurityAlert(config, request, {
      kind: 'login_lockout', accountId: `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`,
    })));
    assert.equal(deliveries, 10);
  } finally { globalThis.fetch = original; }
});

test('provider failures stay contained without leaking token or raw upstream text', async () => {
  const originalFetch = globalThis.fetch;
  const originalError = console.error;
  const messages: string[] = [];
  console.error = (...args) => { messages.push(args.join(' ')); };
  try {
    for (const failure of ['network', 'http', 'rejected', 'json']) {
      globalThis.fetch = async () => {
        if (failure === 'network') throw new Error(`secret URL https://api.telegram.org/bot${token}`);
        if (failure === 'http') return new Response(`upstream echoes ${token}`, { status: 429 });
        if (failure === 'json') return new Response(`bad json ${token}`);
        return Response.json({ ok: false, description: token });
      };
      await sendSecurityAlert(env(), request, { kind: 'login_lockout' });
    }
    assert.equal(messages.length, 4);
    assert.ok(messages.every(message => message.startsWith('security_alert.')));
    assert.ok(!messages.join(' ').includes(token));
    assert.ok(!messages.join(' ').includes('upstream'));
  } finally { globalThis.fetch = originalFetch; console.error = originalError; }
});
