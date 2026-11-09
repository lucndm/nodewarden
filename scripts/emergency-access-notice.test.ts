// The notice the vault owner gets when somebody asks to take over.
//
// The owner is the one who can still refuse it, so the owner is the one who
// has to hear about it while there is time.
//
// These checks prove three things: the notice reaches the owner, it carries
// nothing that could open the vault, and it cannot be made into a flood.
import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { sendEmergencyAccessNotice } from '../src/services/emergency-access-notifier';
import { sqliteD1 } from './sqlite-d1';
import type { Env } from '../src/types';

const OWNER = '00000000-0000-4000-8000-0000000000a1';
const GRANTEE = '00000000-0000-4000-8000-0000000000a2';
const CHAT = '-1001234567890';
const TOKEN = '123456:AAF-fake-token-for-the-check';

/** The messages the notice asked Telegram to send. */
function captureSent(): { sent: string[]; restore: () => void } {
  const sent: string[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.includes('api.telegram.org')) {
      sent.push(String(init?.body || ''));
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    return original(input, init);
  }) as typeof fetch;
  return { sent, restore: () => { globalThis.fetch = original; } };
}

async function fixture(): Promise<Env> {
  const db = new DatabaseSync(':memory:');
  // The rate limiter makes its own table, but it only does so once per
  // process, so a fresh database here has to have the table already.
  db.exec(
    'CREATE TABLE rate_limit_buckets(bucket_key TEXT PRIMARY KEY, count INTEGER NOT NULL, expires_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)'
  );
  return {
    DB: sqliteD1(db),
    TELEGRAM_BOT_TOKEN: TOKEN,
    TELEGRAM_CHAT_ID: CHAT,
  } as unknown as Env;
}

const request = new Request('https://vault.example.test/api/emergency-access/x/initiate', { method: 'POST' });

test('the owner is told that somebody asked to take over', async () => {
  const env = await fixture();
  const capture = captureSent();
  try {
    await sendEmergencyAccessNotice(env, 'vault.example.test', {
      kind: 'recovery_started',
      grantorId: OWNER,
      granteeId: GRANTEE,
      waitTimeDays: 7,
    });
  } finally {
    capture.restore();
  }
  assert.equal(capture.sent.length, 1, 'one notice is sent');
  const message = capture.sent[0];
  assert.ok(message.includes(CHAT), 'it goes to the chat of the owner');
  assert.ok(message.includes('vault.example.test'), 'it names the instance');
  assert.ok(message.includes('asked to take over'), message.slice(0, 200));
  assert.ok(message.includes(OWNER.slice(0, 8)), 'it names the vault');
  assert.ok(message.includes(GRANTEE.slice(0, 8)), 'it names who asked');
  assert.ok(message.includes('7 days'), 'it says how long the wait was');
});

test('the notice carries nothing that could open the vault', async () => {
  const env = await fixture();
  const capture = captureSent();
  try {
    await sendEmergencyAccessNotice(env, 'vault.example.test', {
      kind: 'recovery_started',
      grantorId: OWNER,
      granteeId: GRANTEE,
      waitTimeDays: 7,
    });
  } finally {
    capture.restore();
  }
  const message = capture.sent[0];
  // The bot's own credential is in the URL, not the message, and the message
  // holds no key, no password and no hash.
  assert.ok(!message.includes(TOKEN), 'the bot token is not in the message');
  assert.ok(!/2\.[A-Za-z0-9+/=]+\|/.test(message), 'no encrypted key is in the message');
  assert.ok(!message.includes('master'), 'no master password is in the message');
  assert.ok(!message.includes('hash'), 'no hash is in the message');
  // Only the first few characters of an id are named, the way the other
  // alerts do it.
  assert.ok(!message.includes(OWNER), 'the whole vault id is not in the message');
});

test('a repeated notice for the same vault does not become a flood', async () => {
  const env = await fixture();
  const capture = captureSent();
  try {
    for (let attempt = 0; attempt < 5; attempt += 1) {
      await sendEmergencyAccessNotice(env, 'vault.example.test', {
        kind: 'recovery_started',
        grantorId: OWNER,
        granteeId: GRANTEE,
        waitTimeDays: 7,
      });
    }
  } finally {
    capture.restore();
  }
  assert.equal(capture.sent.length, 1, 'only the first notice goes out');
});

test('a different vault still gets its own notice', async () => {
  const env = await fixture();
  const capture = captureSent();
  const other = '00000000-0000-4000-8000-0000000000a3';
  try {
    await sendEmergencyAccessNotice(env, 'vault.example.test', {
      kind: 'recovery_started',
      grantorId: OWNER,
      granteeId: GRANTEE,
      waitTimeDays: 7,
    });
    await sendEmergencyAccessNotice(env, 'vault.example.test', {
      kind: 'recovery_started',
      grantorId: other,
      granteeId: GRANTEE,
      waitTimeDays: 7,
    });
  } finally {
    capture.restore();
  }
  assert.equal(capture.sent.length, 2, 'each vault is told about its own');
});

test('no bot token means no notice, and no failure either', async () => {
  const db = new DatabaseSync(':memory:');
  db.exec(
    'CREATE TABLE rate_limit_buckets(bucket_key TEXT PRIMARY KEY, count INTEGER NOT NULL, expires_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)'
  );
  const env = { DB: sqliteD1(db) } as unknown as Env;
  const capture = captureSent();
  try {
    await sendEmergencyAccessNotice(env, 'vault.example.test', {
      kind: 'recovery_started',
      grantorId: OWNER,
      granteeId: GRANTEE,
      waitTimeDays: 7,
    });
  } finally {
    capture.restore();
  }
  assert.equal(capture.sent.length, 0);
});

test('a Telegram that refuses the message does not throw', async () => {
  const env = await fixture();
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    if (String(input).includes('api.telegram.org')) {
      return new Response(JSON.stringify({ ok: false }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    return original(input);
  }) as typeof fetch;
  try {
    await sendEmergencyAccessNotice(env, 'vault.example.test', {
      kind: 'recovery_started',
      grantorId: OWNER,
      granteeId: GRANTEE,
      waitTimeDays: 7,
    });
  } finally {
    globalThis.fetch = original;
  }
});
