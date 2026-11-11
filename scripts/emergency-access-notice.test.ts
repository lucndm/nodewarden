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
import { ensureStorageSchema } from '../src/services/storage-schema';
import { StorageService } from '../src/services/storage';
import type { MailBinding } from '../src/services/mail';
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
    if (new URL(String(input)).hostname === 'api.telegram.org') {
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
  await ensureStorageSchema(sqliteD1(db));
  const env = {
    DB: sqliteD1(db),
    TELEGRAM_BOT_TOKEN: TOKEN,
    TELEGRAM_CHAT_ID: CHAT,
  } as unknown as Env;
  const storage = new StorageService(env.DB);
  for (const [id, email] of [
    [OWNER, 'owner@example.test'],
    [GRANTEE, 'grantee@example.test'],
  ]) {
    await storage.createUser({
      id,
      email,
      name: null,
      masterPasswordHint: null,
      masterPasswordHash: 'the-grantor-master-hash',
      key: 'the-grantor-key',
      privateKey: 'the-grantor-private-key',
      publicKey: null,
      kdfType: 0,
      kdfIterations: 600000,
      kdfMemory: null,
      kdfParallelism: null,
      securityStamp: 'stamp',
      role: 'user',
      status: 'active',
      verifyDevices: false,
      totpSecret: null,
      totpRecoveryCode: null,
      yubikeyKey1: null,
      yubikeyKey2: null,
      yubikeyKey3: null,
      yubikeyKey4: null,
      yubikeyNfc: false,
      apiKey: null,
      userKeyId: null,
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-01-01T00:00:00.000Z',
    } as never);
  }
  return env;
}

/** The mails the server handed to the binding. */
type SentMail = Parameters<MailBinding['send']>[0];

/** A server that mails, and the mails it sent. */
async function mailFixture(): Promise<{ env: Env; sent: SentMail[] }> {
  const env = await fixture();
  const sent: SentMail[] = [];
  const EMAIL: MailBinding = {
    async send(message) {
      sent.push(message);
      return { messageId: 'fake-message-id' };
    },
  };
  return {
    env: {
      ...env,
      EMAIL,
      MAIL_FROM: 'no-reply@pass.minhluc.info',
      MAIL_VAULT_URL: 'https://pass.minhluc.info',
    } as unknown as Env,
    sent,
  };
}

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
    if (new URL(String(input)).hostname === 'api.telegram.org') {
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

test('a crafted host cannot write extra lines into the message', async () => {
  const env = await fixture();
  const capture = captureSent();
  try {
    await sendEmergencyAccessNotice(env, 'vault.example.test\nNodeWarden: your vault was taken', {
      kind: 'recovery_started',
      grantorId: OWNER,
      granteeId: GRANTEE,
      waitTimeDays: 7,
    });
  } finally {
    capture.restore();
  }
  assert.equal(capture.sent.length, 1);
  const message = capture.sent[0];
  assert.ok(!message.includes('your vault was taken'), 'the crafted line is not in the message');
  assert.ok(!message.includes('vault.example.test\n'), 'the crafted host is dropped whole');
});

test('the grantor is mailed when a recovery starts', async () => {
  const { env, sent } = await mailFixture();
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
  assert.equal(sent.length, 1, 'one mail is sent');
  assert.equal(sent[0].to, 'owner@example.test');
  assert.equal(sent[0].subject, 'Emergency access to your vault was requested');
  assert.ok(sent[0].text.includes('grantee@example.test'), sent[0].text);
  assert.ok(sent[0].text.includes('7 days'), sent[0].text);
});

test('the mail goes out without Telegram configured', async () => {
  const { env, sent } = await mailFixture();
  const withoutTelegram = {
    ...env,
    TELEGRAM_BOT_TOKEN: undefined,
    TELEGRAM_CHAT_ID: undefined,
  } as unknown as Env;
  await sendEmergencyAccessNotice(withoutTelegram, 'vault.example.test', {
    kind: 'recovery_started',
    grantorId: OWNER,
    granteeId: GRANTEE,
    waitTimeDays: 7,
  });
  assert.equal(sent.length, 1, 'the mail does not wait for the Telegram secrets');
});

test('a grantor who no longer exists is not mailed', async () => {
  const { env, sent } = await mailFixture();
  const capture = captureSent();
  try {
    await sendEmergencyAccessNotice(env, 'vault.example.test', {
      kind: 'recovery_started',
      grantorId: '00000000-0000-4000-8000-0000000000ff',
      granteeId: GRANTEE,
      waitTimeDays: 7,
    });
  } finally {
    capture.restore();
  }
  assert.equal(sent.length, 0, 'there is nobody to mail');
});

test('started and approved are both delivered', async () => {
  const { env, sent } = await mailFixture();
  const capture = captureSent();
  try {
    await sendEmergencyAccessNotice(env, 'vault.example.test', {
      kind: 'recovery_started',
      grantorId: OWNER,
      granteeId: GRANTEE,
      waitTimeDays: 7,
    });
    await sendEmergencyAccessNotice(env, 'vault.example.test', {
      kind: 'recovery_approved',
      grantorId: OWNER,
      granteeId: GRANTEE,
      waitTimeDays: 7,
    });
  } finally {
    capture.restore();
  }
  assert.equal(sent.length, 2, 'both kinds of notice arrive');
});

test('the mail carries nothing that opens the vault', async () => {
  const { env, sent } = await mailFixture();
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
  assert.equal(sent.length, 1);
  const mail = sent[0];
  for (const secret of ['the-grantor-key', 'the-grantor-private-key', 'the-grantor-master-hash']) {
    assert.ok(!mail.text.includes(secret), `the text does not carry ${secret}`);
    assert.ok(!mail.html.includes(secret), `the html does not carry ${secret}`);
  }
});
