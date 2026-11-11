// The mail the server sends.
//
// Mail is the one channel that reaches somebody who is not looking at the
// vault, so it has to be careful twice over: it only goes out when the
// deployment really wants it, and it never takes the request that triggered
// it down with it.
//
// These checks prove that: a server without the binding sends nothing, a
// server with it sends exactly what it was handed, a binding that refuses
// changes nothing, and the same person cannot be mailed twice in a row.
import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { isMailConfigured, mailVaultUrl, sendMail, type MailBinding } from '../src/services/mail';
import { sqliteD1 } from './sqlite-d1';
import type { Env } from '../src/types';

const FROM = 'no-reply@pass.minhluc.info';
const TO = 'grantee@example.test';

/** A binding that keeps what it was asked to send. */
function recordingBinding(): { binding: MailBinding; sent: Parameters<MailBinding['send']>[0][] } {
  const sent: Parameters<MailBinding['send']>[0][] = [];
  return {
    binding: {
      async send(message) {
        sent.push(message);
        return { messageId: 'fake-message-id' };
      },
    },
    sent,
  };
}

/** A binding that refuses, the way an exhausted quota does. */
function failingBinding(): MailBinding {
  return {
    async send() {
      throw Object.assign(new Error('quota'), { code: 'E_RATE_LIMIT_EXCEEDED' });
    },
  };
}

async function fixture(overrides: Partial<Env> = {}): Promise<Env> {
  const db = new DatabaseSync(':memory:');
  // The rate limiter makes its own table, but it only does so once per
  // process, so a fresh database here has to have the table already.
  db.exec(
    'CREATE TABLE rate_limit_buckets(bucket_key TEXT PRIMARY KEY, count INTEGER NOT NULL, expires_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)'
  );
  return { DB: sqliteD1(db), ...overrides } as unknown as Env;
}

const MAIL = {
  kind: 'emergency_access_invite' as const,
  to: TO,
  subject: 'You were named an emergency contact',
  text: 'Hi, you were named an emergency contact.',
  html: '<p>Hi, you were named an emergency contact.</p>',
};

test('mail is not sent when the binding or the sender is missing', async () => {
  const binding = recordingBinding();
  const withoutBinding = await fixture({ MAIL_FROM: FROM });
  const withoutSender = await fixture({ EMAIL: binding.binding });
  const withBoth = await fixture({ EMAIL: binding.binding, MAIL_FROM: FROM });

  assert.equal(isMailConfigured(withoutBinding), false);
  assert.equal(isMailConfigured(withoutSender), false);
  assert.equal(isMailConfigured(withBoth), true);

  assert.equal(await sendMail(withoutBinding, MAIL), false);
  assert.equal(await sendMail(withoutSender, MAIL), false);
  assert.equal(binding.sent.length, 0, 'the binding is never called');
});

test('a configured server hands the mail to the binding', async () => {
  const binding = recordingBinding();
  const env = await fixture({ EMAIL: binding.binding, MAIL_FROM: FROM });

  assert.equal(await sendMail(env, MAIL), true);
  assert.equal(binding.sent.length, 1, 'one mail is sent');
  const message = binding.sent[0];
  assert.equal(message.to, TO);
  assert.equal(message.from.email, FROM);
  assert.equal(message.from.name, 'NodeWarden');
  assert.equal(message.subject, MAIL.subject);
  assert.equal(message.text, MAIL.text);
  assert.equal(message.html, MAIL.html);
});

test('sendMail never throws', async () => {
  const env = await fixture({ EMAIL: failingBinding(), MAIL_FROM: FROM });
  const warnings: unknown[][] = [];
  const originalWarn = console.warn;
  console.warn = (...args: unknown[]) => {
    warnings.push(args);
  };
  try {
    assert.equal(await sendMail(env, MAIL), false);
  } finally {
    console.warn = originalWarn;
  }

  assert.equal(warnings.length, 1, 'one line is logged');
  const line = warnings[0].map((value) => String(value)).join(' ');
  assert.ok(line.includes('mail.send_failed'), line);
  assert.ok(line.includes('E_RATE_LIMIT_EXCEEDED'), line);
  assert.ok(!line.includes(TO), 'the recipient is not in the log line');
});

test('a binding that hangs does not hold the request', async () => {
  const hanging: MailBinding = {
    send() {
      // The binding never answers.
      return new Promise<{ messageId: string }>(() => {});
    },
  };
  const env = await fixture({ EMAIL: hanging, MAIL_FROM: FROM });

  const warnings: string[] = [];
  const originalWarn = console.warn;
  console.warn = (...args: unknown[]) => {
    warnings.push(args.map((value) => String(value)).join(' '));
  };
  try {
    // The wait is shortened here, so the check does not take ten seconds.
    assert.equal(await sendMail(env, MAIL, 20), false);
  } finally {
    console.warn = originalWarn;
  }

  assert.equal(warnings.length, 1, 'one line is logged');
  const line = warnings[0];
  assert.ok(line.includes('mail.send_failed'), line);
  assert.ok(line.includes('timeout'), line);
});

test('one mail per recipient and kind per quarter hour', async () => {
  const binding = recordingBinding();
  const env = await fixture({ EMAIL: binding.binding, MAIL_FROM: FROM });

  assert.equal(await sendMail(env, MAIL), true);
  assert.equal(await sendMail(env, MAIL), false, 'the second mail is held back');
  assert.equal(binding.sent.length, 1, 'only one mail goes out');

  assert.equal(await sendMail(env, { ...MAIL, kind: 'organization_invite' }), true);
  assert.equal(binding.sent.length, 2, 'another kind is another mail');
});

test('an address that is not one address is not mailed', async () => {
  const binding = recordingBinding();
  const env = await fixture({ EMAIL: binding.binding, MAIL_FROM: FROM });

  assert.equal(await sendMail(env, { ...MAIL, to: 'a@b.c, d@e.f' }), false);
  assert.equal(await sendMail(env, { ...MAIL, to: 'a,b@c.d' }), false);
  assert.equal(await sendMail(env, { ...MAIL, to: '<a@b.c>' }), false);
  assert.equal(await sendMail(env, { ...MAIL, to: 'nobody' }), false);
  assert.equal(binding.sent.length, 0, 'the binding is never called');
});

test('mailVaultUrl accepts only an https URL', async () => {
  assert.equal(mailVaultUrl(await fixture({ MAIL_VAULT_URL: 'https://pass.minhluc.info' })), 'https://pass.minhluc.info');
  assert.equal(mailVaultUrl(await fixture({ MAIL_VAULT_URL: 'https://pass.minhluc.info/' })), 'https://pass.minhluc.info');
  assert.equal(mailVaultUrl(await fixture({ MAIL_VAULT_URL: 'javascript:alert(1)' })), null);
  assert.equal(mailVaultUrl(await fixture({ MAIL_VAULT_URL: 'http://x' })), null);
  assert.equal(mailVaultUrl(await fixture({})), null);
});
