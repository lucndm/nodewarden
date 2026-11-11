// The mail that tells somebody they were invited to an organization.
//
// The invitation is also shown in the vault, but the mail is what reaches
// somebody who is not looking at it. Only accounts that exist can be
// invited, so only accounts that exist can be mailed.
//
// These checks prove that every new member is told, that the ones who were
// not invited are not, and that a mail that cannot be delivered changes
// nothing about the invitation.
import assert from 'node:assert/strict';
import test from 'node:test';

import { call, createUser, fixture, ORG, OWNER } from './organization-fixture';
import type { MailBinding } from '../src/services/mail';
import type { Env } from '../src/types';

const INVITE_URL = `https://vault.example.test/api/organizations/${ORG}/users`;

/** The mails the server handed to the binding. */
type SentMail = Parameters<MailBinding['send']>[0];

/** A server that mails, and the mails it sent. */
async function mailFixture(): Promise<{ env: Env; sent: SentMail[] }> {
  const { env, storage } = await fixture();
  // The mail keeps its budget in the strict-budget table. The rate limiter
  // only creates that table once per process, so a fresh database here has
  // to have the table already.
  await env.DB.prepare(
    'CREATE TABLE IF NOT EXISTS rate_limit_buckets(bucket_key TEXT PRIMARY KEY, count INTEGER NOT NULL, expires_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)'
  ).run();
  const sent: SentMail[] = [];
  const EMAIL: MailBinding = {
    async send(message) {
      sent.push(message);
      return { messageId: 'fake-message-id' };
    },
  };
  await createUser(storage, 'user-newcomer', 'newcomer@example.test');
  await createUser(storage, 'user-second', 'second@example.test');
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

test('each new member is mailed', async () => {
  const { env, sent } = await mailFixture();
  const invited = await call(env, INVITE_URL, 'POST', OWNER, {
    emails: ['newcomer@example.test', 'second@example.test'],
    type: 2,
  });
  assert.equal(invited.status, 200);
  assert.equal(sent.length, 2, 'each new member is told');
  assert.deepEqual(
    sent.map((mail) => mail.to).sort(),
    ['newcomer@example.test', 'second@example.test']
  );
  for (const mail of sent) {
    assert.equal(mail.subject, 'You were invited to org-1');
  }
});

test('an address without an account and an existing member get no mail', async () => {
  const { env, sent } = await mailFixture();
  const invited = await call(env, INVITE_URL, 'POST', OWNER, {
    emails: ['nobody@example.test', 'reader@example.test'],
    type: 2,
  });
  assert.equal(invited.status, 200);
  assert.equal(sent.length, 0, 'only new members are told');
});

test('the request succeeds when the mail binding fails', async () => {
  const { env, storage } = await fixture();
  await env.DB.prepare(
    'CREATE TABLE IF NOT EXISTS rate_limit_buckets(bucket_key TEXT PRIMARY KEY, count INTEGER NOT NULL, expires_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)'
  ).run();
  await createUser(storage, 'user-newcomer', 'newcomer@example.test');
  const failing: MailBinding = {
    async send() {
      throw Object.assign(new Error('quota'), { code: 'E_RATE_LIMIT_EXCEEDED' });
    },
  };
  const mailing = {
    ...env,
    EMAIL: failing,
    MAIL_FROM: 'no-reply@pass.minhluc.info',
  } as unknown as Env;

  const warnings: string[] = [];
  const originalWarn = console.warn;
  console.warn = (...args: unknown[]) => {
    warnings.push(args.map((value) => String(value)).join(' '));
  };
  let invited: Response;
  try {
    invited = await call(mailing, INVITE_URL, 'POST', OWNER, {
      emails: ['newcomer@example.test'],
      type: 2,
    });
  } finally {
    console.warn = originalWarn;
  }
  assert.equal(invited.status, 200, 'the invitation is made anyway');
  assert.equal(warnings.length, 1, 'the failure is logged once');
  assert.ok(warnings[0].includes('mail.send_failed'), warnings[0]);

  const membership = await storage.getOrganizationUserForUser(ORG, 'user-newcomer');
  assert.ok(membership, 'the membership exists');
  assert.equal(membership.status, 0, 'the membership is still an invitation');
});

test('nothing is mailed when mail is not configured', async () => {
  const { env, storage } = await fixture();
  await createUser(storage, 'user-newcomer', 'newcomer@example.test');
  const invited = await call(env, INVITE_URL, 'POST', OWNER, {
    emails: ['newcomer@example.test'],
    type: 2,
  });
  assert.equal(invited.status, 200);
  const membership = await storage.getOrganizationUserForUser(ORG, 'user-newcomer');
  assert.ok(membership, 'the membership exists');
});
