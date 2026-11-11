// The text of the mail.
//
// A mail is read by somebody who did not ask for it, so the text has to say
// who is writing, what is wanted and where to go. It must also stay a mail:
// a name that carries HTML must not become HTML, and a name that carries a
// line break must not become a second mail header.
//
// These checks prove that the text names the people involved, that it carries
// the vault address, and that what goes into it cannot break out of it.
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  emergencyAccessInviteMail,
  emergencyAccessRecoveryMail,
  organizationInviteMail,
} from '../src/services/mail-templates';

const VAULT = 'https://pass.minhluc.info';

test('each mail names the person and links the vault', () => {
  const invite = emergencyAccessInviteMail({
    grantorName: 'The Grantor',
    grantorEmail: 'grantor@example.test',
    accessType: 'view',
    waitTimeDays: 7,
    vaultUrl: VAULT,
  });
  assert.ok(invite.text.includes('grantor@example.test'), invite.text);
  assert.match(invite.text, /Sign in at https:\/\/pass\.minhluc\.info(?![\w.-])/, invite.text);
  assert.ok(invite.html.includes('grantor@example.test'), invite.html);
  assert.match(invite.html, /https:\/\/pass\.minhluc\.info(?![\w.-])/, invite.html);

  const recovery = emergencyAccessRecoveryMail({
    kind: 'recovery_started',
    granteeName: 'The Grantee',
    granteeEmail: 'grantee@example.test',
    waitTimeDays: 7,
    vaultUrl: VAULT,
  });
  assert.ok(recovery.text.includes('grantee@example.test'), recovery.text);
  assert.match(recovery.text, /Sign in at https:\/\/pass\.minhluc\.info(?![\w.-])/, recovery.text);
  assert.ok(recovery.html.includes('grantee@example.test'), recovery.html);
  assert.match(recovery.html, /https:\/\/pass\.minhluc\.info(?![\w.-])/, recovery.html);

  const organization = organizationInviteMail({
    organizationName: 'The Organization',
    inviterEmail: 'inviter@example.test',
    vaultUrl: VAULT,
  });
  assert.ok(organization.text.includes('inviter@example.test'), organization.text);
  assert.match(organization.text, /Sign in at https:\/\/pass\.minhluc\.info(?![\w.-])/, organization.text);
  assert.ok(organization.html.includes('inviter@example.test'), organization.html);
  assert.match(organization.html, /https:\/\/pass\.minhluc\.info(?![\w.-])/, organization.html);
});

test('the recovery notice says how long the owner has to refuse', () => {
  const mail = emergencyAccessRecoveryMail({
    kind: 'recovery_started',
    granteeName: null,
    granteeEmail: 'grantee@example.test',
    waitTimeDays: 7,
    vaultUrl: VAULT,
  });
  assert.ok(mail.text.includes('7 days'), mail.text);
  assert.ok(mail.text.includes('reject'), mail.text);
});

test('inserted values are escaped in html', () => {
  const mail = organizationInviteMail({
    organizationName: '<b>x</b>&"\'',
    inviterEmail: 'inviter@example.test',
    vaultUrl: VAULT,
  });
  assert.ok(mail.html.includes('&lt;b&gt;x&lt;/b&gt;&amp;&quot;&#39;'), mail.html);
  assert.ok(!mail.html.includes('<b>x'), mail.html);
});

test('a subject cannot carry a header', () => {
  const mail = organizationInviteMail({
    organizationName: 'Acme\r\nBcc: a@b.c',
    inviterEmail: 'inviter@example.test',
    vaultUrl: VAULT,
  });
  assert.ok(!mail.subject.includes('\r'), mail.subject);
  assert.ok(!mail.subject.includes('\n'), mail.subject);
  assert.ok(mail.subject.startsWith('You were invited to '), mail.subject);
});

test('no vault url, no sign-in line', () => {
  const mail = emergencyAccessInviteMail({
    grantorName: null,
    grantorEmail: 'grantor@example.test',
    accessType: 'takeover',
    waitTimeDays: 7,
    vaultUrl: null,
  });
  assert.ok(!mail.text.includes('Sign in at'), mail.text);
  assert.ok(!mail.html.includes('Sign in at'), mail.html);
});
