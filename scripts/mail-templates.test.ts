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
  emailChangeCodeMail,
  emailChangedNoticeMail,
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
    recipientHasAccount: true,
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
    accessType: null,
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
    accessType: null,
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
    recipientHasAccount: true,
  });
  assert.ok(!mail.text.includes('Sign in at'), mail.text);
  assert.ok(!mail.html.includes('Sign in at'), mail.html);
});

test('the invite tells somebody with an account to sign in and accept', () => {
  const mail = emergencyAccessInviteMail({
    grantorName: 'The Grantor',
    grantorEmail: 'grantor@example.test',
    accessType: 'view',
    waitTimeDays: 7,
    vaultUrl: VAULT,
    recipientHasAccount: true,
  });
  assert.ok(mail.text.includes('Sign in to accept the invitation.'), mail.text);
  assert.ok(!mail.text.includes('invite code'), mail.text);
});

test('the invite tells somebody without an account how to get one', () => {
  const mail = emergencyAccessInviteMail({
    grantorName: 'The Grantor',
    grantorEmail: 'grantor@example.test',
    accessType: 'view',
    waitTimeDays: 7,
    vaultUrl: VAULT,
    recipientHasAccount: false,
  });
  assert.ok(mail.text.includes('invite code'), mail.text);
  assert.ok(mail.text.includes('sign up with this email address'), mail.text);
});

test('the invite says the contact is the one who gets in', () => {
  const view = emergencyAccessInviteMail({
    grantorName: 'The Grantor',
    grantorEmail: 'grantor@example.test',
    accessType: 'view',
    waitTimeDays: 7,
    vaultUrl: VAULT,
    recipientHasAccount: true,
  });
  assert.ok(view.text.includes('you can read their vault 7 days after you ask'), view.text);
  assert.ok(!view.text.includes('they can read their vault'), view.text);

  const takeover = emergencyAccessInviteMail({
    grantorName: 'The Grantor',
    grantorEmail: 'grantor@example.test',
    accessType: 'takeover',
    waitTimeDays: 7,
    vaultUrl: VAULT,
    recipientHasAccount: true,
  });
  assert.ok(takeover.text.includes('you can take over their account'), takeover.text);
});

test('recovery mails name what the grantee can do', () => {
  const view = emergencyAccessRecoveryMail({
    kind: 'recovery_approved',
    granteeName: 'The Grantee',
    granteeEmail: 'grantee@example.test',
    waitTimeDays: 7,
    vaultUrl: VAULT,
    accessType: 'view',
  });
  assert.ok(view.text.includes('can now read your vault'), view.text);
  assert.ok(!view.text.includes('take over'), view.text);

  const takeover = emergencyAccessRecoveryMail({
    kind: 'recovery_approved',
    granteeName: 'The Grantee',
    granteeEmail: 'grantee@example.test',
    waitTimeDays: 7,
    vaultUrl: VAULT,
    accessType: 'takeover',
  });
  assert.ok(takeover.text.includes('can now take over your account'), takeover.text);
  assert.ok(
    takeover.text.includes('Nothing has changed until they set a new password'),
    takeover.text
  );
});

test('the code mail carries the code and its lifetime', () => {
  const mail = emailChangeCodeMail({ code: '123456', vaultUrl: VAULT });
  assert.equal(mail.subject, 'Your email change code');
  assert.ok(mail.text.includes('123456'), mail.text);
  assert.ok(mail.text.includes('15 minutes'), mail.text);
  assert.ok(mail.text.includes('did not ask for it'), mail.text);
  assert.ok(mail.html.includes('123456'), mail.html);
});

test('the code mail says it can be ignored without a vault', () => {
  const mail = emailChangeCodeMail({ code: '123456', vaultUrl: null });
  assert.ok(!mail.text.includes('Sign in at'), mail.text);
  assert.ok(mail.text.includes('123456'), mail.text);
});

test('the notice names the new email', () => {
  const mail = emailChangedNoticeMail({ newEmail: 'new@example.test', vaultUrl: VAULT });
  assert.equal(mail.subject, 'The email of your vault account was changed');
  assert.ok(mail.text.includes('new@example.test'), mail.text);
  assert.ok(
    mail.text.includes(
      "If you did not do this, sign in and change your master password, or contact the server's administrator."
    ),
    mail.text
  );
});

test('the new email is escaped in the html of the notice', () => {
  const mail = emailChangedNoticeMail({ newEmail: '<b>x</b>&"\'', vaultUrl: VAULT });
  assert.ok(mail.html.includes('&lt;b&gt;x&lt;/b&gt;&amp;&quot;&#39;'), mail.html);
  assert.ok(!mail.html.includes('<b>x'), mail.html);
});
