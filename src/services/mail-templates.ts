// The text of the mail.
//
// The mail is read by somebody who did not ask for it, so it stays plain and
// short: who is writing, what is wanted, and where to go.
//
// Two rules run through all of it. A value that comes from the vault (a
// name, an organization name) is escaped before it goes into the HTML part,
// so it stays text. A value that goes into the subject line has its control
// characters removed, so it cannot write a second mail header.
//
// No mail here carries a key, a password, a hash or a token.

export interface MailContent {
  subject: string;
  text: string;
  html: string;
}

/** One paragraph of the mail, in both parts. */
interface Section {
  text: string;
  html: string;
}

/** Escapes a value for the HTML part. */
function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Strips the control characters that would let a value write a header. */
function subjectText(value: string): string {
  const cleaned = [...value]
    .filter((char) => {
      const code = char.codePointAt(0) ?? 0;
      return code >= 0x20 && code !== 0x7f;
    })
    .join('');
  return cleaned.trim().slice(0, 200);
}

/** The name of a person, with their address when one is known. */
function who(name: string | null, email: string): string {
  const cleanName = (name ?? '').trim();
  const cleanEmail = email.trim();
  if (cleanName && cleanEmail) return `${cleanName} (${cleanEmail})`;
  return cleanName || cleanEmail;
}

/** A number of days, in English. */
function days(count: number): string {
  return `${count} ${count === 1 ? 'day' : 'days'}`;
}

/** A paragraph of plain text, and the same paragraph for the HTML part. */
function paragraph(text: string): Section {
  return { text, html: `<p>${escapeHtml(text)}</p>` };
}

/** The line that points at the vault, when there is a vault to point at. */
function signIn(vaultUrl: string | null): Section | null {
  // Only an https address becomes a link, so the template cannot be turned
  // into a link to somewhere else.
  if (!vaultUrl || !/^https:\/\//i.test(vaultUrl)) return null;
  const url = escapeHtml(vaultUrl);
  return { text: `Sign in at ${vaultUrl}`, html: `<p>Sign in at <a href="${url}">${url}</a></p>` };
}

/** Joins the paragraphs into the two parts of the mail. */
function build(subject: string, sections: Section[], vaultUrl: string | null): MailContent {
  const last = signIn(vaultUrl);
  const all = last ? [...sections, last] : sections;
  return {
    subject,
    text: all.map((section) => section.text).join('\n\n'),
    html: `<!DOCTYPE html>\n<html>\n<body>\n${all.map((section) => section.html).join('\n')}\n</body>\n</html>`,
  };
}

/**
 * The mail that tells somebody they were named an emergency contact.
 *
 * The grantor names the grantee, so the grantor is the one who writes.
 * The grantee has to sign in to accept the invitation, so somebody without
 * an account is told how to get one first.
 */
export function emergencyAccessInviteMail(input: {
  grantorName: string | null;
  grantorEmail: string;
  accessType: 'view' | 'takeover';
  waitTimeDays: number;
  vaultUrl: string | null;
  /** Whether the address the invitation went to already has an account here. */
  recipientHasAccount: boolean;
}): MailContent {
  const grantor = who(input.grantorName, input.grantorEmail);
  const reach = input.accessType === 'takeover' ? 'take over their account' : 'read their vault';
  return build(
    subjectText('You were named an emergency contact'),
    [
      paragraph('Hi,'),
      paragraph(`${grantor} named you as an emergency contact for their vault.`),
      paragraph(
        input.recipientHasAccount
          ? 'Sign in to accept the invitation.'
          : "You need an account on this server first. Ask them or the server's administrator for an invite code, sign up with this email address, then sign in to accept the invitation."
      ),
      paragraph(
        `Once they confirm you, you can ask for access if they ever cannot get in: you can ${reach} ${days(input.waitTimeDays)} after you ask, unless they turn the request down.`
      ),
    ],
    input.vaultUrl
  );
}

/**
 * The mail that tells the owner that emergency access is moving.
 *
 * The owner is the one who can still refuse it, so the owner is the one who
 * has to hear about it while there is time.
 */
export function emergencyAccessRecoveryMail(input: {
  kind: 'recovery_started' | 'recovery_approved' | 'account_taken_over';
  granteeName: string | null;
  granteeEmail: string;
  waitTimeDays: number;
  vaultUrl: string | null;
  /** What the grantee gets once the access is confirmed. */
  accessType: 'view' | 'takeover' | null;
}): MailContent {
  const grantee = who(input.granteeName, input.granteeEmail);
  // The grantee may not be known by name, for instance when the account was
  // taken over and the notice comes from the scheduled approval.
  const actor = grantee || 'Somebody you let in';
  const subject =
    input.kind === 'recovery_started'
      ? 'Emergency access to your vault was requested'
      : input.kind === 'recovery_approved'
        ? 'Emergency access to your vault was granted'
        : 'Your account was taken over through emergency access';

  const wait = days(input.waitTimeDays);
  const sections =
    input.kind === 'recovery_started'
      ? [
          paragraph('Hi,'),
          paragraph(`${actor} asked for emergency access to your vault.`),
          paragraph(
            input.accessType === 'takeover'
              ? `They will be able to take over your account after ${wait} unless you reject the request.`
              : input.accessType === 'view'
                ? `They will be able to read your vault after ${wait} unless you reject the request.`
                : `Access is granted automatically after ${wait} unless you reject the request.`
          ),
          paragraph('Reject it in the emergency access settings of your vault, after you sign in.'),
        ]
      : input.kind === 'recovery_approved'
        ? [
            paragraph('Hi,'),
            paragraph(
              input.accessType === 'takeover'
                ? `${actor} can now take over your account.`
                : input.accessType === 'view'
                  ? `${actor} can now read your vault.`
                  : `${actor} can now use the emergency access you gave them.`
            ),
            paragraph(
              input.accessType === 'takeover'
                ? 'Nothing has changed until they set a new password. To stop it, delete the grant in the emergency access settings of your vault.'
                : 'To stop it, delete the grant in the emergency access settings of your vault.'
            ),
          ]
        : [
            paragraph('Hi,'),
            paragraph(`${actor} has taken over your vault.`),
            paragraph(
              'The account password has been replaced and the sessions of that account have been thrown out.'
            ),
          ];

  return build(subjectText(subject), sections, input.vaultUrl);
}

/** The mail that tells somebody they were invited to an organization. */
export function organizationInviteMail(input: {
  organizationName: string;
  inviterEmail: string;
  vaultUrl: string | null;
}): MailContent {
  return build(
    subjectText(`You were invited to ${input.organizationName}`),
    [
      paragraph('Hi,'),
      paragraph(`${input.inviterEmail} invited you to the organization ${input.organizationName}.`),
      paragraph('Accept the invitation in the vault to join it.'),
    ],
    input.vaultUrl
  );
}

/**
 * The mail that carries the code of a pending email change.
 *
 * The code goes to the address the account wants to have, so the person who
 * receives it is the one who owns that address. The code is short-lived, and
 * the mail says so, because a code that arrives late is of no use.
 */
export function emailChangeCodeMail(input: { code: string; vaultUrl: string | null }): MailContent {
  return build(
    subjectText('Your email change code'),
    [
      paragraph('Hi,'),
      paragraph(`Your email change code is ${input.code}.`),
      paragraph('The code is good for 15 minutes.'),
      paragraph('If you did not ask for it, you can ignore this mail: nothing changes.'),
    ],
    input.vaultUrl
  );
}

/**
 * The mail that tells the old address that the account moved to another one.
 *
 * It goes to the address that is no longer the account, so it is the last
 * thing the old address hears about it.
 */
export function emailChangedNoticeMail(input: { newEmail: string; vaultUrl: string | null }): MailContent {
  return build(
    subjectText('The email of your vault account was changed'),
    [
      paragraph('Hi,'),
      paragraph(`The email of your vault account was changed to ${input.newEmail}.`),
      paragraph('The sessions of that account have been thrown out.'),
      paragraph(
        'If you did not do this, sign in and change your master password, or contact the server\'s administrator.'
      ),
    ],
    input.vaultUrl
  );
}
