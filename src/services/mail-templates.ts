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
 */
export function emergencyAccessInviteMail(input: {
  grantorName: string | null;
  grantorEmail: string;
  accessType: 'view' | 'takeover';
  waitTimeDays: number;
  vaultUrl: string | null;
}): MailContent {
  const grantor = who(input.grantorName, input.grantorEmail);
  const reach = input.accessType === 'takeover' ? 'take over their account' : 'read their vault';
  return build(
    subjectText('You were named an emergency contact'),
    [
      paragraph('Hi,'),
      paragraph(`${grantor} named you as an emergency contact for their vault.`),
      paragraph(
        `If they cannot get in themselves, they can ${reach} after a waiting period of ${days(input.waitTimeDays)}.`
      ),
      paragraph('You will see the request in the vault when it happens.'),
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

  const sections =
    input.kind === 'recovery_started'
      ? [
          paragraph('Hi,'),
          paragraph(`${actor} asked for emergency access to your vault.`),
          paragraph(`Access is granted automatically after ${days(input.waitTimeDays)} unless you reject it.`),
          paragraph('Reject it in the emergency access settings of your vault, after you sign in.'),
        ]
      : input.kind === 'recovery_approved'
        ? [
            paragraph('Hi,'),
            paragraph(`${actor} can now take over your vault.`),
            paragraph(
              'Delete the grant if you do not want this. Until the account password is replaced, nothing has changed yet.'
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
