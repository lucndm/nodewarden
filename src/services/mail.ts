// The mail the server sends.
//
// Emergency access and organization invitations reach people who are not
// looking at the vault, so they go by mail. The channel is optional: a
// deployment without the binding, or without a sender address, sends nothing
// and behaves exactly as it did before.
//
// Mail is best effort. It never throws, it never changes the answer of the
// request that triggered it, and it never carries a key, a password, a hash
// or a token: only names, addresses, the wait and the link to the vault.

import type { Env } from '../types';
import { RateLimitService } from './ratelimit';

/** The Cloudflare Email Service Workers binding. */
export interface MailBinding {
  send(message: {
    to: string;
    from: { email: string; name: string };
    subject: string;
    text: string;
    html: string;
  }): Promise<{ messageId: string }>;
}

/** What the mail is about, used for the budget and for the log line. */
export type MailKind =
  | 'emergency_access_invite'
  | 'emergency_access_recovery'
  | 'organization_invite'
  | 'email_change_code'
  | 'email_changed';

export interface OutboundMail {
  kind: MailKind;
  to: string;
  subject: string;
  text: string;
  html: string;
  /**
   * Replaces the kind in the budget key, so two kinds to one recipient do
   * not share one budget.
   */
  budgetKey?: string;
}

const SENDER_NAME = 'NodeWarden';
/** One mail per recipient and kind per quarter of an hour. */
const RECIPIENT_WINDOW_SECONDS = 900;
/** Mails per hour for the whole instance, to protect the monthly quota. */
const GLOBAL_WINDOW_SECONDS = 3600;
const GLOBAL_MAX_PER_WINDOW = 100;
/** How long the binding may take before the mail is given up on. */
export const MAIL_SEND_TIMEOUT_MS = 10_000;

/** True when the deployment has both a binding and a sender address. */
export function isMailConfigured(env: Env): boolean {
  return Boolean(env.EMAIL) && Boolean(env.MAIL_FROM?.trim());
}

/** The address of the vault, when it is a real https address. */
export function mailVaultUrl(env: Env): string | null {
  const raw = env.MAIL_VAULT_URL?.trim();
  if (!raw) return null;
  try {
    const url = new URL(raw);
    if (url.protocol !== 'https:') return null;
    return url.href.replace(/\/+$/, '');
  } catch {
    return null;
  }
}

/**
 * Hands the mail to the binding, if the deployment wants mail and the
 * recipient is a single address.
 *
 * Returns true when the binding took the mail. It never throws: a binding
 * that fails, refuses or hangs must not change the answer of the request
 * that triggered the mail.
 */
export async function sendMail(
  env: Env,
  mail: OutboundMail,
  /** How long the binding may take. The tests shorten it. */
  timeoutMs: number = MAIL_SEND_TIMEOUT_MS
): Promise<boolean> {
  const binding = env.EMAIL;
  const from = env.MAIL_FROM?.trim();
  if (!binding || !from) return false;

  const to = mail.to.trim();
  if (!isSingleEmailAddress(to)) return false;

  try {
    const limiter = new RateLimitService(env.DB);
    // One mail per recipient and kind per quarter of an hour, so a retry
    // cannot become a flood. The global budget keeps a burst of invites from
    // eating the monthly quota.
    const scope = `mail:${mail.budgetKey || mail.kind}:${to.toLowerCase()}`;
    const recipientBudget = await limiter.consumeStrictBudgetWithWindow(
      scope,
      1,
      RECIPIENT_WINDOW_SECONDS
    );
    if (!recipientBudget.allowed) return false;
    const globalBudget = await limiter.consumeStrictBudgetWithWindow(
      'mail:all',
      GLOBAL_MAX_PER_WINDOW,
      GLOBAL_WINDOW_SECONDS
    );
    if (!globalBudget.allowed) return false;

    await sendWithTimeout(
      binding,
      {
        to,
        from: { email: from, name: SENDER_NAME },
        subject: mail.subject,
        text: mail.text,
        html: mail.html,
      },
      timeoutMs
    );
    return true;
  } catch (error) {
    // The log line names the kind and the reason only: never the address and
    // never the body.
    console.warn('mail.send_failed', JSON.stringify({ kind: mail.kind, reason: failureReason(error) }));
    return false;
  }
}

/**
 * Hands the mail to the binding, and gives up on a binding that hangs.
 *
 * A binding that never answers must not hold the request that triggered the
 * mail: the wait ends at the timeout and the mail is dropped.
 */
async function sendWithTimeout(
  binding: MailBinding,
  message: Parameters<MailBinding['send']>[0],
  timeoutMs: number
): Promise<void> {
  // The promise executor is the form this project can type: the TypeScript
  // library here has no Promise.withResolvers.
  let timer: number | undefined;
  const expiry = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject({ code: 'timeout' }), timeoutMs);
  });
  try {
    await Promise.race([binding.send(message), expiry]);
  } finally {
    clearTimeout(timer ?? null);
  }
}

/** The characters that have no business in an address: they separate or hide it. */
const FORBIDDEN_IN_ADDRESS: Partial<Record<string, true>> = {
  ',': true,
  ';': true,
  '<': true,
  '>': true,
  '"': true,
  '(': true,
  ')': true,
};

/** One address, and nothing else: a list of addresses is not an address. */
export function isSingleEmailAddress(value: string): boolean {
  if (!value || /\s/.test(value)) return false;
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    // A control character would let an address carry a second line.
    if (code < 0x20 || code === 0x7f) return false;
    if (FORBIDDEN_IN_ADDRESS[char]) return false;
  }
  const parts = value.split('@');
  return parts.length === 2 && parts[0].length > 0 && parts[1].length > 0;
}

/** The code of the failure, or its name. */
function failureReason(error: unknown): string {
  if (error && typeof error === 'object') {
    if ('code' in error && typeof error.code === 'string' && error.code) return error.code;
    if ('name' in error && typeof error.name === 'string' && error.name) return error.name;
  }
  return 'unknown';
}
