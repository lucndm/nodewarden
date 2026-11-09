// Telling the vault owner that somebody asked to take over.
//
// Emergency access is the one way another person can get into a vault. When
// the person who was let in starts the wait, the owner should hear about it
// right away: they can still refuse it.
//
// The owner is the one who hears it, because the owner is the one who can
// stop it. The message goes to the same chat the security alerts go to, and
// it never carries a key, a password or a hash.
//
// The server has no mail channel, so this is a Telegram message. It is best
// effort: a failure to deliver must never change the result of the request
// that triggered it.

import type { Env } from '../types';
import { RateLimitService } from './ratelimit';

export interface EmergencyAccessNotice {
  /** The account whose vault is at stake: the one that granted the access. */
  grantorId: string;
  /** The account that was let in and now asks to take over. */
  granteeId?: string;
  /** What the notice is about. */
  kind: 'recovery_started' | 'recovery_approved' | 'account_taken_over';
  /** How long the wait was, in days. */
  waitTimeDays: number;
}

const WINDOW_SECONDS = 900;

export async function sendEmergencyAccessNotice(
  env: Env,
  /** The host of the instance, when the caller knows it. */
  host: string | undefined,
  notice: EmergencyAccessNotice
): Promise<void> {
  const token = env.TELEGRAM_BOT_TOKEN?.trim();
  const chatId = env.TELEGRAM_CHAT_ID?.trim();
  if (!token || !chatId) return;
  // Never log the Telegram URL: it contains the bot's credential.
  if (!/^\d+:[A-Za-z0-9_-]+$/.test(token) || !/^-?\d+$/.test(chatId)) {
    console.error('emergency_access_notice.config_invalid');
    return;
  }

  try {
    const limiter = new RateLimitService(env.DB);
    // One notice per vault per kind per quarter of an hour, so a retry cannot
    // become a flood. The global budget keeps a burst of grants from filling
    // the chat.
    const scope = /^[a-f0-9-]{36}$/i.test(notice.grantorId) ? notice.grantorId : 'unknown';
    const accountBudget = await limiter.consumeStrictBudgetWithWindow(
      `emergency_access_notice:${notice.kind}:${scope}`,
      1,
      WINDOW_SECONDS
    );
    if (!accountBudget.allowed) return;
    const globalBudget = await limiter.consumeStrictBudgetWithWindow('emergency_access_notice:all', 10, WINDOW_SECONDS);
    if (!globalBudget.allowed) return;

    const grantee = /^[a-f0-9-]{36}$/i.test(notice.granteeId || '') ? notice.granteeId!.slice(0, 8) : 'unknown';
    const headline =
      notice.kind === 'recovery_started'
        ? 'Somebody you let in asked to take over your vault'
        : notice.kind === 'recovery_approved'
          ? 'Somebody you let in can now take over your vault'
          : 'Somebody you let in has taken over your vault';
    const lastLine =
      notice.kind === 'recovery_started'
        ? 'Open the Emergency access settings to refuse it. Until the wait is over, it cannot be taken.'
        : notice.kind === 'recovery_approved'
          ? 'Delete the grant if you do not want this. Until the master password is replaced, nothing has changed yet.'
          : 'The master password of the account has been replaced and the sessions of that account have been thrown out.';
    const lines = [
      'NodeWarden emergency access',
      headline,
      ...(host ? [`Instance: ${host}`] : []),
      `Vault: ${scope === 'unknown' ? 'unknown' : scope.slice(0, 8)}`,
      `Asked by: ${grantee}`,
      `Wait: ${notice.waitTimeDays} day${notice.waitTimeDays === 1 ? '' : 's'}`,
      `Time (UTC): ${new Date().toISOString()}`,
      lastLine,
    ];

    const response = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text: lines.join('\n'), link_preview_options: { is_disabled: true } }),
      signal: AbortSignal.timeout(5000),
      redirect: 'manual',
    });
    if (!response.ok) {
      console.error('emergency_access_notice.delivery_failed', response.status);
      return;
    }
    const body = (await response.json()) as { ok?: boolean };
    if (body.ok !== true) console.error('emergency_access_notice.delivery_rejected');
  } catch {
    // Best effort: a notice that cannot be delivered must not fail the request
    // that asked for it.
    console.error('emergency_access_notice.unavailable');
  }
}
