import type { Env } from '../types';
import { RateLimitService } from './ratelimit';

interface SecurityAlert {
  kind: 'new_device' | 'login_lockout';
  accountId?: string;
  method?: string;
}

export async function sendSecurityAlert(env: Env, request: Request, event: SecurityAlert): Promise<void> {
  const token = env.TELEGRAM_BOT_TOKEN?.trim();
  const chatId = env.TELEGRAM_CHAT_ID?.trim();
  if (!token || !chatId) return;
  // Never log the Telegram URL: it contains the bot's credential.
  if (!/^\d+:[A-Za-z0-9_-]+$/.test(token) || !/^-?\d+$/.test(chatId)) {
    console.error('security_alert.config_invalid');
    return;
  }

  try {
    const limiter = new RateLimitService(env.DB);
    // ponytail: fixed 15-minute windows reuse D1 budgets; adjacent windows can send close together.
    const accountId = /^[a-f0-9-]{36}$/i.test(event.accountId || '') ? event.accountId! : 'unknown';
    const accountBudget = await limiter.consumeStrictBudgetWithWindow(`telegram:${event.kind}:${accountId}`, 1, 900);
    if (!accountBudget.allowed) return;
    const globalBudget = await limiter.consumeStrictBudgetWithWindow('telegram:all', 10, 900);
    if (!globalBudget.allowed) return;

    const method = ['password', 'webauthn', 'client_credentials', 'authorization_code', 'sso_oidc'].includes(event.method || '')
      ? event.method : 'unknown';
    const text = [
      'NodeWarden security alert',
      event.kind === 'new_device' ? 'Successful sign-in from an unrecognized client session' : 'Repeated sign-in failures triggered a temporary login lockout',
      `Instance: ${new URL(request.url).hostname}`,
      `Account: ${accountId === 'unknown' ? 'unknown' : accountId.slice(0, 8)}`,
      `Method: ${method}`,
      `Time (UTC): ${new Date().toISOString()}`,
      event.kind === 'new_device' ? 'A new client identifier is not proof of an attack. Check your devices and sign-in history.' : 'Check the Log Center. This is a warning signal, not confirmation of compromise.',
    ].join('\n');
    const response = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text, link_preview_options: { is_disabled: true } }),
      signal: AbortSignal.timeout(5000),
      redirect: 'manual',
    });
    if (!response.ok) {
      console.error('security_alert.delivery_failed', response.status);
      return;
    }
    const body = await response.json() as { ok?: boolean };
    if (body.ok !== true) console.error('security_alert.delivery_rejected');
  } catch {
    // Best effort: delivery failure must never change authentication results.
    console.error('security_alert.unavailable');
  }
}
