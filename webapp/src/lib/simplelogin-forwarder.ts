import type { ForwardedEmailOptions, ForwarderAccountConfig } from '@/lib/password-generator';
import { generateForwardedPrefix } from '@/lib/password-generator';

/**
 * Minimal SimpleLogin API client used by the forwarded-email-alias generator.
 * Works with SimpleLogin itself and with self-hosted SimpleLogin-compatible
 * servers such as MailPal.
 */

export type ForwarderErrorKind = 'config' | 'network' | 'auth' | 'quota' | 'server';

export class ForwarderError extends Error {
  readonly kind: ForwarderErrorKind;

  constructor(kind: ForwarderErrorKind, message?: string, cause?: unknown) {
    super(message ?? kind, { cause });
    this.name = 'ForwarderError';
    this.kind = kind;
  }
}

export interface SlAliasSuffix {
  suffix: string;
  signedSuffix: string;
  isCustom: boolean;
  isPremium: boolean;
}

export interface SlAliasOptions {
  canCreate: boolean;
  prefixSuggestion: string;
  suffixes: SlAliasSuffix[];
}

export interface SlAlias {
  id: number;
  email: string;
  enabled: boolean;
}

interface RequestOptions {
  method: string;
  path: string;
  apiKey: string;
  body?: unknown;
}

async function request<T>({ method, path, apiKey, body }: RequestOptions): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      method,
      headers: {
        Authentication: apiKey,
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (cause) {
    throw new ForwarderError('network', 'alias provider request failed', cause);
  }

  if (response.status === 401) throw new ForwarderError('auth');
  if (response.status === 429) throw new ForwarderError('quota');

  const payload = (await response.json().catch(() => null)) as (T & { error?: string }) | null;

  if (!response.ok) {
    if (payload && typeof payload.error === 'string' && /quota|premium|upgrade/i.test(payload.error)) {
      throw new ForwarderError('quota', payload.error);
    }
    throw new ForwarderError('server', payload?.error ?? `HTTP ${response.status}`);
  }
  if (!payload) throw new ForwarderError('server', 'invalid provider response');
  return payload;
}

export async function fetchAliasOptions(
  options: Pick<ForwarderAccountConfig, 'serverUrl' | 'apiKey'>,
  hostname?: string,
): Promise<SlAliasOptions> {
  const query = hostname ? `?hostname=${encodeURIComponent(hostname)}` : '';
  const payload = await request<{ can_create?: boolean; prefix_suggestion?: string; suffixes?: Array<{ suffix?: string; signed_suffix?: string; is_custom?: boolean; is_premium?: boolean }> }>({
    method: 'GET',
    path: `${options.serverUrl}/api/v5/alias/options${query}`,
    apiKey: options.apiKey,
  });
  const suffixes = (payload.suffixes ?? [])
    .filter((item): item is { suffix: string; signed_suffix: string; is_custom?: boolean; is_premium?: boolean } =>
      typeof item.suffix === 'string' && typeof item.signed_suffix === 'string')
    .map((item) => ({
      suffix: item.suffix,
      signedSuffix: item.signed_suffix,
      isCustom: item.is_custom === true,
      isPremium: item.is_premium === true,
    }));
  return {
    canCreate: payload.can_create !== false && suffixes.length > 0,
    prefixSuggestion: typeof payload.prefix_suggestion === 'string' ? payload.prefix_suggestion : '',
    suffixes,
  };
}

export async function createCustomAlias(
  options: Pick<ForwarderAccountConfig, 'serverUrl' | 'apiKey' | 'note'>,
  prefix: string,
  signedSuffix: string,
  hostname?: string,
): Promise<SlAlias> {
  const payload = await request<SlAlias>({
    method: 'POST',
    path: `${options.serverUrl}/api/v3/alias/custom/new${hostname ? `?hostname=${encodeURIComponent(hostname)}` : ''}`,
    apiKey: options.apiKey,
    body: {
      alias_prefix: prefix,
      signed_suffix: signedSuffix,
      mailbox_ids: [],
      ...(options.note ? { note: options.note } : {}),
    },
  });
  return payload;
}

export async function createRandomAlias(
  options: Pick<ForwarderAccountConfig, 'serverUrl' | 'apiKey' | 'note'>,
  mode: 'word' | 'uuid',
  hostname?: string,
): Promise<SlAlias> {
  const payload = await request<SlAlias>({
    method: 'POST',
    path: `${options.serverUrl}/api/alias/random/new?mode=${mode}${hostname ? `&hostname=${encodeURIComponent(hostname)}` : ''}`,
    apiKey: options.apiKey,
    body: options.note ? { note: options.note } : undefined,
  });
  return payload;
}

/**
 * Generates a fresh alias from the configured provider. Custom aliases fall
 * back to the provider's first suffix (self-hosted servers like MailPal have
 * exactly one per domain).
 */
export async function generateForwardedEmail(
  options: ForwardedEmailOptions,
  hostname?: string,
): Promise<string> {
  // One account config per provider type; more providers (addy, duckduckgo,
  // ...) plug in here as they get implemented.
  const account: ForwarderAccountConfig | undefined =
    options.provider === 'simplelogin' ? options.simplelogin : undefined;
  if (!account) throw new ForwarderError('config');

  const serverUrl = account.serverUrl.trim();
  const apiKey = account.apiKey.trim();
  if (!serverUrl || !apiKey) throw new ForwarderError('config');

  if (account.aliasType === 'custom') {
    const prefix = account.prefix.trim() || generateForwardedPrefix();
    const aliasOptions = await fetchAliasOptions({ serverUrl, apiKey }, hostname);
    if (!aliasOptions.canCreate || aliasOptions.suffixes.length === 0) {
      throw new ForwarderError('quota');
    }
    const alias = await createCustomAlias({ serverUrl, apiKey, note: account.note }, prefix, aliasOptions.suffixes[0].signedSuffix, hostname);
    if (!alias?.email) throw new ForwarderError('server', 'provider returned no alias');
    return alias.email;
  }

  const alias = await createRandomAlias({ serverUrl, apiKey, note: account.note }, account.aliasType === 'uuid' ? 'uuid' : 'word', hostname);
  if (!alias?.email) throw new ForwarderError('server', 'provider returned no alias');
  return alias.email;
}
