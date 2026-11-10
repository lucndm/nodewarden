import type { Env, User } from '../types';

// A user verification token stands in for the master password between reading
// a two-step setup and changing it: the official clients ask for the setup
// once with the password, then send this token with the change. It is bound to
// the state it was issued for (the TOTP key, or which YubiKeys or WebAuthn keys
// are registered), so it stops working once that state changes, and to the
// security stamp, so it dies with every session.
const TWO_FACTOR_VERIFICATION_TOKEN_TTL_MS = 10 * 60 * 1000;

function base64UrlEncodeBytes(data: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...data));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecodeBytes(input: string): Uint8Array {
  let base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) base64 += '=';
  const binary = atob(base64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

async function hmacSha256(secret: string, data: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data)));
}

export async function createTwoFactorVerificationToken(env: Env, user: User, binding: string): Promise<string> {
  const payload = {
    sub: user.id,
    key: binding,
    stamp: user.securityStamp,
    exp: Date.now() + TWO_FACTOR_VERIFICATION_TOKEN_TTL_MS,
  };
  const payloadB64 = base64UrlEncodeBytes(new TextEncoder().encode(JSON.stringify(payload)));
  const signatureB64 = base64UrlEncodeBytes(await hmacSha256(env.JWT_SECRET, payloadB64));
  return `${payloadB64}.${signatureB64}`;
}

export async function verifyTwoFactorVerificationToken(
  env: Env,
  user: User,
  binding: string,
  token: string
): Promise<boolean> {
  try {
    const [payloadB64, signatureB64] = String(token || '').split('.');
    if (!payloadB64 || !signatureB64) return false;
    const expected = base64UrlEncodeBytes(await hmacSha256(env.JWT_SECRET, payloadB64));
    if (expected !== signatureB64) return false;
    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecodeBytes(payloadB64))) as {
      sub?: string;
      key?: string;
      stamp?: string;
      exp?: number;
    };
    return (
      payload.sub === user.id &&
      payload.key === binding &&
      payload.stamp === user.securityStamp &&
      typeof payload.exp === 'number' &&
      payload.exp >= Date.now()
    );
  } catch {
    return false;
  }
}

/** The binding of a YubiKey setup: whether it is on, and which keys it holds. */
export function yubiKeyVerificationBinding(enabled: boolean, keys: string[]): string {
  return `yubikey:${enabled ? 1 : 0}:${keys.filter(Boolean).join(',')}`;
}

/**
 * The binding of a two-step WebAuthn setup: which keys it holds, by their
 * stored ids. The ids the clients see are positions in the list, so they do
 * not tell a removed key from a new one.
 */
export function webAuthnVerificationBinding(credentialIds: string[]): string {
  return `webauthn:${credentialIds.length > 0 ? 1 : 0}:${[...credentialIds].sort().join(',')}`;
}

/** The token a request carries, under either spelling the clients use. */
export function readUserVerificationToken(body: Record<string, unknown> | null | undefined): string {
  const value = body?.userVerificationToken ?? body?.UserVerificationToken;
  return typeof value === 'string' ? value : '';
}
