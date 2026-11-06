import type { Cipher } from './types';
import { looksLikeCipherString } from './app-support';

export function firstCipherUri(cipher: Cipher): string {
  const uris = cipher.login?.uris || [];
  for (const uri of uris) {
    const raw = String(uri.decUri || uri.uri || '').trim();
    if (raw && !looksLikeCipherString(raw)) return raw;
  }
  return '';
}

export function hasUnresolvedCipherUri(cipher: Cipher): boolean {
  return (cipher.login?.uris || []).some((uri) => looksLikeCipherString(String(uri.decUri || uri.uri || '')));
}

export function hostFromUri(uri: string): string {
  if (!uri.trim()) return '';
  try {
    const normalized = /^https?:\/\//i.test(uri) ? uri : `https://${uri}`;
    return new URL(normalized).hostname || '';
  } catch {
    return '';
  }
}

export function websiteIconUrl(host: string): string {
  return `/icons/${encodeURIComponent(host)}/icon.png?fallback=404`;
}
