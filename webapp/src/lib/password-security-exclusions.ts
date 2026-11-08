// The items this account does not want checked by the password scan.
//
// The server holds the list; this is the copy the interface works with, so
// the item view and the security page agree without asking again.

import {
  excludeCipherFromScan,
  getScanExclusions,
  includeCipherInScan,
  PASSWORD_HEALTH_SCOPE,
} from '@/lib/api/security';
import type { AuthedFetch } from '@/lib/api/shared';

let exclusions = new Set<string>();
const listeners = new Set<() => void>();

function notify(): void {
  listeners.forEach((listener) => listener());
}

export function getPasswordSecurityExclusions(): string[] {
  return [...exclusions];
}

export function isPasswordSecurityExcluded(cipherId: string): boolean {
  return exclusions.has(cipherId);
}

export function subscribePasswordSecurityExclusions(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function setPasswordSecurityExclusions(ids: string[]): void {
  exclusions = new Set(ids.filter(Boolean));
  notify();
}

/** Reads the exclusions from the server and keeps the copy in step. */
export async function loadPasswordSecurityExclusions(authedFetch: AuthedFetch): Promise<string[]> {
  const rows = await getScanExclusions(authedFetch, PASSWORD_HEALTH_SCOPE);
  setPasswordSecurityExclusions(rows.map((row) => row.cipherId));
  return getPasswordSecurityExclusions();
}

/** Keeps an item out of the password check. */
export async function excludeFromPasswordScan(authedFetch: AuthedFetch, cipherId: string): Promise<void> {
  await excludeCipherFromScan(authedFetch, cipherId, PASSWORD_HEALTH_SCOPE);
  exclusions = new Set([...exclusions, cipherId]);
  notify();
}

/** Puts an item back into the password check. */
export async function includeInPasswordScan(authedFetch: AuthedFetch, cipherId: string): Promise<void> {
  await includeCipherInScan(authedFetch, cipherId, PASSWORD_HEALTH_SCOPE);
  const next = new Set(exclusions);
  next.delete(cipherId);
  exclusions = next;
  notify();
}
