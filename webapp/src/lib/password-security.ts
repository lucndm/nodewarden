import type { Cipher } from '@/lib/types';

const PWNED_PASSWORDS_RANGE_URL = 'https://api.pwnedpasswords.com/range/';
const MAX_CONCURRENT_BREACH_CHECKS = 5;
const COMMON_PASSWORDS = new Set([
  'password', 'password1', '123456', '12345678', '123456789', 'qwerty', 'abc123', 'letmein', 'welcome', 'iloveyou', 'admin', 'changeme',
]);

export interface PasswordBreachResult {
  count: number | null;
  available: boolean;
}

export interface PasswordSecurityItem {
  cipherId: string;
  /** The revision of the item when it was checked: a result belongs to one
   * state of an item, not to the item in general. */
  revisionDate: string;
  exposedCount: number | null;
  reusedCount: number;
  weak: boolean;
}

/**
 * What is known about the password of one item.
 *
 * `source` says how much was looked at: the whole vault check knows about
 * breaches, weakness and reuse, while a check of this password alone only
 * knows whether the breach database knows it.
 */
export interface PasswordSecurityFinding {
  cipherId: string;
  revisionDate: string;
  source: 'scan' | 'breach';
  /** null when the breach database never answered. */
  exposedCount: number | null;
  /** null when reuse was not looked at. */
  reusedCount: number | null;
  /** null when weakness was not looked at. */
  weak: boolean | null;
  checkedAt: number;
}

/**
 * What may be said about the password of an item.
 *
 * `unknown` is the answer whenever there is no valid result: not scanned,
 * failed, expired, or the item changed since. It must never be dressed up as
 * a clean password, because a password nobody looked at is not a safe one.
 */
export type PasswordHealthState =
  | { kind: 'unknown'; reason: 'not-checked' | 'unavailable' }
  | { kind: 'breach-only'; exposed: boolean; exposedCount: number }
  | { kind: 'risks'; exposedCount: number; weak: boolean; reusedCount: number }
  | { kind: 'clean' };

export function passwordHealthState(finding: PasswordSecurityFinding | null): PasswordHealthState {
  if (!finding) return { kind: 'unknown', reason: 'not-checked' };
  if (finding.exposedCount === null) return { kind: 'unknown', reason: 'unavailable' };
  if (finding.source === 'breach') {
    return { kind: 'breach-only', exposed: finding.exposedCount > 0, exposedCount: finding.exposedCount };
  }
  const exposedCount = finding.exposedCount;
  const weak = finding.weak === true;
  const reusedCount = finding.reusedCount || 0;
  if (exposedCount > 0 || weak || reusedCount > 1) return { kind: 'risks', exposedCount, weak, reusedCount };
  return { kind: 'clean' };
}

export interface PasswordSecurityReport {
  eligibleCount: number;
  checkedCount: number;
  exposedCount: number;
  reusedCount: number;
  weakCount: number;
  unavailableCount: number;
  items: PasswordSecurityItem[];
}

type Candidate = {
  cipherId: string;
  revisionDate: string;
  name: string;
  hash: string;
  weak: boolean;
};

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('').toUpperCase();
}

function isAbortError(error: unknown): boolean {
  return !!error && typeof error === 'object' && 'name' in error && (error as { name?: string }).name === 'AbortError';
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) {
    const error = new Error('The operation was aborted.');
    error.name = 'AbortError';
    throw error;
  }
}

export async function sha1Password(password: string): Promise<string> {
  const input = new TextEncoder().encode(password);
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-1', input)));
}

function parseRangeResponse(text: string, suffix: string): number {
  for (const line of text.split(/\r?\n/)) {
    const separator = line.indexOf(':');
    if (separator !== 35) continue;
    if (line.slice(0, separator).toUpperCase() !== suffix) continue;
    const count = Number.parseInt(line.slice(separator + 1), 10);
    return Number.isSafeInteger(count) && count > 0 ? count : 0;
  }
  return 0;
}

export async function checkPasswordHashLeaked(
  hash: string,
  fetchImpl: typeof fetch = fetch,
  signal?: AbortSignal,
): Promise<number> {
  if (!/^[A-F0-9]{40}$/.test(hash)) throw new Error('Password hash is invalid.');
  throwIfAborted(signal);
  const controller = new AbortController();
  const timeout = globalThis.setTimeout(() => controller.abort(), 12_000);
  const onExternalAbort = () => controller.abort();
  signal?.addEventListener('abort', onExternalAbort, { once: true });
  if (signal?.aborted) controller.abort();
  try {
    const response = await fetchImpl(`${PWNED_PASSWORDS_RANGE_URL}${hash.slice(0, 5)}`, {
      method: 'GET',
      mode: 'cors',
      credentials: 'omit',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      headers: { 'Add-Padding': 'true' },
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`Pwned Passwords returned ${response.status}.`);
    return parseRangeResponse(await response.text(), hash.slice(5));
  } catch (error) {
    // External cancel (leave page / re-scan) must stay distinguishable from timeout/network failures.
    if (signal?.aborted) {
      const abortError = new Error('The operation was aborted.');
      abortError.name = 'AbortError';
      throw abortError;
    }
    if (isAbortError(error)) throw new Error('Pwned Passwords request timed out.');
    throw error;
  } finally {
    globalThis.clearTimeout(timeout);
    signal?.removeEventListener('abort', onExternalAbort);
  }
}

export async function checkPasswordLeaked(
  password: string,
  fetchImpl: typeof fetch = fetch,
  signal?: AbortSignal,
): Promise<PasswordBreachResult> {
  if (!password) return { count: 0, available: true };
  try {
    return { count: await checkPasswordHashLeaked(await sha1Password(password), fetchImpl, signal), available: true };
  } catch (error) {
    if (isAbortError(error) || signal?.aborted) throw error;
    return { count: null, available: false };
  }
}

function hasSimpleSequence(value: string): boolean {
  const normalized = value.toLowerCase();
  return ['0123456789', '9876543210', 'abcdefghijklmnopqrstuvwxyz', 'zyxwvutsrqponmlkjihgfedcba', 'qwertyuiop', 'poiuytrewq']
    .some((sequence) => sequence.includes(normalized) || normalized.includes(sequence.slice(0, 5)));
}

export function isWeakPassword(password: string, username: string = ''): boolean {
  const normalized = password.toLowerCase();
  const compactUsername = username.split('@')[0]?.trim().toLowerCase() || '';
  if (COMMON_PASSWORDS.has(normalized) || password.length < 10) return true;
  if (/^(.)\1+$/.test(password) || hasSimpleSequence(password)) return true;
  if (compactUsername.length >= 3 && normalized.includes(compactUsername)) return true;
  const classes = [/[a-z]/.test(password), /[A-Z]/.test(password), /\d/.test(password), /[^A-Za-z0-9]/.test(password)].filter(Boolean).length;
  return password.length < 14 && classes < 3;
}

/** A login item with a password, still in the vault. */
export function isEligibleCipher(cipher: Cipher): boolean {
  return Number(cipher.type) === 1 && !cipher.deletedDate && !(cipher as { deletedAt?: string | null }).deletedAt && !!cipher.login?.decPassword;
}

async function mapWithConcurrency<T, R>(
  values: T[],
  limit: number,
  worker: (value: T) => Promise<R>,
  signal?: AbortSignal,
): Promise<R[]> {
  const results = new Array<R>(values.length);
  let nextIndex = 0;
  const run = async () => {
    while (true) {
      throwIfAborted(signal);
      const index = nextIndex;
      nextIndex += 1;
      if (index >= values.length) return;
      results[index] = await worker(values[index]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, values.length) }, run));
  return results;
}

export async function inspectVaultPasswordSecurity(
  ciphers: Cipher[],
  onProgress?: (checked: number, total: number) => void,
  fetchImpl: typeof fetch = fetch,
  signal?: AbortSignal,
): Promise<PasswordSecurityReport> {
  throwIfAborted(signal);
  const eligible = ciphers.filter(isEligibleCipher);
  const candidates: Candidate[] = await Promise.all(eligible.map(async (cipher) => {
    throwIfAborted(signal);
    const password = String(cipher.login?.decPassword || '');
    const username = String(cipher.login?.decUsername || '');
    return {
      cipherId: cipher.id,
      revisionDate: String(cipher.revisionDate || ''),
      name: String(cipher.decName || cipher.name || ''),
      hash: await sha1Password(password),
      weak: isWeakPassword(password, username),
    };
  }));
  const candidatesByHash = new Map<string, Candidate[]>();
  for (const candidate of candidates) {
    const group = candidatesByHash.get(candidate.hash) || [];
    group.push(candidate);
    candidatesByHash.set(candidate.hash, group);
  }

  const exposureByHash = new Map<string, PasswordBreachResult>();
  let checked = 0;
  await mapWithConcurrency([...candidatesByHash.keys()], MAX_CONCURRENT_BREACH_CHECKS, async (hash) => {
    throwIfAborted(signal);
    let result: PasswordBreachResult;
    try {
      result = { count: await checkPasswordHashLeaked(hash, fetchImpl, signal), available: true };
    } catch (error) {
      if (isAbortError(error) || signal?.aborted) throw error;
      result = { count: null, available: false };
    }
    exposureByHash.set(hash, result);
    // Only a lookup that produced a verdict counts as checked. A password the
    // breach database never answered for stays unchecked, and the report says so.
    if (result.count !== null) checked += candidatesByHash.get(hash)?.length || 0;
    onProgress?.(Math.min(checked, candidates.length), candidates.length);
    return result;
  }, signal);

  throwIfAborted(signal);

  const items = candidates.map((candidate) => {
    const exposure = exposureByHash.get(candidate.hash) || { count: null, available: false };
    return {
      cipherId: candidate.cipherId,
      revisionDate: candidate.revisionDate,
      exposedCount: exposure.count,
      reusedCount: candidatesByHash.get(candidate.hash)?.length || 1,
      weak: candidate.weak,
    };
  }).filter((item) => item.exposedCount === null || (item.exposedCount || 0) > 0 || item.reusedCount > 1 || item.weak)
    .sort((a, b) => (Number(b.exposedCount || 0) - Number(a.exposedCount || 0)) || (b.reusedCount - a.reusedCount) || Number(b.weak) - Number(a.weak) || a.cipherId.localeCompare(b.cipherId));

  return {
    eligibleCount: candidates.length,
    checkedCount: checked,
    exposedCount: candidates.filter((candidate) => (exposureByHash.get(candidate.hash)?.count || 0) > 0).length,
    reusedCount: candidates.filter((candidate) => (candidatesByHash.get(candidate.hash)?.length || 0) > 1).length,
    weakCount: candidates.filter((candidate) => candidate.weak).length,
    unavailableCount: candidates.filter((candidate) => exposureByHash.get(candidate.hash)?.count === null).length,
    items,
  };
}
