import {
  inspectVaultPasswordSecurity,
  isEligibleCipher,
  type PasswordSecurityFinding,
  type PasswordSecurityReport,
} from '@/lib/password-security';
import type { Cipher } from '@/lib/types';

// The report lives in this module's memory only. It is never written to
// localStorage or IndexedDB and never leaves the browser, so a reload clears
// it. SPA navigation keeps it because the module stays loaded.

// A result that is older than this is no longer a result: the password may
// have changed and the breach corpus moves on.
export const PASSWORD_SECURITY_TTL_MS = 24 * 60 * 60 * 1000;

// What is known about the password of each item, bound to the revision of
// that item. A result for one item does not say anything about the others,
// so a change elsewhere in the vault does not throw it away.
const findings = new Map<string, PasswordSecurityFinding>();

function isExpired(checkedAt: number, now: number = Date.now()): boolean {
  return now - checkedAt > PASSWORD_SECURITY_TTL_MS;
}

/**
 * The valid result for an item, or null.
 *
 * Null means there is nothing to say: the item was never checked, the check
 * failed, the result is too old, or the item changed since it was checked.
 */
export function getPasswordSecurityFinding(
  cipherId: string,
  revisionDate: string | null | undefined
): PasswordSecurityFinding | null {
  const finding = findings.get(cipherId);
  if (!finding) return null;
  if (finding.revisionDate !== String(revisionDate || '')) return null;
  if (isExpired(finding.checkedAt)) return null;
  return finding;
}

/** Whether a scan is too old to be shown as a current result. */
export function isPasswordSecurityExpired(scannedAt: number | null | undefined): boolean {
  return !scannedAt || isExpired(scannedAt);
}

/**
 * Records what the vault check found.
 *
 * The report only lists the items that carry a finding, so the items it does
 * not mention were checked and came out clean.
 */
export function recordPasswordSecurityFindings(
  report: PasswordSecurityReport,
  ciphers: Cipher[],
  checkedAt: number
): void {
  const byCipher = new Map(report.items.map((item) => [item.cipherId, item]));
  for (const cipher of ciphers) {
    if (!isEligibleCipher(cipher)) continue;
    const item = byCipher.get(cipher.id);
    findings.set(cipher.id, {
      cipherId: cipher.id,
      revisionDate: item ? item.revisionDate : String(cipher.revisionDate || ''),
      source: 'scan',
      exposedCount: item ? item.exposedCount : 0,
      reusedCount: item ? item.reusedCount : 1,
      weak: item ? item.weak : false,
      checkedAt,
    });
  }
  notify();
}

/** Records the result of a check of one password alone. */
export function recordPasswordBreachFinding(
  cipherId: string,
  revisionDate: string,
  exposedCount: number | null
): void {
  findings.set(cipherId, {
    cipherId,
    revisionDate,
    source: 'breach',
    exposedCount,
    reusedCount: null,
    weak: null,
    checkedAt: Date.now(),
  });
  notify();
}

export interface PasswordSecurityState {
  fingerprint: string;
  report: PasswordSecurityReport | null;
  scannedAt: number | null;
  scanning: boolean;
  progress: { checked: number; total: number };
  scanError: boolean;
}

type InternalPasswordSecurityState = PasswordSecurityState & { controller: AbortController | null };

let state: InternalPasswordSecurityState | null = null;
const listeners = new Set<() => void>();

function notify(): void {
  listeners.forEach((listener) => listener());
}

function createState(fingerprint: string): InternalPasswordSecurityState {
  return { fingerprint, report: null, scannedAt: null, scanning: false, progress: { checked: 0, total: 0 }, scanError: false, controller: null };
}

function ensurePasswordSecurityState(fingerprint: string): InternalPasswordSecurityState {
  if (state?.fingerprint !== fingerprint) {
    state?.controller?.abort();
    state = createState(fingerprint);
  }
  return state;
}

export function getPasswordSecurityState(fingerprint: string): PasswordSecurityState {
  return ensurePasswordSecurityState(fingerprint);
}

export function readPasswordSecurityState(fingerprint: string): PasswordSecurityState | null {
  return state?.fingerprint === fingerprint ? state : null;
}

export function subscribePasswordSecurityState(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function startPasswordSecurityScan(fingerprint: string, ciphers: Cipher[]): void {
  const current = ensurePasswordSecurityState(fingerprint);
  current.controller?.abort();
  const controller = new AbortController();
  const total = ciphers.filter(isEligibleCipher).length;
  state = { ...current, report: null, scannedAt: null, scanning: true, progress: { checked: 0, total }, scanError: false, controller };
  notify();

  void (async () => {
    try {
      const report = await inspectVaultPasswordSecurity(ciphers, (checked, total) => {
        if (controller.signal.aborted || state?.controller !== controller) return;
        state = { ...state, progress: { checked, total } };
        notify();
      }, fetch, controller.signal);
      if (controller.signal.aborted || state?.controller !== controller) return;
      const scannedAt = Date.now();
      state = { ...state, report, scannedAt };
      recordPasswordSecurityFindings(report, ciphers, scannedAt);
    } catch (error) {
      if (controller.signal.aborted || (error as { name?: string } | null)?.name === 'AbortError') return;
      if (state?.controller === controller) state = { ...state, scanError: true };
    } finally {
      if (state?.controller === controller) state = { ...state, controller: null, scanning: false };
      notify();
    }
  })();
}

export function clearPasswordSecurityCache(): void {
  state?.controller?.abort();
  state = null;
  findings.clear();
  notify();
}
