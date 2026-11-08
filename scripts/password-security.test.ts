// Checks the contract of the password health of an item.
//
// The check is real: the browser hashes the password and sends only an
// anonymous prefix to the breach database. What matters here is what may be
// said about a password afterwards: a password nobody looked at, a check that
// failed and a result that went stale are all "unknown", and none of them may
// be shown as a clean password.
//
// Coverage:
//   - the scan finds exposed, reused and weak passwords, and carries the
//     revision of the item it looked at;
//   - a breach database that never answered is unknown, not clean;
//   - a result for an older revision of the item does not answer for the
//     current one;
//   - a result that went stale is unknown;
//   - a check of one password alone says only what the breach database knows;
//   - unknown never turns into clean.
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  inspectVaultPasswordSecurity,
  isWeakPassword,
  passwordHealthState,
  sha1Password,
  type PasswordSecurityReport,
} from '../webapp/src/lib/password-security';
import {
  PASSWORD_SECURITY_TTL_MS,
  clearPasswordSecurityCache,
  getPasswordSecurityFinding,
  isPasswordSecurityExpired,
  recordPasswordBreachFinding,
  recordPasswordSecurityFindings,
} from '../webapp/src/lib/password-security-cache';
import type { Cipher } from '../webapp/src/lib/types';

const REVISION = '2026-11-08T00:00:00.000Z';

function cipher(id: string, password: string, revisionDate = REVISION, username = 'user@example.test'): Cipher {
  return {
    id,
    type: 1,
    revisionDate,
    login: { decPassword: password, decUsername: username, uris: null, totp: null },
  } as unknown as Cipher;
}

/**
 * A breach database that knows the given passwords.
 *
 * The real service answers with the suffixes that share the five character
 * prefix of the hash, so the stub has to know the hashes of the passwords it
 * is asked about.
 */
async function breachFetch(counts: Record<string, number>): Promise<typeof fetch> {
  const byPrefix = new Map<string, string[]>();
  for (const [password, count] of Object.entries(counts)) {
    const hash = await sha1Password(password);
    const prefix = hash.slice(0, 5);
    const lines = byPrefix.get(prefix) || [];
    lines.push(`${hash.slice(5)}:${count}`);
    byPrefix.set(prefix, lines);
  }
  return (async (input: RequestInfo | URL) => {
    const url = String(input);
    const prefix = url.slice(url.lastIndexOf('/') + 1);
    return new Response(`${(byPrefix.get(prefix) || []).join('\n')}\n`, { status: 200 });
  }) as unknown as typeof fetch;
}

test('the scan finds the risks and carries the revision of each item', async () => {
  const items = [
    cipher('exposed', 'Exposed-Password-1'),
    cipher('reused', 'Reused-Password-1'),
    cipher('reused-again', 'Reused-Password-1'),
    cipher('weak', 'abc'),
  ];
  const report = await inspectVaultPasswordSecurity(
    items,
    undefined,
    await breachFetch({ 'Exposed-Password-1': 3, 'Reused-Password-1': 0, abc: 0 })
  );
  assert.equal(report.eligibleCount, 4);
  const exposed = report.items.find((item) => item.cipherId === 'exposed');
  assert.equal(exposed?.exposedCount, 3);
  assert.equal(exposed?.revisionDate, REVISION, 'the result belongs to the state of the item');
  const reused = report.items.find((item) => item.cipherId === 'reused');
  assert.equal(reused?.reusedCount, 2);
  assert.equal(report.items.find((item) => item.cipherId === 'weak')?.weak, true);
  assert.equal(report.unavailableCount, 0);
});

test('a breach database that never answered is unknown, not clean', async () => {
  const failing = (async () => {
    throw new Error('the breach database is unreachable');
  }) as unknown as typeof fetch;
  const report = await inspectVaultPasswordSecurity([cipher('one', 'Some-Password-9')], undefined, failing);
  assert.equal(report.unavailableCount, 1);
  assert.equal(report.checkedCount, 0);
  const item = report.items.find((entry) => entry.cipherId === 'one');
  assert.equal(item?.exposedCount, null);
  assert.equal(passwordHealthState({
    cipherId: 'one',
    revisionDate: REVISION,
    source: 'scan',
    exposedCount: null,
    reusedCount: 1,
    weak: false,
    checkedAt: Date.now(),
  }).kind, 'unknown');
});

test('a scanned item without a risk is clean, and a changed item is unknown', () => {
  clearPasswordSecurityCache();
  const clean = cipher('clean', 'Long-Enough-Password-1');
  const report: PasswordSecurityReport = {
    eligibleCount: 1,
    checkedCount: 1,
    exposedCount: 0,
    reusedCount: 0,
    weakCount: 0,
    unavailableCount: 0,
    items: [],
  };
  recordPasswordSecurityFindings(report, [clean], Date.now());
  const finding = getPasswordSecurityFinding('clean', REVISION);
  assert.ok(finding, 'the scan answered for the item');
  assert.equal(finding.exposedCount, 0);
  assert.equal(passwordHealthState(finding).kind, 'clean');

  // The item changed since: the result belongs to the older state.
  assert.equal(getPasswordSecurityFinding('clean', '2026-11-09T00:00:00.000Z'), null);
  assert.equal(passwordHealthState(getPasswordSecurityFinding('clean', '2026-11-09T00:00:00.000Z')).kind, 'unknown');
});

test('a result that went stale is unknown', () => {
  clearPasswordSecurityCache();
  const item = cipher('stale', 'Long-Enough-Password-1');
  const report: PasswordSecurityReport = {
    eligibleCount: 1,
    checkedCount: 1,
    exposedCount: 0,
    reusedCount: 0,
    weakCount: 0,
    unavailableCount: 0,
    items: [],
  };
  const longAgo = Date.now() - PASSWORD_SECURITY_TTL_MS - 60_000;
  recordPasswordSecurityFindings(report, [item], longAgo);
  assert.equal(getPasswordSecurityFinding('stale', REVISION), null, 'an old result is no result');
  assert.equal(isPasswordSecurityExpired(longAgo), true);
  assert.equal(isPasswordSecurityExpired(Date.now()), false);
});

test('a check of one password alone says only what the breach database knows', () => {
  clearPasswordSecurityCache();
  recordPasswordBreachFinding('one', REVISION, 0);
  const finding = getPasswordSecurityFinding('one', REVISION);
  assert.ok(finding);
  assert.equal(finding.source, 'breach');
  assert.equal(finding.reusedCount, null, 'reuse was not looked at');
  assert.equal(finding.weak, null, 'weakness was not looked at');
  const state = passwordHealthState(finding);
  assert.equal(state.kind, 'breach-only');
  assert.equal(state.kind === 'breach-only' ? state.exposed : true, false);

  // A check that failed is unknown, never clean.
  recordPasswordBreachFinding('one', REVISION, null);
  assert.equal(passwordHealthState(getPasswordSecurityFinding('one', REVISION)).kind, 'unknown');
});

test('an item nobody looked at is unknown', () => {
  clearPasswordSecurityCache();
  assert.equal(getPasswordSecurityFinding('never', REVISION), null);
  const state = passwordHealthState(null);
  assert.equal(state.kind, 'unknown');
  assert.equal(state.kind === 'clean', false);
});

test('the weak check is a heuristic and says nothing about breaches', () => {
  assert.equal(isWeakPassword('password'), true);
  assert.equal(isWeakPassword('aaaaaaaaaaaa'), true);
  assert.equal(isWeakPassword('1234567890123'), true);
  assert.equal(isWeakPassword('correct-horse-battery-staple'), false);
});
