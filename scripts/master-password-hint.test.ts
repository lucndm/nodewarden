// Master password hints are stored as plaintext (the bundled web vault writes
// user-typed text). Two callers build a profile response, with different
// needs:
//
//   - /api/sync (handleSync) feeds the response to the official Bitwarden
//     SDK, which parses masterPasswordHint as an EncString and throws
//     "Invalid length" on plaintext. Suppression is opt-in via
//     { suppressNonEncStringHint: true }. Suppression is unconditional on
//     this path: there is no shape check that cannot be faked, so the SDK
//     must never receive any stored value at all.
//
//   - /api/accounts/profile (handleGetProfile / handleUpdateProfile) is also
//     read by the bundled web vault to prefill the Settings form. That path
//     must return the stored plaintext as-is, including real EncStrings.
//     Default = no suppression.
//
// These tests cover both routes independently.
import assert from 'node:assert/strict';
import test from 'node:test';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { buildProfileResponse } from '../src/utils/profile-response';
import type { User } from '../src/types';

function makeUser(overrides: Partial<User> = {}): User {
  const base: User = {
    id: '00000000-0000-4000-8000-000000000001',
    email: 'alice@example.test',
    name: 'Alice',
    masterPasswordHint: null,
    masterPasswordHash: 'h',
    key: 'kwtest',
    privateKey: 'priv',
    publicKey: 'pub',
    kdfType: 0,
    kdfIterations: 100000,
    securityStamp: 'stamp',
    role: 'user',
    status: 'active',
    totpSecret: null,
    totpRecoveryCode: null,
    yubikeyKey1: null,
    yubikeyKey2: null,
    yubikeyKey3: null,
    yubikeyKey4: null,
    yubikeyKey5: null,
    yubikeyNfc: false,
    apiKey: null,
    ssoSubject: null,
    createdAt: '2026-10-16T00:00:00.000Z',
    updatedAt: '2026-10-16T00:00:00.000Z',
  };
  return { ...base, ...overrides };
}

const ENC = (value: string) =>
  `2.${Buffer.from('iv-' + value).toString('base64')}|${Buffer.from('ct-' + value).toString('base64')}|${Buffer.from('mac-' + value).toString('base64')}`;

// ── /api/sync path (official clients; SDK must never see plaintext) ────────
// /api/sync unconditionally suppresses masterPasswordHint to null. Anything
// less risks the SDK choking on a fakable shape.

test('/api/sync suppresses the plaintext 9-char hint to null', () => {
  // Mirrors the exact failing case from the Android 2026.9.1 flight recorder.
  const profile = buildProfileResponse(makeUser({ masterPasswordHint: 'myhint12' }), undefined, {
    suppressNonEncStringHint: true,
  });
  assert.equal(profile.masterPasswordHint, null);
});

test('/api/sync suppresses every non-EncString-shaped hint to null', () => {
  for (const value of [
    'plain',
    '',
    '   ',
    'no-dot-or-pipes',
    '2.noPipeParts',
    '2.',
    '.iv|ct|mac',
    'has.dot.but.no.pipes',
  ]) {
    const profile = buildProfileResponse(makeUser({ masterPasswordHint: value }), undefined, {
      suppressNonEncStringHint: true,
    });
    assert.equal(profile.masterPasswordHint, null, `hint ${JSON.stringify(value)} should be null`);
  }
});

// The previous shape-check was bypassable: any value matching "<dot>|<pipe>|<pipe>"
// passes it. These are the exact strings the prior fix leaked through. With
// unconditional suppression, they MUST all be null on /api/sync — and the
// test asserts it, so any future reintroduction of a shape-based filter
// makes this test fail.
test('/api/sync suppresses every fakable shape to null (no shape check left)', () => {
  for (const value of [
    'x.y|z', // not even close to EncString, but matched the old shape rule
    'foo.bar|baz|qux', // arbitrary text with the right shape
    'a.b|c', // the minimal-bypass string
    '2.a|b|c', // even a literal type-2 prefix cannot save it
  ]) {
    const profile = buildProfileResponse(makeUser({ masterPasswordHint: value }), undefined, {
      suppressNonEncStringHint: true,
    });
    assert.equal(
      profile.masterPasswordHint,
      null,
      `hint ${JSON.stringify(value)} must be suppressed on /api/sync`
    );
  }
});

test('/api/sync suppresses a real EncString-shaped hint to null', () => {
  // Even a real EncString is suppressed on /api/sync: there is no way for
  // the server to prove it is real without decoding it (which it does not do,
  // and which would defeat the purpose). The pre-existing
  // /api/accounts/profile path is the one that returns stored values verbatim.
  const realHint = ENC('real encrypted hint payload');
  const profile = buildProfileResponse(
    makeUser({ masterPasswordHint: realHint }),
    undefined,
    { suppressNonEncStringHint: true }
  );
  assert.equal(profile.masterPasswordHint, null);
});

// ── /api/accounts/profile path (bundled web vault prefill) ─────────────────

test('/api/accounts/profile returns the stored 9-char plaintext hint unchanged', () => {
  // The webapp SettingsPage reads profile.masterPasswordHint back to prefill
  // the hint input. A null here would look like "the hint disappeared" to
  // the user — it must round-trip verbatim.
  const profile = buildProfileResponse(makeUser({ masterPasswordHint: 'myhint12' }));
  assert.equal(profile.masterPasswordHint, 'myhint12');
});

test('/api/accounts/profile returns any stored plaintext hint unchanged', () => {
  for (const value of ['plain', 'no-dot-or-pipes', '2.noPipeParts', 'has.dot.but.no.pipes']) {
    const profile = buildProfileResponse(makeUser({ masterPasswordHint: value }));
    assert.equal(profile.masterPasswordHint, value, `hint ${JSON.stringify(value)} must round-trip`);
  }
});

test('/api/accounts/profile returns a legitimate EncString hint unchanged', () => {
  const realHint = ENC('real encrypted hint payload');
  const profile = buildProfileResponse(makeUser({ masterPasswordHint: realHint }));
  assert.equal(profile.masterPasswordHint, realHint);
});

test('null hint stays null on both paths', () => {
  assert.equal(
    buildProfileResponse(makeUser({ masterPasswordHint: null })).masterPasswordHint,
    null
  );
  assert.equal(
    buildProfileResponse(makeUser({ masterPasswordHint: null }), undefined, {
      suppressNonEncStringHint: true,
    }).masterPasswordHint,
    null
  );
});