// The official Bitwarden Rust SDK parses profile.masterPasswordHint as an
// EncString (type.iv|ciphertext|mac). NodeWarden's bundled web vault writes
// plaintext ("myhint12"), which the SDK throws "EncString error, Invalid
// length: expected 32, got 9" on after every /api/sync — recorded 12 times
// in a single flight recorder.
//
// Strategy: keep accepting any string on write (web vault UX preserved) but
// suppress non-EncString values on read so the SDK never sees them.
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

test('plaintext 9-char hint is suppressed to null in profile response', () => {
  // Mirrors the exact failing case from the flight recorder.
  const profile = buildProfileResponse(makeUser({ masterPasswordHint: 'myhint12' }));
  assert.equal(profile.masterPasswordHint, null);
});

test('any non-EncString-shaped hint is suppressed to null', () => {
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
    const profile = buildProfileResponse(makeUser({ masterPasswordHint: value }));
    assert.equal(profile.masterPasswordHint, null, `hint ${JSON.stringify(value)} should be null`);
  }
});

test('legitimate EncString hint is passed through verbatim', () => {
  const realHint = ENC('real encrypted hint payload');
  const profile = buildProfileResponse(makeUser({ masterPasswordHint: realHint }));
  assert.equal(profile.masterPasswordHint, realHint);
});

test('null hint stays null', () => {
  const profile = buildProfileResponse(makeUser({ masterPasswordHint: null }));
  assert.equal(profile.masterPasswordHint, null);
});