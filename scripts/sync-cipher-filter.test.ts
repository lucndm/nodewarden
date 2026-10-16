// isCipherResponseSyncCompatible is the gate on /api/sync: any cipher whose
// `name` fails the validator is silently dropped from the sync response, so
// the item vanishes in the client UI without an error. The validator is
// isValidEncString with one bug fixed: type 4 (RSA-2048-OAEP-SHA1) carries a
// single segment, not two, per bitwarden/sdk-internal
// (crates/bitwarden-crypto/src/enc_string/asymmetric.rs, parsers for enc_type
// 4 expect parts.len() == 1). The previous code lumped type 4 into the {0,1}
// branch (`>=2` segments) and dropped every RSA-2048 item on Android.
//
// These tests round-trip through cipherToResponse exactly as /api/sync does:
// the response is built first, then isCipherResponseSyncCompatible is asked.
import assert from 'node:assert/strict';
import test from 'node:test';

import { installTestGlobals } from './test-env';
installTestGlobals();

import {
  cipherToResponse,
  isCipherResponseSyncCompatible,
} from '../src/handlers/ciphers';
import type { Cipher } from '../src/types';

const B64 = (value: string) => Buffer.from(value, 'utf8').toString('base64');

function cipher(name: string): Cipher {
  return {
    id: 'cipher-id',
    userId: 'user-id',
    organizationId: null,
    type: 1,
    name,
    notes: null,
    folderId: null,
    favorite: false,
    data: null,
    key: null,
    archivedDate: null,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
    deletedAt: null,
    revisionDate: '2026-01-01T00:00:00.000Z',
    reprompt: 0,
    fields: null,
    login: null,
    identity: null,
    card: null,
    secureNote: null,
    sshKey: null,
    attachments: null,
    organizationUseTotp: false,
  } as unknown as Cipher;
}

// Build the public CipherResponse the same way /api/sync does, so the filter
// sees what the wire sees (cipherToResponse trims valid EncStrings, so the
// test must compare against the trimmed form).
function responseKept(name: string): boolean {
  const out = cipherToResponse(cipher(name));
  return isCipherResponseSyncCompatible(out);
}

// Spec: bitwarden/sdk-internal asymmetric.rs parses type 4 with 1 part.
// RSA-2048-OAEP-SHA1 is the canonical single-segment EncString.
test('type 4 RSA-2048 single-segment name is KEPT on /api/sync', () => {
  assert.equal(responseKept(`4.${B64('ciphertext')}`), true);
});

test('type 2 AES-256-CBC-HMAC three-segment name is KEPT on /api/sync', () => {
  // iv|data|mac — exactly three non-empty parts.
  assert.equal(responseKept(`2.${B64('iv')}|${B64('data')}|${B64('mac')}`), true);
});

test('type 0 legacy AES-256-CBC two-segment name is KEPT on /api/sync', () => {
  assert.equal(responseKept(`0.${B64('iv')}|${B64('data')}`), true);
});

test('type 5 COSE-ish / RSA-2048-OAEP-SHA256-HMAC two-segment name is KEPT on /api/sync', () => {
  // Per the symmetric parser scheme on the wire: type 5 carries data|mac
  // (2 parts). The validator's unknown-type branch keeps >=1 part, so this
  // must survive.
  assert.equal(responseKept(`5.${B64('a')}|${B64('b')}`), true);
});

test('plaintext (non-EncString) name is DROPPED on /api/sync', () => {
  assert.equal(responseKept('My Login'), false);
});

test('empty EncString `4.` (no parts) is DROPPED on /api/sync', () => {
  assert.equal(responseKept('4.'), false);
});

// Type 4 is single-segment per spec; `4.a|b|c` carries three parts and is
// not a valid type 4 wire string — it must be rejected so malformed data
// does not slip past the validator. (Other branches were `>=N` and would
// have accepted this; the bug was the exact inverse.)
test('type 4 with extra segments is malformed and is DROPPED on /api/sync', () => {
  assert.equal(responseKept(`4.${B64('a')}|${B64('b')}|${B64('c')}`), false);
});

// Defensive coverage: the rest of the wire types the spec documents.
test('type 6 RSA-2048-OAEP-SHA1-HMAC two-segment name is KEPT on /api/sync', () => {
  assert.equal(responseKept(`6.${B64('data')}|${B64('mac')}`), true);
});

test('unrecognized type with one part is KEPT (future-compat fallback)', () => {
  // The unknown-type branch keeps >=1 part so new upstream variants don't
  // get silently dropped.
  assert.equal(responseKept(`99.${B64('x')}`), true);
});
