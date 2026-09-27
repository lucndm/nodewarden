// Handler-level tests for cipher tags (NodeWarden web-vault organization
// feature). Bitwarden has no tags; the field rides on the cipher payload and
// is preserved across official-client edits.
//
// Coverage:
//   - create stores a normalized tag list;
//   - a full update WITHOUT a tags field (what official Bitwarden clients
//     send) preserves existing tags;
//   - a full update WITH tags replaces them; tags: null clears them;
//   - normalizeCipherTags trims/dedupes/caps and rejects non-arrays.
import assert from 'node:assert/strict';
import test from 'node:test';

import { installTestGlobals } from './test-env';
installTestGlobals();

import {
  handleCreateCipher,
  handleUpdateCipher,
  normalizeCipherTags,
} from '../src/handlers/ciphers';
import { MemoryD1 } from './memory-d1';
import type { Env } from '../src/types';

const ENC = (value: string) =>
  `2.${Buffer.from('iv-' + value).toString('base64')}|${Buffer.from('ct-' + value).toString('base64')}|${Buffer.from('mac-' + value).toString('base64')}`;

function env(): Env {
  return { DB: new MemoryD1() } as unknown as Env;
}

async function createCipherWithTags(envArg: Env, tags: unknown): Promise<Record<string, unknown>> {
  const response = await handleCreateCipher(
    new Request('https://vault.example.test/api/ciphers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 1, name: ENC('Example'), tags }),
    }),
    envArg,
    'user-1'
  );
  assert.equal(response.status, 200, 'create must succeed');
  return (await response.json()) as Record<string, unknown>;
}

test('normalizeCipherTags trims, dedupes case-insensitively, caps and rejects junk', () => {
  assert.equal(normalizeCipherTags('not-an-array'), null);
  assert.equal(normalizeCipherTags(null), null);
  assert.deepEqual(normalizeCipherTags([]), null, 'empty list collapses to null');
  assert.deepEqual(
    normalizeCipherTags(['  work ', 'Work', 'WORK', '', '  ', 'finance', 'x'.repeat(100)]),
    ['work', 'finance', 'x'.repeat(64)]
  );
  const many = Array.from({ length: 40 }, (_, i) => `tag${i}`);
  assert.equal(normalizeCipherTags(many)!.length, 24);
});

test('full update round-trip: absent tags preserved, present tags replaced, null clears', async () => {
  const db = new MemoryD1();
  const envArg = { DB: db } as unknown as Env;
  const created = await createCipherWithTags(envArg, ['work']);

  const preserved = await handleUpdateCipher(
    new Request(`https://vault.example.test/api/ciphers/${created.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 1, name: ENC('Renamed 1') }),
    }),
    envArg,
    'user-1',
    String(created.id)
  );
  assert.equal(preserved.status, 200);
  const preservedBody = (await preserved.json()) as { tags?: string[] };
  assert.deepEqual(preservedBody.tags, ['work'], 'absent tags field must not wipe tags');

  const replaced = await handleUpdateCipher(
    new Request(`https://vault.example.test/api/ciphers/${created.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 1, name: ENC('Renamed 2'), tags: ['travel', 'to-do'] }),
    }),
    envArg,
    'user-1',
    String(created.id)
  );
  assert.equal(replaced.status, 200);
  const replacedBody = (await replaced.json()) as { tags?: string[] };
  assert.deepEqual(replacedBody.tags, ['travel', 'to-do']);

  const cleared = await handleUpdateCipher(
    new Request(`https://vault.example.test/api/ciphers/${created.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 1, name: ENC('Renamed 3'), tags: null }),
    }),
    envArg,
    'user-1',
    String(created.id)
  );
  assert.equal(cleared.status, 200);
  const clearedBody = (await cleared.json()) as { tags?: string[] | null };
  assert.equal(clearedBody.tags, null, 'explicit null clears tags');
});
