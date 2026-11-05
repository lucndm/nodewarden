// The webapp owns two rules of the password copy counters: how a new count is
// merged into the ones it already knows, and how the vault list is ordered by
// them. The counters themselves live on the server.
import assert from 'node:assert/strict';
import test from 'node:test';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { mergeCipherUsageEntry, type CipherUsageMap } from '../webapp/src/lib/api/vault';
import { compareCipherUsage } from '../webapp/src/components/vault/vault-page-helpers';

const collator = new Intl.Collator(undefined, { sensitivity: 'base', numeric: true });

test('a copy updates the count of that item only', () => {
  const usage: CipherUsageMap = { a: { useCount: 1, lastUsedAt: null } };
  const merged = mergeCipherUsageEntry(usage, 'b', { useCount: 2, lastUsedAt: '2026-05-02T09:00:00.000Z' });
  assert.deepEqual(merged, {
    a: { useCount: 1, lastUsedAt: null },
    b: { useCount: 2, lastUsedAt: '2026-05-02T09:00:00.000Z' },
  });
  assert.deepEqual(usage, { a: { useCount: 1, lastUsedAt: null } });
});

test('counters that never loaded stay unknown instead of turning into zeros', () => {
  assert.equal(mergeCipherUsageEntry(null, 'a', { useCount: 1, lastUsedAt: null }), null);
});

test('a slow answer never lowers a count a newer answer already set', () => {
  const usage: CipherUsageMap = { a: { useCount: 3, lastUsedAt: '2026-05-02T09:00:00.000Z' } };
  const merged = mergeCipherUsageEntry(usage, 'a', { useCount: 2, lastUsedAt: '2026-05-01T09:00:00.000Z' });
  assert.deepEqual(merged, usage);
});

test('most used puts the most copied item first', () => {
  const counts = new Map([['a', 3], ['b', 7], ['c', 1]]);
  const items = [{ id: 'a', name: 'Alpha' }, { id: 'b', name: 'Bravo' }, { id: 'c', name: 'Charlie' }];
  const sorted = [...items].sort((x, y) => compareCipherUsage(x, y, counts, collator));
  assert.deepEqual(sorted.map((item) => item.id), ['b', 'a', 'c']);
});

test('equal counts fall back to the name and then to the id', () => {
  const counts = new Map([['b', 2], ['a', 2], ['c', 2]]);
  const items = [{ id: 'c', name: 'Same' }, { id: 'b', name: 'Same' }, { id: 'a', name: 'Same' }];
  const sorted = [...items].sort((x, y) => compareCipherUsage(x, y, counts, collator));
  assert.deepEqual(sorted.map((item) => item.id), ['a', 'b', 'c']);
});

test('an item without a counter counts as zero', () => {
  const counts = new Map([['b', 1]]);
  const items = [{ id: 'a', name: 'Alpha' }, { id: 'b', name: 'Bravo' }];
  const sorted = [...items].sort((x, y) => compareCipherUsage(x, y, counts, collator));
  assert.deepEqual(sorted.map((item) => item.id), ['b', 'a']);
});
