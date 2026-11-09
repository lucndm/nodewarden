// The vault list names the day of an item the way the user would say it:
// today and yesterday are named, the rest is a date.
//
// The day is the day of the user's own clock, not of the server, so the test
// passes the clock in rather than reading it.
import assert from 'node:assert/strict';
import test from 'node:test';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { relativeDayLabel } from '../webapp/src/components/vault/vault-page-helpers';

const LABELS = { today: 'Today', yesterday: 'Yesterday' };
// A fixed moment: 2026-06-15 at 14:30 local time.
const NOW = new Date(2026, 5, 15, 14, 30, 0).getTime();

test('a moment of today is named today', () => {
  const earlier = new Date(2026, 5, 15, 0, 5, 0).getTime();
  assert.equal(relativeDayLabel(earlier, LABELS, NOW), 'Today');
});

test('a moment of yesterday is named yesterday', () => {
  const earlier = new Date(2026, 5, 14, 23, 55, 0).getTime();
  assert.equal(relativeDayLabel(earlier, LABELS, NOW), 'Yesterday');
});

test('a moment of the day before yesterday is a date, not a name', () => {
  const earlier = new Date(2026, 5, 13, 23, 55, 0).getTime();
  const label = relativeDayLabel(earlier, LABELS, NOW);
  assert.notEqual(label, 'Today');
  assert.notEqual(label, 'Yesterday');
  assert.match(label, /2026/);
});

test('the day before yesterday is still yesterday across a year boundary', () => {
  // 2027-01-01 at noon: the day before is 2026-12-31, which is a different
  // number of days from the start of the year than one day.
  const newYear = new Date(2027, 0, 1, 12, 0, 0).getTime();
  const lastYear = new Date(2026, 11, 31, 23, 0, 0).getTime();
  assert.equal(relativeDayLabel(lastYear, LABELS, newYear), 'Yesterday');
  assert.equal(relativeDayLabel(newYear, LABELS, newYear), 'Today');
});

test('the day before yesterday is yesterday across a month boundary', () => {
  const firstOfMonth = new Date(2026, 6, 1, 12, 0, 0).getTime();
  const lastOfJune = new Date(2026, 5, 30, 23, 0, 0).getTime();
  assert.equal(relativeDayLabel(lastOfJune, LABELS, firstOfMonth), 'Yesterday');
});

test('the day before yesterday is yesterday across a leap day', () => {
  const afterLeap = new Date(2028, 2, 1, 12, 0, 0).getTime();
  const leapDay = new Date(2028, 1, 29, 23, 0, 0).getTime();
  assert.equal(relativeDayLabel(leapDay, LABELS, afterLeap), 'Yesterday');
});

test('a moment that is not a time has no label', () => {
  assert.equal(relativeDayLabel(Number.NaN, LABELS, NOW), '');
});

test('the label comes from the caller, so it can be translated', () => {
  const translated = { today: 'Heute', yesterday: 'Gestern' };
  const earlier = new Date(2026, 5, 15, 0, 5, 0).getTime();
  assert.equal(relativeDayLabel(earlier, translated, NOW), 'Heute');
});
