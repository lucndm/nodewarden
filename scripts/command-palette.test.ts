// The command palette finds the pages, the items and the fields of the items.
// These tests cover the matching, the ranking and the rule that a secret
// never reaches a result. No value of an item is printed.
import assert from 'node:assert/strict';
import test from 'node:test';

import { normalizeQuery, searchPalette, type PageEntry, type PaletteEntry } from '../webapp/src/lib/command-palette';
import type { Cipher } from '../webapp/src/lib/types';

const PAGES: PageEntry[] = [
  { id: 'vault', label: 'Vault', href: '/vault' },
  { id: 'sends', label: 'Sends', href: '/sends' },
  { id: 'verification-code', label: 'Verification Code', href: '/vault/totp' },
  { id: 'generator', label: 'Generator', href: '/generator' },
  { id: 'password-security', label: 'Password Security', href: '/security/password-health' },
  { id: 'import-export', label: 'Import & Export', href: '/backup/import-export' },
  { id: 'account-settings', label: 'Account Settings', href: '/settings/account' },
  { id: 'device-management', label: 'Device Management', href: '/settings/security/device-management' },
  { id: 'domain-rules', label: 'Domain Rules', href: '/settings/domain-rules' },
  { id: 'settings-appearance', label: 'Appearance', hint: 'Account Settings', href: '/settings/account', settingsSection: 'appearance' },
  { id: 'settings-session', label: 'Session timeout', hint: 'Account Settings', href: '/settings/account', settingsSection: 'session' },
  { id: 'settings-master-password', label: 'Master Password', hint: 'Account Settings', href: '/settings/account', settingsSection: 'masterPassword' },
  { id: 'settings-two-step', label: 'Two-step login', hint: 'Account Settings', href: '/settings/account', settingsSection: 'twoStep' },
  { id: 'settings-keys', label: 'Keys', hint: 'Account Settings', href: '/settings/account', settingsSection: 'keys' },
  { id: 'settings-sso', label: 'Single sign-on', hint: 'Account Settings', href: '/settings/account', settingsSection: 'sso' },
  { id: 'settings-emergency-access', label: 'Emergency access', hint: 'Account Settings', href: '/settings/account', settingsSection: 'emergencyAccess' },
];

const DIGITALOCEAN: Cipher = {
  id: 'cipher-digitalocean',
  type: 1,
  decName: 'Digitalocean',
  login: {
    decUsername: 'ops@digitalocean.com',
    decPassword: 'digitalocean-pass',
    decTotp: 'JBSWY3DPEHPK3PXP',
    uris: [{ uri: 'https://cloud.digitalocean.com/settings', decUri: 'https://cloud.digitalocean.com/settings' }],
  },
};

const BANK: Cipher = {
  id: 'cipher-bank',
  type: 1,
  decName: 'Bank',
  login: {
    decUsername: 'me@example.org',
    uris: [{ uri: 'https://secure.example.com/login', decUri: 'https://secure.example.com/login' }],
  },
};

const TRASHED: Cipher = {
  id: 'cipher-trashed',
  type: 1,
  decName: 'Old Mail',
  deletedDate: '2026-02-01T00:00:00.000Z',
  login: {
    decUsername: 'old@mail.com',
    decPassword: 'trashed-pass',
    uris: [{ uri: 'https://old.example.com', decUri: 'https://old.example.com' }],
  },
};

const GUARDED: Cipher = {
  id: 'cipher-guarded',
  type: 1,
  decName: 'Guarded',
  reprompt: 1,
  login: { decUsername: 'guard@example.com', decPassword: 'guarded-pass' },
};

const NO_SECRETS: Cipher = {
  id: 'cipher-no-secrets',
  type: 1,
  decName: 'No Secrets',
  viewPassword: false,
  login: { decUsername: 'hidden@example.com', decPassword: 'no-secrets-pass', decTotp: 'JBSWY3DPEHPK3PXP' },
} as Cipher;

const RICH: Cipher = {
  id: 'cipher-rich',
  type: 1,
  decName: 'Rich Item',
  decNotes: 'the note of the rich item',
  login: {
    decUsername: 'rich@example.com',
    decPassword: 'rich-pass',
    decTotp: 'JBSWY3DPEHPK3PXP',
    uris: [{ uri: 'https://rich.example.com', decUri: 'https://rich.example.com' }],
  },
  card: { decNumber: '4111111111111111', decCode: '987654' },
  fields: [
    { type: 0, decName: 'Reference', decValue: 'plain-reference' },
    { type: 1, decName: 'Recovery Key', decValue: 'hidden-secret-value' },
    { type: 2, decName: 'Flag', decValue: 'true' },
  ],
};

const KNOWN_FIELDS: Cipher = {
  id: 'cipher-known-fields',
  type: 1,
  decName: 'Known Fields',
  fields: [{ type: 0, decName: 'E-mail', decValue: 'known@example.test' }],
} as Cipher;

const AUTOFILL: Cipher = {
  id: 'cipher-autofill',
  type: 1,
  decName: 'Autofill Form',
  fields: [
    { type: 0, decName: 'remember me', decValue: '1' },
    { type: 0, decName: 'E-mail', decValue: 'autofill@example.test' },
  ],
} as Cipher;

const CIPHERS = [DIGITALOCEAN, BANK, TRASHED, GUARDED, NO_SECRETS, RICH, KNOWN_FIELDS, AUTOFILL];

const SECRETS = [
  'digitalocean-pass',
  'trashed-pass',
  'guarded-pass',
  'no-secrets-pass',
  'rich-pass',
  'JBSWY3DPEHPK3PXP',
  'hidden-secret-value',
  '4111111111111111',
  '987654',
  'the note of the rich item',
];

function pageEntries(results: PaletteEntry[]): Array<Extract<PaletteEntry, { kind: 'page' }>> {
  return results.filter((entry): entry is Extract<PaletteEntry, { kind: 'page' }> => entry.kind === 'page');
}

function itemEntries(results: PaletteEntry[]): Array<Extract<PaletteEntry, { kind: 'item' }>> {
  return results.filter((entry): entry is Extract<PaletteEntry, { kind: 'item' }> => entry.kind === 'item');
}

function fieldEntries(results: PaletteEntry[]): Array<Extract<PaletteEntry, { kind: 'field' }>> {
  return results.filter((entry): entry is Extract<PaletteEntry, { kind: 'field' }> => entry.kind === 'field');
}

test('a query loses its case, its diacritics and its extra spaces', () => {
  assert.equal(normalizeQuery('  Đăng  NHẬP '), 'dang nhap');
});

test('an empty query returns the pages only', () => {
  const results = searchPalette('', PAGES, CIPHERS);

  assert.ok(results.length > 0);
  assert.ok(results.every((entry) => entry.kind === 'page'));
});

test('a word of the query finds the tab of the settings page', () => {
  const results = searchPalette('two', PAGES, CIPHERS);
  const pages = pageEntries(results);

  assert.equal(pages.length, 1);
  assert.equal(pages[0].label, 'Two-step login');
  assert.equal(pages[0].settingsSection, 'twoStep');
});

test('an item is found by the host of its link', () => {
  const results = searchPalette('secure.example.com', PAGES, CIPHERS);
  const items = itemEntries(results);

  assert.equal(items.length, 1);
  assert.equal(items[0].cipherId, 'cipher-bank');
  assert.equal(items[0].hint, 'me@example.org · secure.example.com');
});

test('an item in the trash is gone from the results', () => {
  const results = searchPalette('old', PAGES, CIPHERS);

  assert.ok(!results.some((entry) => entry.kind !== 'page' && entry.cipherId === 'cipher-trashed'));
});

test('a field of an item is found by the name of the field', () => {
  const results = searchPalette('digital pass', PAGES, CIPHERS);
  const fields = fieldEntries(results);

  assert.equal(fields.length, 1);
  assert.equal(fields[0].field.type, 'password');
  assert.equal(fields[0].cipherId, 'cipher-digitalocean');
  assert.equal(fields[0].hint, 'Digitalocean');
  assert.ok(!fields[0].label.includes('digitalocean-pass'));
  assert.ok(!fields[0].hint.includes('digitalocean-pass'));
});

test('an item behind the master password still lists its fields', () => {
  const results = searchPalette('guarded', PAGES, CIPHERS);
  const fields = fieldEntries(results);

  assert.ok(fields.some((entry) => entry.cipherId === 'cipher-guarded' && entry.field.type === 'password'));
});

test('an item that hides its secrets lists no password and no one time code', () => {
  const results = searchPalette('no secrets', PAGES, CIPHERS);
  const fields = fieldEntries(results).filter((entry) => entry.cipherId === 'cipher-no-secrets');

  assert.ok(fields.some((entry) => entry.field.type === 'username'));
  assert.ok(!fields.some((entry) => entry.field.type === 'password' || entry.field.type === 'totp'));
});

test('a boolean field is not a result', () => {
  const results = searchPalette('rich', PAGES, CIPHERS);

  assert.ok(!fieldEntries(results).some((entry) => entry.label === 'Flag'));
});

test('a field with a known kind shows its translated label', () => {
  const results = searchPalette('known mail', PAGES, CIPHERS);
  const fields = fieldEntries(results);

  // The label of the field is the word of its kind, translated. A raw key
  // would be shown to the reader.
  assert.ok(fields.some((entry) => entry.label === 'Email'));
  assert.ok(!fields.some((entry) => entry.label.includes('txt_field_kind_')));
});

test('a noise field of an autofilled form is not a result', () => {
  const results = searchPalette('autofill', PAGES, CIPHERS);
  const fields = fieldEntries(results);

  assert.ok(fields.some((entry) => entry.cipherId === 'cipher-autofill' && entry.label === 'Email'));
  assert.ok(!fields.some((entry) => entry.label === 'remember me'));
});

test('no result carries a secret of an item', () => {
  for (const query of ['rich', 'item', 'e', 'key', 'number']) {
    for (const entry of searchPalette(query, PAGES, CIPHERS)) {
      const text = `${entry.label} ${entry.kind === 'page' ? '' : entry.hint}`;
      for (const secret of SECRETS) {
        assert.ok(!text.includes(secret), `a result of "${query}" carries a secret`);
      }
    }
  }
});
