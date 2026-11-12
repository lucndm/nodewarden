// The field display rules decide how a stored field is presented. These tests
// cover the label matching, the secret and noise detection and the note
// parsing. No field value is printed.
import assert from 'node:assert/strict';
import test from 'node:test';

import { normalizeLabel, parseNote, presentField, usernameKind } from '../webapp/src/lib/field-display';
import en from '../webapp/src/lib/i18n/locales/en';

test('labels are matched without case, diacritics and separators', () => {
  assert.equal(normalizeLabel('Họ và tên'), 'ho va ten');
  assert.equal(normalizeLabel('E-mail'), 'e mail');
  assert.equal(normalizeLabel('user[name]'), 'user name');
  assert.equal(normalizeLabel('code_box_input_item'), 'code box input item');
});

test('a known label resolves to its canonical kind', () => {
  assert.equal(presentField('E-mail', 0).kind, 'email');
  assert.equal(presentField('sdt', 0).kind, 'phone');
  assert.equal(presentField('Ngap cap', 0).kind, 'idIssueDate');
  assert.equal(presentField('CCCD', 0).kind, 'nationalId');
  assert.equal(presentField('calling code', 0).kind, 'other');
});

test('a canonical kind carries a label key that the locales know', () => {
  // A kind without a key of its own carries none, and every other kind names
  // a key that is translated, so a raw key never reaches the screen.
  assert.equal(presentField('calling code', 0).labelKey, null);
  for (const label of ['E-mail', 'sdt', 'Ngap cap', 'CCCD', 'username', 'website', 'one time code']) {
    const key = presentField(label, 0).labelKey;
    assert.ok(key, `${label} should carry a label key`);
    assert.ok(en[key], `${key} is not translated`);
  }
});

test('a label that looks like a secret is masked', () => {
  assert.equal(presentField('access key', 0).secret, true);
  assert.equal(presentField('API key', 0).secret, true);
  assert.equal(presentField('private ket', 0).secret, true);
  assert.equal(presentField('anything', 1).secret, true);
});

test('a plain label and a one time code stay readable', () => {
  assert.equal(presentField('client id', 0).secret, false);
  assert.equal(presentField('one-time code', 0).secret, false);
});

test('a boolean field is never a secret', () => {
  const field = presentField('remember me', 2);

  assert.equal(field.noise, true);
  assert.equal(field.secret, false);
});

test('leftovers of an autofilled form are noise', () => {
  assert.equal(presentField('Remember me', 0).noise, true);
  assert.equal(presentField('agreetoterms', 0).noise, true);
  assert.equal(presentField('Ghi nhớ đăng nhập', 0).noise, true);
  assert.equal(presentField('bef-data', 0).noise, true);
  assert.equal(presentField('email', 0).noise, false);
});

test('the username kind follows the value', () => {
  assert.equal(usernameKind('a@b.co'), 'email');
  assert.equal(usernameKind('+84 912 345 678'), 'phone');
  assert.equal(usernameKind('admin'), 'username');
});

test('a list of codes becomes one recovery code block', () => {
  const codes = ['A1B2C3D4', 'E5F6G7H8', 'I9J0K1L2', 'M3N4O5P6', 'Q7R8S9T0', 'U1V2W3X4'];
  const blocks = parseNote(codes.join('\n'));

  assert.equal(blocks.length, 1);
  const block = blocks[0];
  assert.equal(block.kind, 'recoveryCodes');
  assert.deepEqual(block.kind === 'recoveryCodes' ? block.codes : [], codes);
});

test('a key block keeps the text around it', () => {
  const blocks = parseNote(
    [
      'Text before the key',
      '-----BEGIN RSA PRIVATE KEY-----',
      'MIIEabc123',
      '-----END RSA PRIVATE KEY-----',
      'Text after the key',
    ].join('\n'),
  );

  assert.deepEqual(blocks.map((block) => block.kind), ['text', 'pem', 'text']);
});

test('a note with labelled lines becomes pairs', () => {
  const blocks = parseNote('Host: a\nPort: 22\nmật khẩu: x');

  assert.equal(blocks.length, 1);
  const block = blocks[0];
  assert.equal(block.kind, 'pairs');
  assert.deepEqual(block.kind === 'pairs' ? block.pairs : [], [
    { label: 'Host', value: 'a', secret: false },
    { label: 'Port', value: '22', secret: false },
    { label: 'mật khẩu', value: 'x', secret: true },
  ]);
});

test('free text stays one text block', () => {
  const blocks = parseNote('Just a note\nwith two lines');

  assert.deepEqual(blocks.map((block) => block.kind), ['text']);
});

test('an empty note has no blocks', () => {
  assert.deepEqual(parseNote(''), []);
});
