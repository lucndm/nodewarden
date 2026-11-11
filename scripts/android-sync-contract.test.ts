// The sync as the Bitwarden Android app parses it.
//
// The Android app decodes /api/sync with kotlinx.serialization: a field that is
// neither nullable nor defaulted is required, and one missing field drops the
// whole sync ("Fields [keyConnectorEnabled, selfHost, permissions] are
// required ... at path: $.profile.organizations[0]"). The TypeScript clients
// read leniently and never notice, so this checks the stricter reader.
//
// REQUIRED lists those fields per class, taken from bitwarden/android
// network/src/main/kotlin/com/bitwarden/network/model/SyncResponseJson.kt at
// 4cca57b0ce (2026-10-27). When the app adds a required field, add it here.
//
// ENCRYPTED lists the fields the SDK decrypts, so they have to arrive as
// encrypted strings: a plain value stops the sync with "CollectionDecrypt:
// The encrypted string is malformed" and takes the whole organization down
// with it. The list comes from the models the SDK decrypts in
// bitwarden/sdk-internal; add a field here when the official client starts
// decrypting a new one.
//
// The vault below holds one of everything the sync answers, and the test
// checks every class appeared at least once, so it cannot pass on an empty
// sync. Attachments are not covered: creating one needs an upload, which is
// out of scope here.
import assert from 'node:assert/strict';
import test from 'node:test';

import { NOW, ORG, WRITER, COL_SHARED, ENC, RSA_ENC, fixture, call } from './organization-fixture';
import { isValidEncString } from '../src/utils/enc-string';
import type { Env } from '../src/types';

/** The parts of the sync payload the checks walk. */
interface SyncPayload {
  profile?: { organizations?: Array<Record<string, unknown>> } & Record<string, unknown>;
  folders?: Array<Record<string, unknown>>;
  policies?: Array<Record<string, unknown>>;
  collections?: Array<Record<string, unknown>>;
  ciphers?: Array<CipherPayload>;
  sends?: Array<SendPayload>;
  domains?: { globalEquivalentDomains?: Array<Record<string, unknown>> } & Record<string, unknown>;
}

interface CipherPayload extends Record<string, unknown> {
  login?: { uris?: Array<Record<string, unknown>>; fido2Credentials?: Array<Record<string, unknown>> } & Record<string, unknown>;
  card?: Record<string, unknown>;
  identity?: Record<string, unknown>;
  sshKey?: Record<string, unknown>;
  fields?: Array<Record<string, unknown>>;
  passwordHistory?: Array<Record<string, unknown>>;
}

interface SendPayload extends Record<string, unknown> {
  text?: Record<string, unknown>;
}

const REQUIRED: Record<string, string[]> = {
  Profile: ['premiumFromOrganization', 'forcePasswordReset', 'emailVerified', 'twoFactorEnabled', 'premium', 'usesKeyConnector', 'id', 'creationDate'],
  Organization: ['usePolicies', 'keyConnectorEnabled', 'type', 'enabled', 'selfHost', 'permissions', 'id', 'useGroups', 'useDirectory', 'usersGetPremium', 'use2fa', 'useEvents', 'useTotp', 'useApi', 'status'],
  Permissions: ['manageResetPassword', 'managePolicies'],
  Folder: ['revisionDate', 'id'],
  Policy: ['organizationId', 'id', 'type', 'enabled'],
  Collection: ['organizationId', 'hidePasswords', 'name', 'readOnly', 'id'],
  Cipher: ['organizationUseTotp', 'reprompt', 'edit', 'revisionDate', 'type', 'creationDate', 'id', 'viewPassword', 'favorite'],
  CipherPermissions: ['delete', 'restore'],
  Field: ['type'],
  PasswordHistory: ['password', 'lastUsedDate'],
  SecureNote: ['type'],
  SshKey: ['privateKey'],
  Fido2Credential: ['credentialId', 'keyValue', 'rpId', 'counter', 'discoverable', 'creationDate'],
  Send: ['accessCount', 'revisionDate', 'hideEmail', 'type', 'deletionDate', 'disabled', 'id'],
  Text: ['hidden'],
  GlobalEquivalentDomain: ['excluded', 'type'],
};

/** The fields the SDK decrypts, per class. A plain value stops the sync. */
const ENCRYPTED: Record<string, string[]> = {
  Profile: ['key', 'privateKey'],
  Organization: ['key'],
  Folder: ['name'],
  Collection: ['name'],
  Cipher: ['name', 'notes', 'key'],
  Login: ['username', 'password', 'totp'],
  LoginUri: ['uri', 'uriChecksum'],
  Fido2Credential: ['credentialId', 'keyType', 'keyAlgorithm', 'keyCurve', 'keyValue', 'rpId', 'userHandle', 'userName', 'counter', 'rpName', 'userDisplayName', 'discoverable'],
  Card: ['cardholderName', 'brand', 'number', 'expMonth', 'expYear', 'code'],
  Identity: ['title', 'firstName', 'middleName', 'lastName', 'address1', 'address2', 'address3', 'city', 'state', 'postalCode', 'country', 'company', 'email', 'phone', 'ssn', 'username', 'passportNumber', 'licenseNumber'],
  SshKey: ['privateKey', 'publicKey', 'keyFingerprint'],
  Field: ['name', 'value'],
  PasswordHistory: ['password'],
  Send: ['name', 'notes', 'key'],
  Text: ['text'],
};

/** A field counts as present when it is there and not null, whatever its case. */
function check(kind: string, value: unknown, path: string, missing: string[], seen: Set<string>): void {
  if (!value || typeof value !== 'object') return;
  seen.add(kind);
  const fields = new Map(Object.entries(value as Record<string, unknown>).map(([k, v]) => [k.toLowerCase(), v]));
  for (const field of REQUIRED[kind]) {
    const present = fields.get(field.toLowerCase());
    if (present === undefined || present === null) missing.push(`${path}.${field}`);
  }
}

function each(list: unknown, fn: (item: any, index: number) => void): void {
  if (Array.isArray(list)) list.forEach(fn);
}

/**
 * A field the SDK decrypts has to arrive as an encrypted string: it may be
 * absent or null, but a plain value makes the app stop syncing.
 */
function checkEncrypted(kind: string, value: unknown, path: string, bad: string[], seen: Set<string>): void {
  if (!value || typeof value !== 'object') return;
  seen.add(kind);
  const fields = new Map(Object.entries(value as Record<string, unknown>).map(([k, v]) => [k.toLowerCase(), v]));
  for (const field of ENCRYPTED[kind]) {
    const present = fields.get(field.toLowerCase());
    if (present === undefined || present === null) continue;
    if (!isValidEncString(present)) bad.push(`${path}.${field} = ${String(present).slice(0, 40)}`);
  }
}

/**
 * The vault the sync is read from: one of everything the sync answers, every
 * value that has to be encrypted already encrypted.
 */
async function seedVault(env: Env): Promise<void> {
  await env.DB.prepare(
    'INSERT INTO organization_policies (id, org_id, type, enabled, data, revision_date) VALUES (?, ?, ?, ?, ?, ?)'
  )
    .bind('policy-1', ORG, 1, 1, '{"minLength":12}', NOW)
    .run();

  const created = [
    await call(env, 'https://vault.example.test/api/ciphers', 'POST', WRITER, {
      type: 1,
      name: ENC('Shared login'),
      login: { username: ENC('user'), password: ENC('pass') },
      organizationId: ORG,
      collectionIds: [COL_SHARED],
      key: ENC('item-key'),
    }),
    await call(env, 'https://vault.example.test/api/ciphers', 'POST', WRITER, {
      type: 1,
      name: ENC('Personal login'),
      notes: ENC('note'),
      login: {
        username: ENC('me'),
        password: ENC('pw'),
        totp: ENC('totp'),
        uris: [{ uri: ENC('https://a.example'), uriChecksum: ENC('checksum'), match: null }],
        fido2Credentials: [{
          credentialId: ENC('cred'),
          keyType: ENC('public-key'),
          keyAlgorithm: ENC('ECDSA'),
          keyCurve: ENC('P-256'),
          keyValue: ENC('key'),
          rpId: ENC('a.example'),
          userHandle: ENC('handle'),
          userName: ENC('user'),
          counter: ENC('0'),
          rpName: ENC('relying party'),
          userDisplayName: ENC('display name'),
          discoverable: ENC('true'),
          creationDate: NOW,
        }],
      },
      fields: [{ type: 0, name: ENC('field'), value: ENC('value') }],
      passwordHistory: [{ password: ENC('old'), lastUsedDate: NOW }],
    }),
    await call(env, 'https://vault.example.test/api/ciphers', 'POST', WRITER, {
      type: 2,
      name: ENC('Note'),
      secureNote: { type: 0 },
    }),
    await call(env, 'https://vault.example.test/api/ciphers', 'POST', WRITER, {
      type: 3,
      name: ENC('Card'),
      card: {
        cardholderName: ENC('Holder'),
        brand: ENC('Visa'),
        number: ENC('4111111111111111'),
        expMonth: ENC('12'),
        expYear: ENC('2030'),
        code: ENC('123'),
      },
    }),
    await call(env, 'https://vault.example.test/api/ciphers', 'POST', WRITER, {
      type: 4,
      name: ENC('Identity'),
      identity: {
        title: ENC('Dr'),
        firstName: ENC('First'),
        middleName: ENC('Middle'),
        lastName: ENC('Last'),
        address1: ENC('Address 1'),
        address2: ENC('Address 2'),
        address3: ENC('Address 3'),
        city: ENC('City'),
        state: ENC('State'),
        postalCode: ENC('12345'),
        country: ENC('Country'),
        company: ENC('Company'),
        email: ENC('me@example.test'),
        phone: ENC('123456789'),
        ssn: ENC('111222333'),
        username: ENC('me'),
        passportNumber: ENC('P1234567'),
        licenseNumber: ENC('L1234567'),
      },
    }),
    await call(env, 'https://vault.example.test/api/ciphers', 'POST', WRITER, {
      type: 5,
      name: ENC('SSH'),
      sshKey: { privateKey: ENC('private'), publicKey: ENC('public'), keyFingerprint: ENC('fingerprint') },
    }),
    await call(env, 'https://vault.example.test/api/folders', 'POST', WRITER, { name: ENC('Folder') }),
    // No hideEmail: a client that leaves it out stores null.
    await call(env, 'https://vault.example.test/api/sends', 'POST', WRITER, {
      type: 0,
      name: ENC('Send'),
      key: ENC('send-key'),
      text: { text: ENC('text'), hidden: false },
      deletionDate: new Date(Date.now() + 86_400_000).toISOString(),
      disabled: false,
    }),
    // An organization the way a client creates one, so its default collection
    // and its wrapped key travel the path the server takes.
    await call(env, 'https://vault.example.test/api/organizations', 'POST', WRITER, {
      name: 'Acme',
      key: RSA_ENC('wrapped-org-key'),
      collectionName: ENC('Default'),
      keys: { publicKey: 'public', encryptedPrivateKey: ENC('org-private') },
    }),
  ];
  for (const response of created) assert.equal(response.status, 200, await response.clone().text());
}

test('the sync carries every field the Android app requires', async () => {
  const { env } = await fixture();
  await seedVault(env);

  const sync = (await (await call(env, 'https://vault.example.test/api/sync', 'GET', WRITER)).json()) as SyncPayload;
  const missing: string[] = [];
  const seen = new Set<string>();

  check('Profile', sync.profile, 'profile', missing, seen);
  each(sync.profile?.organizations, (o, i) => {
    check('Organization', o, `profile.organizations[${i}]`, missing, seen);
    check('Permissions', o?.permissions, `profile.organizations[${i}].permissions`, missing, seen);
  });
  each(sync.folders, (o, i) => check('Folder', o, `folders[${i}]`, missing, seen));
  each(sync.policies, (o, i) => check('Policy', o, `policies[${i}]`, missing, seen));
  each(sync.collections, (o, i) => check('Collection', o, `collections[${i}]`, missing, seen));
  each(sync.ciphers, (c, i) => {
    const path = `ciphers[${i}]`;
    check('Cipher', c, path, missing, seen);
    check('CipherPermissions', c?.permissions, `${path}.permissions`, missing, seen);
    each(c?.fields, (f, j) => check('Field', f, `${path}.fields[${j}]`, missing, seen));
    each(c?.passwordHistory, (h, j) => check('PasswordHistory', h, `${path}.passwordHistory[${j}]`, missing, seen));
    check('SecureNote', c?.secureNote, `${path}.secureNote`, missing, seen);
    check('SshKey', c?.sshKey, `${path}.sshKey`, missing, seen);
    each(c?.login?.fido2Credentials, (f, j) => check('Fido2Credential', f, `${path}.login.fido2Credentials[${j}]`, missing, seen));
  });
  each(sync.sends, (s, i) => {
    check('Send', s, `sends[${i}]`, missing, seen);
    check('Text', s?.text, `sends[${i}].text`, missing, seen);
  });
  each(sync.domains?.globalEquivalentDomains, (d, i) => check('GlobalEquivalentDomain', d, `domains.globalEquivalentDomains[${i}]`, missing, seen));

  assert.deepEqual(missing, [], 'fields the Android app requires are missing');
  assert.deepEqual(
    Object.keys(REQUIRED).filter((kind) => !seen.has(kind)),
    [],
    'every class the check knows appears in the sync at least once'
  );
});

test('every encrypted field of the sync is an encrypted string', async () => {
  const { env } = await fixture();
  await seedVault(env);

  const sync = (await (await call(env, 'https://vault.example.test/api/sync', 'GET', WRITER)).json()) as SyncPayload;
  const bad: string[] = [];
  const seen = new Set<string>();

  checkEncrypted('Profile', sync.profile, 'profile', bad, seen);
  each(sync.profile?.organizations, (o, i) => checkEncrypted('Organization', o, `profile.organizations[${i}]`, bad, seen));
  each(sync.folders, (o, i) => checkEncrypted('Folder', o, `folders[${i}]`, bad, seen));
  each(sync.collections, (o, i) => checkEncrypted('Collection', o, `collections[${i}]`, bad, seen));
  each(sync.ciphers, (c, i) => {
    const path = `ciphers[${i}]`;
    checkEncrypted('Cipher', c, path, bad, seen);
    checkEncrypted('Login', c?.login, `${path}.login`, bad, seen);
    each(c?.login?.uris, (u, j) => checkEncrypted('LoginUri', u, `${path}.login.uris[${j}]`, bad, seen));
    checkEncrypted('Card', c?.card, `${path}.card`, bad, seen);
    checkEncrypted('Identity', c?.identity, `${path}.identity`, bad, seen);
    checkEncrypted('SshKey', c?.sshKey, `${path}.sshKey`, bad, seen);
    each(c?.fields, (f, j) => checkEncrypted('Field', f, `${path}.fields[${j}]`, bad, seen));
    each(c?.passwordHistory, (h, j) => checkEncrypted('PasswordHistory', h, `${path}.passwordHistory[${j}]`, bad, seen));
    each(c?.login?.fido2Credentials, (f, j) => checkEncrypted('Fido2Credential', f, `${path}.login.fido2Credentials[${j}]`, bad, seen));
  });
  each(sync.sends, (s, i) => {
    checkEncrypted('Send', s, `sends[${i}]`, bad, seen);
    checkEncrypted('Text', s?.text, `sends[${i}].text`, bad, seen);
  });

  assert.deepEqual(bad, [], 'every encrypted field of the sync is an encrypted string');
  assert.deepEqual(
    Object.keys(ENCRYPTED).filter((kind) => !seen.has(kind)),
    [],
    'every encrypted field the check knows appears in the sync at least once'
  );
});
