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
// The vault below holds one of everything the sync answers, and the test
// checks every class appeared at least once, so it cannot pass on an empty
// sync.
import assert from 'node:assert/strict';
import test from 'node:test';

import { NOW, ORG, WRITER, COL_SHARED, ENC, fixture, call } from './organization-fixture';

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

test('the sync carries every field the Android app requires', async () => {
  const { env } = await fixture();
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
      login: {
        username: ENC('me'),
        password: ENC('pw'),
        uris: [{ uri: ENC('https://a.example'), match: null }],
        fido2Credentials: [{
          credentialId: ENC('cred'),
          keyType: ENC('public-key'),
          keyAlgorithm: ENC('ECDSA'),
          keyCurve: ENC('P-256'),
          keyValue: ENC('key'),
          rpId: ENC('a.example'),
          counter: ENC('0'),
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
  ];
  for (const response of created) assert.equal(response.status, 200, await response.clone().text());

  const sync = (await (await call(env, 'https://vault.example.test/api/sync', 'GET', WRITER)).json()) as any;
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
