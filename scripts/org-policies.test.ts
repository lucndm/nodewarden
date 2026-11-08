// Checks an organization policy: what the members may do, and who enforces it.
//
// A policy is the organization's decision for its members ("nobody in this
// organization may use Send"). The clients read it so they can grey out the
// button and say why; the server refuses the action itself, because a client
// that never reads a policy must not be able to ignore one.
//
// Coverage:
//   - only an owner or an admin sets a policy, and only for a known type;
//   - the policy reaches the clients: /api/policies and the sync carry it in
//     the shape the official clients read, with usePolicies set;
//   - a policy binds the members, not an invitation that was not answered;
//   - the server refuses Send for a member whose organization turned it off,
//     whoever calls and whatever client they use;
//   - turning the policy off gives Send back;
//   - an unknown policy type is refused instead of stored and ignored.
import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { installTestGlobals } from './test-env';
installTestGlobals();
import { handlePublicRoute } from '../src/router-public';
import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { StorageService } from '../src/services/storage';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { SEND_CONTROLS_POLICY } from '../src/services/storage-policy-repo';
import { buildBackupArchive, parseBackupArchive } from '../src/services/backup-archive';
import { importBackupArchiveBytes } from '../src/services/backup-import';
import { DatabaseSync as BackupDatabase } from 'node:sqlite';
import { sqliteD1 } from './sqlite-d1';
import type { Env, User } from '../src/types';

function enc(value: string): string {
  return `2.${Buffer.from(`iv-${value}`).toString('base64')}|${Buffer.from(`ct-${value}`).toString('base64')}|${Buffer.from(`mac-${value}`).toString('base64')}`;
}

interface Fixture {
  env: Env;
  storage: StorageService;
  owner: User;
  member: User;
  outsider: User;
  orgId: string;
}

/** The first account of an instance is the admin; the others need an invite. */
async function registerFirstAccount(env: Env, email: string): Promise<User> {
  const request = new Request('https://vault.example.test/api/accounts/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: 'https://vault.example.test' },
    body: JSON.stringify({
      email,
      name: email,
      masterPasswordHash: Buffer.from(`hash-${email}`).toString('base64'),
      key: enc(`vault-key-${email}`),
      kdf: 0,
      kdfIterations: 600000,
      keys: {
        publicKey: Buffer.from(`public-${email}`).toString('base64'),
        encryptedPrivateKey: enc(`private-${email}`),
      },
    }),
  });
  const response = await handlePublicRoute(request, env, '/api/accounts/register', 'POST', async () => null);
  assert.ok(response);
  assert.equal(response.status, 200, await response.clone().text());
  const user = await new StorageService(env.DB).getUser(email);
  assert.ok(user, `the account ${email} exists`);
  return user;
}

/** The rest of the accounts, written straight in: this check is about policies. */
async function addAccount(storage: StorageService, email: string): Promise<User> {
  const now = new Date().toISOString();
  const user: User = {
    id: crypto.randomUUID(),
    email,
    name: email,
    masterPasswordHint: null,
    masterPasswordHash: Buffer.from(`hash-${email}`).toString('base64'),
    key: enc(`vault-key-${email}`),
    privateKey: enc(`private-${email}`),
    publicKey: Buffer.from(`public-${email}`).toString('base64'),
    kdfType: 0,
    kdfIterations: 600000,
    securityStamp: crypto.randomUUID(),
    role: 'user',
    status: 'active',
    verifyDevices: false,
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
    userKeyId: null,
    createdAt: now,
    updatedAt: now,
  };
  await storage.createUser(user);
  return user;
}

async function fixture(): Promise<Fixture> {
  const db = new DatabaseSync(':memory:');
  await ensureStorageSchema(sqliteD1(db));
  const env = { DB: sqliteD1(db), JWT_SECRET: 'org-policies-secret-0123456789abcdef' } as unknown as Env;
  const storage = new StorageService(env.DB);
  const owner = await registerFirstAccount(env, 'org-owner@example.test');
  const member = await addAccount(storage, 'org-member@example.test');
  const outsider = await addAccount(storage, 'not-in-an-org@example.test');

  const orgId = 'org-policies-test';
  const now = new Date().toISOString();
  await storage.createOrganizationWithOwner({
    id: orgId,
    name: 'Policy Org',
    privateKey: enc('org-private'),
    publicKey: Buffer.from('org-public').toString('base64'),
    ownerUserId: owner.id,
    ownerMembershipId: 'membership-owner',
    wrappedOrganizationKey: enc('wrapped-org-key'),
    collectionId: 'collection-default',
    collectionName: enc('Default'),
    now,
  });
  await storage.addOrganizationUser({
    id: 'membership-member',
    userId: member.id,
    orgId,
    type: 2,
    status: 2,
    now,
  });
  return { env, storage, owner, member, outsider, orgId };
}

async function call(
  fixture: Fixture,
  path: string,
  method: string,
  actor: User,
  body?: unknown
): Promise<Response> {
  const request = new Request(`https://vault.example.test${path}`, {
    method,
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const response = await handleAuthenticatedRoute(request, fixture.env, actor.id, actor as never, path, method);
  assert.ok(response, `no route answered ${method} ${path}`);
  return response;
}

const setSendPolicy = (fixture: Fixture, actor: User, enabled: boolean) =>
  call(fixture, `/api/organizations/${fixture.orgId}/policies/${SEND_CONTROLS_POLICY}`, 'PUT', actor, {
    enabled,
    data: { DisableSend: enabled },
  });

const createSend = (fixture: Fixture, actor: User) =>
  call(fixture, '/api/sends', 'POST', actor, {
    type: 0,
    name: enc('A text send'),
    key: enc('send-key'),
    text: { text: enc('hello'), hidden: false },
    deletionDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
  });

test('only an owner or an admin sets a policy, and only for a known type', async () => {
  const current = await fixture();
  const memberAttempt = await setSendPolicy(current, current.member, true);
  assert.equal(memberAttempt.status, 403);

  const unknownType = await call(
    current,
    `/api/organizations/${current.orgId}/policies/999`,
    'PUT',
    current.owner,
    { enabled: true, data: {} }
  );
  assert.equal(unknownType.status, 400);
  const body = await unknownType.json() as { error?: string };
  assert.match(String(body.error || ''), /not supported/i);

  const ownerAttempt = await setSendPolicy(current, current.owner, true);
  assert.equal(ownerAttempt.status, 200);
  const saved = await ownerAttempt.json() as { data?: { DisableSend?: boolean }; enabled?: boolean; object?: string };
  assert.equal(saved.object, 'policy');
  assert.equal(saved.enabled, true);
  assert.equal(saved.data?.DisableSend, true);
});

test('the policy reaches the clients through the policies list and the sync', async () => {
  const current = await fixture();
  assert.equal((await setSendPolicy(current, current.owner, true)).status, 200);

  const list = await call(current, '/api/policies', 'GET', current.member);
  assert.equal(list.status, 200);
  const body = await list.json() as { data?: Array<{ type?: number; organizationId?: string; data?: { DisableSend?: boolean } }> };
  assert.equal(body.data?.length, 1);
  assert.equal(body.data?.[0].type, SEND_CONTROLS_POLICY);
  assert.equal(body.data?.[0].organizationId, current.orgId);
  assert.equal(body.data?.[0].data?.DisableSend, true);

  const sync = await call(current, '/api/sync', 'GET', current.member);
  assert.equal(sync.status, 200);
  const synced = await sync.json() as {
    policies?: Array<{ type?: number }>;
    policiesNew?: Array<{ type?: number }>;
    profile?: { organizations?: Array<{ usePolicies?: boolean }> };
  };
  assert.equal(synced.policies?.length, 1);
  assert.equal(synced.policiesNew?.length, 1);
  assert.equal(synced.profile?.organizations?.[0].usePolicies, true);

  // Someone who is not in the organization reads no policy at all.
  const outsiderList = await call(current, '/api/policies', 'GET', current.outsider);
  const outsiderBody = await outsiderList.json() as { data?: unknown[] };
  assert.equal(outsiderBody.data?.length, 0);
});

test('the server refuses Send for a member, and gives it back when the policy is off', async () => {
  const current = await fixture();
  // Before the policy, a personal Send is made the usual way.
  const before = await createSend(current, current.member);
  assert.equal(before.status, 200, await before.clone().text());

  assert.equal((await setSendPolicy(current, current.owner, true)).status, 200);

  const refused = await createSend(current, current.member);
  assert.equal(refused.status, 403);
  const body = await refused.json() as { error?: string };
  assert.match(String(body.error || ''), /turned off/i);

  // The refusal is the server's, so a client that never reads the policy is
  // refused the same way: this call carries nothing but the request itself.
  const ownerRefused = await createSend(current, current.owner);
  assert.equal(ownerRefused.status, 403);

  // An account outside the organization keeps its Send.
  const outsider = await createSend(current, current.outsider);
  assert.equal(outsider.status, 200, await outsider.clone().text());

  assert.equal((await setSendPolicy(current, current.owner, false)).status, 200);
  const after = await createSend(current, current.member);
  assert.equal(after.status, 200, await after.clone().text());
});

test('the policy survives an instance backup and restore', async () => {
  const current = await fixture();
  assert.equal((await setSendPolicy(current, current.owner, true)).status, 200);

  const archive = await buildBackupArchive(current.env, new Date(), { includeAttachments: false });
  const payload = parseBackupArchive(archive.bytes).payload;
  const exported = (payload.db as { organization_policies?: Array<Record<string, unknown>> }).organization_policies || [];
  assert.equal(exported.length, 1, 'the archive carries the policy');
  assert.equal(exported[0].org_id, current.orgId);
  assert.equal(Number(exported[0].type), SEND_CONTROLS_POLICY);
  assert.equal(Number(exported[0].enabled), 1);

  // A fresh instance, restored from that archive, holds the same policy.
  const targetDb = new BackupDatabase(':memory:');
  await ensureStorageSchema(sqliteD1(targetDb));
  const targetEnv = { DB: sqliteD1(targetDb), JWT_SECRET: 'org-policies-secret-0123456789abcdef' } as unknown as Env;
  const result = await importBackupArchiveBytes(archive.bytes, targetEnv, current.owner.id, false);
  assert.ok(result, 'the restore ran');
  const restored = new StorageService(targetEnv.DB);
  const policy = await restored.getOrganizationPolicy(current.orgId, SEND_CONTROLS_POLICY);
  assert.ok(policy, 'the policy comes back with the instance');
  assert.equal(policy?.enabled, true);
  assert.equal(policy?.data, JSON.stringify({ DisableSend: true }));
  assert.equal(await restored.userHasSendDisabled(current.owner.id), true);
});

test('a policy binds the members, not an invitation that was not answered', async () => {
  const current = await fixture();
  assert.equal((await setSendPolicy(current, current.owner, true)).status, 200);

  const invited = await addAccount(current.storage, 'org-invited@example.test');
  await current.storage.addOrganizationUser({
    id: 'membership-invited',
    userId: invited.id,
    orgId: current.orgId,
    type: 2,
    status: 0,
    now: new Date().toISOString(),
  });

  const list = await call(current, '/api/policies', 'GET', invited);
  const body = await list.json() as { data?: unknown[] };
  assert.equal(body.data?.length, 0, 'an unanswered invitation carries no policy');

  const send = await createSend(current, invited);
  assert.equal(send.status, 200, 'and it does not lose the Send it never agreed to');
});
