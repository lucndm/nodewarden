// The emergency access table.
//
// One account lets another person in when they cannot get in themselves.
// The row holds the grantor's wrapped key, so the server never holds a key
// it could open. These checks pin the storage contract: the grant is found
// from either side, a grant that was addressed to an address is found before
// anybody claims it, and the wait is counted from the moment the recovery
// started.
import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { ensureStorageSchema } from '../src/services/storage-schema';
import { StorageService } from '../src/services/storage';
import {
  createEmergencyAccess,
  deleteEmergencyAccess,
  emergencyAccessDeadline,
  getEmergencyAccess,
  isEmergencyRecoveryAllowed,
  isValidEmergencyWaitDays,
  listEmergencyAccessByEmail,
  listEmergencyAccessByGrantee,
  listEmergencyAccessByGrantor,
  updateEmergencyAccess,
  EMERGENCY_ACCESS_STATUS_ACCEPTED,
  EMERGENCY_ACCESS_STATUS_CONFIRMED,
  EMERGENCY_ACCESS_TYPE_TAKEOVER,
  EMERGENCY_ACCESS_TYPE_VIEW,
  type EmergencyAccessRow,
} from '../src/services/storage-emergency-access-repo';
import { sqliteD1 } from './sqlite-d1';
import type { Env } from '../src/types';

const GRANTOR = '00000000-0000-4000-8000-0000000000a1';
const GRANTEE = '00000000-0000-4000-8000-0000000000a2';
const NOW = '2026-01-01T00:00:00.000Z';

async function fixture(): Promise<{ env: Env; storage: StorageService }> {
  const db = new DatabaseSync(':memory:');
  await ensureStorageSchema(sqliteD1(db));
  const env = { DB: sqliteD1(db) } as unknown as Env;
  const storage = new StorageService(env.DB);
  for (const [id, email] of [
    [GRANTOR, 'grantor@example.test'],
    [GRANTEE, 'grantee@example.test'],
  ]) {
    await storage.createUser({
      id,
      email,
      name: null,
      masterPasswordHint: null,
      masterPasswordHash: 'hash',
      key: 'key',
      privateKey: null,
      publicKey: null,
      kdfType: 0,
      kdfIterations: 600000,
      kdfMemory: null,
      kdfParallelism: null,
      securityStamp: 'stamp',
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
      userKeyId: null,
      createdAt: NOW,
      updatedAt: NOW,
    } as never);
  }
  return { env, storage };
}

function grant(overrides: Partial<EmergencyAccessRow> = {}): EmergencyAccessRow {
  return {
    id: 'grant-1',
    grantorId: GRANTOR,
    granteeId: null,
    email: 'grantee@example.test',
    wrappedKey: '4.wrapped-key',
    type: EMERGENCY_ACCESS_TYPE_VIEW,
    status: 0,
    waitTimeDays: 7,
    recoveryInitiatedAt: null,
    lastNotificationAt: null,
    createdAt: NOW,
    updatedAt: NOW,
    ...overrides,
  };
}

test('a grant is found from the side that gave it and the side that was given it', async () => {
  const { env } = await fixture();
  await createEmergencyAccess(env.DB, grant({ id: 'grant-1', granteeId: GRANTEE }));
  await createEmergencyAccess(env.DB, grant({ id: 'grant-2', email: 'someone-else@example.test' }));

  const given = await listEmergencyAccessByGrantor(env.DB, GRANTOR);
  assert.equal(given.length, 2);
  assert.deepEqual(given.map((row) => row.id).sort(), ['grant-1', 'grant-2']);

  const received = await listEmergencyAccessByGrantee(env.DB, GRANTEE);
  assert.equal(received.length, 1);
  assert.equal(received[0].id, 'grant-1');
  assert.equal(received[0].wrappedKey, '4.wrapped-key');
});

test('a grant that nobody claimed yet is still found by the address it was sent to', async () => {
  const { env } = await fixture();
  await createEmergencyAccess(env.DB, grant({ id: 'unclaimed', granteeId: null }));

  const byEmail = await listEmergencyAccessByEmail(env.DB, 'grantee@example.test');
  assert.equal(byEmail.length, 1);
  assert.equal(byEmail[0].id, 'unclaimed');
  assert.equal(byEmail[0].granteeId, null);
});

test('the grantor does not see the grants of somebody else', async () => {
  const { env } = await fixture();
  await createEmergencyAccess(env.DB, grant({ id: 'mine' }));
  const others = await listEmergencyAccessByGrantor(env.DB, GRANTEE);
  assert.equal(others.length, 0);
});

test('claiming a grant records the grantee and the status', async () => {
  const { env } = await fixture();
  await createEmergencyAccess(env.DB, grant({ id: 'grant-1' }));

  await updateEmergencyAccess(env.DB, 'grant-1', {
    granteeId: GRANTEE,
    status: EMERGENCY_ACCESS_STATUS_ACCEPTED,
    updatedAt: NOW,
  });
  const row = await getEmergencyAccess(env.DB, 'grant-1');
  assert.equal(row?.granteeId, GRANTEE);
  assert.equal(row?.status, EMERGENCY_ACCESS_STATUS_ACCEPTED);

  await updateEmergencyAccess(env.DB, 'grant-1', {
    granteeId: GRANTEE,
    status: EMERGENCY_ACCESS_STATUS_CONFIRMED,
    updatedAt: NOW,
  });
  assert.equal((await getEmergencyAccess(env.DB, 'grant-1'))?.status, EMERGENCY_ACCESS_STATUS_CONFIRMED);
});

test('a deleted grant is gone', async () => {
  const { env } = await fixture();
  await createEmergencyAccess(env.DB, grant({ id: 'grant-1' }));
  await deleteEmergencyAccess(env.DB, 'grant-1');
  assert.equal(await getEmergencyAccess(env.DB, 'grant-1'), null);
});

test('the wait is counted from the moment the recovery started', async () => {
  const { env } = await fixture();
  await createEmergencyAccess(env.DB, grant({ id: 'grant-1', waitTimeDays: 7 }));

  // The recovery has not started: there is no deadline to pass.
  const waiting = await getEmergencyAccess(env.DB, 'grant-1');
  assert.equal(emergencyAccessDeadline(waiting!), null);
  assert.equal(isEmergencyRecoveryAllowed(waiting!), false);

  await updateEmergencyAccess(env.DB, 'grant-1', {
    recoveryInitiatedAt: '2026-01-01T00:00:00.000Z',
    updatedAt: NOW,
  });
  const started = (await getEmergencyAccess(env.DB, 'grant-1'))!;
  assert.equal(emergencyAccessDeadline(started), '2026-01-08T00:00:00.000Z');

  // A day before the deadline the grantor may not approve yet.
  assert.equal(isEmergencyRecoveryAllowed(started, new Date('2026-01-07T23:59:59.000Z').getTime()), false);
  // At the deadline it may.
  assert.equal(isEmergencyRecoveryAllowed(started, new Date('2026-01-08T00:00:00.000Z').getTime()), true);
});

test('the wait time is one the format allows', () => {
  assert.equal(isValidEmergencyWaitDays(1), true);
  assert.equal(isValidEmergencyWaitDays(90), true);
  assert.equal(isValidEmergencyWaitDays(0), false);
  assert.equal(isValidEmergencyWaitDays(91), false);
  assert.equal(isValidEmergencyWaitDays(7.5), false);
});

test('a takeover is a different grant than a view', async () => {
  const { env } = await fixture();
  await createEmergencyAccess(env.DB, grant({ id: 'takeover', type: EMERGENCY_ACCESS_TYPE_TAKEOVER }));
  const row = await getEmergencyAccess(env.DB, 'takeover');
  assert.equal(row?.type, EMERGENCY_ACCESS_TYPE_TAKEOVER);
  assert.equal(row?.type === EMERGENCY_ACCESS_TYPE_VIEW, false);
});
