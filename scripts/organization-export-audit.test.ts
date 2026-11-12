// The record of an export of an organization's items.
//
// The server never sees the exported data, so this record is the only trace
// an export leaves. These checks prove that an owner and an admin may record
// an export, that nobody else may, that a body which does not describe an
// export is refused, and that an export which cannot be written fails instead
// of passing unnoticed.
import assert from 'node:assert/strict';
import test from 'node:test';
import type {} from '@cloudflare/workers-types';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { call, createUser, fixture, NOW, ORG, OUTSIDER, OWNER, RSA_ENC, WRITER } from './organization-fixture';
import type { StorageService } from '../src/services/storage';
import type { Env } from '../src/types';

const ADMIN = 'user-admin';
const INVITED = 'user-invited';
const EXPORT_URL = `https://vault.example.test/api/organizations/${ORG}/export-events`;

interface ExportEvent {
  actorUserId: string | null;
  action: string;
  category: string;
  level: string;
  targetType: string | null;
  targetId: string | null;
  metadata: Record<string, unknown>;
}

/** The export events the server wrote. */
async function exportEvents(env: Env): Promise<ExportEvent[]> {
  const rows = await env.DB.prepare(
    'SELECT actor_user_id, action, category, level, target_type, target_id, metadata FROM audit_logs WHERE action = ?'
  )
    .bind('organization.vault.export')
    .all<Record<string, string>>();
  return (rows.results || []).map((row) => ({
    actorUserId: row.actor_user_id ?? null,
    action: row.action,
    category: row.category,
    level: row.level,
    targetType: row.target_type ?? null,
    targetId: row.target_id ?? null,
    metadata: JSON.parse(row.metadata || '{}') as Record<string, unknown>,
  }));
}

/** Adds a member to the organization of the fixture. */
async function addMember(env: Env, storage: StorageService, id: string, userId: string, type: number, status: number): Promise<void> {
  await createUser(storage, userId, `${userId}@example.test`);
  await env.DB.prepare(
    'INSERT INTO organization_users (id, user_id, org_id, type, status, key, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  )
    .bind(id, userId, ORG, type, status, RSA_ENC('wrapped-org-key'), NOW, NOW)
    .run();
}

test('an owner records an export of the organization', async () => {
  const { env } = await fixture();

  const response = await call(env, EXPORT_URL, 'POST', OWNER, { format: 'bitwarden_json', itemCount: 12 });

  assert.equal(response.status, 204);
  const events = await exportEvents(env);
  assert.equal(events.length, 1);
  assert.equal(events[0].actorUserId, OWNER);
  assert.equal(events[0].targetType, 'organization');
  assert.equal(events[0].targetId, ORG);
  assert.equal(events[0].category, 'data');
  assert.equal(events[0].level, 'security');
  assert.equal(events[0].metadata.format, 'bitwarden_json');
  assert.equal(events[0].metadata.itemCount, 12);
});

test('an admin records an export of the organization', async () => {
  const { env, storage } = await fixture();
  await addMember(env, storage, 'ou-admin', ADMIN, 1, 2);

  const response = await call(env, EXPORT_URL, 'POST', ADMIN, { format: 'bitwarden_csv', itemCount: 3 });

  assert.equal(response.status, 204);
  const events = await exportEvents(env);
  assert.equal(events.length, 1);
  assert.equal(events[0].actorUserId, ADMIN);
  assert.equal(events[0].metadata.format, 'bitwarden_csv');
  assert.equal(events[0].metadata.itemCount, 3);
});

test('a member who may not export is refused and nothing is written', async () => {
  const { env, storage } = await fixture();
  await addMember(env, storage, 'ou-invited', INVITED, 2, 0);

  const member = await call(env, EXPORT_URL, 'POST', WRITER, { format: 'bitwarden_json', itemCount: 1 });
  const invited = await call(env, EXPORT_URL, 'POST', INVITED, { format: 'bitwarden_json', itemCount: 1 });

  assert.equal(member.status, 404);
  assert.equal(invited.status, 404);
  assert.deepEqual(await exportEvents(env), []);
});

test('somebody outside the organization is refused and nothing is written', async () => {
  const { env } = await fixture();

  const response = await call(env, EXPORT_URL, 'POST', OUTSIDER, { format: 'bitwarden_json', itemCount: 1 });

  assert.equal(response.status, 404);
  assert.deepEqual(await exportEvents(env), []);
});

test('a body that does not describe an export is refused and nothing is written', async () => {
  const { env } = await fixture();

  const unknownFormat = await call(env, EXPORT_URL, 'POST', OWNER, { format: 'nodewarden_json', itemCount: 1 });
  const negativeCount = await call(env, EXPORT_URL, 'POST', OWNER, { format: 'bitwarden_json', itemCount: -1 });
  const missingCount = await call(env, EXPORT_URL, 'POST', OWNER, { format: 'bitwarden_json' });
  const brokenBody = await call(env, EXPORT_URL, 'POST', OWNER, 'not json');

  assert.equal(unknownFormat.status, 400);
  assert.equal(negativeCount.status, 400);
  assert.equal(missingCount.status, 400);
  assert.equal(brokenBody.status, 400);
  assert.deepEqual(await exportEvents(env), []);
});

test('an export that cannot be written fails instead of passing unnoticed', async () => {
  const { env } = await fixture();

  // The audit write fails, so the record of the export cannot be kept.
  const failingStatement: D1PreparedStatement = {
    bind: () => failingStatement,
    all: async () => ({ success: true, meta: { changes: 0 }, results: [] }),
    first: async () => null,
    raw: async () => ({ success: true, meta: { changes: 0 }, results: [] }),
    run: async () => {
      throw new Error('the audit write failed');
    },
  };
  const failingDb = {
    prepare: (sql: string) => (/INSERT INTO audit_logs/i.test(sql) ? failingStatement : env.DB.prepare(sql)),
    batch: (statements: D1PreparedStatement[]) => env.DB.batch(statements),
  };
  const failingEnv = { ...env, DB: failingDb as unknown as D1Database } as unknown as Env;

  const response = await call(failingEnv, EXPORT_URL, 'POST', OWNER, { format: 'bitwarden_json', itemCount: 2 });

  assert.equal(response.status, 503);
  // The record was not written, so the export must not happen either.
  assert.deepEqual(await exportEvents(env), []);
});
