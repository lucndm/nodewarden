// Checks the export of the audit log.
//
// The log holds the events that matter for the account. Whoever has to read
// it outside the app needs a file, and that file must not carry a secret -
// not even one that an old event was written with.
//
// Coverage:
//   - the export answers a CSV with the columns an auditor reads;
//   - the filters on screen apply to the export as well;
//   - the metadata is cleaned again on the way out, so a stored row that
//     holds a secret does not carry it into the file;
//   - only an admin may export; anyone else is refused;
//   - the export says when it was cut short.
import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { installTestGlobals } from './test-env';
installTestGlobals();
import { handlePublicRoute } from '../src/router-public';
import { handleAdminRoute } from '../src/router-admin';
import { StorageService } from '../src/services/storage';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { writeAuditEvent } from '../src/services/audit-events';
import { sqliteD1 } from './sqlite-d1';
import type { Env } from '../src/types';
import type { User } from '../src/types';

const EMAIL = 'audit-export@example.test';
const PASSWORD = Buffer.from(`hash-${EMAIL}`).toString('base64');

function enc(value: string): string {
  return `2.${Buffer.from(`iv-${value}`).toString('base64')}|${Buffer.from(`ct-${value}`).toString('base64')}|${Buffer.from(`mac-${value}`).toString('base64')}`;
}

async function fixture(): Promise<{ env: Env; storage: StorageService; admin: User }> {
  const db = new DatabaseSync(':memory:');
  await ensureStorageSchema(sqliteD1(db));
  const env = { DB: sqliteD1(db), JWT_SECRET: 'audit-export-secret-0123456789abcdef' } as unknown as Env;
  const storage = new StorageService(env.DB);

  const request = new Request('https://vault.example.test/api/accounts/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: 'https://vault.example.test' },
    body: JSON.stringify({
      email: EMAIL,
      name: 'Audit Export',
      masterPasswordHash: PASSWORD,
      key: enc('vault-key'),
      kdf: 0,
      kdfIterations: 600000,
      keys: {
        publicKey: Buffer.from('public-key').toString('base64'),
        encryptedPrivateKey: enc('private-key'),
      },
    }),
  });
  const registered = await handlePublicRoute(request, env, '/api/accounts/register', 'POST', async () => null);
  assert.ok(registered, 'the register route answered');
  assert.equal(registered.status, 200, await registered.clone().text());

  const user = await storage.getUser(EMAIL);
  assert.ok(user, 'the account exists');
  // The first account of an instance is the admin, which is who may export.
  const admin = { ...user, role: 'admin', status: 'active' } as User;
  return { env, storage, admin };
}

async function exportCsv(env: Env, admin: User, query = ''): Promise<Response> {
  const request = new Request(`https://vault.example.test/api/admin/logs/export${query}`);
  const response = await handleAdminRoute(request, env, admin, '/api/admin/logs/export', 'GET');
  assert.ok(response, 'the export route answered');
  return response;
}

test('the export answers a CSV with the columns an auditor reads', async () => {
  const { env, storage, admin } = await fixture();
  await writeAuditEvent(storage, {
    actorUserId: admin.id,
    action: 'security.scan.exclude',
    category: 'security',
    level: 'info',
    targetType: 'cipher',
    targetId: 'cipher-1',
    metadata: { email: 'someone@example.test', method: 'PUT' },
  });

  const response = await exportCsv(env, admin);
  assert.equal(response.status, 200);
  assert.match(response.headers.get('Content-Type') || '', /text\/csv/);
  assert.match(response.headers.get('Content-Disposition') || '', /audit-log-\d{4}-\d{2}-\d{2}\.csv/);

  const csv = await response.text();
  const lines = csv.trim().split('\n');
  assert.match(lines[0], /"id","created_at","actor_email","action","category","level"/);
  // The header and every event the account has, the registration included.
  assert.equal(lines.length, Number(response.headers.get('X-Audit-Export-Rows')) + 1);
  const row = lines.find((line) => line.includes('security.scan.exclude'));
  assert.ok(row, 'the event is in the file');
  assert.ok(row.includes('security'));
  assert.ok(row.includes(admin.email));
  assert.ok(row.includes('someone@example.test'));
  assert.equal(response.headers.get('X-Audit-Export-Truncated'), 'false');
});

test('the filters on screen apply to the export as well', async () => {
  const { env, storage, admin } = await fixture();
  await writeAuditEvent(storage, {
    actorUserId: admin.id,
    action: 'security.scan.exclude',
    category: 'security',
    level: 'info',
    targetType: 'cipher',
    targetId: 'cipher-1',
  });
  await writeAuditEvent(storage, {
    actorUserId: admin.id,
    action: 'user.login',
    category: 'auth',
    level: 'warn',
    targetType: 'user',
    targetId: admin.id,
  });

  const onlySecurity = await (await exportCsv(env, admin, '?category=security')).text();
  assert.ok(onlySecurity.includes('security.scan.exclude'));
  assert.ok(!onlySecurity.includes('user.login'));

  const onlyWarn = await (await exportCsv(env, admin, '?level=warn')).text();
  assert.ok(onlyWarn.includes('user.login'));
  assert.ok(!onlyWarn.includes('security.scan.exclude'));
});

test('a secret that an old event was written with does not reach the file', async () => {
  const { env, admin } = await fixture();
  // Written straight into the table, the way a row from before the rule
  // existed would look.
  await env.DB.prepare(
    'INSERT INTO audit_logs (id, actor_user_id, action, category, level, target_type, target_id, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
  )
    .bind(
      'dirty-row',
      admin.id,
      'account.keys.update',
      'security',
      'info',
      'user',
      admin.id,
      JSON.stringify({ email: 'someone@example.test', password: 'hunter2', apiKey: 'sk-live-1234', secret: 'do-not-leak' }),
      new Date().toISOString()
    )
    .run();

  const csv = await (await exportCsv(env, admin)).text();
  assert.ok(csv.includes('someone@example.test'), 'the allowed metadata is kept');
  assert.ok(!csv.includes('hunter2'), 'the password is not in the file');
  assert.ok(!csv.includes('sk-live-1234'), 'the api key is not in the file');
  assert.ok(!csv.includes('do-not-leak'), 'the secret is not in the file');
});

test('only an admin may export', async () => {
  const { env, admin } = await fixture();
  const member = { ...admin, role: 'user' } as User;
  const response = await exportCsv(env, member);
  assert.equal(response.status, 403);
  const body = await response.text();
  assert.ok(!body.includes('"id","created_at"'), 'no rows are handed out');
});

test('the retention keeps the log for the days that were set', async () => {
  const { env, storage, admin } = await fixture();
  const old = new Date(Date.now() - 200 * 24 * 60 * 60 * 1000).toISOString();
  const fresh = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString();
  await storage.createAuditLog({
    id: 'old-row',
    actorUserId: admin.id,
    action: 'user.login',
    category: 'auth',
    level: 'info',
    targetType: 'user',
    targetId: admin.id,
    metadata: '{}',
    createdAt: old,
  } as never);
  await storage.createAuditLog({
    id: 'fresh-row',
    actorUserId: admin.id,
    action: 'user.login',
    category: 'auth',
    level: 'info',
    targetType: 'user',
    targetId: admin.id,
    metadata: '{}',
    createdAt: fresh,
  } as never);

  // The setting the Log Center offers: keep the log for 90 days.
  const cutoff = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString();
  const removed = await storage.pruneAuditLogs(cutoff);
  assert.equal(removed, 1);

  const csv = await (await exportCsv(env, admin, '?category=auth')).text();
  assert.ok(!csv.includes('old-row'), 'the event past the retention is gone');
  assert.ok(csv.includes('fresh-row'), 'the event inside the retention is kept');
});

test('the export says when it was cut short', async () => {
  const { storage, admin } = await fixture();
  for (let index = 0; index < 3; index += 1) {
    await writeAuditEvent(storage, {
      actorUserId: admin.id,
      action: 'user.login',
      category: 'auth',
      level: 'info',
      targetType: 'user',
      targetId: admin.id,
      metadata: { index: String(index) },
    });
  }
  // The storage is asked for fewer rows than there are, the way the handler
  // does when the export reaches its cap.
  const capped = await storage.listAuditLogsForExport(admin.id, { category: 'auth' }, 2);
  assert.equal(capped.logs.length, 2);
  assert.equal(capped.truncated, true);

  const full = await storage.listAuditLogsForExport(admin.id, { category: 'auth' }, 10);
  assert.equal(full.logs.length, 3);
  assert.equal(full.truncated, false);
});
