// The notification center and the event upload of the official clients.
//
// NodeWarden keeps no end-user notifications and records no client events.
// These checks pin the answers the clients get instead of the router's
// generic "Not found": an empty list, a notification that is never found,
// and an event upload that is accepted and dropped.
import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { sqliteD1 } from './sqlite-d1';
import type { Env } from '../src/types';

const USER_ID = '00000000-0000-4000-8000-0000000000c1';
const NOTIFICATION_ID = '00000000-0000-4000-8000-0000000000c2';

async function call(method: string, path: string, body?: unknown): Promise<Response> {
  const db = new DatabaseSync(':memory:');
  await ensureStorageSchema(sqliteD1(db));
  const env = { DB: sqliteD1(db) } as unknown as Env;
  const request = new Request(`https://vault.example.test${path}`, {
    method,
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const response = await handleAuthenticatedRoute(request, env, USER_ID, { id: USER_ID } as never, path, method);
  assert.ok(response, `no route answered ${method} ${path}`);
  return response;
}

test('the notification list is empty', async () => {
  const response = await call('GET', '/api/notifications');
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.deepEqual(body.data, []);
  assert.equal(body.object, 'list');
});

test('a notification is never found, by a route of its own', async () => {
  for (const [method, path] of [
    ['PATCH', `/api/notifications/${NOTIFICATION_ID}/read`],
    ['DELETE', `/api/notifications/${NOTIFICATION_ID}/delete`],
  ]) {
    const response = await call(method, path);
    assert.equal(response.status, 404, `${method} ${path}`);
    assert.equal((await response.json()).error, 'Notification not found.');
  }
});

test('an event upload is accepted and dropped', async () => {
  const response = await call('POST', '/events/collect', [
    { type: 1107, cipherId: NOTIFICATION_ID, date: '2026-11-10T00:00:00.000Z' },
  ]);
  assert.equal(response.status, 200);
});
