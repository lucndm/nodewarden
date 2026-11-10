// An organization with an owner, two members and an outsider, their
// collections and rights, on an in-memory database: the shared ground of the
// tests that need members and shared items.
//
// The owner owns org-1; the writer may write col-shared and only read
// col-readonly; the reader may only read col-shared; the outsider belongs to
// org-2.
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { StorageService } from '../src/services/storage';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { sqliteD1 } from './sqlite-d1';
import type { Env } from '../src/types';

export const NOW = '2026-11-07T00:00:00.000Z';
export const OWNER = 'user-owner';
export const WRITER = 'user-writer';
export const READER = 'user-reader';
export const OUTSIDER = 'user-outsider';
export const ORG = 'org-1';
export const OTHER_ORG = 'org-2';
export const COL_SHARED = 'col-shared';
export const COL_READONLY = 'col-readonly';
export const COL_OTHER = 'col-other';

export const ENC = (value: string) =>
  `2.${Buffer.from(`iv-${value}`).toString('base64')}|${Buffer.from(`ct-${value}`).toString('base64')}|${Buffer.from(`mac-${value}`).toString('base64')}`;

export async function fixture(): Promise<{ env: Env; storage: StorageService }> {
  const db = new DatabaseSync(':memory:');
  await ensureStorageSchema(sqliteD1(db));
  const env = { DB: sqliteD1(db) } as unknown as Env;
  const storage = new StorageService(env.DB);

  for (const [id, email] of [
    [OWNER, 'owner@example.test'],
    [WRITER, 'writer@example.test'],
    [READER, 'reader@example.test'],
    [OUTSIDER, 'outsider@example.test'],
  ]) {
    await createUser(storage, id, email);
  }

  for (const id of [ORG, OTHER_ORG]) {
    await env.DB.prepare(
      'INSERT INTO organizations (id, name, private_key, public_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)'
    )
      .bind(id, id, 'enc-private', 'public', NOW, NOW)
      .run();
  }

  // Only the owner is an owner; the others are plain members, so what they
  // reach depends on the collections they were given.
  const memberships: Array<[string, string, string, number]> = [
    ['ou-owner', OWNER, ORG, 0],
    ['ou-writer', WRITER, ORG, 2],
    ['ou-reader', READER, ORG, 2],
    ['ou-outsider', OUTSIDER, OTHER_ORG, 2],
  ];
  for (const [id, userId, orgId, type] of memberships) {
    await env.DB.prepare(
      'INSERT INTO organization_users (id, user_id, org_id, type, status, key, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    )
      .bind(id, userId, orgId, type, 2, 'wrapped', NOW, NOW)
      .run();
  }

  for (const [id, orgId, name] of [
    [COL_SHARED, ORG, 'Shared'],
    [COL_READONLY, ORG, 'Read only'],
    [COL_OTHER, OTHER_ORG, 'Other'],
  ]) {
    await env.DB.prepare('INSERT INTO collections (id, org_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
      .bind(id, orgId, name, NOW, NOW)
      .run();
  }

  // The writer may write the shared collection; the reader may only read it.
  // The owner is an owner, so every collection of the organization is open.
  for (const [collectionId, orgUserId, readOnly] of [
    [COL_SHARED, 'ou-writer', 0],
    [COL_SHARED, 'ou-reader', 1],
    [COL_READONLY, 'ou-writer', 1],
  ] as const) {
    await env.DB.prepare(
      'INSERT INTO collection_users (collection_id, org_user_id, read_only, hide_passwords, manage) VALUES (?, ?, ?, 0, 0)'
    )
      .bind(collectionId, orgUserId, readOnly)
      .run();
  }

  return { env, storage };
}

/** An account, so a member can be invited before they join an organization. */
export async function createUser(storage: StorageService, id: string, email: string): Promise<void> {
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
    yubikeyNfc: false,
    apiKey: null,
    userKeyId: null,
    createdAt: NOW,
    updatedAt: NOW,
  } as never);
}

export async function call(
  env: Env,
  url: string,
  method: string,
  userId: string,
  body?: unknown
): Promise<Response> {
  const request = new Request(url, {
    method,
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const path = new URL(url).pathname;
  const response = await handleAuthenticatedRoute(request, env, userId, { id: userId } as never, path, method);
  assert.ok(response, `no route answered ${method} ${path}`);
  return response;
}

