import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import { StorageService } from '../src/services/storage';
import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { cipherToResponse } from '../src/handlers/ciphers';
import { bytesToBase64, encryptBw, decryptStr } from '../webapp/src/lib/crypto';
import { decryptSingleCipher } from '../webapp/src/lib/decrypt-cipher';
import { decryptVaultCore } from '../webapp/src/lib/vault-decrypt';
import { updateCipher, updateFolder, buildCipherImportPayload, repairCipherKeyMismatches } from '../webapp/src/lib/api/vault';
import { importCipherToDraft } from '../webapp/src/lib/app-support';
import { draftFromCipher } from '../webapp/src/components/vault/vault-page-helpers';
import { t as translate } from '../webapp/src/lib/i18n';

const owner = '00000000-0000-4000-8000-000000000001';
const otherOwner = '00000000-0000-4000-8000-000000000002';
const id = '00000000-0000-4000-8000-000000000003';
const otherId = '00000000-0000-4000-8000-000000000004';
const attachmentId = '00000000-0000-4000-8000-000000000005';
const revision = '2026-10-04T00:00:00.000Z';
const enc = new Uint8Array(32).fill(1);
const mac = new Uint8Array(32).fill(2);
const session: any = { symEncKey: bytesToBase64(enc), symMacKey: bytesToBase64(mac) };
const encrypt = (value: string) => encryptBw(new TextEncoder().encode(value), enc, mac);

async function fixture(ctx: TestContext) {
  // Execute production SQL in a fresh in-memory SQLite database. Only the D1
  // result wrapper and unrelated audit/notification integrations are substituted.
  const sqlite = new DatabaseSync(':memory:');
  ctx.after(async () => { await new Promise((resolve) => setImmediate(resolve)); sqlite.close(); });
  sqlite.exec(`
    CREATE TABLE ciphers(id TEXT PRIMARY KEY, user_id TEXT, type INTEGER,
      folder_id TEXT, name TEXT, notes TEXT, favorite INTEGER, data TEXT,
      reprompt INTEGER, key TEXT, created_at TEXT, updated_at TEXT,
      archived_at TEXT, deleted_at TEXT);
    CREATE TABLE attachments(id TEXT PRIMARY KEY, cipher_id TEXT,
      file_name TEXT, size INTEGER, size_name TEXT, key TEXT);
    CREATE TABLE folders(id TEXT PRIMARY KEY, user_id TEXT, name TEXT, tag_name TEXT, created_at TEXT, updated_at TEXT);
    CREATE TABLE devices(user_id TEXT, push_token TEXT);
  `);
  const db: any = {
    prepare(sql: string) {
      let values: any[] = [];
      const statement = {
        bind(...bound: any[]) { values = bound; return statement; },
        async run() { const result = sqlite.prepare(sql).run(...values); return { success: true, meta: { changes: Number(result.changes) } }; },
        async all() { return { success: true, results: sqlite.prepare(sql).all(...values) }; },
        async first() { return sqlite.prepare(sql).get(...values) ?? null; },
      };
      return statement;
    },
  };
  let revisionBumps = 0;
  ctx.mock.method(StorageService.prototype, 'updateRevisionDate', async () => {
    revisionBumps += 1;
    return revision;
  });
  ctx.mock.method(StorageService.prototype, 'createAuditLog', async () => {});
  ctx.mock.method(StorageService.prototype, 'getConfigValue', async () => null);
  ctx.mock.method(StorageService.prototype, 'pruneAuditLogs', async () => {});
  const deletedBlobs: string[] = [];
  const notifications: any[] = [];
  const env: any = {
    DB: db,
    ATTACHMENTS: { delete: async (key: string) => { deletedBlobs.push(key); } },
    NOTIFICATIONS_HUB: {
      idFromName: (name: string) => name,
      get: () => ({ fetch: async (_url: string, init: RequestInit) => { notifications.push(JSON.parse(init.body as string)); return new Response(null, { status: 204 }); } }),
    },
  };
  const storage = new StorageService(db);
  const base: any = {
    id, userId: owner, type: 1, name: await encrypt('Initial title'),
    notes: await encrypt('Notes'), favorite: false, folderId: null, key: null,
    login: { username: await encrypt('Username'), password: await encrypt('Password') },
    createdAt: revision, updatedAt: revision, deletedAt: null,
  };
  await storage.saveCipher(base);
  await storage.saveCipher({ ...base, id: otherId, userId: otherOwner });
  const route = async (path: string, method: string, body?: unknown, headers: Record<string, string> = {}) => {
    const request = new Request(`https://vault.example.test${path}`, {
      method, headers: { 'Content-Type': 'application/json', ...headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const response = await handleAuthenticatedRoute(request, env, owner, { id: owner } as any, path, method);
    assert.ok(response, `${method} ${path} must be handled`);
    return response;
  };
  const attachment = { id: attachmentId, cipherId: id, fileName: await encrypt('file.txt'), key: null, size: 7, sizeName: '7 B' };
  return { storage, base, env, sqlite, route, deletedBlobs, notifications, attachment, revisionBumps: () => revisionBumps };
}

for (const method of ['PUT', 'POST']) {
  test(`${method} bulk soft delete and restore retain ownership and return restored items`, async (ctx) => {
    const f = await fixture(ctx);
    await f.storage.saveAttachment(f.attachment);
    const ids = [id, otherId, id, '00000000-0000-4000-8000-000000000099'];
    assert.equal((await f.route('/api/ciphers/delete', method, { ids })).status, 204);
    assert.ok((await f.storage.getCipherForUser(id, owner))?.deletedAt);
    assert.equal((await f.storage.getCipherForUser(otherId, otherOwner))?.deletedAt, null);
    const response = await f.route('/api/ciphers/restore', method, { ids });
    assert.equal(response.status, 200);
    const body: any = await response.json();
    assert.equal(body.object, 'list');
    assert.equal(body.continuationToken, null);
    assert.equal(body.data.length, 1);
    assert.equal(body.data[0].id, id);
    assert.equal(body.data[0].deletedDate, null);
    assert.equal(body.data[0].attachments[0].id, attachmentId);
    assert.deepEqual(f.deletedBlobs, []);
    const empty: any = await (await f.route('/api/ciphers/restore', method, { ids: [] })).json();
    assert.deepEqual(empty.data, []);
  });
}

for (const [path, method] of [['/api/ciphers', 'DELETE'], ['/api/ciphers/delete-permanent', 'POST']]) {
  test(`${method} ${path} permanently deletes only owned items and their attachments`, async (ctx) => {
    const f = await fixture(ctx);
    await f.storage.saveAttachment(f.attachment);
    await f.storage.saveAttachment({ ...f.attachment, id: otherId, cipherId: otherId });
    assert.equal((await f.route(path, method, { ids: [id, otherId, id] })).status, 204);
    assert.equal(await f.storage.getCipherForUser(id, owner), null);
    assert.ok(await f.storage.getCipherForUser(otherId, otherOwner));
    assert.equal(await f.storage.getAttachment(attachmentId), null);
    assert.ok(await f.storage.getAttachment(otherId));
    assert.deepEqual(f.deletedBlobs, [`${id}/${attachmentId}`]);
  });
}

test('single POST delete alias is permanent; existing root DELETE still moves an active item to trash', async (ctx) => {
  const f = await fixture(ctx);
  assert.equal((await f.route(`/api/ciphers/${id}`, 'DELETE')).status, 200);
  assert.ok((await f.storage.getCipherForUser(id, owner))?.deletedAt);
  assert.equal((await f.route(`/api/ciphers/${id}/delete`, 'POST')).status, 204);
  assert.equal(await f.storage.getCipherForUser(id, owner), null);
  assert.equal((await f.route(`/api/ciphers/${otherId}/delete`, 'POST')).status, 404);
});

test('invalid bulk requests are rejected without changing vault items', async (ctx) => {
  const f = await fixture(ctx);
  for (const [path, method] of [['/api/ciphers', 'DELETE'], ['/api/ciphers/delete', 'PUT'], ['/api/ciphers/restore', 'PUT']]) {
    assert.equal((await f.route(path, method, {})).status, 400);
    assert.equal((await f.route(path, method, { ids: 'invalid' })).status, 400);
  }
  assert.deepEqual(await f.storage.getCipherForUser(id, owner), await f.storage.getCipher(id));
  assert.equal((await f.storage.getCipherForUser(id, owner))?.deletedAt, null);
});

test('stale updates less than a second apart cannot bypass checks with attachment metadata', async (ctx) => {
  const f = await fixture(ctx);
  await f.storage.saveAttachment(f.attachment);
  await f.storage.saveCipher({ ...f.base, updatedAt: '2026-10-04T00:00:00.001Z' });
  const response = await f.route(`/api/ciphers/${id}`, 'PUT', {
    name: await encrypt('Stale title'), lastKnownRevisionDate: revision,
    attachments2: { [attachmentId]: { fileName: await encrypt('Stale file') } },
  });
  assert.equal(response.status, 400);
  assert.equal((await f.storage.getCipherForUser(id, owner))?.name, f.base.name);
  assert.equal((await f.storage.getAttachment(attachmentId))?.fileName, f.attachment.fileName);
  assert.equal(f.notifications.length, 0);
});

test('a write conflict detected after reading leaves attachment metadata untouched', async (ctx) => {
  const f = await fixture(ctx);
  await f.storage.saveAttachment(f.attachment);
  const update = StorageService.prototype.updateCipherIfUnchanged;
  ctx.mock.method(StorageService.prototype, 'updateCipherIfUnchanged', async function (this: StorageService, cipher: any, expected: string) {
    await f.storage.saveCipher({ ...f.base, updatedAt: '2026-10-04T00:00:01.000Z' });
    return update.call(this, cipher, expected);
  });
  assert.equal((await f.route(`/api/ciphers/${id}`, 'PUT', {
    name: await encrypt('Stale title'), lastKnownRevisionDate: revision,
    attachments2: { [attachmentId]: { fileName: await encrypt('Stale file') } },
  })).status, 400);
  assert.equal((await f.storage.getAttachment(attachmentId))?.fileName, f.attachment.fileName);
  assert.equal(f.notifications.length, 0);
});

test('concurrent saves from the same revision accept only one, even in the same millisecond', async (ctx) => {
  const f = await fixture(ctx);
  ctx.mock.method(Date, 'now', () => Date.parse(revision));
  const response = await Promise.all(['First title', 'Second title'].map(async (title) =>
    f.route(`/api/ciphers/${id}`, 'PUT', { name: await encrypt(title), lastKnownRevisionDate: revision })
  ));
  assert.deepEqual(response.map((r) => r.status).sort(), [200, 400]);
  assert.equal((await f.storage.getCipherForUser(id, owner))?.updatedAt, '2026-10-04T00:00:00.001Z');
});

test('a save that changes nothing does not write, bump the revision or notify', async (ctx) => {
  const f = await fixture(ctx);
  const body = {
    id: f.base.id,
    type: f.base.type,
    name: f.base.name,
    notes: f.base.notes,
    favorite: f.base.favorite,
    folderId: f.base.folderId,
    key: f.base.key,
    login: f.base.login,
  };
  // The first save stores the normalised row; the second one carries no change.
  assert.equal((await f.route(`/api/ciphers/${id}`, 'PUT', { ...body, lastKnownRevisionDate: revision })).status, 200);
  assert.equal(f.revisionBumps(), 1);
  const stored = await f.storage.getCipherForUser(id, owner);
  const notificationsAfterFirstSave = f.notifications.length;

  const response = await f.route(`/api/ciphers/${id}`, 'PUT', { ...body, lastKnownRevisionDate: stored?.updatedAt });
  assert.equal(response.status, 200);
  assert.equal(f.revisionBumps(), 1, 'a save without changes must not bump the revision');
  assert.equal(f.notifications.length, notificationsAfterFirstSave, 'a save without changes must not notify the other clients');
  const after = await f.storage.getCipherForUser(id, owner);
  assert.equal(after?.updatedAt, stored?.updatedAt);
  assert.equal(after?.name, stored?.name);
});

test('a save that only renames an attachment still writes and notifies', async (ctx) => {
  const f = await fixture(ctx);
  await f.storage.saveAttachment(f.attachment);
  const response = await f.route(`/api/ciphers/${id}`, 'PUT', {
    id: f.base.id,
    type: f.base.type,
    name: f.base.name,
    notes: f.base.notes,
    favorite: f.base.favorite,
    folderId: f.base.folderId,
    key: f.base.key,
    login: f.base.login,
    lastKnownRevisionDate: revision,
    attachments2: { [attachmentId]: { fileName: await encrypt('renamed.txt') } },
  });
  assert.equal(response.status, 200);
  assert.equal(f.revisionBumps(), 1);
  assert.ok(f.notifications.length > 0);
  assert.notEqual((await f.storage.getCipherForUser(id, owner))?.updatedAt, revision);
});

test('a competing deletion cannot be resurrected by a delayed update', async (ctx) => {
  const f = await fixture(ctx);
  const get = StorageService.prototype.getCipherForUser;
  ctx.mock.method(StorageService.prototype, 'getCipherForUser', async function (this: StorageService, ...args: [string, string]) {
    const result = await get.apply(this, args);
    await f.storage.deleteCipher(id, owner);
    return result;
  });
  assert.equal((await f.route(`/api/ciphers/${id}`, 'PUT', { name: await encrypt('Delayed title') })).status, 400);
  assert.equal(await f.storage.getCipher(id), null);
});

test('normal legacy saves without a revision still work and nullable fields can be cleared', async (ctx) => {
  const f = await fixture(ctx);
  assert.equal((await f.route(`/api/ciphers/${id}`, 'PUT', { name: await encrypt('Legacy title'), notes: null, fields: [] })).status, 200);
  const saved = await f.storage.getCipherForUser(id, owner);
  assert.equal(saved?.notes, null);
  assert.deepEqual(saved?.fields, []);
});

test('storage conditional updates cannot change another owner or recreate missing items', async (ctx) => {
  const f = await fixture(ctx);
  assert.equal(await f.storage.updateCipherIfUnchanged({ ...f.base, userId: otherOwner }, revision), false);
  await f.storage.deleteCipher(id, owner);
  assert.equal(await f.storage.updateCipherIfUnchanged(f.base, revision), false);
  assert.equal(await f.storage.getCipher(id), null);
});

test('Web editing preserves linked IDs and field metadata through reorder, removal, encryption, storage and response', async (ctx) => {
  const f = await fixture(ctx);
  const extra = await encrypt('Future encrypted field');
  const cipher = {
    ...f.base,
    fields: [
      { type: 3, name: await encrypt('Linked username'), value: null, linkedId: 100, futureValue: extra },
      { type: 0, name: await encrypt('Remove me'), value: await encrypt('Remove value') },
      { type: 1, name: await encrypt('Keep me'), value: await encrypt('Secret'), futureValue: extra },
    ],
  };
  await f.storage.saveCipher(cipher);
  const decrypted = await decryptSingleCipher(cipherToResponse(cipher) as any, enc, mac);
  const draft = draftFromCipher(decrypted);
  draft.customFields = [draft.customFields[2], draft.customFields[0]];
  draft.name = 'Edited title';
  const updated = await updateCipher((path, init) => f.route(path, init!.method!, JSON.parse(init!.body as string)), session, decrypted, draft);
  assert.equal(updated.fields?.length, 2);
  assert.equal('lastKnownRevisionDate' in updated, false);
  assert.equal(updated.fields?.[1].linkedId, 100);
  for (const field of updated.fields || []) {
    assert.equal((field as any).futureValue, extra);
    assert.equal('decName' in field, false);
    assert.equal('decValue' in field, false);
  }
  const roundtrip = await decryptSingleCipher(updated, enc, mac);
  assert.equal(roundtrip.decName, 'Edited title');
  assert.equal(roundtrip.fields?.[0].decValue, 'Secret');
  assert.equal((await f.storage.getCipherForUser(id, owner))?.fields?.[1].linkedId, 100);
});

for (const [type, property] of [[3, 'card'], [4, 'identity'], [2, 'secureNote']] as const) {
  test(`Web editing ${property} keeps unknown encrypted values without sending decoded properties`, async (ctx) => {
    const f = await fixture(ctx);
    const extra = await encrypt('Future secret');
    const source = { ...f.base, type, login: null, [property]: { futureEncrypted: extra, decFutureEncrypted: 'Decoded secret', type: 0 } };
    await f.storage.saveCipher(source);
    const decrypted = await decryptSingleCipher(cipherToResponse(source) as any, enc, mac);
    const draft = draftFromCipher(decrypted);
    draft.name = 'Changed';
    let payload: any;
    const updated = await updateCipher((path, init) => { payload = JSON.parse(init!.body as string); return f.route(path, init!.method!, payload); }, session, decrypted, draft);
    assert.equal(payload[property].futureEncrypted, extra);
    assert.equal('decFutureEncrypted' in payload[property], false);
    assert.equal((updated as any)[property].futureEncrypted, extra);
  });
}

test('Web sends the revision captured at edit start and exposes a localized conflict while preserving the draft', async (ctx) => {
  const f = await fixture(ctx);
  const initial = await decryptSingleCipher(cipherToResponse(f.base) as any, enc, mac);
  const draft = draftFromCipher(initial);
  draft.name = 'Unsaved edit';
  const newer = { ...f.base, name: await encrypt('New remote title'), updatedAt: '2026-10-04T00:00:00.500Z' };
  await f.storage.saveCipher(newer);
  const synced = await decryptSingleCipher(cipherToResponse(newer) as any, enc, mac);
  let submitted: any;
  await assert.rejects(updateCipher((path, init) => {
    submitted = JSON.parse(init!.body as string);
    return f.route(path, init!.method!, submitted);
  }, session, synced, draft), (error: any) => {
    assert.equal(error.status, 400);
    assert.equal(error.message, translate('txt_item_changed_elsewhere'));
    return true;
  });
  assert.equal(submitted.lastKnownRevisionDate, revision);
  assert.equal(draft.name, 'Unsaved edit');
  assert.equal((await f.storage.getCipherForUser(id, owner))?.name, newer.name);
});

test('plaintext import keeps linked field IDs attached to the encrypted field', async () => {
  const draft = importCipherToDraft({ type: 1, name: 'Imported', fields: [{ type: 3, name: 'Linked', value: null, linkedId: 100 }] }, '');
  assert.equal(draft.customFields[0].linkedId, 100);
  const payload: any = await buildCipherImportPayload(session, draft);
  assert.equal(payload.fields[0].linkedId, 100);
  assert.equal(await decryptStr(payload.fields[0].name, enc, mac), 'Linked');
  assert.equal('lastKnownRevisionDate' in payload, false);
});

test('a draft cannot be saved into a different item after the selection changes', async (ctx) => {
  const f = await fixture(ctx);
  const cipher = await decryptSingleCipher(cipherToResponse(f.base) as any, enc, mac);
  const draft = draftFromCipher(cipher);
  let requested = false;
  await assert.rejects(updateCipher(async () => { requested = true; return new Response(); }, session, { ...cipher, id: otherId }, draft));
  assert.equal(requested, false);
});

test('automatic item-key repair preserves linked metadata and the intentional revision-date behavior', async (ctx) => {
  const f = await fixture(ctx);
  const itemEnc = new Uint8Array(32).fill(3);
  const itemMac = new Uint8Array(32).fill(4);
  const itemKey = new Uint8Array([...itemEnc, ...itemMac]);
  const extra = await encryptBw(new TextEncoder().encode('Future secret'), itemEnc, itemMac);
  const mixed = { ...f.base, key: await encryptBw(itemKey, enc, mac), fields: [
    { type: 3, name: await encrypt('Linked username'), value: null, linkedId: 100, futureEncrypted: extra },
  ] };
  await f.storage.saveCipher(mixed);
  const decrypted = await decryptSingleCipher(cipherToResponse(mixed) as any, enc, mac);
  const repaired = await repairCipherKeyMismatches((path, init) =>
    f.route(path, init!.method!, JSON.parse(init!.body as string), init!.headers as Record<string, string>), session, [decrypted]);
  assert.equal(repaired, 1);
  const saved = (await f.storage.getCipherForUser(id, owner))!;
  assert.equal(saved.updatedAt, revision);
  assert.equal(saved.fields?.[0].linkedId, 100);
  assert.equal((saved.fields?.[0] as any).futureEncrypted, extra);
  assert.equal(await decryptStr(saved.name, itemEnc, itemMac), 'Initial title');
  assert.equal(await decryptStr(saved.fields![0].name!, itemEnc, itemMac), 'Linked username');
  assert.equal('lastKnownRevisionDate' in saved, false);
});

test('bulk move replaces folder-position tag, preserves secondary tags and isolates owners', async (ctx) => {
  const f = await fixture(ctx);
  const first = '00000000-0000-4000-8000-000000000011';
  const target = '00000000-0000-4000-8000-000000000012';
  for (const [folderId, name] of [[first, 'Work'], [target, 'Personal']] as const) {
    await f.storage.saveFolder({ id: folderId, userId: owner, name, createdAt: revision, updatedAt: revision });
  }
  await f.storage.saveCipher({ ...f.base, folderId: first, tags: ['Work', 'Shared'], login: f.base.login });
  const before = await f.storage.getCipherForUser(id, owner);

  assert.equal((await f.route('/api/ciphers/move', 'POST', { ids: [id, otherId], folderId: target })).status, 204);
  const moved = await f.storage.getCipherForUser(id, owner);
  assert.deepEqual(moved?.tags, ['Personal', 'Shared']);
  assert.equal(moved?.folderId, target);
  assert.equal(moved?.name, before?.name);
  assert.deepEqual(moved?.login, before?.login);
  assert.equal((await f.storage.getCipherForUser(otherId, otherOwner))?.folderId, null);
  const list: any = await (await f.route('/api/ciphers', 'GET')).json();
  assert.deepEqual(list.data.find((cipher: any) => cipher.id === id).tags, ['Personal', 'Shared']);

  assert.equal((await f.route('/api/ciphers/move', 'PUT', { ids: [id], folderId: null })).status, 204);
  const unfiled = await f.storage.getCipherForUser(id, owner);
  assert.deepEqual(unfiled?.tags, ['Shared']);
  assert.equal(unfiled?.folderId, (await f.storage.getAllFolders(owner)).find((folder) => folder.name === 'Shared')?.id);
  assert.equal((await f.route('/api/ciphers/move', 'POST', { ids: [id], folderId: otherId })).status, 404);
});
test('Web encrypted folder move keeps plaintext tags and stable Bitwarden folder identity', async (ctx) => {
  const f = await fixture(ctx);
  const encryptedName = await encrypt('Personal');
  const response = await f.route('/api/folders', 'POST', { name: encryptedName, tagName: 'Personal' });
  assert.equal(response.status, 200);
  const folder = await response.json() as { id: string; name: string };
  assert.equal(folder.name, encryptedName);
  await f.storage.saveCipher({ ...f.base, tags: ['Work', 'Shared'] });
  assert.equal((await f.route('/api/ciphers/move', 'POST', { ids: [id], folderId: folder.id })).status, 204);
  const moved = await f.storage.getCipherForUser(id, owner);
  assert.deepEqual(moved?.tags, ['Personal', 'Shared']);
  assert.equal(moved?.folderId, folder.id);
  const list = await f.route('/api/ciphers', 'GET');
  assert.equal(list.status, 200);
  const body = await list.json() as { data: Array<{ id: string; folderId: string; tags: string[] }> };
  assert.deepEqual(body.data.find((entry) => entry.id === id)?.tags, ['Personal', 'Shared']);
  assert.equal((await f.storage.getFolderForUser(folder.id, owner))?.name, encryptedName);
});

test('converting a legacy plain-text folder name keeps the tag instead of writing ciphertext into it', async (ctx) => {
  const f = await fixture(ctx);
  // A Bitwarden JSON import stores the folder name unencrypted and carries no
  // tag_name; /sync then backfills that name as the first tag of its items.
  const folderId = '00000000-0000-4000-8000-0000000000f9';
  const legacyId = '00000000-0000-4000-8000-0000000000c9';
  await f.storage.saveFolder({
    id: folderId, userId: owner, name: 'Legacy JSON Folder', tagName: null, createdAt: revision, updatedAt: revision,
  });
  await f.storage.saveCipher({ ...f.base, id: legacyId, folderId, tags: ['Legacy JSON Folder'] });

  // The Web Vault conversion: encrypt the stored name and send the revision.
  const encryptedName = await encrypt('Legacy JSON Folder');
  assert.equal((await f.route(`/api/folders/${folderId}`, 'PUT', { name: encryptedName })).status, 200);

  const folder = await f.storage.getFolderForUser(folderId, owner);
  assert.equal(folder?.name, encryptedName, 'official clients need the encrypted name');
  assert.equal(folder?.tagName, 'Legacy JSON Folder', 'the tag keeps the plain text it already had');
  const cipher = await f.storage.getCipherForUser(legacyId, owner);
  assert.deepEqual(cipher?.tags, ['Legacy JSON Folder'], 'item tags must never become ciphertext');
  assert.equal(cipher?.folderId, folderId, 'the item stays in the same folder');
});

test('official encrypted folder writes retain folder identity without leaking ciphertext into tags', async (ctx) => {
  const f = await fixture(ctx);
  const name = await encrypt('Official folder');
  const response = await f.route('/api/folders', 'POST', { name });
  assert.equal(response.status, 200);
  const folder = await response.json() as { id: string };
  const create = await f.route('/api/ciphers', 'POST', { type: 1, name: await encrypt('Official item'), folderId: folder.id });
  assert.equal(create.status, 200);
  const created = await create.json() as { id: string; folderId: string; tags: string[] | null };
  assert.equal(created.folderId, folder.id);
  assert.deepEqual(created.tags ?? [], []);
  const saved = await f.storage.getCipherForUser(created.id, owner);
  assert.equal(saved?.folderId, folder.id);
  assert.deepEqual(saved?.tags ?? [], []);
  assert.equal(await f.storage.migrateFolderCiphersToTags(owner), false);
  assert.equal((await f.storage.getCipherForUser(created.id, owner))?.folderId, folder.id);
});

test('legacy Folder converts with the vault key without losing its ID, tags, or client name', async (ctx) => {
  const f = await fixture(ctx);
  const folderId = '00000000-0000-4000-8000-000000000012';
  await f.storage.saveFolder({ id: folderId, userId: owner, name: 'Work', createdAt: revision, updatedAt: revision });
  await f.storage.saveCipher({ ...f.base, folderId, tags: ['Work', 'Shared'] });
  const response = await updateFolder((path, init) => f.route(path, init!.method!, JSON.parse(init!.body as string)), session, folderId, 'Work');
  assert.equal(await decryptStr(response.name, enc, mac), 'Work');
  assert.notEqual(response.name, 'Work');
  assert.equal(await decryptStr((await f.storage.getFolderForUser(folderId, owner))!.name, enc, mac), 'Work');
  const saved = await f.storage.getCipherForUser(id, owner);
  assert.equal(saved?.folderId, folderId);
  assert.deepEqual(saved?.tags, ['Work', 'Shared']);
  assert.equal((await f.route('/api/ciphers/move', 'POST', { ids: [id], folderId })).status, 204);
  assert.equal((await f.storage.getCipherForUser(id, owner))?.folderId, folderId);
});

test('legacy Folder conversion rejects a stale revision without changing name or tags', async (ctx) => {
  const f = await fixture(ctx);
  const folderId = '00000000-0000-4000-8000-000000000012';
  await f.storage.saveFolder({ id: folderId, userId: owner, name: 'Concurrent name', tagName: 'Work', createdAt: revision, updatedAt: '2026-10-05T00:00:00.000Z' });
  await f.storage.saveCipher({ ...f.base, folderId, tags: ['Work', 'Shared'] });
  const response = await f.route(`/api/folders/${folderId}`, 'PUT', { name: await encrypt('Work'), tagName: 'Work' }, { 'If-Match': revision });
  assert.equal(response.status, 409);
  assert.equal((await f.storage.getFolderForUser(folderId, owner))?.name, 'Concurrent name');
  assert.deepEqual((await f.storage.getCipherForUser(id, owner))?.tags, ['Work', 'Shared']);
});

test('official encrypted Folder bulk moves preserve secondary tags across sync and repeated moves', async (ctx) => {
  const f = await fixture(ctx);
  const encryptedName = await encrypt('CLI Folder');
  const created = await f.route('/api/folders', 'POST', { name: encryptedName });
  const folder = await created.json() as { id: string };
  const folders = await f.storage.ensureFoldersForTags(owner, ['Work', 'Shared']);
  await f.storage.saveCipher({ ...f.base, folderId: folders.get('Work'), tags: ['Work', 'Shared'] });
  for (const method of ['POST', 'PUT']) {
    assert.equal((await f.route('/api/ciphers/move', method, { ids: [id, otherId], folderId: folder.id })).status, 204);
    const moved = await f.storage.getCipherForUser(id, owner);
    assert.equal(moved?.folderId, folder.id);
    assert.deepEqual(moved?.tags, ['Shared']);
    assert.equal((await f.storage.getCipherForUser(otherId, otherOwner))?.folderId, null);
    const decrypted = await decryptVaultCore({ folders: await f.storage.getAllFolders(owner), ciphers: [moved!], symEncKeyB64: session.symEncKey, symMacKeyB64: session.symMacKey });
    assert.deepEqual(decrypted.ciphers[0].tags, ['CLI Folder', 'Shared']);
    assert.equal(decrypted.ciphers[0].decName, 'Initial title');
  }
  assert.equal((await f.route('/api/ciphers/move', 'PUT', { ids: [id], folderId: folders.get('Work') })).status, 204);
  assert.deepEqual((await f.storage.getCipherForUser(id, owner))?.tags, ['Work', 'Shared']);
  for (const path of [`/api/ciphers/${id}`, `/api/ciphers/${id}/partial`]) {
    const payload = path.endsWith('/partial') ? { folderId: folder.id } : { type: 1, name: f.base.name, folderId: folder.id };
    assert.equal((await f.route(path, 'PUT', payload)).status, 200);
    assert.deepEqual((await f.storage.getCipherForUser(id, owner))?.tags, ['Shared']);
    assert.equal((await f.route(path, 'PUT', payload)).status, 200);
    assert.deepEqual((await f.storage.getCipherForUser(id, owner))?.tags, ['Shared']);
    assert.equal((await f.route('/api/ciphers/move', 'PUT', { ids: [id], folderId: folders.get('Work') })).status, 204);
  }
  assert.equal((await f.route('/api/ciphers/move', 'PUT', { ids: [id], folderId: folder.id })).status, 204);
  assert.equal((await f.route('/api/ciphers/move', 'PUT', { ids: [id], folderId: null })).status, 204);
  assert.deepEqual((await f.storage.getCipherForUser(id, owner))?.tags, ['Shared']);
  assert.equal((await f.storage.getCipherForUser(id, owner))?.folderId, folders.get('Shared'));
  await f.storage.saveCipher({ ...f.base, folderId: folders.get('Work'), tags: ['Work', 'Shared'] });
  assert.equal((await f.route('/api/ciphers/move', 'PUT', { ids: [id], folderId: folder.id })).status, 204);
  assert.equal((await f.route(`/api/folders/${folder.id}`, 'DELETE')).status, 204);
  assert.equal((await f.storage.getCipherForUser(id, owner))?.folderId, folders.get('Shared'));
  assert.deepEqual((await f.storage.getCipherForUser(id, owner))?.tags, ['Shared']);
});

test('bulk move refuses to overwrite a concurrent cipher edit', async (ctx) => {
  const f = await fixture(ctx);
  const first = '00000000-0000-4000-8000-000000000011';
  const target = '00000000-0000-4000-8000-000000000012';
  for (const [folderId, name] of [[first, 'Work'], [target, 'Personal']] as const) {
    await f.storage.saveFolder({ id: folderId, userId: owner, name, createdAt: revision, updatedAt: revision });
  }
  await f.storage.saveCipher({ ...f.base, folderId: first, tags: ['Work', 'Shared'] });
  const concurrentName = await encrypt('Concurrent edit');
  const prepare = f.env.DB.prepare.bind(f.env.DB);
  let injected = false;
  f.env.DB.prepare = (sql: string) => {
    const statement = prepare(sql);
    if (injected || !sql.includes('UPDATE ciphers SET folder_id = ?, updated_at = ?, data = ?')) return statement;
    const bind = statement.bind.bind(statement);
    statement.bind = (...values: any[]) => {
      bind(...values);
      const run = statement.run.bind(statement);
      statement.run = async () => {
        injected = true;
        await f.storage.saveCipher({ ...f.base, folderId: first, tags: ['Work', 'Shared'], name: concurrentName });
        return run();
      };
      return statement;
    };
    return statement;
  };
  const response = await f.route('/api/ciphers/move', 'POST', { ids: [id], folderId: target });
  assert.equal(response.status, 409);
  assert.equal(injected, true);
  const saved = await f.storage.getCipherForUser(id, owner);
  assert.deepEqual(saved?.tags, ['Work', 'Shared']);
  assert.equal(saved?.folderId, first);
  assert.equal(saved?.name, concurrentName);
});

test('a later move conflict still advances the vault revision for earlier items', async (ctx) => {
  const f = await fixture(ctx);
  const target = '00000000-0000-4000-8000-000000000012';
  const second = '00000000-0000-4000-8000-000000000013';
  await f.storage.saveFolder({ id: target, userId: owner, name: 'Personal', createdAt: revision, updatedAt: revision });
  await f.storage.saveCipher({ ...f.base, tags: ['Work', 'Shared'] });
  await f.storage.saveCipher({ ...f.base, id: second, tags: ['Work', 'Shared'] });
  const updatedName = await encrypt('Edited during move');
  const prepare = f.env.DB.prepare.bind(f.env.DB);
  let updates = 0;
  f.env.DB.prepare = (sql: string) => {
    const stmt = prepare(sql);
    if (!sql.includes('UPDATE ciphers SET folder_id = ?, updated_at = ?, data = ?')) return stmt;
    const run = stmt.run.bind(stmt);
    stmt.run = async () => {
      if (++updates === 2) await f.storage.saveCipher({ ...f.base, id: second, tags: ['Work', 'Shared'], name: updatedName });
      return run();
    };
    return stmt;
  };
  assert.equal((await f.route('/api/ciphers/move', 'POST', { ids: [id, second], folderId: target })).status, 409);
  assert.deepEqual((await f.storage.getCipherForUser(id, owner))?.tags, ['Personal', 'Shared']);
  assert.deepEqual((await f.storage.getCipherForUser(second, owner))?.tags, ['Work', 'Shared']);
  assert.equal((await f.storage.getCipherForUser(second, owner))?.name, updatedName);
  assert.equal(f.revisionBumps(), 1);
});

test('a D1 error after an earlier move still advances the vault revision', async (ctx) => {
  const f = await fixture(ctx);
  const target = '00000000-0000-4000-8000-000000000012';
  const second = '00000000-0000-4000-8000-000000000013';
  await f.storage.saveFolder({ id: target, userId: owner, name: 'Personal', createdAt: revision, updatedAt: revision });
  await f.storage.saveCipher({ ...f.base, tags: ['Work', 'Shared'] });
  await f.storage.saveCipher({ ...f.base, id: second, tags: ['Work', 'Shared'] });
  const prepare = f.env.DB.prepare.bind(f.env.DB);
  let updates = 0;
  f.env.DB.prepare = (sql: string) => {
    const stmt = prepare(sql);
    if (!sql.includes('UPDATE ciphers SET folder_id = ?, updated_at = ?, data = ?')) return stmt;
    const run = stmt.run.bind(stmt);
    stmt.run = async () => {
      if (++updates === 2) throw new Error('D1 write failed');
      return run();
    };
    return stmt;
  };
  await assert.rejects(f.route('/api/ciphers/move', 'POST', { ids: [id, second], folderId: target }), /D1 write failed/);
  assert.deepEqual((await f.storage.getCipherForUser(id, owner))?.tags, ['Personal', 'Shared']);
  assert.deepEqual((await f.storage.getCipherForUser(second, owner))?.tags, ['Work', 'Shared']);
  assert.equal(f.revisionBumps(), 1);
});
