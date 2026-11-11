// The sync endpoint must answer with the shared items of a vault that was
// moved into an organization.
//
// A vault that was moved holds hundreds of shared items. The sync response
// names the collections they sit in, and that read binds one parameter per
// item. When the statement binds more parameters than D1 accepts, the whole
// sync fails with a 500, and the client falls back to the snapshot it already
// has: the organization shows up in the sidebar with nothing in it.
//
// These checks boot a throwaway Worker with its own D1, give it an
// organization with a collection and hundreds of shared items, and read the
// official sync endpoint:
//   - the sync answers 200;
//   - every shared item is in the response;
//   - every shared item carries the organization and its collection.
import { startLocalWorker, createChecks } from './local-worker.mjs';
import { DatabaseSync } from 'node:sqlite';
import { readdirSync } from 'node:fs';
import { join } from 'node:path';

/**
 * The database file the local worker keeps its D1 in.
 */
function findDatabase(persistDir) {
  const root = join(persistDir, 'v3', 'd1', 'miniflare-D1DatabaseObject');
  for (const entry of readdirSync(root)) {
    if (entry.endsWith('.sqlite')) return join(root, entry);
  }
  throw new Error(`no D1 database in ${root}`);
}

/**
 * Writes shared items into the worker's database: an item of the organization
 * that sits in its collection.
 */
function writeSharedItems(persistDir, { userId, orgId, collectionId, count }) {
  const db = new DatabaseSync(findDatabase(persistDir));
  const ids = [];
  const now = new Date().toISOString();
  const insertCipher = db.prepare(
    'INSERT INTO ciphers (id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, organization_id) ' +
      'VALUES (?, ?, 1, NULL, ?, NULL, 0, ?, 0, NULL, ?, ?, ?)'
  );
  const insertLink = db.prepare('INSERT INTO collection_ciphers (cipher_id, collection_id) VALUES (?, ?)');
  for (let index = 0; index < count; index += 1) {
    const id = `shared-${index}`;
    // The server keeps the collections of an item in the item's own payload,
    // next to the row that links them.
    const data = JSON.stringify({ collectionIds: [collectionId], name: `2.${Buffer.from(`name-${index}`).toString('base64')}|${Buffer.from(`ct-${index}`).toString('base64')}|${Buffer.from(`mac-${index}`).toString('base64')}` });
    insertCipher.run(id, userId, `2.${Buffer.from(`name-${index}`).toString('base64')}|${Buffer.from(`ct-${index}`).toString('base64')}|${Buffer.from(`mac-${index}`).toString('base64')}`, data, now, now, orgId);
    insertLink.run(id, collectionId);
    ids.push(id);
  }
  db.close();
  return ids;
}

/**
 * The id of the account that owns the vault.
 */
async function ownerId(baseUrl, token) {
  const response = await api(baseUrl, '/api/accounts/profile', { token });
  return response.body?.id || '';
}

const enc = (value) => {
  const part = (text) => Buffer.from(text, 'utf8').toString('base64');
  return `2.${part(`iv-${value}`)}|${part(`ct-${value}`)}|${part(`mac-${value}`)}`;
};

const OWNER = 'scale-owner@example.test';
const ORG_NAME = 'Scale Org';
const COLLECTION_NAME = 'General';
// The number of shared items a moved vault holds. It is what makes the read
// bind more parameters than D1 accepts.
const SHARED_ITEMS = 300;

async function api(baseUrl, path, options = {}) {
  const { method = 'GET', token, body, form, headers = {} } = options;
  const init = { method, headers: { ...headers } };
  if (token) init.headers.Authorization = `Bearer ${token}`;
  if (form) {
    init.headers['Content-Type'] = 'application/x-www-form-urlencoded';
    init.body = new URLSearchParams(form).toString();
  } else if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const response = await fetch(`${baseUrl}${path}`, init);
  const text = await response.text();
  let parsed = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = text;
  }
  return { status: response.status, body: parsed };
}

async function register(baseUrl, email) {
  return api(baseUrl, '/api/accounts/register', {
    method: 'POST',
    headers: { Origin: baseUrl },
    body: {
      email,
      name: 'Scale Check',
      masterPasswordHash: Buffer.from(`hash-${email}`).toString('base64'),
      key: enc(`vault-key-${email}`),
      kdf: 0,
      kdfIterations: 600000,
      keys: {
        publicKey: Buffer.from('public-key').toString('base64'),
        encryptedPrivateKey: enc('private-key'),
      },
    },
  });
}

async function login(baseUrl, email) {
  const response = await api(baseUrl, '/identity/connect/token', {
    method: 'POST',
    form: {
      grant_type: 'password',
      username: email,
      password: Buffer.from(`hash-${email}`).toString('base64'),
      scope: 'api offline_access',
      deviceIdentifier: 'scale-check-device',
      deviceName: 'scale check',
      deviceType: '14',
    },
  });
  return response.body?.access_token || null;
}

async function run(worker, checks) {
  const baseUrl = worker.baseUrl;
  const registered = await register(baseUrl, OWNER);
  if (!checks.equal('register the owner', registered.status, 200, JSON.stringify(registered.body))) return;
  const token = await login(baseUrl, OWNER);
  if (!checks.ok('the owner logs in', !!token)) return;

  const created = await api(baseUrl, '/api/organizations', {
    method: 'POST',
    token,
    body: {
      name: ORG_NAME,
      key: enc('wrapped-organization-key'),
      collectionName: enc(COLLECTION_NAME),
      keys: {
        publicKey: Buffer.from('org-public-key').toString('base64'),
        encryptedPrivateKey: enc('org-private-key'),
      },
    },
  });
  if (!checks.equal('create the organization', created.status, 200, JSON.stringify(created.body))) return;
  const orgId = created.body?.id;
  const listed = await api(baseUrl, `/api/organizations/${orgId}/collections`, { token });
  const collectionId = (listed.body?.data || listed.body || [])
    .map((collection) => collection.id)
    .find(Boolean);
  if (!checks.ok('the organization has a collection', !!collectionId)) return;

  // The shared items are what a moved vault holds: each one belongs to the
  // organization and sits in its collection. They are written into the
  // worker's own database: the check is about the read that follows, and
  // writing hundreds of items over HTTP would only run into the rate limit.
  const sharedIds = writeSharedItems(worker.persistDir, {
    userId: await ownerId(baseUrl, token),
    orgId,
    collectionId,
    count: SHARED_ITEMS,
  });
  checks.equal('the shared items are written', sharedIds.length, SHARED_ITEMS);

  const sync = await api(baseUrl, '/api/sync', { token });
  checks.equal('the official sync endpoint answers', sync.status, 200, JSON.stringify(sync.body).slice(0, 300));

  const ciphers = sync.body?.ciphers || [];
  const sharedInSync = ciphers.filter((cipher) => sharedIds.includes(cipher.id));
  checks.equal('every shared item is in the sync payload', sharedInSync.length, SHARED_ITEMS);
  checks.ok(
    'a shared item names its organization',
    sharedInSync.every((cipher) => cipher.organizationId === orgId),
    JSON.stringify(sharedInSync[0] || {}).slice(0, 200)
  );
  checks.ok(
    'a shared item names its collection',
    sharedInSync.every((cipher) => (cipher.collectionIds || []).includes(collectionId)),
    JSON.stringify(sharedInSync[0] || {}).slice(0, 400)
  );
}

const worker = await startLocalWorker({ label: 'scale' });
const checks = createChecks('the sync endpoint answers for a vault of hundreds of shared items');
try {
  await run(worker, checks);
} finally {
  await worker.stop();
}
checks.finish();
