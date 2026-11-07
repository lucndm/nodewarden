// Local API end-to-end check.
//
// Boots a throwaway Worker with its own D1 and drives the vault over HTTP:
// register, log in, create an item, change it, read the item history, restore
// an old state. The payloads are opaque ciphertext as far as the server is
// concerned, so no key material is needed here; the browser check
// (local-ui-e2e.mjs) covers the encrypted round trip.
//
// Run it before pushing to main:
//   npm run test:local
import { startLocalWorker, createChecks } from './local-worker.mjs';

const enc = (value) => {
  const part = (text) => Buffer.from(text, 'utf8').toString('base64');
  return `2.${part(`iv-${value}`)}|${part(`ct-${value}`)}|${part(`mac-${value}`)}`;
};

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

async function register(baseUrl, email, inviteCode) {
  const response = await api(baseUrl, '/api/accounts/register', {
    method: 'POST',
    headers: { Origin: baseUrl },
    body: {
      email,
      name: 'Local Check',
      masterPasswordHash: Buffer.from(`hash-${email}`).toString('base64'),
      key: enc(`vault-key-${email}`),
      kdf: 0,
      kdfIterations: 600000,
      inviteCode,
      keys: {
        publicKey: Buffer.from('public-key').toString('base64'),
        encryptedPrivateKey: enc('private-key'),
      },
    },
  });
  return response;
}

async function login(baseUrl, email) {
  const response = await api(baseUrl, '/identity/connect/token', {
    method: 'POST',
    form: {
      grant_type: 'password',
      username: email,
      password: Buffer.from(`hash-${email}`).toString('base64'),
      scope: 'api offline_access',
      deviceIdentifier: 'local-check-device',
      deviceName: 'local check',
      deviceType: '14',
    },
  });
  return response.body?.access_token || null;
}

async function run(baseUrl, checks) {
  const owner = 'local-owner@example.test';
  const stranger = 'local-stranger@example.test';

  const registered = await register(baseUrl, owner);
  if (!checks.equal('register the owner', registered.status, 200, JSON.stringify(registered.body))) return;
  const token = await login(baseUrl, owner);
  if (!checks.ok('log in and get a token', !!token)) return;

  const created = await api(baseUrl, '/api/ciphers', {
    method: 'POST',
    token,
    body: {
      type: 1,
      name: enc('Local Login'),
      notes: enc('first notes'),
      login: { username: enc('user-v1'), password: enc('pass-v1') },
    },
  });
  if (!checks.equal('create a login item', created.status, 200, JSON.stringify(created.body))) return;
  const cipherId = created.body?.id;
  const revision = created.body?.revisionDate;
  checks.ok('the new item has an id', !!cipherId);
  checks.ok('the new item has a revision', !!revision);

  const empty = await api(baseUrl, `/api/ciphers/${cipherId}/versions`, { token });
  checks.equal('a new item has no history', empty.status, 200);
  checks.equal('the history is empty', (empty.body?.data || []).length, 0);

  const edited = await api(baseUrl, `/api/ciphers/${cipherId}`, {
    method: 'PUT',
    token,
    body: {
      type: 1,
      name: enc('Local Login'),
      notes: enc('second notes'),
      login: { username: enc('user-v2'), password: enc('pass-v1') },
    },
  });
  checks.equal('change the username', edited.status, 200, JSON.stringify(edited.body));

  const listed = await api(baseUrl, `/api/ciphers/${cipherId}/versions`, { token });
  const versions = listed.body?.data || [];
  checks.equal('the change recorded one version', versions.length, 1);
  checks.equal('the version is the state the item was created in', versions[0]?.kind, 'created');
  checks.equal('the version keeps the old name', versions[0]?.name, enc('Local Login'));

  const snapshot = await api(baseUrl, `/api/ciphers/${cipherId}/versions/${versions[0]?.id}`, { token });
  checks.equal('read the version snapshot', snapshot.status, 200);
  const snapshotPayload = JSON.parse(snapshot.body?.data || '{}');
  checks.equal('the snapshot keeps the old username', snapshotPayload.login?.username, enc('user-v1'));
  checks.equal('the snapshot keeps the old notes', snapshot.body?.notes, enc('first notes'));

  const moved = await api(baseUrl, `/api/ciphers/${cipherId}`, {
    method: 'PUT',
    token,
    body: {
      type: 1,
      name: enc('Local Login'),
      notes: enc('second notes'),
      login: { username: enc('user-v2'), password: enc('pass-v1') },
      tags: ['work'],
    },
  });
  checks.equal('move the item into a folder', moved.status, 200);
  const afterMove = await api(baseUrl, `/api/ciphers/${cipherId}/versions`, { token });
  checks.equal('a folder move records no version', (afterMove.body?.data || []).length, 1);

  const stale = await api(baseUrl, `/api/ciphers/${cipherId}/versions/${versions[0]?.id}/restore`, {
    method: 'POST',
    token,
    headers: { 'If-Match': '2020-01-01T00:00:00.000Z' },
  });
  checks.equal('a restore with a stale revision is refused', stale.status, 409);

  const current = await api(baseUrl, `/api/ciphers/${cipherId}`, { token });
  const restored = await api(baseUrl, `/api/ciphers/${cipherId}/versions/${versions[0]?.id}/restore`, {
    method: 'POST',
    token,
    headers: { 'If-Match': current.body?.revisionDate || '' },
  });
  checks.equal('restore the old state', restored.status, 200, JSON.stringify(restored.body));
  checks.equal('the item keeps its id', restored.body?.id, cipherId);
  checks.equal('the old username is back', restored.body?.login?.username, enc('user-v1'));
  checks.ok('the revision moved', restored.body?.revisionDate !== current.body?.revisionDate);

  const afterRestore = await api(baseUrl, `/api/ciphers/${cipherId}/versions`, { token });
  checks.equal('the replaced state was kept as a version', (afterRestore.body?.data || []).length, 2);

  const sync = await api(baseUrl, '/api/sync', { token });
  checks.equal('the official sync endpoint still answers', sync.status, 200);
  const syncedCipher = (sync.body?.ciphers || []).find((entry) => entry.id === cipherId);
  checks.ok('the restored item is in the sync payload', !!syncedCipher);
  checks.equal('the sync payload carries the restored username', syncedCipher?.login?.username, enc('user-v1'));

  // The first account is the admin, so it can hand out an invite code.
  const invite = await api(baseUrl, '/api/admin/invites', {
    method: 'POST',
    token,
    body: {
      masterPasswordHash: Buffer.from(`hash-${owner}`).toString('base64'),
      expiresInHours: 1,
    },
  });
  checks.equal('the admin creates an invite', invite.status, 201, JSON.stringify(invite.body));
  const otherRegistered = await register(baseUrl, stranger, invite.body?.code);
  checks.equal('register a second account with the invite', otherRegistered.status, 200, JSON.stringify(otherRegistered.body));
  const otherToken = await login(baseUrl, stranger);
  const foreignList = await api(baseUrl, `/api/ciphers/${cipherId}/versions`, { token: otherToken });
  checks.equal('another account sees no history', foreignList.status, 404);
  const foreignRestore = await api(baseUrl, `/api/ciphers/${cipherId}/versions/${versions[0]?.id}/restore`, {
    method: 'POST',
    token: otherToken,
  });
  checks.equal('another account cannot restore', foreignRestore.status, 404);
}

const worker = await startLocalWorker({ label: 'api-e2e' });
try {
  console.log(`local Worker: ${worker.baseUrl}`);
  const checks = createChecks('local API end-to-end');
  await run(worker.baseUrl, checks);
  checks.finish();
} finally {
  await worker.stop();
}
