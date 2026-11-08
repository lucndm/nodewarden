// Local end-to-end check driven by the official Bitwarden CLI.
//
// Boots a throwaway Worker with its own D1, registers an account with real
// key material and then lets the official CLI do the work: log in, create an
// item, read it back, edit it, sync. The item history endpoints are NodeWarden
// specific and have no official client, so they are called over HTTP; the
// restored state is then read back through the CLI, which proves the round
// trip with the real client.
//
// Run it before pushing to main:
//   npm run test:local-cli
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { webcrypto } from 'node:crypto';

import { startLocalWorker, startTlsProxy, createChecks } from './local-worker.mjs';
import { bytesToBase64, decryptBw, decryptStr, encryptBw, hkdfExpand, pbkdf2 } from '../webapp/src/lib/crypto.ts';
import { applyOrganizationKeyRotation } from '../webapp/src/lib/organization-key-rotation.ts';

const EMAIL = 'local-cli@example.test';
const PASSWORD = 'Local-CLI-Check-2026!';
const KDF_ITERATIONS = 600000;

function findCli() {
  const candidates = [
    process.env.NODEWARDEN_BW_CLI,
    'node_modules/.bin/bw',
    '/tmp/bw-cli-install/node_modules/@bitwarden/cli/build/bw.js',
    '/tmp/bw-cli-2025/node_modules/@bitwarden/cli/build/bw.js',
  ].filter(Boolean);
  for (const candidate of candidates) {
    if (candidate.includes('/') && existsSync(candidate)) return candidate;
  }
  return null;
}

async function runCli(cli, args, { env = {}, cwd } = {}) {
  const command = cli.endsWith('.js') ? process.execPath : cli;
  const argv = cli.endsWith('.js') ? [cli, ...args] : args;
  return new Promise((resolve) => {
    const child = spawn(command, argv, {
      env: { ...process.env, ...env },
      cwd,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr?.on('data', (chunk) => {
      stderr += chunk.toString();
    });
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

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

// The key material the Web Vault would derive, so the CLI can log in with the
// same password later.
async function createAccount(baseUrl, email = EMAIL, inviteCode = null) {
  const subtle = webcrypto.subtle;
  const masterKey = await pbkdf2(PASSWORD, email, KDF_ITERATIONS, 32);
  const masterHash = await pbkdf2(masterKey, PASSWORD, 1, 32);
  const encKey = await hkdfExpand(masterKey, 'enc', 32);
  const macKey = await hkdfExpand(masterKey, 'mac', 32);
  const vaultKey = webcrypto.getRandomValues(new Uint8Array(64));

  const keyPair = await subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' },
    true,
    ['encrypt', 'decrypt']
  );
  const publicKey = new Uint8Array(await subtle.exportKey('spki', keyPair.publicKey));
  const privateKey = new Uint8Array(await subtle.exportKey('pkcs8', keyPair.privateKey));

  const response = await api(baseUrl, '/api/accounts/register', {
    method: 'POST',
    headers: { Origin: baseUrl },
    body: {
      email,
      name: 'Local CLI',
      inviteCode,
      masterPasswordHash: bytesToBase64(masterHash),
      key: await encryptBw(vaultKey, encKey, macKey),
      kdf: 0,
      kdfIterations: KDF_ITERATIONS,
      keys: {
        publicKey: bytesToBase64(publicKey),
        encryptedPrivateKey: await encryptBw(privateKey, vaultKey.slice(0, 32), vaultKey.slice(32, 64)),
      },
    },
  });
  return {
    status: response.status,
    body: response.body,
    masterHash,
    vaultKey,
    publicKey,
    privateKey,
    // The RSA private key as the account stores it: encrypted under the
    // member's own vault key, in the shape an encrypted string has.
    encryptedPrivateKey: await encryptBw(privateKey, vaultKey.slice(0, 32), vaultKey.slice(32, 64)),
  };
}

// The client encrypts item fields with the item key and stores that key under
// the vault key, so a stored snapshot has to be decrypted with the key the
// version carries.
async function decryptField(cipherString, itemKeyCipher, vaultKey) {
  if (!cipherString) return '';
  let encKey = vaultKey.slice(0, 32);
  let macKey = vaultKey.slice(32, 64);
  if (itemKeyCipher) {
    const itemKey = await decryptBw(itemKeyCipher, encKey, macKey);
    encKey = itemKey.slice(0, 32);
    macKey = itemKey.slice(32, 64);
  }
  return decryptStr(cipherString, encKey, macKey);
}

async function run(baseUrl, checks, cli, cliEnv, workerLog = () => '') {
  const account = await createAccount(baseUrl);
  if (!checks.equal('register the account', account.status, 200, JSON.stringify(account.body))) return;

  const configured = await runCli(cli, ['config', 'server', cliEnv.BW_SERVER], { env: cliEnv });
  if (!checks.equal('point the CLI at the local Worker', configured.code, 0, configured.stderr.trim())) return;

  const login = await runCli(cli, ['login', EMAIL, PASSWORD, '--raw'], { env: cliEnv });
  const session = login.stdout.trim();
  if (!checks.ok('the CLI logs in', login.code === 0 && session.length > 0, login.stderr.trim())) return;
  const env = { ...cliEnv, BW_SESSION: session };

  const created = await runCli(
    cli,
    ['create', 'item', Buffer.from(JSON.stringify({
      type: 1,
      name: 'CLI History Login',
      notes: 'written by the official CLI',
      login: { username: 'cli-user-v1', password: 'cli-pass-v1' },
    })).toString('base64'), '--raw'],
    { env }
  );
  if (!checks.ok('the CLI creates an item', created.code === 0, created.stderr.trim())) return;
  await runCli(cli, ['sync'], { env });
  const listOutput = await runCli(cli, ['list', 'items', '--raw'], { env });
  let listedItems = [];
  try {
    listedItems = JSON.parse(listOutput.stdout || '[]');
  } catch {
    listedItems = [];
  }
  const createdItem = listedItems.find((entry) => entry?.name === 'CLI History Login');
  const itemId = createdItem?.id || '';
  if (!checks.ok('the new item is in the CLI vault', !!itemId, listOutput.stderr.trim())) return;

  const read = await runCli(cli, ['get', 'item', itemId, '--raw'], { env });
  let item = null;
  try {
    item = JSON.parse(read.stdout || '{}');
  } catch {
    item = null;
  }
  checks.equal('the CLI reads the item back', read.code, 0, read.stderr.trim());
  checks.equal('the CLI decrypts the username', item?.login?.username, 'cli-user-v1');

  const token = await api(baseUrl, '/identity/connect/token', {
    method: 'POST',
    form: {
      grant_type: 'password',
      username: EMAIL,
      password: bytesToBase64(account.masterHash),
      scope: 'api offline_access',
      deviceIdentifier: 'local-cli-check',
      deviceName: 'local cli check',
      deviceType: '14',
    },
  }).then((response) => response.body?.access_token || null);
  if (!checks.ok('the API issues a token for the same account', !!token)) return;

  const empty = await api(baseUrl, `/api/ciphers/${itemId}/versions`, { token });
  checks.equal('a new item has no history', (empty.body?.data || []).length, 0);

  const edited = await runCli(
    cli,
    [
      'edit',
      'item',
      itemId,
      Buffer.from(JSON.stringify({
        id: itemId,
        type: 1,
        name: 'CLI History Login',
        notes: 'written by the official CLI',
        login: { username: 'cli-user-v2', password: 'cli-pass-v1' },
      })).toString('base64'),
    ],
    { env }
  );
  if (!checks.ok('the CLI edits the item', edited.code === 0, edited.stderr.trim())) return;

  const listed = await api(baseUrl, `/api/ciphers/${itemId}/versions`, { token });
  const versions = listed.body?.data || [];
  checks.equal('the CLI edit recorded one version', versions.length, 1);
  checks.equal('the version is the state the item was created in', versions[0]?.kind, 'created');

  const currentCipher = (await api(baseUrl, `/api/ciphers/${itemId}`, { token })).body;
  const snapshot = await api(baseUrl, `/api/ciphers/${itemId}/versions/${versions[0]?.id}`, { token });
  const payload = JSON.parse(snapshot.body?.data || '{}');
  // The server stores the snapshot as ciphertext; the client decrypts it with
  // the vault key, and it must hold the username from before the edit.
  const snapshotUsername = await decryptField(
    payload.login?.username,
    snapshot.body?.key,
    account.vaultKey
  );
  checks.equal('the snapshot decrypts to the old username', snapshotUsername, 'cli-user-v1');
  const liveUsername = await decryptField(
    currentCipher?.login?.username,
    currentCipher?.key,
    account.vaultKey
  );
  checks.equal('the live item holds the new username', liveUsername, 'cli-user-v2');

  const restored = await api(baseUrl, `/api/ciphers/${itemId}/versions/${versions[0]?.id}/restore`, {
    method: 'POST',
    token,
    headers: { 'If-Match': currentCipher?.revisionDate || '' },
  });
  checks.equal('restore the old state', restored.status, 200, JSON.stringify(restored.body));

  // The CLI knows folders, not tags: its move must place the item in the
  // folder without turning the encrypted folder name into a tag.
  const folderCreated = await runCli(
    cli,
    ['create', 'folder', Buffer.from(JSON.stringify({ name: 'CLI Folder' })).toString('base64')],
    { env }
  );
  if (!checks.ok('the CLI creates a folder', folderCreated.code === 0, folderCreated.stderr.trim())) return;
  // The CLI prints either the id or the whole folder, depending on the version.
  const rawFolder = folderCreated.stdout.trim();
  let folderId = rawFolder;
  try {
    const parsed = JSON.parse(rawFolder);
    if (parsed?.id) folderId = String(parsed.id);
  } catch {
    folderId = rawFolder;
  }
  checks.ok('the CLI reports the new folder id', folderId.length > 0, folderCreated.stdout);
  const serverFolders = (await api(baseUrl, '/api/folders', { token })).body?.data || [];
  checks.ok(
    'the server knows the folder the CLI created',
    serverFolders.some((folder) => folder.id === folderId),
    JSON.stringify(serverFolders).slice(0, 300)
  );

  await runCli(cli, ['sync'], { env });
  const cipherBefore = (await api(baseUrl, `/api/ciphers/${itemId}`, { token })).body;
  const usernameBeforeMove = await decryptField(
    cipherBefore?.login?.username,
    cipherBefore?.key,
    account.vaultKey
  );
  // The CLI edits from the item it holds, so the move sends the whole item
  // with the new folder, exactly like the official client would.
  const currentItem = JSON.parse((await runCli(cli, ['get', 'item', itemId, '--raw'], { env })).stdout || '{}');
  const moved = await runCli(
    cli,
    [
      'edit',
      'item',
      itemId,
      Buffer.from(JSON.stringify({ ...currentItem, folderId })).toString('base64'),
    ],
    { env }
  );
  if (!checks.ok('the CLI moves the item into the folder', moved.code === 0, moved.stderr.trim())) return;

  const movedItem = JSON.parse((await runCli(cli, ['get', 'item', itemId, '--raw'], { env })).stdout || '{}');
  checks.equal('the CLI shows the item in the new folder', movedItem.folderId, folderId);

  const movedCipher = (await api(baseUrl, `/api/ciphers/${itemId}`, { token })).body;
  checks.equal('the server keeps the folder position', movedCipher?.folderId, folderId);
  const tagList = Array.isArray(movedCipher?.tags) ? movedCipher.tags : [];
  checks.ok(
    'the encrypted folder name never lands in the tags',
    tagList.every((tag) => !/^\d+\.[^|]*\|[^|]*\|[^|]*$/.test(String(tag))),
    JSON.stringify(tagList)
  );
  // The official CLI re-encrypts the whole item on every edit, so the stored
  // ciphertext changes even though the content does not. What matters is that
  // the item still holds the same values and sits in the new folder.
  const usernameAfterMove = await decryptField(
    movedCipher?.login?.username,
    movedCipher?.key,
    account.vaultKey
  );
  checks.equal('the folder move leaves the content alone', usernameAfterMove, usernameBeforeMove);
  checks.equal('the folder move leaves the username alone', usernameAfterMove, 'cli-user-v1');

  const synced = await runCli(cli, ['sync'], { env });
  checks.equal('the CLI syncs', synced.code, 0, synced.stderr.trim());
  const afterRestore = await runCli(cli, ['get', 'item', itemId, '--raw'], { env });
  let restoredItem = null;
  try {
    restoredItem = JSON.parse(afterRestore.stdout || '{}');
  } catch {
    restoredItem = null;
  }
  checks.equal('the CLI sees the restored username', restoredItem?.login?.username, 'cli-user-v1');
  checks.equal('the restored item keeps its id', restoredItem?.id, itemId);

  // Sharing. An organization item is encrypted with the organization key,
  // which the server stores wrapped with the member's own RSA key. The CLI
  // has to unwrap it before it can read a single shared item, so a decrypted
  // name here is the proof that the wrapping is the shape the official client
  // expects.
  const subtle = webcrypto.subtle;
  const organizationKey = webcrypto.getRandomValues(new Uint8Array(64));
  const importedMemberKey = await subtle.importKey(
    'spki',
    account.publicKey.buffer.slice(account.publicKey.byteOffset, account.publicKey.byteOffset + account.publicKey.byteLength),
    { name: 'RSA-OAEP', hash: 'SHA-1' },
    false,
    ['encrypt']
  );
  const wrappedOrganizationKey = `4.${bytesToBase64(
    new Uint8Array(
      await subtle.encrypt(
        { name: 'RSA-OAEP' },
        importedMemberKey,
        organizationKey.buffer.slice(0, 64)
      )
    )
  )}`;

  const organization = await api(baseUrl, '/api/organizations', {
    method: 'POST',
    token,
    body: {
      name: 'CLI Team',
      // A real client encrypts the collection name with the organization key,
      // and the official client refuses a name it cannot decrypt.
      collectionName: await encryptBw(
        new TextEncoder().encode('CLI Shared'),
        organizationKey.slice(0, 32),
        organizationKey.slice(32, 64)
      ),
      key: wrappedOrganizationKey,
      keys: {
        publicKey: bytesToBase64(account.publicKey),
        encryptedPrivateKey: await encryptBw(
          account.privateKey,
          organizationKey.slice(0, 32),
          organizationKey.slice(32, 64)
        ),
      },
    },
  });
  if (!checks.equal('create the organization', organization.status, 200, JSON.stringify(organization.body))) return;
  const organizationId = organization.body?.id || '';

  // The CLI reads the organization and its collections from its own synced
  // copy, so it has to sync before it can see either.
  const syncAfterOrg = await runCli(cli, ['sync'], { env });
  checks.equal('the CLI syncs after the organization is created', syncAfterOrg.code, 0, syncAfterOrg.stderr.trim());
  const orgCollections = await runCli(cli, ['list', 'org-collections', '--organizationid', organizationId, '--raw'], { env });
  let listedCollections = [];
  try {
    listedCollections = JSON.parse(orgCollections.stdout || '[]');
  } catch {
    listedCollections = [];
  }
  checks.ok(
    'the CLI decrypts the collection name',
    listedCollections.some((entry) => entry?.name === 'CLI Shared'),
    orgCollections.stdout.slice(0, 300) || orgCollections.stderr.trim()
  );

  const collections = await api(baseUrl, '/api/collections', { token });
  const collectionId = (collections.body?.data || [])[0]?.id || '';
  if (!checks.ok('the organization has a collection', !!collectionId, JSON.stringify(collections.body).slice(0, 300))) return;

  // An item the Web Vault would have written: its key wrapped with the
  // organization key, its payload under that item key.
  const sharedItemKey = webcrypto.getRandomValues(new Uint8Array(64));
  const sharedEncrypt = (value) =>
    encryptBw(new TextEncoder().encode(value), sharedItemKey.slice(0, 32), sharedItemKey.slice(32, 64));
  const sharedItem = await api(baseUrl, '/api/ciphers', {
    method: 'POST',
    token,
    body: {
      type: 1,
      name: await sharedEncrypt('Web Vault Shared Login'),
      organizationId,
      collectionIds: [collectionId],
      key: await encryptBw(sharedItemKey, organizationKey.slice(0, 32), organizationKey.slice(32, 64)),
      login: { username: await sharedEncrypt('shared-user'), password: await sharedEncrypt('shared-pass') },
    },
  });
  if (!checks.equal('write a shared item', sharedItem.status, 200, JSON.stringify(sharedItem.body))) return;
  const sharedItemId = sharedItem.body?.id || '';

  await runCli(cli, ['sync'], { env });
  const orgList = await runCli(cli, ['list', 'organizations', '--raw'], { env });
  let organizations = [];
  try {
    organizations = JSON.parse(orgList.stdout || '[]');
  } catch {
    organizations = [];
  }
  checks.ok(
    'the CLI lists the organization',
    organizations.some((entry) => entry?.id === organizationId),
    orgList.stderr.trim() || orgList.stdout.slice(0, 300)
  );
  const orgItems = await runCli(cli, ['list', 'items', '--organizationid', organizationId, '--raw'], { env });
  let sharedItems = [];
  try {
    sharedItems = JSON.parse(orgItems.stdout || '[]');
  } catch {
    sharedItems = [];
  }
  const readShared = sharedItems.find((entry) => entry?.id === sharedItemId);
  checks.ok(
    'the CLI decrypts the shared item the server holds',
    readShared?.name === 'Web Vault Shared Login',
    JSON.stringify(readShared || {}).slice(0, 400) || orgItems.stderr.trim()
  );
  checks.equal('the CLI decrypts the shared username', readShared?.login?.username, 'shared-user');

  // The other direction: the CLI puts an item into the organization, which
  // means it wrapped the item key under the organization key itself.
  const personal = await runCli(
    cli,
    ['create', 'item', Buffer.from(JSON.stringify({
      type: 1,
      name: 'CLI Shared Login',
      login: { username: 'cli-shared-user', password: 'cli-shared-pass' },
    })).toString('base64'), '--raw'],
    { env }
  );
  if (!checks.ok('the CLI creates an item to share', personal.code === 0, personal.stderr.trim())) return;
  // The create output is not the id, so the item is looked up the way a user
  // would find it.
  await runCli(cli, ['sync'], { env });
  const personalList = await runCli(cli, ['list', 'items', '--raw'], { env });
  let personalItems = [];
  try {
    personalItems = JSON.parse(personalList.stdout || '[]');
  } catch {
    personalItems = [];
  }
  const personalId = personalItems.find((entry) => entry?.name === 'CLI Shared Login')?.id || '';
  if (!checks.ok('the new item is in the CLI vault', !!personalId, personalList.stdout.slice(0, 300))) return;
  await runCli(cli, ['sync'], { env });
  const movedToOrganization = await runCli(
    cli,
    ['move', personalId, organizationId, Buffer.from(JSON.stringify([collectionId])).toString('base64')],
    { env }
  );
  checks.equal(
    'the CLI moves an item into the organization',
    movedToOrganization.code,
    0,
    movedToOrganization.stderr.trim() + '\n' + workerLog().slice(-2500)
  );

  await runCli(cli, ['sync'], { env });
  const movedItems = await runCli(cli, ['list', 'items', '--organizationid', organizationId, '--raw'], { env });
  let itemsAfterMove = [];
  try {
    itemsAfterMove = JSON.parse(movedItems.stdout || '[]');
  } catch {
    itemsAfterMove = [];
  }
  const movedShared = itemsAfterMove.find((entry) => entry?.id === personalId);
  checks.equal('the CLI reads back the item it shared', movedShared?.name, 'CLI Shared Login');
  checks.equal('the shared item keeps its username', movedShared?.login?.username, 'cli-shared-user');

  // What the server stored is an organization item, in the collection.
  const stored = (await api(baseUrl, `/api/ciphers/${personalId}`, { token })).body;
  checks.equal('the server keeps the item in the organization', stored?.organizationId, organizationId);
  checks.ok(
    'the server keeps the collection the CLI chose',
    Array.isArray(stored?.collectionIds) && stored.collectionIds.includes(collectionId),
    JSON.stringify(stored?.collectionIds)
  );

  // The real question about sharing: does the item travel from one member to
  // another? A second account joins the organization, and the CLI reads the
  // item the owner wrote - through the organization key wrapped for that
  // second member.
  const memberEmail = 'cli-member@example.test';
  const invite = await api(baseUrl, '/api/admin/invites', {
    method: 'POST',
    token,
    body: { masterPasswordHash: bytesToBase64(account.masterHash), expiresInHours: 24 },
  });
  if (!checks.equal('the owner can make an invite', invite.status, 201, JSON.stringify(invite.body))) return;
  const memberAccount = await createAccount(baseUrl, memberEmail, invite.body?.code);
  if (!checks.equal('the second account registers', memberAccount.status, 200, JSON.stringify(memberAccount.body))) return;

  // The organization key is wrapped for the second member with their own RSA
  // key, exactly as an admin's client does when it invites somebody.
  const importedSecondMemberKey = await subtle.importKey(
    'spki',
    memberAccount.publicKey.buffer.slice(
      memberAccount.publicKey.byteOffset,
      memberAccount.publicKey.byteOffset + memberAccount.publicKey.byteLength
    ),
    { name: 'RSA-OAEP', hash: 'SHA-1' },
    false,
    ['encrypt']
  );
  const wrappedForMember = `4.${bytesToBase64(
    new Uint8Array(
      await subtle.encrypt(
        { name: 'RSA-OAEP' },
        importedSecondMemberKey,
        organizationKey.buffer.slice(0, 64)
      )
    )
  )}`;
  // The invitation goes out without a key: the member has to answer it
  // first, and the owner hands the key over afterwards.
  const invited = await api(baseUrl, `/api/organizations/${organizationId}/users`, {
    method: 'POST',
    token,
    body: { emails: [memberEmail] },
  });
  if (!checks.equal('the second member is invited', invited.status, 200, JSON.stringify(invited.body))) return;
  const memberList = await api(baseUrl, `/api/organizations/${organizationId}/users`, { token });
  const memberRow = (memberList.body?.data || []).find((entry) => entry?.email === memberEmail);
  checks.equal('the invitation is unanswered', memberRow?.status, 0);

  // The member answers it.
  const memberToken = await api(baseUrl, '/identity/connect/token', {
    method: 'POST',
    form: {
      grant_type: 'password',
      username: memberEmail,
      password: bytesToBase64(memberAccount.masterHash),
      scope: 'api offline_access',
      deviceIdentifier: 'local-cli-member',
      deviceName: 'local cli member',
      deviceType: '14',
    },
  }).then((response) => response.body?.access_token || null);
  if (!checks.ok('the second member gets a token', !!memberToken)) return;
  const accepted = await api(baseUrl, `/api/organizations/${organizationId}/accept`, {
    method: 'POST',
    token: memberToken,
  });
  checks.equal('the second member accepts the invitation', accepted.status, 200, JSON.stringify(accepted.body));

  // The owner hands over the organization key, wrapped for the member.
  const confirmed = await api(
    baseUrl,
    `/api/organizations/${organizationId}/users/${memberRow?.id}/confirm`,
    { method: 'POST', token, body: { key: wrappedForMember } }
  );
  checks.equal('the owner hands the organization key over', confirmed.status, 200, JSON.stringify(confirmed.body));
  const memberListAfter = await api(baseUrl, `/api/organizations/${organizationId}/users`, { token });
  const memberRowAfter = (memberListAfter.body?.data || []).find((entry) => entry?.email === memberEmail);
  checks.equal('the second member is confirmed', memberRowAfter?.status, 2);

  // A member reaches an item through the collections they hold rights on, so
  // the owner gives the second member the collection.
  const assigned = await api(
    baseUrl,
    `/api/organizations/${organizationId}/users/${memberRow?.id}`,
    {
      method: 'PUT',
      token,
      body: {
        collections: [
          { id: collectionId, readOnly: false, hidePasswords: false, manage: false },
        ],
      },
    }
  );
  if (!checks.equal('the owner gives the second member the collection', assigned.status, 200, JSON.stringify(assigned.body).slice(0, 300))) return;

  // The second member logs in with the official CLI, in its own data
  // directory, and reads the item the owner wrote.
  const memberDataDir = await mkdtemp(join(tmpdir(), 'nodewarden-bw-cli-member-'));
  const memberEnv = {
    ...cliEnv,
    BITWARDENCLI_APPDATA_DIR: memberDataDir,
  };
  await runCli(cli, ['config', 'server', cliEnv.BW_SERVER], { env: memberEnv });
  const memberLogin = await runCli(cli, ['login', memberEmail, PASSWORD, '--raw'], { env: memberEnv });
  const memberSession = memberLogin.stdout.trim();
  if (!checks.ok('the second member logs in', memberLogin.code === 0 && memberSession.length > 0, memberLogin.stderr.trim())) return;
  const memberCliEnv = { ...memberEnv, BW_SESSION: memberSession };
  await runCli(cli, ['sync'], { env: memberCliEnv });
  const memberItems = await runCli(cli, ['list', 'items', '--organizationid', organizationId, '--raw'], { env: memberCliEnv });
  let itemsForMember = [];
  try {
    itemsForMember = JSON.parse(memberItems.stdout || '[]');
  } catch {
    itemsForMember = [];
  }
  const sharedWithMember = itemsForMember.find((entry) => entry?.id === sharedItemId);
  checks.equal(
    'the second member reads the item the owner wrote',
    sharedWithMember?.name,
    'Web Vault Shared Login'
  );
  checks.equal('the second member reads its username', sharedWithMember?.login?.username, 'shared-user');

  // Rotating the key replaces the key every member holds. The member that was
  // not removed has to be able to open the items again with the new key, so
  // this is where the rotation is checked against the official client.
  const rotationData = await api(baseUrl, `/api/organizations/${organizationId}/rotation-data`, { token });
  if (!checks.equal('the owner reads the rotation data', rotationData.status, 200, JSON.stringify(rotationData.body).slice(0, 300))) return;
  const rotation = await applyOrganizationKeyRotation({
    authedFetch: async (url, init) => {
      const response = await api(baseUrl, url, {
        method: init?.method || 'GET',
        token,
        body: init?.body ? JSON.parse(String(init.body)) : undefined,
      });
      return new Response(JSON.stringify(response.body ?? {}), {
        status: response.status,
        headers: { 'Content-Type': 'application/json' },
      });
    },
    organization: { id: organizationId, wrappedKey: wrappedOrganizationKey },
    encryptedPrivateKey: account.encryptedPrivateKey,
    userEncKey: account.vaultKey.slice(0, 32),
    userMacKey: account.vaultKey.slice(32, 64),
    organizationPrivateKey: rotationData.body?.organization?.privateKey ?? null,
    members: (rotationData.body?.members ?? []).map((member) => ({
      membershipId: member.membershipId,
      publicKey: member.publicKey,
    })),
    ciphers: (rotationData.body?.ciphers ?? []).map((cipher) => ({
      id: cipher.id,
      key: cipher.key,
      name: cipher.name,
      notes: cipher.notes,
      data: cipher.data ?? {},
    })),
  });
  checks.ok('the key is rotated', !!rotation?.rotatedAt, JSON.stringify(rotation).slice(0, 300));

  await runCli(cli, ['sync'], { env: memberCliEnv });
  const afterRotation = await runCli(cli, ['list', 'items', '--organizationid', organizationId, '--raw'], { env: memberCliEnv });
  let itemsAfterRotation = [];
  try {
    itemsAfterRotation = JSON.parse(afterRotation.stdout || '[]');
  } catch {
    itemsAfterRotation = [];
  }
  const sharedAfterRotation = itemsAfterRotation.find((entry) => entry?.id === sharedItemId);
  checks.equal(
    'the member reads the item again after the key was rotated',
    sharedAfterRotation?.name,
    'Web Vault Shared Login'
  );
  checks.equal(
    'the item still holds its username after the rotation',
    sharedAfterRotation?.login?.username,
    'shared-user'
  );

  // The member that stayed must also still read the items the owner wrote.
  await runCli(cli, ['sync'], { env });
  const ownerAfterRotation = await runCli(cli, ['list', 'items', '--organizationid', organizationId, '--raw'], { env });
  let ownerItemsAfterRotation = [];
  try {
    ownerItemsAfterRotation = JSON.parse(ownerAfterRotation.stdout || '[]');
  } catch {
    ownerItemsAfterRotation = [];
  }
  const ownerItemAfterRotation = ownerItemsAfterRotation.find((entry) => entry?.id === personalId);
  checks.equal(
    'the owner reads the item it shared after the rotation',
    ownerItemAfterRotation?.name,
    'CLI Shared Login'
  );

  await runCli(cli, ['logout'], { env: memberEnv });
  await rm(memberDataDir, { recursive: true, force: true });
}

const cli = findCli();
if (!cli) {
  console.log('skipped: no Bitwarden CLI found.');
  console.log('Install one with `npm i -D @bitwarden/cli` or set NODEWARDEN_BW_CLI to a bw binary.');
  process.exit(0);
}

const worker = await startLocalWorker({ label: 'cli-e2e' });
const appDataDir = await mkdtemp(join(tmpdir(), 'nodewarden-bw-cli-'));
let proxy = null;
try {
  // The official CLI refuses plain http, so the Worker is served over https
  // with a throwaway certificate the CLI is told to trust.
  proxy = await startTlsProxy(worker.baseUrl);
  const cliEnv = {
    BITWARDENCLI_APPDATA_DIR: appDataDir,
    BW_SERVER: proxy.baseUrl,
    NODE_EXTRA_CA_CERTS: proxy.certPath,
  };
  console.log(`local Worker: ${worker.baseUrl} (https for the CLI: ${proxy.baseUrl})`);
  console.log(`Bitwarden CLI: ${cli}`);
  const checks = createChecks('local end-to-end through the official Bitwarden CLI');
  await run(worker.baseUrl, checks, cli, cliEnv, worker.log);
  checks.finish();
} finally {
  await runCli(cli, ['logout'], { env: { BITWARDENCLI_APPDATA_DIR: appDataDir } });
  if (proxy) await proxy.stop();
  await worker.stop();
  await rm(appDataDir, { recursive: true, force: true });
}
