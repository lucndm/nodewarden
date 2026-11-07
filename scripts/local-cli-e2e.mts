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
async function createAccount(baseUrl) {
  const subtle = webcrypto.subtle;
  const masterKey = await pbkdf2(PASSWORD, EMAIL, KDF_ITERATIONS, 32);
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
      email: EMAIL,
      name: 'Local CLI',
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
  return { status: response.status, body: response.body, masterHash, vaultKey };
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

async function run(baseUrl, checks, cli, cliEnv) {
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
  await run(worker.baseUrl, checks, cli, cliEnv);
  checks.finish();
} finally {
  await runCli(cli, ['logout'], { env: { BITWARDENCLI_APPDATA_DIR: appDataDir } });
  if (proxy) await proxy.stop();
  await worker.stop();
  await rm(appDataDir, { recursive: true, force: true });
}
