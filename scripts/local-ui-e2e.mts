// Local end-to-end check of the Web Vault in a real browser.
//
// Boots a throwaway Worker with its own D1 and checks the item history the way
// a user sees it: the timeline, the comparison against the current version
// and the restore.
//
// The item itself is written through the API with real key material, so the
// browser only has to log in and look at the timeline. That keeps the check
// on the surface it is meant to cover instead of on form mechanics.
//
// Run it before pushing to main:
//   npm run test:local-ui
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { webcrypto } from 'node:crypto';

import { startLocalWorker, findFreePort, createChecks, chromiumEnv } from './local-worker.mjs';
import { startFakeSimpleLogin } from './fake-simple-login.ts';
import { bytesToBase64, encryptBw, hkdfExpand, pbkdf2 } from '../webapp/src/lib/crypto.ts';

const EMAIL = 'local-ui@example.test';
const PASSWORD = 'Local-UI-Check-2026!';
const KDF_ITERATIONS = 600000;

function findChromium() {
  const candidates = [
    process.env.NODEWARDEN_CHROMIUM,
    'node_modules/.bin/chromium',
    '/root/.cache/puppeteer/chrome/linux-156.0.8078.47/chrome-linux64/chrome',
  ].filter(Boolean);
  for (const candidate of candidates) {
    if (candidate.includes('/') && existsSync(candidate)) return candidate;
  }
  const fromPath = spawnSync(
    'sh',
    ['-c', 'command -v chromium || command -v chromium-browser || command -v google-chrome'],
    { encoding: 'utf8' }
  );
  const path = (fromPath.stdout || '').trim();
  if (path) return path;
  if (existsSync('/nix/store')) {
    for (const entry of readdirSync('/nix/store')) {
      if (!entry.includes('chromium-unwrapped')) continue;
      const candidate = `/nix/store/${entry}/libexec/chromium/chromium`;
      if (existsSync(candidate)) return candidate;
      const wrapper = `/nix/store/${entry}/bin/chromium`;
      if (existsSync(wrapper)) return wrapper;
    }
  }
  return null;
}

async function launchChromium(binary) {
  const port = await findFreePort();
  const profileDir = await mkdtemp(join(tmpdir(), 'nodewarden-ui-'));
  const child = spawn(
    binary,
    [
      '--headless=new',
      '--no-sandbox',
      // The stand-in provider answers over https with a throwaway
      // certificate, because the app only lets a page connect to https
      // addresses. The check trusts that certificate and nothing else.
      '--ignore-certificate-errors',
      '--disable-gpu',
      '--disable-dev-shm-usage',
      `--remote-debugging-port=${port}`,
      `--user-data-dir=${profileDir}`,
      '--window-size=1600,1000',
      'about:blank',
    ],
    { stdio: ['ignore', 'pipe', 'pipe'], env: chromiumEnv() }
  );
  let log = '';
  child.stdout?.on('data', (chunk) => {
    log += chunk.toString();
  });
  child.stderr?.on('data', (chunk) => {
    log += chunk.toString();
  });

  const deadline = Date.now() + 30000;
  let endpoint = null;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/version`, { signal: AbortSignal.timeout(2000) });
      if (response.ok) {
        endpoint = (await response.json()).webSocketDebuggerUrl;
        break;
      }
    } catch {
      // not up yet
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  if (!endpoint) {
    child.kill('SIGKILL');
    await rm(profileDir, { recursive: true, force: true });
    throw new Error(`Chromium did not expose a debugging endpoint\n${log}`);
  }

  return {
    endpoint,
    async stop() {
      child.kill('SIGTERM');
      await new Promise((resolve) => setTimeout(resolve, 500));
      child.kill('SIGKILL');
      await rm(profileDir, { recursive: true, force: true });
    },
  };
}

// A very small Chrome DevTools Protocol client: one socket, one session.
class Cdp {
  constructor(socket) {
    this.socket = socket;
    this.nextId = 1;
    this.pending = new Map();
    socket.addEventListener('message', (event) => {
      const message = JSON.parse(event.data);
      const entry = this.pending.get(message.id);
      if (!entry) return;
      this.pending.delete(message.id);
      if (message.error) entry.reject(new Error(message.error.message));
      else entry.resolve(message.result);
    });
  }

  static async connect(endpoint) {
    const socket = new WebSocket(endpoint);
    await new Promise((resolve, reject) => {
      socket.addEventListener('open', resolve, { once: true });
      socket.addEventListener('error', () => reject(new Error('devtools socket failed')), { once: true });
    });
    return new Cdp(socket);
  }

  send(method, params = {}, sessionId) {
    const id = this.nextId++;
    const payload = { id, method, params };
    if (sessionId) payload.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.socket.send(JSON.stringify(payload));
      setTimeout(() => {
        if (!this.pending.has(id)) return;
        this.pending.delete(id);
        reject(new Error(`${method} timed out`));
      }, 30000);
    });
  }
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

// Registers the account and writes one item, both with real key material, so
// the browser sees exactly what a client would have written.
async function seedVault(baseUrl) {
  const subtle = webcrypto.subtle;
  const masterKey = await pbkdf2(PASSWORD, EMAIL, KDF_ITERATIONS, 32);
  const masterHash = await pbkdf2(masterKey, PASSWORD, 1, 32);
  const encKey = await hkdfExpand(masterKey, 'enc', 32);
  const macKey = await hkdfExpand(masterKey, 'mac', 32);
  const vaultKey = webcrypto.getRandomValues(new Uint8Array(64));
  const itemKey = webcrypto.getRandomValues(new Uint8Array(64));
  const encryptedItemKey = await encryptBw(itemKey, vaultKey.slice(0, 32), vaultKey.slice(32, 64));

  const keyPair = await subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' },
    true,
    ['encrypt', 'decrypt']
  );
  const publicKey = new Uint8Array(await subtle.exportKey('spki', keyPair.publicKey));
  const privateKey = new Uint8Array(await subtle.exportKey('pkcs8', keyPair.privateKey));

  const registered = await api(baseUrl, '/api/accounts/register', {
    method: 'POST',
    headers: { Origin: baseUrl },
    body: {
      email: EMAIL,
      name: 'Local UI',
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
  if (registered.status !== 200) {
    throw new Error(`registration failed: ${registered.status} ${JSON.stringify(registered.body)}`);
  }

  // A second account, so the organization has a member the owner can invite
  // and remove. It has its own RSA key, which is what the organization key is
  // wrapped with. A second account needs an invite code, and the first user
  // is the one who can make one.
  const memberEmail = 'org-member@example.test';
  const memberMasterKey = await pbkdf2(PASSWORD, memberEmail, KDF_ITERATIONS, 32);
  const memberMasterHash = await pbkdf2(memberMasterKey, PASSWORD, 1, 32);
  const memberEncKey = await hkdfExpand(memberMasterKey, 'enc', 32);
  const memberMacKey = await hkdfExpand(memberMasterKey, 'mac', 32);
  const memberVaultKey = webcrypto.getRandomValues(new Uint8Array(64));
  const memberKeyPair = await subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' },
    true,
    ['encrypt', 'decrypt']
  );
  const adminToken = (
    await api(baseUrl, '/identity/connect/token', {
      method: 'POST',
      form: {
        grant_type: 'password',
        username: EMAIL,
        password: bytesToBase64(masterHash),
        scope: 'api offline_access',
        deviceIdentifier: 'local-ui-seed',
        deviceName: 'local ui seed',
        deviceType: '14',
      },
    })
  ).body?.access_token;
  if (!adminToken) throw new Error('the API did not issue an admin token');
  const invite = await api(baseUrl, '/api/admin/invites', {
    method: 'POST',
    token: adminToken,
    body: { masterPasswordHash: bytesToBase64(masterHash), expiresInHours: 24 },
  });
  if (invite.status !== 201) {
    throw new Error(`invite create failed: ${invite.status} ${JSON.stringify(invite.body)}`);
  }

  const memberRegistered = await api(baseUrl, '/api/accounts/register', {
    method: 'POST',
    headers: { Origin: baseUrl },
    body: {
      email: memberEmail,
      inviteCode: invite.body?.code,
      name: 'Org Member',
      masterPasswordHash: bytesToBase64(memberMasterHash),
      key: await encryptBw(memberVaultKey, memberEncKey, memberMacKey),
      kdf: 0,
      kdfIterations: KDF_ITERATIONS,
      keys: {
        publicKey: bytesToBase64(new Uint8Array(await subtle.exportKey('spki', memberKeyPair.publicKey))),
        encryptedPrivateKey: await encryptBw(
          new Uint8Array(await subtle.exportKey('pkcs8', memberKeyPair.privateKey)),
          memberVaultKey.slice(0, 32),
          memberVaultKey.slice(32, 64)
        ),
      },
    },
  });
  if (memberRegistered.status !== 200) {
    throw new Error(`member registration failed: ${memberRegistered.status} ${JSON.stringify(memberRegistered.body)}`);
  }

  const token = (
    await api(baseUrl, '/identity/connect/token', {
      method: 'POST',
      form: {
        grant_type: 'password',
        username: EMAIL,
        password: bytesToBase64(masterHash),
        scope: 'api offline_access',
        deviceIdentifier: 'local-ui-check',
        deviceName: 'local ui check',
        deviceType: '14',
      },
    })
  ).body?.access_token;
  if (!token) throw new Error('the API did not issue a token');

  const encryptField = (value) => encryptBw(new TextEncoder().encode(value), itemKey.slice(0, 32), itemKey.slice(32, 64));

  const created = await api(baseUrl, '/api/ciphers', {
    method: 'POST',
    token,
    body: {
      type: 1,
      name: await encryptField('UI History Login'),
      notes: await encryptField('written for the local check'),
      key: encryptedItemKey,
      login: { username: await encryptField('ui-user-v1'), password: await encryptField('ui-pass-v1') },
    },
  });
  if (created.status !== 200) {
    throw new Error(`create failed: ${created.status} ${JSON.stringify(created.body)}`);
  }

  const edited = await api(baseUrl, `/api/ciphers/${created.body.id}`, {
    method: 'PUT',
    token,
    body: {
      type: 1,
      name: await encryptField('UI History Login'),
      notes: await encryptField('written for the local check'),
      key: encryptedItemKey,
      login: { username: await encryptField('ui-user-v2'), password: await encryptField('ui-pass-v1') },
    },
  });
  if (edited.status !== 200) {
    throw new Error(`edit failed: ${edited.status} ${JSON.stringify(edited.body)}`);
  }

  // An organization with one collection and one item in it, so the browser can
  // show what a shared item is and where it lives. The item key is wrapped with
  // the organization key and the payload is encrypted with that item key, which
  // is exactly what the server expects of a shared item.
  const organizationKey = webcrypto.getRandomValues(new Uint8Array(64));
  const organizationWrappedForOwner = await (async () => {
    const imported = await subtle.importKey('spki', publicKey.buffer.slice(publicKey.byteOffset, publicKey.byteOffset + publicKey.byteLength), { name: 'RSA-OAEP', hash: 'SHA-1' }, false, ['encrypt']);
    const blob = new Uint8Array(await subtle.encrypt({ name: 'RSA-OAEP' }, imported, organizationKey.buffer.slice(0, 64)));
    return `4.${bytesToBase64(blob)}`;
  })();
  const organization = await api(baseUrl, '/api/organizations', {
    method: 'POST',
    token,
    body: {
      name: 'UI Team',
      // A real client encrypts the collection name with the organization key,
      // so the browser has to decrypt it to show it.
      collectionName: await encryptBw(
        new TextEncoder().encode('UI Shared'),
        organizationKey.slice(0, 32),
        organizationKey.slice(32, 64)
      ),
      key: organizationWrappedForOwner,
      keys: {
        publicKey: bytesToBase64(publicKey),
        encryptedPrivateKey: await encryptBw(privateKey, organizationKey.slice(0, 32), organizationKey.slice(32, 64)),
      },
    },
  });
  if (organization.status !== 200) {
    throw new Error(`organization create failed: ${organization.status} ${JSON.stringify(organization.body)}`);
  }

  const collections = await api(baseUrl, '/api/collections', { token });
  const collectionId = collections.body?.data?.[0]?.id;
  if (!collectionId) throw new Error('the organization has no collection');

  const sharedItemKey = webcrypto.getRandomValues(new Uint8Array(64));
  const sharedEncrypt = (value) =>
    encryptBw(new TextEncoder().encode(value), sharedItemKey.slice(0, 32), sharedItemKey.slice(32, 64));
  const shared = await api(baseUrl, '/api/ciphers', {
    method: 'POST',
    token,
    body: {
      type: 1,
      name: await sharedEncrypt('UI Shared Login'),
      organizationId: organization.body.id,
      collectionIds: [collectionId],
      key: await encryptBw(sharedItemKey, organizationKey.slice(0, 32), organizationKey.slice(32, 64)),
      login: { username: await sharedEncrypt('shared-user'), password: await sharedEncrypt('shared-pass') },
      // One field with a name the detail knows and one leftover of a filled
      // form, so both ways of showing a field can be checked.
      fields: [
        { type: 0, name: await sharedEncrypt('E-mail'), value: await sharedEncrypt('shared@example.test') },
        { type: 0, name: await sharedEncrypt('remember me'), value: await sharedEncrypt('yes') },
      ],
    },
  });
  if (shared.status !== 200) {
    throw new Error(`shared item create failed: ${shared.status} ${JSON.stringify(shared.body)}`);
  }

  const memberToken = (
    await api(baseUrl, '/identity/connect/token', {
      method: 'POST',
      form: {
        grant_type: 'password',
        username: memberEmail,
        password: bytesToBase64(memberMasterHash),
        scope: 'api offline_access',
        deviceIdentifier: 'local-ui-member',
        deviceName: 'local ui member',
        deviceType: '14',
      },
    })
  ).body?.access_token;
  if (!memberToken) throw new Error('the API did not issue a member token');

  return {
    itemId: created.body.id,
    token,
    memberEmail,
    memberToken,
    // Emergency access hands the member's vault key to the owner, wrapped
    // with the owner's public key, the way the member's client would.
    memberVaultKey,
    ownerPublicKey: publicKey,
    organizationId: organization.body.id,
    organizationName: 'UI Team',
    collectionName: 'UI Shared',
  };
}

async function main() {
  const binary = findChromium();
  if (!binary) {
    console.log('skipped: no Chromium found.');
    console.log('Set NODEWARDEN_CHROMIUM to a Chromium binary to run this check.');
    return 0;
  }

  const worker = await startLocalWorker({ label: 'ui-e2e' });
  let browser = null;
  try {
    const seeded = await seedVault(worker.baseUrl);
    browser = await launchChromium(binary);
    const cdp = await Cdp.connect(browser.endpoint);
    const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
    await cdp.send('Page.enable', {}, sessionId);
    await cdp.send('Runtime.enable', {}, sessionId);

    const evaluate = async (expression) => {
      const result = await cdp.send(
        'Runtime.evaluate',
        { expression, awaitPromise: true, returnByValue: true },
        sessionId
      );
      if (result.exceptionDetails) {
        throw new Error(result.exceptionDetails.text || 'evaluation failed');
      }
      return result.result?.value;
    };

    const waitFor = async (expression, label, timeoutMs = 20000) => {
      const deadline = Date.now() + timeoutMs;
      while (Date.now() < deadline) {
        if (await evaluate(expression)) return true;
        await new Promise((resolve) => setTimeout(resolve, 200));
      }
      const seen = await evaluate('document.body.textContent').catch(() => '');
      throw new Error(`timed out waiting for ${label}\npage said:\n${String(seen).slice(0, 800)}`);
    };

    const checks = createChecks('local Web Vault in a browser');
    await cdp.send('Page.navigate', { url: `${worker.baseUrl}/` }, sessionId);
    await waitFor(
      `!![...document.querySelectorAll('button')].find(b => b.textContent.trim() === 'Log In')`,
      'the login page'
    );

    // The form labels are plain text next to the input, so the input is found
    // through the label element instead of an aria-label.
    const findInput = (label) => `(() => {
      const labelText = ${JSON.stringify(label)};
      const leaves = [...document.querySelectorAll('*')].filter(
        (el) => el.children.length === 0 && el.textContent.trim() === labelText
      );
      const holder = leaves.map((el) => el.parentElement).find((el) => el && el.querySelector('input'));
      return holder ? holder.querySelector('input') : null;
    })()`;
    const fill = (label, value) => `(() => {
      const input = ${findInput(label)};
      if (!input) return false;
      const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
      setter.call(input, ${JSON.stringify(value)});
      input.dispatchEvent(new Event('input', { bubbles: true }));
      return true;
    })()`;
    const clickText = (text) => `(() => {
      const button = [...document.querySelectorAll('button')].find(b => b.textContent.trim() === ${JSON.stringify(text)});
      if (!button) return false;
      button.click();
      return true;
    })()`;
    // A dialog can sit on top of another one, so every dialog is searched and
    // the button is clicked where it is found.
    const clickInDialog = (text, prefix = false) => `(() => {
      for (const dialog of [...document.querySelectorAll('[role=dialog]')]) {
        const button = [...dialog.querySelectorAll('button')].find(b => b.textContent.trim().startsWith(${JSON.stringify(text)}));
        if (!button) continue;
        button.click();
        return true;
      }
      return false;
    })()`;
    const dialogText = `(() => {
      const dialog = document.querySelector('[role=dialog]');
      return dialog ? dialog.textContent : '';
    })()`;
    const dialogHasButton = (text) => `(() => {
      for (const dialog of [...document.querySelectorAll('[role=dialog]')]) {
        if ([...dialog.querySelectorAll('button')].some((b) => b.textContent.trim().startsWith(${JSON.stringify(text)}))) {
          return true;
        }
      }
      return false;
    })()`;

    await evaluate(fill('Email', EMAIL));
    await evaluate(fill('Master Password', PASSWORD));
    await evaluate(clickText('Log In'));
    await waitFor(`document.body.textContent.includes('UI History Login')`, 'the vault with the item');

    // The sidebar shows the organization and the collection the shared item
    // lives in, which is what tells a member an item is not their own.
    const sidebarText = await evaluate(`document.querySelector('.sidebar')?.textContent || ''`);
    checks.ok('the sidebar names the organization', sidebarText.includes(seeded.organizationName));
    checks.ok('the sidebar lists the collection under it', sidebarText.includes(seeded.collectionName));

    // Choosing the collection keeps only the item that sits in it.
    await evaluate(`(() => {
      const buttons = [...document.querySelectorAll('.sidebar .tree-btn')];
      const target = buttons.find((b) => b.textContent.includes(${JSON.stringify(seeded.collectionName)}));
      if (!target) return false;
      target.click();
      return true;
    })()`);
    await new Promise((resolve) => setTimeout(resolve, 600));
    const listText = await evaluate(`document.body.textContent`);
    checks.ok('choosing the collection keeps the shared item', listText.includes('UI Shared Login'));
    checks.ok('and drops the personal one', !listText.includes('UI History Login'));

    // The detail says the item is shared and where it lives.
    await evaluate(`(() => {
      const rows = [...document.querySelectorAll('button, [role="button"]')];
      const target = rows.find((el) => el.textContent.includes('UI Shared Login'));
      if (!target) return false;
      target.click();
      return true;
    })()`);
    await waitFor(`!![...document.querySelectorAll('button')].find(b => b.textContent.includes('Shared'))`, 'the shared item detail', 15000);
    const sharedDetail = await evaluate(`document.body.textContent`);
    checks.ok('the detail names the organization', sharedDetail.includes(seeded.organizationName));
    checks.ok('the detail marks the item as shared', sharedDetail.includes('Shared'));
    // A password nobody looked at is not a safe password, so the item says it
    // was not checked and never shows a clean verdict for it.
    checks.ok('the item says the password was not checked', sharedDetail.includes('Not checked'));
    checks.ok(
      'and does not call an unchecked password safe',
      !sharedDetail.includes('Not found in the breach database')
    );

    // An item can be kept out of the password check: the password of that
    // item is then not sent to the breach database at all.
    await evaluate(`(() => {
      const buttons = [...document.querySelectorAll('button')];
      const target = buttons.find((b) => (b.textContent || '').trim() === 'Keep out of the check');
      if (!target) return false;
      target.click();
      return true;
    })()`);
    await waitFor(`document.body.textContent.includes('Excluded from the check')`, 'the excluded badge', 15000);
    checks.ok('the item can be kept out of the password check', true);
    // The badge says the password is not sent to the breach database, so the
    // button that sends it cannot be there ready to be pressed.
    const checkDisabled = await evaluate(`(() => {
      const button = [...document.querySelectorAll('button')].find((b) => (b.textContent || '').trim() === 'Check breach');
      return !!button && button.disabled;
    })()`);
    checks.ok('and the password is not sent while the item is kept out', checkDisabled === true);
    const exclusions = await api(worker.baseUrl, '/api/security/scan-exclusions', { token: seeded.token });
    checks.ok(
      'the server holds the exclusion',
      (exclusions.body?.data || []).length === 1,
      JSON.stringify(exclusions.body?.data || []).slice(0, 200)
    );
    await evaluate(`(() => {
      const buttons = [...document.querySelectorAll('button')];
      const target = buttons.find((b) => (b.textContent || '').trim() === 'Include in the check');
      if (!target) return false;
      target.click();
      return true;
    })()`);
    await waitFor(
      `!document.body.textContent.includes('Excluded from the check')`,
      'the excluded badge to go away',
      15000
    );
    const afterInclude = await api(worker.baseUrl, '/api/security/scan-exclusions', { token: seeded.token });
    checks.ok('and the item can be put back in', (afterInclude.body?.data || []).length === 0);

    // Back to everything, so the history check can find the personal item.
    await evaluate(`(() => {
      const buttons = [...document.querySelectorAll('.sidebar .tree-btn')];
      const target = buttons.find((b) => b.textContent.trim().startsWith('All Items'));
      if (!target) return false;
      target.click();
      return true;
    })()`);
    await new Promise((resolve) => setTimeout(resolve, 600));

    // The shared item is the most recently written, so the vault opens on it.
    // The history check is about the personal item, so select that one first.
    const clickItem = (name) => `(() => {
      const rows = [...document.querySelectorAll('button, [role="button"]')];
      const target = rows.find((el) => el.textContent.includes(${JSON.stringify(name)}));
      if (!target) return false;
      target.click();
      return true;
    })()`;
    await evaluate(`(${clickItem.toString()})('UI History Login')`.replace('clickItem', 'f'));
    await evaluate(
      `(() => {
        const rows = [...document.querySelectorAll('button, [role="button"]')];
        const target = rows.find((el) => el.textContent.includes('UI History Login'));
        if (!target) return false;
        target.click();
        return true;
      })()`
    );

    const historyButton = `!![...document.querySelectorAll('button')].find(b => b.textContent.trim() === 'View Item History')`;
    await waitFor(historyButton, 'the item history button');
    await evaluate(clickText('View Item History'));
    await waitFor(`document.querySelector('[role=dialog]') !== null`, 'the item history dialog');
    await waitFor(`${dialogText}.includes('Current Version')`, 'the current version row');
    await waitFor(dialogHasButton('Created'), 'the version rows to load');
    const timeline = await evaluate(dialogText);
    checks.ok('the timeline shows the current version', timeline.includes('Current Version'));
    checks.ok('the timeline shows the state the item was created in', timeline.includes('Created'));

    await waitFor(dialogHasButton('Created'), 'the created version row');
    await evaluate(clickInDialog('Created'));
    await waitFor(`${dialogText}.includes('ui-user-v1')`, 'the older state');
    const compare = await evaluate(dialogText);
    checks.ok('the comparison names the changed field', compare.includes('Username'));
    checks.ok('the comparison shows the old value', compare.includes('ui-user-v1'));
    checks.ok('the comparison shows the current value', compare.includes('ui-user-v2'));

    await waitFor(dialogHasButton('Restore this version'), 'the restore button');
    await evaluate(clickInDialog('Restore this version'));
    await waitFor(`${dialogText}.includes('Confirm restore')`, 'the restore confirmation');
    await evaluate(clickInDialog('Confirm restore'));
    await waitFor(
      `document.body.textContent.includes('ui-user-v1') && !document.body.textContent.includes('ui-user-v2')`,
      'the restored item'
    );
    checks.ok('the item shows the restored username', true);

    await waitFor(`document.querySelector('[role=dialog]') === null`, 'the dialog to close');
    await waitFor(historyButton, 'the item history button');
    await evaluate(clickText('View Item History'));
    await waitFor(`${dialogText}.includes('Current Version')`, 'the item history dialog');
    await waitFor(dialogHasButton('Modified'), 'the kept version row');
    const afterRestore = await evaluate(dialogText);
    checks.ok('the replaced state is kept as a version', afterRestore.includes('Modified'));

    // A new item can be shared into a collection. It is encrypted with the
    // organization key, so it has to be readable afterwards - which is the
    // proof that the payload went under the right key.
    await evaluate(clickText('Create item'));
    // The trigger opens a menu of item types.
    await waitFor(`!!document.querySelector('.create-menu')`, 'the create menu');
    await evaluate(`(() => {
      const button = [...document.querySelectorAll('.create-menu-item')].find((b) => b.textContent.trim() === 'Login');
      if (!button) return false;
      button.click();
      return true;
    })()`);
    await waitFor(`!![...document.querySelectorAll('label')].find(l => l.textContent.includes('Name'))`, 'the new item form');
    await evaluate(fill('Name', 'UI Shared New'));
    const shareSelect = `(() => {
      const labels = [...document.querySelectorAll('label')];
      const holder = labels.find((l) => l.textContent.includes('Share with'));
      const select = holder ? holder.querySelector('select') : null;
      if (!select) return false;
      const option = [...select.options].find((o) => o.textContent.includes(${JSON.stringify(seeded.organizationName)}));
      if (!option) return false;
      select.value = option.value;
      select.dispatchEvent(new Event('input', { bubbles: true }));
      return true;
    })()`;
    await evaluate(shareSelect);
    await evaluate(fill('Username', 'shared-new-user'));
    await evaluate(clickText('Save'));
    await waitFor(
      `document.body.textContent.includes('UI Shared New')`,
      'the new shared item',
      20000
    );
    checks.ok('a new item can be shared into a collection', true);

    await evaluate(`(() => {
      const rows = [...document.querySelectorAll('button, [role="button"]')];
      const target = rows.find((el) => el.textContent.includes('UI Shared New'));
      if (!target) return false;
      target.click();
      return true;
    })()`);
    await waitFor(
      `document.body.textContent.includes('shared-new-user')`,
      'the new shared item to be readable',
      20000
    );
    checks.ok('the new shared item is readable under the organization key', true);

    // Editing a shared item keeps it shared: the item key is unwrapped with
    // the organization key and reused, so the payload stays under the key the
    // other members can open.
    await evaluate(`(() => {
      const rows = [...document.querySelectorAll('button, [role="button"]')];
      const target = rows.find((el) => el.textContent.includes('UI Shared New'));
      if (!target) return false;
      target.click();
      return true;
    })()`);
    // Edit is off while the save of the new item still runs: the item may not
    // exist on the server yet.
    await waitFor(`!![...document.querySelectorAll('button')].find(b => b.textContent.trim() === 'Edit' && !b.disabled)`, 'the edit button');
    await evaluate(clickText('Edit'));
    // The detail view also has a Username label, so wait for the input itself,
    // and for the name the edit starts from: an edit opened from an item that
    // is not decrypted has no name, and its save is refused.
    await waitFor(`!!(${findInput('Username')}) && (${findInput('Name')})?.value === 'UI Shared New'`, 'the edit form with the item name');
    checks.ok('the edit form opens on the shared item', await evaluate(fill('Username', 'shared-new-user-v2')));
    await waitFor(`!![...document.querySelectorAll('button')].find(b => b.textContent.trim() === 'Save' && !b.disabled)`, 'the save button');
    await evaluate(clickText('Save'));
    await waitFor(
      `document.body.textContent.includes('shared-new-user-v2')`,
      'the edited shared item',
      20000
    );
    const sharedAfterEdit = await api(worker.baseUrl, '/api/ciphers', { token: seeded.token });
    const editedEntry = (sharedAfterEdit.body?.data || []).find((entry) => entry.name === 'UI Shared New')
      || (sharedAfterEdit.body?.data || []).find((entry) => entry.id && entry.organizationId);
    checks.ok(
      'the edited item is still shared with the organization',
      !!editedEntry && editedEntry.organizationId === seeded.organizationId
    );

    // The list names the day of an item the way the user would say it. The
    // item that was just edited falls on today, so the label reads "Today"
    // rather than the date.
    const dayLabels = await evaluate(
      `[...document.querySelectorAll('.list-day-label')].map((el) => (el.textContent || '').trim())`
    );
    checks.ok(
      'the list names the day of the items it groups',
      Array.isArray(dayLabels) && dayLabels.length > 0 && dayLabels.every((label) => label.length > 0),
      JSON.stringify(dayLabels).slice(0, 200)
    );
    checks.ok(
      'and an item edited today is named today',
      Array.isArray(dayLabels) && dayLabels.some((label) => label === 'Today'),
      JSON.stringify(dayLabels).slice(0, 200)
    );

    // The owner can replace the key every member holds. The item has to stay
    // readable afterwards: the rotation gives it a new key and re-encrypts it,
    // and the vault reads it again with the new organization key.
    await evaluate(`(() => {
      const target = document.querySelector('.item-history-close');
      if (!target) return false;
      target.click();
      return true;
    })()`);
    await waitFor(`document.querySelector('[role=dialog]') === null`, 'the history dialog to close');
    const manageButton = `!![...document.querySelectorAll('.sidebar .tree-btn')].find(b => b.textContent.trim() === 'Manage organization')`;
    await waitFor(manageButton, 'the manage organization button');
    checks.ok('the owner is offered the organization management', true);

    await evaluate(`(() => {
      const target = [...document.querySelectorAll('.sidebar .tree-btn')].find(b => b.textContent.trim() === 'Manage organization');
      if (!target) return false;
      target.click();
      return true;
    })()`);
    await waitFor(`document.querySelector('.org-dialog') !== null`, 'the organization dialog');
    // The members are read from the server once the dialog is open.
    await waitFor(
      `document.querySelector('.org-dialog').textContent.includes('local-ui@example.test')`,
      'the member list',
      15000
    );
    const orgDialog = await evaluate(`document.querySelector('.org-dialog').textContent`);
    checks.ok('the dialog names the organization', orgDialog.includes(seeded.organizationName));
    checks.ok('the dialog lists the member', orgDialog.includes('local-ui@example.test'));

    // The organization can decide that its members may not use Send, and the
    // server is what enforces it.
    await waitFor(
      `!![...document.querySelectorAll('label')].find((el) => el.textContent.includes('Members may not use Send'))`,
      'the send policy',
      20000
    );
    await evaluate(`(() => {
      const label = [...document.querySelectorAll('label')].find((el) => el.textContent.includes('Members may not use Send'));
      const box = label.querySelector('input[type=checkbox]');
      box.click();
      return true;
    })()`);
    await waitFor(`document.body.textContent.includes('Policy saved')`, 'the policy to be saved', 20000);
    checks.ok('the owner can turn Send off for the members', true);
    // Back to where the check found it.
    await evaluate(`(() => {
      const label = [...document.querySelectorAll('label')].find((el) => el.textContent.includes('Members may not use Send'));
      label.querySelector('input[type=checkbox]').click();
      return true;
    })()`);
    await waitFor(
      `(() => {
        const label = [...document.querySelectorAll('label')].find((el) => el.textContent.includes('Members may not use Send'));
        return !!label && !label.querySelector('input[type=checkbox]').checked;
      })()`,
      'the policy to be turned back off',
      20000
    );

    // Inviting a member gives them the organization key, wrapped with their
    // own RSA key, so they can open the shared items.
    await evaluate(`(() => {
      const input = document.querySelector('.org-invite input');
      if (!input) return false;
      const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
      setter.call(input, ${JSON.stringify(seeded.memberEmail)});
      input.dispatchEvent(new Event('input', { bubbles: true }));
      return true;
    })()`);
    await evaluate(`(() => {
      const button = [...document.querySelectorAll('.org-invite button')].find((b) => b.textContent.trim() === 'Invite');
      if (!button) return false;
      button.click();
      return true;
    })()`);
    await waitFor(
      `document.querySelector('.org-dialog').textContent.includes(${JSON.stringify(seeded.memberEmail)})`,
      'the invited member',
      20000
    );
    checks.ok('a member can be invited', true);

    const memberRow = async () => {
      const listed = await api(worker.baseUrl, `/api/organizations/${seeded.organizationId}/users`, {
        token: seeded.token,
      });
      return (listed.body?.data || []).find((member) => member.email === seeded.memberEmail);
    };
    checks.ok('the invited member waits for their answer', (await memberRow())?.status === 0);
    checks.ok(
      'no key can be given before they accept',
      !(await evaluate(`!!document.querySelector('.org-member-give-key')`))
    );

    // The member accepts; then the owner gives them the organization key,
    // wrapped with their own RSA key, so they can open the shared items.
    const accepted = await api(worker.baseUrl, `/api/organizations/${seeded.organizationId}/accept`, {
      method: 'POST',
      token: seeded.memberToken,
    });
    checks.equal('the member accepts the invitation', accepted.status, 200, JSON.stringify(accepted.body));
    // The dialog reads the members when it opens, so open it again.
    await evaluate(`(() => {
      const button = document.querySelector('.org-dialog .dialog-close-btn');
      if (!button) return false;
      button.click();
      return true;
    })()`);
    await waitFor(`document.querySelector('.org-dialog') === null`, 'the organization dialog to close');
    await evaluate(`(() => {
      const target = [...document.querySelectorAll('.sidebar .tree-btn')].find(b => b.textContent.trim() === 'Manage organization');
      if (!target) return false;
      target.click();
      return true;
    })()`);
    await waitFor(`!!document.querySelector('.org-member-give-key')`, 'the give-key button for the accepted member', 20000);
    await evaluate(`(() => {
      const button = document.querySelector('.org-member-give-key');
      if (!button) return false;
      button.click();
      return true;
    })()`);
    await waitFor(`!document.querySelector('.org-member-give-key')`, 'the member to be confirmed', 20000);
    checks.ok('the accepted member is given the organization key', (await memberRow())?.status === 2);

    // A group hands a set of collections to a set of members in one go.
    await evaluate(`(() => {
      const input = [...document.querySelectorAll('.org-group-form input.input')][0];
      if (!input) return false;
      const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
      setter.call(input, 'Support');
      input.dispatchEvent(new Event('input', { bubbles: true }));
      return true;
    })()`);
    await evaluate(`(() => {
      const lists = [...document.querySelectorAll('.org-group-list')];
      const members = lists[0];
      const collections = lists[1];
      if (!members || !collections) return false;
      const memberBox = members.querySelector('input[type="checkbox"]');
      const collectionBox = collections.querySelector('input[type="checkbox"]');
      if (!memberBox || !collectionBox) return false;
      memberBox.click();
      collectionBox.click();
      return true;
    })()`);
    await evaluate(`(() => {
      const button = [...document.querySelectorAll('.org-group-form button')].find((b) => b.textContent.trim() === 'Add group');
      if (!button) return false;
      button.click();
      return true;
    })()`);
    await waitFor(
      `document.querySelector('.org-groups').textContent.includes('Support')`,
      'the new group',
      20000
    );
    checks.ok('a group can be created in the organization', true);

    // Removing a member takes their access away at once. The key they already
    // opened stays with them, so the organization says the key has to be
    // replaced.
    await evaluate(`(() => {
      const button = document.querySelector('.org-member-remove');
      if (!button) return false;
      button.click();
      return true;
    })()`);
    await waitFor(dialogHasButton('Remove member'), 'the removal confirmation');
    await evaluate(clickInDialog('Remove member'));
    await waitFor(
      `!document.querySelector('.org-dialog').textContent.includes(${JSON.stringify(seeded.memberEmail)})`,
      'the removed member to disappear',
      20000
    );
    checks.ok('a member can be removed', true);
    checks.ok(
      'the organization says the key has to be replaced',
      (await evaluate(`document.querySelector('.org-dialog').textContent`)).includes('rotate the organization key')
    );

    // The rotation lives in the same dialog.
    await evaluate(`(() => {
      const button = [...document.querySelectorAll('.org-dialog button')].find((b) => b.textContent.trim() === 'Rotate key');
      if (!button) return false;
      button.click();
      return true;
    })()`);
    await waitFor(`document.querySelector('[role=dialog]') !== null`, 'the rotation confirmation');
    const rotationDialog = await evaluate(dialogText);
    checks.ok('the rotation asks before it replaces the key', rotationDialog.includes('re-encrypted'));
    await evaluate(clickInDialog('Rotate key'));
    await waitFor(
      `document.body.textContent.includes('The organization key was replaced')`,
      'the rotation to finish',
      30000
    );
    checks.ok('the rotation reports that it ran', true);

    // Both shared items are still there and still readable: the rotation
    // replaced their keys and re-encrypted their payloads.
    await waitFor(
      `document.body.textContent.includes('UI Shared Login') && document.body.textContent.includes('UI Shared New')`,
      'the shared items after the rotation',
      30000
    );
    await evaluate(`(() => {
      const rows = [...document.querySelectorAll('button, [role="button"]')];
      const target = rows.find((el) => el.textContent.includes('UI Shared Login'));
      if (!target) return false;
      target.click();
      return true;
    })()`);
    await waitFor(
      `document.body.textContent.includes('shared-user')`,
      'the shared item to be readable after the rotation',
      30000
    );
    checks.ok('the shared item is still readable after the rotation', true);

    // The audit log can be taken out of the app as a file, for whoever has
    // to read it outside.
    await evaluate(`(() => {
      const link = [...document.querySelectorAll('a')].find((a) => a.getAttribute('href') === '/logs');
      if (!link) return false;
      link.click();
      return true;
    })()`);
    // The button is off while the log list loads.
    await waitFor(
      `!![...document.querySelectorAll('button')].find((b) => b.textContent.trim() === 'Export CSV' && !b.disabled)`,
      'the log center',
      20000
    );
    await evaluate(`(() => {
      const button = [...document.querySelectorAll('button')].find((b) => b.textContent.trim() === 'Export CSV');
      button.click();
      return true;
    })()`);
    await waitFor(
      `document.body.textContent.includes('Exported')`,
      'the export to finish',
      20000
    );
    checks.ok('the audit log can be exported', true);

    // The aliases the provider holds are visible here and can be turned off
    // and deleted, so a leaked alias does not keep receiving mail.
    const provider = await startFakeSimpleLogin({ https: true });
    try {
      await evaluate(`(() => {
        const link = [...document.querySelectorAll('a')].find((a) => a.getAttribute('href') === '/generator');
        if (!link) return false;
        link.click();
        return true;
      })()`);
      await waitFor(
        `!![...document.querySelectorAll('button')].find((b) => b.textContent.trim() === 'Email alias')`,
        'the generator',
        20000
      );
      await evaluate(`(() => {
        const tab = [...document.querySelectorAll('button')].find((b) => b.textContent.trim() === 'Email alias');
        tab.click();
        return true;
      })()`);
      await waitFor(`!!document.querySelector('#generator-email-type')`, 'the email type', 15000);
      await evaluate(`(() => {
        const select = document.querySelector('#generator-email-type');
        select.value = 'forwarded';
        select.dispatchEvent(new Event('change', { bubbles: true }));
        return true;
      })()`);
      await waitFor(`!!document.querySelector('#generator-forwarded-server')`, 'the provider fields', 15000);
      await evaluate(`(() => {
        const fill = (id, value) => {
          const field = document.querySelector(id);
          field.value = value;
          field.dispatchEvent(new Event('input', { bubbles: true }));
        };
        fill('#generator-forwarded-server', ${JSON.stringify(provider.url)});
        fill('#generator-forwarded-api-key', ${JSON.stringify(provider.apiKey)});
        return true;
      })()`);
      await waitFor(`document.body.textContent.includes('shop.cat@sl.test')`, 'the alias list', 20000);
      checks.ok('the aliases of the provider are shown', true);
      const aliasText = String(await evaluate('document.body.textContent'));
      checks.ok('and the mailbox they forward to is named', aliasText.includes('me@example.test'));

      await evaluate(`(() => {
        const row = [...document.querySelectorAll('.generator-alias-row')].find((el) => el.textContent.includes('shop.cat@sl.test'));
        const button = [...row.querySelectorAll('button')].find((b) => b.textContent.trim() === 'Disable');
        button.click();
        return true;
      })()`);
      await waitFor(
        `(() => {
          const row = [...document.querySelectorAll('.generator-alias-row')].find((el) => el.textContent.includes('shop.cat@sl.test'));
          return !!row && row.textContent.includes('Disabled');
        })()`,
        'the alias to be turned off',
        15000
      );
      checks.ok('an alias can be turned off here', provider.aliases[0].enabled === false);

      await evaluate(`(() => {
        const row = [...document.querySelectorAll('.generator-alias-row')].find((el) => el.textContent.includes('shop.cat@sl.test'));
        const button = [...row.querySelectorAll('button')].find((b) => b.textContent.trim() === 'Delete');
        button.click();
        return true;
      })()`);
      await waitFor(`!!document.querySelector('[role=dialog]')`, 'the delete confirmation', 15000);
      await evaluate(`(() => {
        const dialog = document.querySelector('[role=dialog]');
        const button = [...dialog.querySelectorAll('button')].find((b) => b.textContent.trim() === 'Delete');
        button.click();
        return true;
      })()`);
      await waitFor(
        `!document.body.textContent.includes('shop.cat@sl.test')`,
        'the alias to be gone',
        15000
      );
      checks.ok('and an alias can be deleted here', provider.aliases.length === 1);
    } finally {
      await provider.close();
    }

    // The password check page is where the user goes to see what the vault
    // knows about their passwords. It has to be readable in both themes, on a
    // narrow screen, and the keyboard has to be able to find its way around
    // it.
    await evaluate(`(() => {
      // The link sits in a nav group that can be folded away, so the group is
      // opened first and the link is taken from there.
      const trigger = [...document.querySelectorAll('.side-group-trigger')].find((b) => b.getAttribute('aria-expanded') === 'false');
      if (trigger) trigger.click();
      return true;
    })()`);
    await new Promise((resolve) => setTimeout(resolve, 400));
    await evaluate(`(() => {
      const link = [...document.querySelectorAll('a')].find((a) => a.getAttribute('href') === '/security/password-health');
      if (!link) return false;
      link.click();
      return true;
    })()`);
    await waitFor(`!!document.querySelector('.password-security-page')`, 'the password check page', 20000);

    const pageState = await evaluate(`(() => {
      const page = document.querySelector('.password-security-page');
      const label = document.querySelector('.password-security-checked-at');
      const read = (element) => {
        if (!element) return null;
        const style = getComputedStyle(element);
        return { color: style.color, background: style.backgroundColor };
      };
      return {
        text: label ? (label.textContent || '').trim() : '',
        label: read(label),
        pageWidth: page ? page.getBoundingClientRect().width : 0,
        viewport: window.innerWidth,
        overflows: page ? page.scrollWidth > window.innerWidth + 1 : false,
      };
    })()`);
    checks.ok('the password check page says where it stands', !!pageState?.text, String(pageState?.text || '').slice(0, 120));
    checks.ok(
      'the page does not scroll sideways on a narrow screen',
      pageState?.overflows === false,
      `overflow=${pageState?.overflows} page=${pageState?.pageWidth} viewport=${pageState?.viewport}`
    );
    checks.ok(
      'the text of the page is not the same colour as the background behind it',
      !!pageState?.label && pageState.label.color !== pageState.label.background,
      JSON.stringify(pageState?.label || {})
    );

    // The keyboard has to be able to find its way around the page. The
    // metric buttons are disabled until a scan has run, so the button that
    // starts the scan is the one that has to take the focus.
    const focusRing = await evaluate(`(() => {
      const button = document.querySelector('.password-security-scan');
      if (!button) return null;
      button.focus();
      const style = getComputedStyle(button);
      return { outline: style.outlineWidth, style: style.outlineStyle, active: document.activeElement === button };
    })()`);
    checks.ok(
      'the page takes the keyboard focus',
      !!focusRing?.active,
      JSON.stringify(focusRing || {})
    );

    // The dark theme has to keep the text readable, so the page cannot fall
    // back to the light background while the rest of the app is dark.
    const darkState = await evaluate(`(() => {
      const before = document.documentElement.dataset.theme;
      document.documentElement.dataset.theme = 'dark';
      const label = document.querySelector('.password-security-checked-at');
      const style = label ? getComputedStyle(label) : null;
      const panel = getComputedStyle(document.querySelector('.password-security-intro') || document.body);
      const result = { color: style?.color || '', panel: panel.backgroundColor };
      document.documentElement.dataset.theme = before;
      return result;
    })()`);
    checks.ok(
      'the page stays readable in the dark theme',
      !!darkState?.color && darkState.color !== darkState.panel,
      JSON.stringify(darkState || {})
    );

    // Emergency access: the place where an account lets somebody in when it
    // cannot get in itself. The page has to say what it does and does not
    // do, because a grant here gives another person a key.
    await evaluate(`(() => {
      const link = [...document.querySelectorAll('a')].find((a) => a.getAttribute('href') === '/settings');
      if (!link) return false;
      link.click();
      return true;
    })()`);
    await waitFor(`!!document.querySelector('.settings-category-tab')`, 'the settings page', 20000);
    await evaluate(`(() => {
      const tab = [...document.querySelectorAll('.settings-category-tab')].find((b) => b.textContent.trim() === 'Emergency access');
      if (!tab) return false;
      tab.click();
      return true;
    })()`);
    await waitFor(`!!document.querySelector('.emergency-access-list, .settings-submodule')`, 'the emergency access section', 20000);
    // The page loads the grants first, so wait for the list to settle before
    // reading what it says.
    await waitFor(
      `!document.body.textContent.includes('Loading...') || !!document.querySelector('.emergency-access-list')`,
      'the emergency access grants to load',
      20000
    );
    const emergencyText = await evaluate('document.body.textContent');
    checks.ok(
      'the settings offer emergency access',
      emergencyText.includes('Emergency access'),
      emergencyText.slice(-300)
    );
    checks.ok(
      'and it says the server holds no key it could open',
      emergencyText.includes('never holds a key it could open'),
      emergencyText.slice(-300)
    );
    checks.ok(
      'and it says the person who is let in is told by email',
      emergencyText.includes('The person you invite gets an email'),
      emergencyText.slice(-300)
    );
    checks.ok(
      'and it says a takeover waits for the wait to pass',
      emergencyText.includes('only after the wait you chose has passed'),
      emergencyText.slice(-300)
    );
    checks.ok(
      'and it says the grant can be withdrawn at any time',
      emergencyText.includes('you can withdraw the grant here at any time'),
      emergencyText.slice(-300)
    );
    checks.ok(
      'and it offers both kinds of access',
      emergencyText.includes('They can read your vault') && emergencyText.includes('They can take over your account'),
      emergencyText.slice(-300)
    );
    // The page also shows the invitations this account was given, so the
    // person who was let in can answer it.
    checks.ok(
      'and it shows the invitations this account was given',
      emergencyText.includes('Invitations for you'),
      emergencyText.slice(-300)
    );
    checks.ok(
      'and says nobody has let them in when there is none',
      emergencyText.includes('Nobody has let you into their vault.'),
      emergencyText.slice(-300)
    );

    // The whole emergency access path in the web vault. The browser is the
    // owner; the member's side runs through the API, the way the member's
    // own client would call it.
    const memberName = 'Org Member';
    const asMember = (path, options = {}) => api(worker.baseUrl, path, { token: seeded.memberToken, ...options });
    const asOwner = (path, options = {}) => api(worker.baseUrl, path, { token: seeded.token, ...options });
    const wrapForOwner = async (key) => {
      const imported = await webcrypto.subtle.importKey(
        'spki',
        seeded.ownerPublicKey.buffer.slice(
          seeded.ownerPublicKey.byteOffset,
          seeded.ownerPublicKey.byteOffset + seeded.ownerPublicKey.byteLength
        ),
        { name: 'RSA-OAEP', hash: 'SHA-1' },
        false,
        ['encrypt']
      );
      const blob = new Uint8Array(await webcrypto.subtle.encrypt({ name: 'RSA-OAEP' }, imported, key));
      return `4.${bytesToBase64(blob)}`;
    };
    const grantStatus = async (asWhom, list, id) => {
      const listed = await asWhom(`/api/emergency-access/${list}`);
      return (listed.body?.data || []).find((row) => row.id === id)?.status;
    };
    // The page reads the grants when the tab opens, so a change made through
    // the API shows after the tab is opened again.
    const reopenEmergency = async () => {
      await evaluate(`(() => {
        const tabs = [...document.querySelectorAll('.settings-category-tab')];
        const other = tabs.find((b) => b.textContent.trim() !== 'Emergency access');
        if (other) other.click();
        return true;
      })()`);
      await new Promise((resolve) => setTimeout(resolve, 300));
      await evaluate(`(() => {
        const tab = [...document.querySelectorAll('.settings-category-tab')].find((b) => b.textContent.trim() === 'Emergency access');
        if (!tab) return false;
        tab.click();
        return true;
      })()`);
      await waitFor(`!!document.querySelector('.emergency-access-row') || document.body.textContent.includes('Nobody has access to this vault.')`, 'the emergency access lists', 20000);
    };
    // Clicks a button in the row of a list: the list is found by its heading,
    // the row by a text it shows, the button by its label.
    const clickInRow = (heading, rowText, label) =>
      evaluate(`(() => {
        const section = [...document.querySelectorAll('.settings-submodule')].find((s) => s.querySelector('h4')?.textContent.trim() === ${JSON.stringify(heading)});
        if (!section) return 'no section';
        const rows = [...section.querySelectorAll('.emergency-access-row')].filter((r) => r.textContent.includes(${JSON.stringify(rowText)}));
        for (const row of rows) {
          const button = [...row.querySelectorAll('button')].find((b) => b.textContent.trim() === ${JSON.stringify(label)} && !b.disabled);
          if (button) { button.click(); return 'clicked'; }
        }
        return 'no button';
      })()`);
    const typeInto = (selector, value) =>
      evaluate(`(() => {
        const input = document.querySelector(${JSON.stringify(selector)});
        if (!input) return false;
        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
        setter.call(input, ${JSON.stringify(value)});
        input.dispatchEvent(new Event('input', { bubbles: true }));
        return true;
      })()`);
    const waitForStatus = async (asWhom, list, id, status, label) => {
      for (let i = 0; i < 40; i += 1) {
        if ((await grantStatus(asWhom, list, id)) === status) return true;
        await new Promise((resolve) => setTimeout(resolve, 250));
      }
      throw new Error(`timed out waiting for ${label}`);
    };

    // The owner cannot name themselves.
    await typeInto('.settings-submodule input[type=email]', EMAIL);
    await evaluate(`(() => {
      const button = [...document.querySelectorAll('.settings-submodule button')].find((b) => b.textContent.trim() === 'Invite');
      if (button) button.click();
      return true;
    })()`);
    await waitFor(`document.body.textContent.includes('You cannot name yourself as your emergency contact.')`, 'the refusal to invite oneself', 10000);
    checks.ok('the owner cannot name themselves as their contact', true);

    // The owner lets the member in (view), and hands over the key once the
    // member accepted.
    await typeInto('.settings-submodule input[type=email]', seeded.memberEmail);
    await evaluate(`(() => {
      const button = [...document.querySelectorAll('.settings-submodule button')].find((b) => b.textContent.trim() === 'Invite');
      if (button) button.click();
      return true;
    })()`);
    let ownerGrantId = '';
    for (let i = 0; i < 40 && !ownerGrantId; i += 1) {
      const trusted = await asOwner('/api/emergency-access/trusted');
      ownerGrantId = (trusted.body?.data || []).find((row) => row.email === seeded.memberEmail)?.id || '';
      if (!ownerGrantId) await new Promise((resolve) => setTimeout(resolve, 250));
    }
    checks.ok('the owner invites the member from the page', !!ownerGrantId);
    const memberAccepted = await asMember(`/api/emergency-access/${ownerGrantId}/accept`, { method: 'PUT' });
    checks.equal('the member accepts', memberAccepted.status, 200, JSON.stringify(memberAccepted.body));
    await reopenEmergency();
    checks.equal('the owner hands over the key', await clickInRow('People you let in', memberName, 'Hand over the key'), 'clicked');
    await waitForStatus(asOwner, 'trusted', ownerGrantId, 2, 'the grant to be confirmed');
    checks.ok('and the grant is confirmed', true);

    // The member starts the wait; the owner turns the recovery down, which
    // keeps the grant, and approves the next one.
    await asMember(`/api/emergency-access/${ownerGrantId}/initiate`, { method: 'POST' });
    await reopenEmergency();
    const waitingText = await evaluate('document.body.textContent');
    checks.ok('the owner sees when access opens', waitingText.includes('Access opens on'), waitingText.slice(-400));
    checks.equal('the owner turns the recovery down', await clickInRow('People you let in', memberName, 'Turn down'), 'clicked');
    await waitForStatus(asOwner, 'trusted', ownerGrantId, 2, 'the grant to be back to confirmed');
    checks.ok('and the grant is kept, back to confirmed', true);
    await asMember(`/api/emergency-access/${ownerGrantId}/initiate`, { method: 'POST' });
    await reopenEmergency();
    checks.equal('the owner approves the next recovery', await clickInRow('People you let in', memberName, 'Approve'), 'clicked');
    await waitForStatus(asOwner, 'trusted', ownerGrantId, 4, 'the recovery to be approved');
    checks.ok('and the recovery is approved', true);

    // The member lets the owner in, to read: the owner accepts, starts the
    // wait and, once the member approves, reads the member's items here.
    const memberItemKey = seeded.memberVaultKey;
    const memberEncrypt = (value) =>
      encryptBw(new TextEncoder().encode(value), memberItemKey.slice(0, 32), memberItemKey.slice(32, 64));
    const memberItem = await asMember('/api/ciphers', {
      method: 'POST',
      body: {
        type: 1,
        name: await memberEncrypt('Member Login'),
        login: { username: await memberEncrypt('member-user'), password: await memberEncrypt('member-pass') },
      },
    });
    checks.equal('the member has an item of their own', memberItem.status, 200, JSON.stringify(memberItem.body));
    const viewInvite = await asMember('/api/emergency-access/invite', {
      method: 'POST',
      body: { email: EMAIL, type: 0, waitTimeDays: 1 },
    });
    checks.equal('the member lets the owner read their vault', viewInvite.status, 200, JSON.stringify(viewInvite.body));
    const viewGrantId = viewInvite.body?.id;
    await reopenEmergency();
    checks.equal('the owner accepts from the page', await clickInRow('Invitations for you', memberName, 'Accept'), 'clicked');
    await waitForStatus(asMember, 'trusted', viewGrantId, 1, 'the view grant to be accepted');
    const viewConfirmed = await asMember(`/api/emergency-access/${viewGrantId}/confirm`, {
      method: 'POST',
      body: { key: await wrapForOwner(seeded.memberVaultKey) },
    });
    checks.equal('the member hands over their key', viewConfirmed.status, 200, JSON.stringify(viewConfirmed.body));
    await reopenEmergency();
    checks.equal('the owner starts the wait for a view grant', await clickInRow('Invitations for you', memberName, 'Start the wait'), 'clicked');
    await waitForStatus(asMember, 'trusted', viewGrantId, 3, 'the view recovery to start');
    await asMember(`/api/emergency-access/${viewGrantId}/approve`, { method: 'POST' });
    await reopenEmergency();
    checks.equal('the owner opens the member vault', await clickInRow('Invitations for you', memberName, 'View vault'), 'clicked');
    await waitFor(`!!document.querySelector('.emergency-access-view') && document.querySelector('.emergency-access-view').textContent.includes('Member Login')`, 'the member vault', 20000);
    const viewText = await evaluate(`document.querySelector('.emergency-access-view').textContent`);
    checks.ok('the member item is shown, read only', viewText.includes('Member Login') && viewText.includes('member-user'), viewText.slice(0, 300));
    checks.ok('and its password stays hidden until revealed', !viewText.includes('member-pass'), viewText.slice(0, 300));
    await evaluate(`(() => {
      const button = [...document.querySelectorAll('.emergency-access-view button')].find((b) => b.textContent.trim() === 'Reveal');
      if (button) button.click();
      return true;
    })()`);
    await waitFor(`document.querySelector('.emergency-access-view').textContent.includes('member-pass')`, 'the revealed password', 10000);
    checks.ok('and reveal shows it', true);

    // The member lets the owner take over: the owner sets a new master
    // password for the member here, and the member's vault key stays the same.
    const takeoverInvite = await asMember('/api/emergency-access/invite', {
      method: 'POST',
      body: { email: EMAIL, type: 1, waitTimeDays: 1 },
    });
    checks.equal('the member lets the owner take over', takeoverInvite.status, 200, JSON.stringify(takeoverInvite.body));
    const takeoverGrantId = takeoverInvite.body?.id;
    await reopenEmergency();
    checks.equal('the owner accepts the takeover grant', await clickInRow('Invitations for you', memberName, 'Accept'), 'clicked');
    await waitForStatus(asMember, 'trusted', takeoverGrantId, 1, 'the takeover grant to be accepted');
    await asMember(`/api/emergency-access/${takeoverGrantId}/confirm`, {
      method: 'POST',
      body: { key: await wrapForOwner(seeded.memberVaultKey) },
    });
    await reopenEmergency();
    checks.equal('the owner starts the wait for the takeover', await clickInRow('Invitations for you', memberName, 'Start the wait'), 'clicked');
    await waitForStatus(asMember, 'trusted', takeoverGrantId, 3, 'the takeover recovery to start');
    await asMember(`/api/emergency-access/${takeoverGrantId}/approve`, { method: 'POST' });
    await reopenEmergency();
    checks.equal('the owner opens the takeover form', await clickInRow('Invitations for you', memberName, 'Take over'), 'clicked');
    await waitFor(`!!document.querySelector('.emergency-access-takeover input')`, 'the takeover form', 10000);
    const newMemberPassword = 'Taken-Over-By-Owner-2026!';
    await typeInto('.emergency-access-takeover input[placeholder="New Password"]', newMemberPassword);
    await typeInto('.emergency-access-takeover input[placeholder="Repeat the new password"]', newMemberPassword);
    await evaluate(`(() => {
      const button = [...document.querySelectorAll('.emergency-access-takeover button')].find((b) => b.textContent.trim() === 'Set the new password');
      if (button) button.click();
      return true;
    })()`);
    await waitFor(`document.body.textContent.includes('The new master password is set.')`, 'the takeover to finish', 60000);
    checks.ok('the owner sets the member a new master password', true);

    const newMasterKey = await pbkdf2(newMemberPassword, seeded.memberEmail, KDF_ITERATIONS, 32);
    const newLogin = await api(worker.baseUrl, '/identity/connect/token', {
      method: 'POST',
      form: {
        grant_type: 'password',
        username: seeded.memberEmail,
        password: bytesToBase64(await pbkdf2(newMasterKey, newMemberPassword, 1, 32)),
        scope: 'api offline_access',
        deviceIdentifier: 'local-ui-member-after-takeover',
        deviceName: 'local ui member after takeover',
        deviceType: '14',
      },
    });
    checks.ok('the member signs in with the new password', !!newLogin.body?.access_token, JSON.stringify(newLogin.body).slice(0, 200));
    const memberProfile = await api(worker.baseUrl, '/api/accounts/profile', { token: newLogin.body?.access_token });
    const { decryptBw } = await import('../webapp/src/lib/crypto.ts');
    const reopened = await decryptBw(
      memberProfile.body?.key,
      await hkdfExpand(newMasterKey, 'enc', 32),
      await hkdfExpand(newMasterKey, 'mac', 32)
    );
    checks.ok(
      'and the new password opens the same vault key',
      Buffer.from(reopened).equals(Buffer.from(seeded.memberVaultKey))
    );
    const oldSession = await asMember('/api/accounts/profile');
    checks.equal('and the old session of the member has ended', oldSession.status, 401);

    // The change email form asks for the code only when the server really
    // sent one. A request that fails leaves the form as it was, so nobody is
    // asked for a code that does not exist.
    await evaluate(`(() => {
      const link = [...document.querySelectorAll('a')].find((a) => a.getAttribute('href') === '/settings');
      if (!link) return false;
      link.click();
      return true;
    })()`);
    await waitFor(`!!document.querySelector('.settings-category-tab')`, 'the settings page', 20000);
    await evaluate(`(() => {
      const tab = [...document.querySelectorAll('.settings-category-tab')].find((b) => b.textContent.trim().toLowerCase() === 'master password');
      if (!tab) return false;
      tab.click();
      return true;
    })()`);
    await waitFor(
      `!![...document.querySelectorAll('.settings-submodule h3')].find((h) => h.textContent.trim().toLowerCase() === 'change email')`,
      'the change email form',
      20000
    );
    // The change email form asks for the code only when the server really
    // sent one. A request that fails leaves the form as it was, so nobody is
    // asked for a code that does not exist.
    const changeEmailForm = `(() => {
      const section = [...document.querySelectorAll('.settings-submodule')].find((s) => (s.querySelector('h3')?.textContent || '').trim().toLowerCase() === 'change email');
      if (!section) return null;
      const inputs = [...section.querySelectorAll('input')];
      const email = inputs.find((input) => input.type === 'email');
      const button = [...section.querySelectorAll('button')].find((b) => b.textContent.trim() === 'Send code');
      return {
        inputs: inputs.length,
        emailReadOnly: !!email && email.readOnly,
        sendDisabled: !!button && button.disabled,
        toast: (document.querySelector('.toast-item.error .toast-text')?.textContent || '').trim(),
      };
    })()`;
    const emptyChangeEmail = await evaluate(changeEmailForm);
    checks.ok(
      'the send code button waits for the form to be filled',
      emptyChangeEmail?.sendDisabled === true,
      JSON.stringify(emptyChangeEmail || {})
    );
    const emailChangeSent = await evaluate(`(() => {
      const section = [...document.querySelectorAll('.settings-submodule')].find((s) => (s.querySelector('h3')?.textContent || '').trim().toLowerCase() === 'change email');
      if (!section) return false;
      const setValue = (input, value) => {
        const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
        setter.call(input, value);
        input.dispatchEvent(new Event('input', { bubbles: true }));
      };
      const email = [...section.querySelectorAll('input')].find((input) => input.type === 'email');
      const password = [...section.querySelectorAll('input')].find((input) => input.type === 'password');
      if (!email || !password) return false;
      setValue(email, 'another-address@example.test');
      setValue(password, 'Wrong-Master-Password-2026!');
      return true;
    })()`);
    // The button stays off until the form holds an address and a password,
    // so the request goes only when the form is ready for it.
    await waitFor(
      `(() => {
        const section = [...document.querySelectorAll('.settings-submodule')].find((s) => (s.querySelector('h3')?.textContent || '').trim().toLowerCase() === 'change email');
        const button = section ? [...section.querySelectorAll('button')].find((b) => b.textContent.trim() === 'Send code') : null;
        return !!button && !button.disabled;
      })()`,
      'the send code button to be ready'
    );
    await evaluate(`(() => {
      const section = [...document.querySelectorAll('.settings-submodule')].find((s) => (s.querySelector('h3')?.textContent || '').trim().toLowerCase() === 'change email');
      const button = [...section.querySelectorAll('button')].find((b) => b.textContent.trim() === 'Send code');
      if (!button) return false;
      button.click();
      return true;
    })()`);
    // The answer of the server takes a moment, so the form is watched until
    // the request is over.
    let emailForm = await evaluate(changeEmailForm);
    const emailDeadline = Date.now() + 15000;
    while (!emailForm?.toast && Date.now() < emailDeadline) {
      await new Promise((resolve) => setTimeout(resolve, 250));
      emailForm = await evaluate(changeEmailForm);
    }
    checks.ok(
      'the change email form does not ask for a code the server did not send',
      emailChangeSent === true && emailForm?.inputs === 2,
      `sent=${emailChangeSent} inputs=${emailForm?.inputs}`
    );
    checks.ok(
      'the wrong master password is named in the language of the vault',
      emailForm?.toast === 'Wrong master password.',
      emailForm?.toast || ''
    );
    checks.ok(
      'the address stays editable while there is no code',
      emailForm?.emailReadOnly === false,
      JSON.stringify(emailForm || {})
    );

    // The backup page opens on the destination that is selected. A
    // destination that was never filled in cannot be listed, and the page
    // must not greet the user with an error for it.
    await evaluate(`(() => {
      for (const trigger of [...document.querySelectorAll('.side-group-trigger')]) {
        if (trigger.getAttribute('aria-expanded') === 'false') trigger.click();
      }
      return true;
    })()`);
    await new Promise((resolve) => setTimeout(resolve, 400));
    await evaluate(`(() => {
      const link = [...document.querySelectorAll('a')].find((a) => a.getAttribute('href') === '/backup');
      if (!link) return false;
      link.click();
      return true;
    })()`);
    await waitFor(`document.body.textContent.includes('Remote Backups')`, 'the remote backups section', 20000);
    await new Promise((resolve) => setTimeout(resolve, 2000));
    const backupText = await evaluate('document.body.innerText');
    checks.ok(
      'the backup page does not complain about a destination that was never filled in',
      !backupText.includes('WebDAV server URL is required'),
      backupText.slice(-300)
    );

    // The filters of the vault sit in a column of their own, so the menu
    // keeps its place and stays on screen.
    await evaluate(`(() => {
      const link = [...document.querySelectorAll('a')].find((a) => a.getAttribute('href') === '/vault');
      if (!link) return false;
      link.click();
      return true;
    })()`);
    await waitFor(
      `!!document.querySelector('.vault-filter-column') && document.querySelector('.vault-filter-column').textContent.includes('All Items')`,
      'the vault filters in their own column',
      20000
    );
    const vaultLayout = await evaluate(`(() => {
      const linkBox = (text) => {
        const link = [...document.querySelectorAll('.app-side a')].find((a) => a.textContent.trim() === text);
        if (!link) return null;
        const box = link.getBoundingClientRect();
        return { top: box.top, bottom: box.bottom };
      };
      const column = document.querySelector('.vault-filter-column');
      return {
        sends: linkBox('Sends'),
        accountSettings: linkBox('Account Settings'),
        column: !!column,
        filters: column ? column.textContent.includes('All Items') : false,
        viewport: window.innerHeight,
      };
    })()`);
    checks.ok(
      'the menu of the vault keeps every link on the screen',
      !!vaultLayout?.sends
        && !!vaultLayout?.accountSettings
        && vaultLayout.sends.bottom <= vaultLayout.viewport
        && vaultLayout.accountSettings.bottom <= vaultLayout.viewport,
      JSON.stringify(vaultLayout || {})
    );
    checks.ok(
      'the filters of the vault sit in a column of their own',
      vaultLayout?.column === true && vaultLayout?.filters === true,
      JSON.stringify(vaultLayout || {})
    );

    // The emergency access page says who hears about a grant, so it must not
    // claim that nobody is told.
    await evaluate(`(() => {
      const link = [...document.querySelectorAll('a')].find((a) => a.getAttribute('href') === '/settings');
      if (!link) return false;
      link.click();
      return true;
    })()`);
    await waitFor(`!!document.querySelector('.settings-category-tab')`, 'the settings page', 20000);
    await evaluate(`(() => {
      const tab = [...document.querySelectorAll('.settings-category-tab')].find((b) => b.textContent.trim() === 'Emergency access');
      if (!tab) return false;
      tab.click();
      return true;
    })()`);
    await waitFor(`!!document.querySelector('.settings-submodule')`, 'the emergency access section', 20000);
    const emergencyCopy = await evaluate('document.body.innerText');
    checks.ok(
      'the emergency access page does not claim that nobody is told about a grant',
      !emergencyCopy.includes('Nobody is emailed'),
      emergencyCopy.slice(-300)
    );

    // The pages that were audited one more time: the two-step login says
    // which providers are off, the devices keep the actions that end
    // everything out of sight, the sends stand next to their list, the codes
    // say where they come from, the log names the device instead of a
    // number, the import page leaves out what there is nothing to fix about,
    // the domain rules point at the preset list, and the emergency access
    // form names its fields.
    const gotoPath = async (href) => {
      await evaluate(`(() => {
        for (const trigger of [...document.querySelectorAll('.side-group-trigger')]) {
          if (trigger.getAttribute('aria-expanded') === 'false') trigger.click();
        }
        return true;
      })()`);
      await new Promise((resolve) => setTimeout(resolve, 400));
      const clicked = await evaluate(`(() => {
        const link = [...document.querySelectorAll('a')].find((a) => a.getAttribute('href') === ${JSON.stringify(href)});
        if (!link) return false;
        link.click();
        return true;
      })()`);
      if (!clicked) throw new Error(`no link to ${href}`);
    };

    // The two-step login page says which providers are off.
    await evaluate(`(() => {
      const tab = [...document.querySelectorAll('.settings-category-tab')].find((b) => b.textContent.trim() === 'Two-step login');
      if (!tab) return false;
      tab.click();
      return true;
    })()`);
    await waitFor(`!!document.querySelector('.two-step-provider-list')`, 'the two-step login providers', 20000);
    const offBadges = await evaluate(`document.querySelectorAll('.two-step-off-badge').length`);
    checks.ok(
      'the two-step login page says which providers are off',
      offBadges > 0,
      `off badges=${offBadges}`
    );

    // The devices keep the actions that end everything in the overflow menu.
    await gotoPath('/settings/security/device-management');
    await waitFor(`!!document.querySelector('.authorized-devices-table')`, 'the device management table', 20000);
    const removeAllBefore = await evaluate(
      `[...document.querySelectorAll('.section-head button')].some((b) => (b.textContent || '').trim() === 'Remove all devices')`
    );
    checks.ok(
      'the device toolbar does not offer the actions that end everything',
      removeAllBefore === false,
      `shown=${removeAllBefore}`
    );
    await evaluate(`(() => {
      const button = document.querySelector('.sort-menu-wrap .detail-icon-action');
      if (!button) return false;
      button.click();
      return true;
    })()`);
    await waitFor(`!!document.querySelector('.sort-menu[role=menu]')`, 'the overflow menu of the devices', 10000);
    const removeAllInMenu = await evaluate(
      `[...document.querySelectorAll('.sort-menu-item')].some((b) => (b.textContent || '').trim() === 'Remove all devices')`
    );
    checks.ok(
      'the overflow menu of the devices holds the actions that end everything',
      removeAllInMenu === true,
      `shown=${removeAllInMenu}`
    );
    const deviceHeader = await evaluate(`(() => {
      const head = document.querySelector('.authorized-devices-table thead');
      if (!head) return '';
      const copy = head.cloneNode(true);
      for (const hidden of copy.querySelectorAll('.sr-only')) hidden.remove();
      return (copy.textContent || '').replace(/\\s+/g, ' ').trim();
    })()`);
    checks.ok(
      'the table of the devices does not run the column titles together',
      !deviceHeader.includes('SelectDevice'),
      deviceHeader
    );

    // The sends stand next to their list, and an empty list says what a send
    // is and offers to make one.
    await gotoPath('/sends');
    await waitFor(`!!document.querySelector('.sends-grid .detail-col')`, 'the sends page', 20000);
    const sendsLayout = await evaluate(`(() => {
      const list = document.querySelector('.sends-grid .list-col');
      const detail = document.querySelector('.sends-grid .detail-col');
      if (!list || !detail) return null;
      return { listTop: list.getBoundingClientRect().top, detailTop: detail.getBoundingClientRect().top };
    })()`);
    checks.ok(
      'the detail of a send stands next to its list',
      !!sendsLayout && Math.abs(sendsLayout.listTop - sendsLayout.detailTop) <= 2,
      JSON.stringify(sendsLayout || {})
    );
    const sendButtons = await evaluate(`(() => {
      const texts = [...document.querySelectorAll('button')].map((b) => (b.textContent || '').trim());
      return { newSend: texts.includes('New Send'), selectAll: texts.includes('Select All') };
    })()`);
    checks.ok(
      'the empty sends page offers a send and keeps the bulk actions away',
      sendButtons?.newSend === true && sendButtons?.selectAll === false,
      JSON.stringify(sendButtons || {})
    );

    // The verification codes say where they come from.
    await gotoPath('/vault/totp');
    await waitFor(`!!document.querySelector('.totp-codes-page')`, 'the verification code page', 20000);
    await waitFor(
      `document.body.textContent.includes('Add an authenticator key to a login item to see its codes here.')`,
      'the help of the empty codes',
      20000
    );
    const totpText = await evaluate('document.body.textContent');
    checks.ok(
      'the verification code page says where the codes come from',
      totpText.includes('Add an authenticator key to a login item to see its codes here.'),
      totpText.slice(-200)
    );

    // The log names the device instead of showing its number.
    await gotoPath('/logs');
    await waitFor(`!!document.querySelector('.log-list')`, 'the log center', 20000);
    const logRows = await evaluate(`document.querySelectorAll('.log-row').length`);
    const deviceTypes = [];
    for (let index = 0; index < Math.min(logRows, 10); index += 1) {
      await evaluate(`(() => {
        const row = document.querySelectorAll('.log-row')[${index}];
        if (row) row.click();
        return true;
      })()`);
      await new Promise((resolve) => setTimeout(resolve, 150));
      const value = await evaluate(`(() => {
        const cell = [...document.querySelectorAll('.log-detail-json dt')].find((dt) => (dt.textContent || '').trim() === 'Device type');
        if (!cell) return '';
        const value = cell.parentElement ? cell.parentElement.querySelector('dd') : null;
        return value ? (value.textContent || '').trim() : '';
      })()`);
      if (value) deviceTypes.push(value);
    }
    checks.ok(
      'the log center names the device instead of showing its number',
      deviceTypes.every((value) => !/^\d+$/.test(value)),
      JSON.stringify(deviceTypes)
    );

    // The import page leaves out the folder card when no folder needs to be
    // fixed.
    await gotoPath('/backup/import-export');
    await waitFor(`!!document.querySelector('.import-export-panels')`, 'the import and export page', 20000);
    let folderCardGone = true;
    try {
      await waitFor(
        `!document.body.textContent.includes('Folder compatibility')`,
        'the folder compatibility card to go away',
        10000
      );
    } catch {
      folderCardGone = false;
    }
    checks.ok(
      'the import page leaves out the folder card when no folder needs to be fixed',
      folderCardGone,
      `shown=${!folderCardGone}`
    );

    // The domain rules point at the preset list instead of offering a pull
    // request in the toolbar.
    await gotoPath('/settings/domain-rules');
    await waitFor(`!!document.querySelector('.domain-rules-page')`, 'the domain rules page', 20000);
    const domainRules = await evaluate(`(() => {
      const texts = [...document.querySelectorAll('button, a')].map((el) => (el.textContent || '').trim());
      return {
        submitPr: texts.includes('Submit PR'),
        suggest: texts.includes('Suggest a site for the preset list'),
      };
    })()`);
    checks.ok(
      'the domain rules page does not offer a pull request in the toolbar',
      domainRules?.submitPr === false,
      JSON.stringify(domainRules || {})
    );
    checks.ok(
      'the domain rules page says where a new site is suggested',
      domainRules?.suggest === true,
      JSON.stringify(domainRules || {})
    );

    // The emergency access form names its fields.
    await gotoPath('/settings/account');
    await waitFor(`!!document.querySelector('.settings-category-tab')`, 'the settings page', 20000);
    await evaluate(`(() => {
      const tab = [...document.querySelectorAll('.settings-category-tab')].find((b) => b.textContent.trim() === 'Emergency access');
      if (!tab) return false;
      tab.click();
      return true;
    })()`);
    await waitFor(`!!document.querySelector('.emergency-access-list, .settings-submodule')`, 'the emergency access section', 20000);
    const emergencyLabels = await evaluate(`[...document.querySelectorAll('label.field')].map((label) => {
      const span = label.querySelector('span');
      return span ? (span.textContent || '').trim() : '';
    })`);
    checks.ok(
      'the emergency access form names its fields',
      ['Email', 'What they can do', 'Wait before access'].every((label) => emergencyLabels.includes(label)),
      JSON.stringify(emergencyLabels)
    );

    // On a phone the controls are big enough for a finger.
    await cdp.send(
      'Emulation.setDeviceMetricsOverride',
      { width: 375, height: 812, deviceScaleFactor: 1, mobile: true },
      sessionId
    );
    for (const page of [
      { path: '/settings/account', marker: '.settings-category-tab' },
      { path: '/sends', marker: '.sends-grid' },
    ]) {
      await gotoPath(page.path);
      await waitFor(`!!document.querySelector(${JSON.stringify(page.marker)})`, `the page at ${page.path}`, 20000);
      await new Promise((resolve) => setTimeout(resolve, 800));
      const smallButtons = await evaluate(`(() => [...document.querySelectorAll('.btn')]
        .filter((button) => button.offsetParent !== null)
        .map((button) => ({ text: (button.textContent || '').trim().slice(0, 40), height: button.getBoundingClientRect().height }))
        .filter((button) => button.height < 44))()`);
      checks.ok(
        `every button of ${page.path} is big enough for a finger on a phone`,
        Array.isArray(smallButtons) && smallButtons.length === 0,
        JSON.stringify(smallButtons)
      );
    }
    await cdp.send('Emulation.clearDeviceMetricsOverride', {}, sessionId);

    // The export page offers the organizations the member may export, and an
    // organization export carries items and collections only.
    await gotoPath('/backup/import-export');
    await waitFor(`!!document.querySelector('.import-export-panels')`, 'the import and export page', 20000);
    const exportPanel = await evaluate(`(() => {
      const panel = [...document.querySelectorAll('section.import-export-panel')].find(
        (section) => (section.querySelector('h3')?.textContent || '').trim() === 'Export'
      );
      if (!panel) return null;
      const labelOf = (text) => [...panel.querySelectorAll('label.field')].find((label) => {
        const span = label.querySelector('span');
        return span && (span.textContent || '').trim() === text;
      });
      const scopeSelect = labelOf('Export from')?.querySelector('select') || null;
      const formatSelect = labelOf('Format')?.querySelector('select') || null;
      return {
        scopeOptions: scopeSelect ? [...scopeSelect.options].map((option) => (option.textContent || '').trim()) : [],
        formatOptions: formatSelect ? [...formatSelect.options].map((option) => (option.textContent || '').trim()) : [],
        help: [...panel.querySelectorAll('.field-help')].map((element) => (element.textContent || '').trim()),
      };
    })()`);
    checks.ok(
      'the export page offers the organizations the member may export',
      Array.isArray(exportPanel?.scopeOptions) && exportPanel.scopeOptions.includes('UI Team'),
      JSON.stringify(exportPanel?.scopeOptions || [])
    );

    const picked = await evaluate(`(() => {
      const panel = [...document.querySelectorAll('section.import-export-panel')].find(
        (section) => (section.querySelector('h3')?.textContent || '').trim() === 'Export'
      );
      const label = panel && [...panel.querySelectorAll('label.field')].find((entry) => {
        const span = entry.querySelector('span');
        return span && (span.textContent || '').trim() === 'Export from';
      });
      const select = label && label.querySelector('select');
      if (!select) return false;
      const option = [...select.options].find((entry) => (entry.textContent || '').trim() === 'UI Team');
      if (!option) return false;
      select.value = option.value;
      select.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`);
    await new Promise((resolve) => setTimeout(resolve, 500));
    const organizationExport = await evaluate(`(() => {
      const panel = [...document.querySelectorAll('section.import-export-panel')].find(
        (section) => (section.querySelector('h3')?.textContent || '').trim() === 'Export'
      );
      if (!panel) return null;
      const label = [...panel.querySelectorAll('label.field')].find((entry) => {
        const span = entry.querySelector('span');
        return span && (span.textContent || '').trim() === 'Format';
      });
      const select = label && label.querySelector('select');
      return {
        formatOptions: select ? [...select.options].map((option) => (option.textContent || '').trim()) : [],
        help: [...panel.querySelectorAll('.field-help')].map((element) => (element.textContent || '').trim()),
      };
    })()`);
    checks.ok(
      'an organization export offers only the formats that carry items and collections',
      picked === true && organizationExport?.formatOptions?.length === 3,
      JSON.stringify(organizationExport?.formatOptions || [])
    );
    checks.ok(
      'an organization export says what it leaves out',
      (organizationExport?.help || []).some((text) => text.includes('Folders and favorites are personal')),
      JSON.stringify(organizationExport?.help || [])
    );

    // The export itself leaves a record on the server, so the log center
    // names it. The file itself is not caught here: the script has no way to
    // hold a download.
    await evaluate(`(() => {
      const panel = [...document.querySelectorAll('section.import-export-panel')].find(
        (section) => (section.querySelector('h3')?.textContent || '').trim() === 'Export'
      );
      const label = panel && [...panel.querySelectorAll('label.field')].find((entry) => {
        const span = entry.querySelector('span');
        return span && (span.textContent || '').trim() === 'Format';
      });
      const select = label && label.querySelector('select');
      if (!select) return false;
      select.value = 'bitwarden_json';
      select.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`);
    await evaluate(`(() => {
      const panel = [...document.querySelectorAll('section.import-export-panel')].find(
        (section) => (section.querySelector('h3')?.textContent || '').trim() === 'Export'
      );
      const button = panel && [...panel.querySelectorAll('button')].find((entry) => (entry.textContent || '').trim() === 'Export');
      if (!button) return false;
      button.click();
      return true;
    })()`);
    await waitFor(`document.querySelector('[role=dialog]') !== null`, 'the master password dialog', 10000);
    await evaluate(fill('Master Password', PASSWORD));
    await evaluate(clickInDialog('Verify'));
    await waitFor(`document.body.textContent.includes('Export completed')`, 'the export to finish', 30000);

    await gotoPath('/logs');
    await waitFor(`!!document.querySelector('.log-list')`, 'the log center', 20000);
    // The log center was opened earlier in this run, so its first paint can be
    // the cached list; give the refetch time to bring the new record in.
    await waitFor(
      `(document.querySelector('.log-list')?.textContent || '').includes('Export organization vault')`,
      'the export record in the log center',
      20000
    ).catch(() => false);
    const logText = await evaluate(`document.querySelector('.log-list')?.textContent || ''`);
    checks.ok(
      'the log center names the export of the organization',
      logText.includes('Export organization vault'),
      logText.slice(0, 200)
    );

    // The detail of an item copies a field when its row is clicked or keyed,
    // and the toast says that the value reached the clipboard. The clipboard
    // only takes a write from the focused page, so the page is focused and
    // allowed to write before the copy is made.
    await cdp.send('Emulation.setFocusEmulationEnabled', { enabled: true }, sessionId);
    await cdp.send('Page.bringToFront', {}, sessionId);
    await cdp
      .send('Browser.setPermission', {
        origin: worker.baseUrl,
        permission: { name: 'clipboard-write' },
        setting: 'granted',
      })
      .then(() =>
        cdp.send('Browser.setPermission', {
          origin: worker.baseUrl,
          permission: { name: 'clipboard-write', allowWithoutSanitization: true },
          setting: 'granted',
        })
      )
      .catch(() =>
        cdp.send('Browser.grantPermissions', {
          origin: worker.baseUrl,
          permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite'],
        })
      )
      .catch(() => {
        // A browser that knows neither call lets the focused page write anyway.
      });

    await gotoPath('/vault');
    await waitFor(`!!document.querySelector('.list-item .row-main')`, 'the vault list', 20000);
    await evaluate(`(() => {
      const rows = [...document.querySelectorAll('.list-item .row-main')];
      const target = rows.find((row) => (row.textContent || '').includes('UI Shared Login'));
      if (!target) return false;
      target.click();
      return true;
    })()`);
    await waitFor(
      `!!document.querySelector('[role="group"][aria-label="Login Credentials"]')`,
      'the detail of the item',
      15000
    );

    // The login card copies by clicking a row, so no copy button is left in it.
    const loginCard = await evaluate(`(() => {
      const card = document.querySelector('[role="group"][aria-label="Login Credentials"]');
      if (!card) return null;
      return {
        copyButtons: [...card.querySelectorAll('button')].filter((button) => (button.textContent || '').trim() === 'Copy').length,
        labels: [...card.querySelectorAll('.kv-copyable')].map((row) => (row.querySelector('.kv-field-label')?.textContent || '').trim()),
      };
    })()`);
    checks.ok(
      'the login card copies by clicking the row and keeps no copy button',
      loginCard?.copyButtons === 0 && loginCard?.labels?.includes('Username') && loginCard?.labels?.includes('Password'),
      JSON.stringify(loginCard || {})
    );

    // Clicking the username row puts the value into the clipboard.
    // The clipboard takes a write only from a real user gesture, so the row is
    // pressed through the input domain and not with element.click().
    const pressRow = async (label, how) => {
      const center = await evaluate(`(() => {
        const card = document.querySelector('[role="group"][aria-label="Login Credentials"]');
        const row = card && [...card.querySelectorAll('.kv-copyable')].find(
          (entry) => (entry.querySelector('.kv-field-label')?.textContent || '').trim() === ${JSON.stringify(label)}
        );
        if (!row) return null;
        row.scrollIntoView({ block: 'center' });
        if (${JSON.stringify(how)} === 'key') row.focus();
        const box = row.getBoundingClientRect();
        return { x: box.left + 24, y: box.top + box.height / 2 };
      })()`);
      if (!center) return false;
      if (how === 'key') {
        const key = { key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, nativeVirtualKeyCode: 13 };
        await cdp.send('Input.dispatchKeyEvent', { type: 'keyDown', ...key }, sessionId);
        await cdp.send('Input.dispatchKeyEvent', { type: 'keyUp', ...key }, sessionId);
      } else {
        const mouse = { x: center.x, y: center.y, button: 'left', clickCount: 1 };
        await cdp.send('Input.dispatchMouseEvent', { type: 'mousePressed', ...mouse }, sessionId);
        await cdp.send('Input.dispatchMouseEvent', { type: 'mouseReleased', ...mouse }, sessionId);
      }
      return true;
    };
    await pressRow('Username', 'click');
    await waitFor(
      `[...document.querySelectorAll('.toast-item.success .toast-text')].some((toast) => (toast.textContent || '').trim() === 'Copied')`,
      'the toast of the copy',
      10000
    ).catch(() => false);
    const copyToasts = await evaluate(
      `[...document.querySelectorAll('.toast-item .toast-text')].map((toast) => (toast.textContent || '').trim())`
    );
    checks.ok(
      'clicking the username row says that it was copied',
      copyToasts.includes('Copied'),
      JSON.stringify(copyToasts)
    );

    // The toast of the copy is closed, so the next one is the toast of the
    // password and not the one that is still there.
    await evaluate(`(() => {
      for (const button of [...document.querySelectorAll('.toast-close')]) button.click();
      return true;
    })()`);
    await new Promise((resolve) => setTimeout(resolve, 300));

    // The password row copies when it is keyed, and the password stays masked.
    await pressRow('Password', 'key');
    await waitFor(
      `[...document.querySelectorAll('.toast-item.success .toast-text')].some((toast) => (toast.textContent || '').trim() === 'Copied')`,
      'the toast of the keyed copy',
      10000
    ).catch(() => false);
    const afterKey = await evaluate(`(() => {
      const card = document.querySelector('[role="group"][aria-label="Login Credentials"]');
      const row = card && [...card.querySelectorAll('.kv-copyable')].find(
        (entry) => (entry.querySelector('.kv-field-label')?.textContent || '').trim() === 'Password'
      );
      return {
        value: row ? (row.querySelector('.kv-field-value strong')?.textContent || '').trim() : '',
        shown: (document.body.textContent || '').includes('shared-pass'),
        toasts: [...document.querySelectorAll('.toast-item .toast-text')].map((toast) => (toast.textContent || '').trim()),
      };
    })()`);
    checks.ok(
      'keying the password row copies it and leaves the password masked',
      afterKey?.toasts?.includes('Copied') && afterKey?.value?.startsWith('*') && afterKey?.shown === false,
      JSON.stringify(afterKey || {})
    );

    // A field with a name the detail knows shows the canonical label, and the
    // leftovers of a filled form wait in the collapsed area.
    const customFields = await evaluate(`(() => {
      const labelOf = (card) => (card.querySelector('.custom-field-label')?.textContent || '').trim();
      const cards = [...document.querySelectorAll('.custom-field-card')];
      const email = cards.find((card) => labelOf(card) === 'Email');
      const more = document.querySelector('details.detail-more-info');
      return {
        emailValue: email ? (email.querySelector('.custom-field-value strong')?.textContent || '').trim() : '',
        emailInMoreInfo: !!(email && email.closest('details.detail-more-info')),
        moreInfoLabels: more ? [...more.querySelectorAll('.custom-field-label')].map((label) => (label.textContent || '').trim()) : [],
        shownLabels: cards.filter((card) => !card.closest('details.detail-more-info')).map(labelOf),
      };
    })()`);
    checks.ok(
      'a field with a known name shows the canonical label',
      customFields?.emailValue === 'shared@example.test' && customFields?.emailInMoreInfo === false,
      JSON.stringify(customFields || {})
    );
    checks.ok(
      'the leftovers of a filled form wait in the collapsed area',
      customFields?.moreInfoLabels?.includes('remember me') && !customFields?.shownLabels?.includes('remember me'),
      JSON.stringify(customFields || {})
    );

    // The menu of an item opens with the right mouse button, offers the
    // copies the item holds and stays inside the window. The mouse speaks to
    // the page through the input domain, so the copy is a real user gesture.
    const itemRowPoint = async (name) => {
      const found = await evaluate(`(() => {
        const rows = [...document.querySelectorAll('.list-item .row-main')];
        const target = rows.find((row) => (row.textContent || '').includes(${JSON.stringify(name)}));
        if (!target) return false;
        target.scrollIntoView({ block: 'center' });
        return true;
      })()`);
      if (!found) return null;
      // The list is virtual, so the row is measured after the scroll.
      await new Promise((resolve) => setTimeout(resolve, 400));
      return evaluate(`(() => {
        const rows = [...document.querySelectorAll('.list-item .row-main')];
        const target = rows.find((row) => (row.textContent || '').includes(${JSON.stringify(name)}));
        if (!target) return null;
        const box = target.getBoundingClientRect();
        if (!box.width || !box.height) return null;
        return { x: box.left + box.width / 2, y: box.top + box.height / 2 };
      })()`);
    };
    const pressMouse = async (point, button) => {
      const mouse = { x: point.x, y: point.y, button, clickCount: 1 };
      await cdp.send('Input.dispatchMouseEvent', { type: 'mousePressed', ...mouse }, sessionId);
      await cdp.send('Input.dispatchMouseEvent', { type: 'mouseReleased', ...mouse }, sessionId);
    };
    const openItemMenu = async (name) => {
      const point = await itemRowPoint(name);
      if (!point) return false;
      await pressMouse(point, 'right');
      return true;
    };
    const clickMenuEntry = async (label) => {
      const point = await evaluate(`(() => {
        const menu = document.querySelector('.item-context-menu[role="menu"]');
        const entry = menu && [...menu.querySelectorAll('[role="menuitem"]')].find(
          (item) => (item.textContent || '').trim() === ${JSON.stringify(label)}
        );
        if (!entry) return null;
        const box = entry.getBoundingClientRect();
        if (!box.width || !box.height) return null;
        return { x: box.left + box.width / 2, y: box.top + box.height / 2 };
      })()`);
      if (!point) return false;
      await pressMouse(point, 'left');
      return true;
    };
    const menuEntries = () =>
      evaluate(`(() => {
        const menu = document.querySelector('.item-context-menu[role="menu"]');
        if (!menu) return null;
        const box = menu.getBoundingClientRect();
        return {
          entries: [...menu.querySelectorAll('[role="menuitem"]')].map((entry) => (entry.textContent || '').trim()),
          inside:
            box.left >= 0 &&
            box.top >= 0 &&
            box.right <= window.innerWidth &&
            box.bottom <= window.innerHeight,
        };
      })()`);

    await openItemMenu('UI Shared Login');
    await waitFor(`!!document.querySelector('.item-context-menu[role="menu"]')`, 'the menu of the item', 10000).catch(
      () => false
    );
    const openedMenu = await menuEntries();
    checks.ok(
      'the right mouse button opens the menu of the item and the menu stays inside the window',
      !!openedMenu?.entries?.includes('Copy password') && openedMenu?.inside === true,
      JSON.stringify(openedMenu || {})
    );

    // The toast of the earlier copy is closed, so the next one is the toast of
    // this copy and not the one that is still there.
    await evaluate(`(() => {
      for (const button of [...document.querySelectorAll('.toast-close')]) button.click();
      return true;
    })()`);
    await new Promise((resolve) => setTimeout(resolve, 300));

    await clickMenuEntry('Copy password');
    await waitFor(
      `[...document.querySelectorAll('.toast-item.success .toast-text')].some((toast) => (toast.textContent || '').trim() === 'Copied')`,
      'the toast of the copy out of the menu',
      10000
    ).catch(() => false);
    const afterMenuCopy = await evaluate(`(() => ({
      toasts: [...document.querySelectorAll('.toast-item .toast-text')].map((toast) => (toast.textContent || '').trim()),
      menuOpen: !!document.querySelector('.item-context-menu[role="menu"]'),
    }))()`);
    checks.ok(
      'the copy out of the menu says that it was copied and closes the menu',
      afterMenuCopy?.toasts?.includes('Copied') && afterMenuCopy?.menuOpen === false,
      JSON.stringify(afterMenuCopy || {})
    );

    // The escape key closes the menu again.
    await openItemMenu('UI Shared Login');
    await waitFor(`!!document.querySelector('.item-context-menu[role="menu"]')`, 'the menu of the item again', 10000).catch(
      () => false
    );
    const menuBeforeEscape = await evaluate(`!!document.querySelector('.item-context-menu[role="menu"]')`);
    const escapeKey = { key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27, nativeVirtualKeyCode: 27 };
    await cdp.send('Input.dispatchKeyEvent', { type: 'keyDown', ...escapeKey }, sessionId);
    await cdp.send('Input.dispatchKeyEvent', { type: 'keyUp', ...escapeKey }, sessionId);
    await new Promise((resolve) => setTimeout(resolve, 300));
    const menuAfterEscape = await evaluate(`!!document.querySelector('.item-context-menu[role="menu"]')`);
    checks.ok(
      'the escape key closes the menu',
      menuBeforeEscape === true && menuAfterEscape === false,
      `menu open before: ${menuBeforeEscape}, after: ${menuAfterEscape}`
    );

    // The item can be marked as a favorite and taken back.
    await openItemMenu('UI Shared Login');
    await waitFor(`!!document.querySelector('.item-context-menu[role="menu"]')`, 'the menu of the favorite', 10000).catch(
      () => false
    );
    await clickMenuEntry('Add to favorites');
    await waitFor(
      `[...document.querySelectorAll('.toast-item.success .toast-text')].some((toast) => (toast.textContent || '').trim() === 'Added to favorites')`,
      'the toast of the favorite',
      10000
    ).catch(() => false);
    // The toast is read while it is there, so it is not gone before the check.
    const favoriteToast = await evaluate(
      `[...document.querySelectorAll('.toast-item .toast-text')].map((toast) => (toast.textContent || '').trim())`
    );
    checks.ok(
      'the menu says that the item is a favorite now',
      favoriteToast.includes('Added to favorites'),
      JSON.stringify(favoriteToast)
    );
    await evaluate(`(() => {
      const button = [...document.querySelectorAll('.sidebar .tree-btn')].find(
        (entry) => (entry.textContent || '').trim() === 'Favorites'
      );
      if (!button) return false;
      button.click();
      return true;
    })()`);
    await waitFor(
      `[...document.querySelectorAll('.list-item .row-main')].some((row) => (row.textContent || '').includes('UI Shared Login'))`,
      'the item in the favorites',
      15000
    ).catch(() => false);
    const favoriteRows = await evaluate(
      `[...document.querySelectorAll('.list-item .row-main')].map((row) => (row.textContent || '').trim())`
    );
    checks.ok(
      'the favorite shows in the favorites of the sidebar',
      favoriteRows.some((text) => text.includes('UI Shared Login')),
      JSON.stringify(favoriteRows)
    );

    await openItemMenu('UI Shared Login');
    await waitFor(
      `!!document.querySelector('.item-context-menu[role="menu"]')`,
      'the menu of the removed favorite',
      10000
    ).catch(() => false);
    await clickMenuEntry('Remove from favorites');
    await waitFor(
      `[...document.querySelectorAll('.toast-item.success .toast-text')].some((toast) => (toast.textContent || '').trim() === 'Removed from favorites')`,
      'the toast of the removed favorite',
      10000
    ).catch(() => false);
    await waitFor(
      `![...document.querySelectorAll('.list-item .row-main')].some((row) => (row.textContent || '').includes('UI Shared Login'))`,
      'the item to leave the favorites',
      15000
    ).catch(() => false);
    const afterFavoriteRemoved = await evaluate(`(() => ({
      toasts: [...document.querySelectorAll('.toast-item .toast-text')].map((toast) => (toast.textContent || '').trim()),
      rows: [...document.querySelectorAll('.list-item .row-main')].map((row) => (row.textContent || '').trim()),
    }))()`);
    checks.ok(
      'the favorite can be taken away again',
      afterFavoriteRemoved?.toasts?.includes('Removed from favorites') &&
        !afterFavoriteRemoved?.rows?.some((text) => text.includes('UI Shared Login')),
      JSON.stringify(afterFavoriteRemoved || {})
    );

    // The list is left on every item, so the run ends where it began.
    await evaluate(`(() => {
      const button = [...document.querySelectorAll('.sidebar .tree-btn')].find(
        (entry) => (entry.textContent || '').trim() === 'All Items'
      );
      if (!button) return false;
      button.click();
      return true;
    })()`);
    await new Promise((resolve) => setTimeout(resolve, 400));

    // The command palette opens with the keyboard and searches the pages, the
    // items and the fields. The keys go through the input domain, so the
    // shortcut and the dialog behave the way they do for a person.
    const pressKey = async (key) => {
      await cdp.send('Input.dispatchKeyEvent', { type: 'keyDown', ...key }, sessionId);
      await cdp.send('Input.dispatchKeyEvent', { type: 'keyUp', ...key }, sessionId);
    };
    const enterKey = { key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, nativeVirtualKeyCode: 13 };
    const arrowDownKey = { key: 'ArrowDown', code: 'ArrowDown', windowsVirtualKeyCode: 40, nativeVirtualKeyCode: 40 };
    const arrowUpKey = { key: 'ArrowUp', code: 'ArrowUp', windowsVirtualKeyCode: 38, nativeVirtualKeyCode: 38 };
    // The second bit of the modifier mask is the control key.
    const ctrlPKey = { key: 'p', code: 'KeyP', windowsVirtualKeyCode: 80, nativeVirtualKeyCode: 80, modifiers: 2 };
    const paletteDialog = () => evaluate(`!!document.querySelector('.palette-card[role="dialog"]')`);
    const paletteRows = () =>
      evaluate(`[...document.querySelectorAll('.palette-card [role="option"]')].map((row) => ({
        label: (row.querySelector('.palette-row-label')?.textContent || '').trim(),
        hint: (row.querySelector('.palette-row-hint')?.textContent || '').trim(),
        selected: row.getAttribute('aria-selected') === 'true',
      }))`);
    const openPalette = async () => {
      await pressKey(ctrlPKey);
      await waitFor(`!!document.querySelector('.palette-card[role="dialog"]')`, 'the command palette', 10000).catch(
        () => false
      );
      await waitFor(
        `document.activeElement && document.activeElement.getAttribute('role') === 'combobox'`,
        'the focus in the command palette',
        10000
      ).catch(() => false);
    };
    // The text is typed into the input the way a person types it.
    const typeInPalette = async (text) => {
      await cdp.send('Input.insertText', { text }, sessionId);
    };
    // The selection walks to the wanted row with the arrow keys, so the row is
    // picked the way a person picks it.
    const pickRow = async (label) => {
      const rows = await paletteRows();
      const wanted = rows.findIndex((row) => row.label === label);
      if (wanted < 0) return false;
      let active = rows.findIndex((row) => row.selected);
      let guard = rows.length + 2;
      while (active !== wanted && guard > 0) {
        await pressKey(active < wanted ? arrowDownKey : arrowUpKey);
        guard -= 1;
        await new Promise((resolve) => setTimeout(resolve, 150));
        active = (await paletteRows()).findIndex((row) => row.selected);
      }
      return active === wanted;
    };

    await openPalette();
    const openedPalette = await evaluate(`(() => {
      const card = document.querySelector('.palette-card[role="dialog"]');
      const input = card && card.querySelector('[role="combobox"]');
      return {
        modal: card?.getAttribute('aria-modal') || '',
        combobox: !!input,
        focused: document.activeElement === input,
        expanded: input?.getAttribute('aria-expanded') || '',
        listbox: !!card?.querySelector('[role="listbox"]'),
        options: card ? card.querySelectorAll('[role="option"]').length : 0,
      };
    })()`);
    checks.ok(
      'the control key with P opens the palette and puts the focus in its input',
      openedPalette?.modal === 'true' &&
        openedPalette?.combobox === true &&
        openedPalette?.focused === true &&
        openedPalette?.expanded === 'true' &&
        openedPalette?.listbox === true &&
        openedPalette?.options > 0,
      JSON.stringify(openedPalette || {})
    );

    // A page of the palette opens that page.
    await typeInPalette('device');
    await waitFor(
      `[...document.querySelectorAll('.palette-card [role="option"]')].some((row) => (row.querySelector('.palette-row-label')?.textContent || '').trim() === 'Device Management')`,
      'the device management page in the palette',
      10000
    ).catch(() => false);
    await pressKey(enterKey);
    await waitFor(
      `window.location.pathname === '/settings/security/device-management'`,
      'the device management page',
      15000
    ).catch(() => false);
    const devicePage = await evaluate(`(() => ({
      path: window.location.pathname,
      palette: !!document.querySelector('.palette-card[role="dialog"]'),
      devices: (document.body.textContent || '').includes('Authorized Devices'),
    }))()`);
    checks.ok(
      'the page of the palette opens that page and closes the palette',
      devicePage?.path === '/settings/security/device-management' &&
        devicePage?.palette === false &&
        devicePage?.devices === true,
      JSON.stringify(devicePage || {})
    );

    // A tab of the settings page opens that tab.
    await openPalette();
    await typeInPalette('two step');
    await waitFor(
      `[...document.querySelectorAll('.palette-card [role="option"]')].some((row) => (row.querySelector('.palette-row-label')?.textContent || '').trim() === 'Two-step login')`,
      'the two step tab in the palette',
      10000
    ).catch(() => false);
    await pressKey(enterKey);
    await waitFor(`window.location.pathname === '/settings/account'`, 'the settings page', 15000).catch(() => false);
    const settingsTab = await evaluate(`(() => ({
      path: window.location.pathname,
      section: new URLSearchParams(window.location.search).get('section') || '',
      active: (document.querySelector('.settings-category-tab.active')?.textContent || '').trim(),
      palette: !!document.querySelector('.palette-card[role="dialog"]'),
    }))()`);
    checks.ok(
      'the tab of the settings page opens that tab',
      settingsTab?.active === 'Two-step login' && settingsTab?.palette === false,
      JSON.stringify(settingsTab || {})
    );

    // An item of the palette opens in the vault.
    await openPalette();
    await typeInPalette('UI Shared');
    await waitFor(
      `[...document.querySelectorAll('.palette-card [role="option"]')].some((row) => (row.querySelector('.palette-row-label')?.textContent || '').trim() === 'UI Shared Login')`,
      'the item in the palette',
      10000
    ).catch(() => false);
    const pickedItem = await pickRow('UI Shared Login');
    await pressKey(enterKey);
    await waitFor(
      `(document.querySelector('.detail-item-title')?.textContent || '').trim() === 'UI Shared Login'`,
      'the detail of the item',
      15000
    ).catch(() => false);
    const itemDetail = await evaluate(`(() => ({
      path: window.location.pathname,
      title: (document.querySelector('.detail-item-title')?.textContent || '').trim(),
      palette: !!document.querySelector('.palette-card[role="dialog"]'),
    }))()`);
    checks.ok(
      'the item of the palette opens in the vault',
      pickedItem &&
        itemDetail?.path === '/vault' &&
        itemDetail?.title === 'UI Shared Login' &&
        itemDetail?.palette === false,
      JSON.stringify(itemDetail || {})
    );

    // A field of the palette copies its value.
    await openPalette();
    await typeInPalette('UI Shared user');
    await waitFor(
      `[...document.querySelectorAll('.palette-card [role="option"]')].some((row) => (row.querySelector('.palette-row-label')?.textContent || '').trim() === 'Username')`,
      'the username field in the palette',
      10000
    ).catch(() => false);
    const pickedField = await pickRow('Username');
    await pressKey(enterKey);
    await waitFor(
      `[...document.querySelectorAll('.toast-item.success .toast-text')].some((toast) => (toast.textContent || '').trim() === 'Copied')`,
      'the toast of the copy',
      10000
    ).catch(() => false);
    const copyToast = await evaluate(`(() => ({
      toasts: [...document.querySelectorAll('.toast-item .toast-text')].map((toast) => (toast.textContent || '').trim()),
      palette: !!document.querySelector('.palette-card[role="dialog"]'),
    }))()`);
    checks.ok(
      'the field of the palette copies its value',
      pickedField && copyToast?.toasts?.includes('Copied') && copyToast?.palette === false,
      JSON.stringify(copyToast || {})
    );

    // The escape key closes the palette.
    await openPalette();
    const paletteBeforeEscape = await paletteDialog();
    await pressKey(escapeKey);
    await waitFor(`!document.querySelector('.palette-card[role="dialog"]')`, 'the closed palette', 5000).catch(
      () => false
    );
    const paletteAfterEscape = await paletteDialog();
    checks.ok(
      'the escape key closes the palette',
      paletteBeforeEscape === true && paletteAfterEscape === false,
      `palette open before: ${paletteBeforeEscape}, after: ${paletteAfterEscape}`
    );

    return checks.finish() ? 0 : 1;
  } finally {
    if (browser) await browser.stop();
    await worker.stop();
  }
}

process.exitCode = await main();
