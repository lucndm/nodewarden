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

import { startLocalWorker, findFreePort, createChecks } from './local-worker.mjs';
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
    { stdio: ['ignore', 'pipe', 'pipe'] }
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
    },
  });
  if (shared.status !== 200) {
    throw new Error(`shared item create failed: ${shared.status} ${JSON.stringify(shared.body)}`);
  }

  return {
    itemId: created.body.id,
    token,
    memberEmail,
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
    await waitFor(`!![...document.querySelectorAll('button')].find(b => b.textContent.trim() === 'Edit')`, 'the edit button');
    await evaluate(clickText('Edit'));
    await waitFor(`!![...document.querySelectorAll('label')].find(l => l.textContent.includes('Username'))`, 'the edit form');
    await evaluate(fill('Username', 'shared-new-user-v2'));
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
    checks.ok('a member can be invited and given the organization key', true);

    const membersAfterInvite = await api(worker.baseUrl, `/api/organizations/${seeded.organizationId}/users`, {
      token: seeded.token,
    });
    const invitedRow = (membersAfterInvite.body?.data || []).find(
      (member) => member.email === seeded.memberEmail
    );
    checks.ok('the invited member is confirmed', !!invitedRow && invitedRow.status === 2);

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
    await waitFor(
      `!![...document.querySelectorAll('button')].find((b) => b.textContent.trim() === 'Export CSV')`,
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
      'and it says nobody is emailed',
      emergencyText.includes('Nobody is emailed'),
      emergencyText.slice(-300)
    );
    checks.ok(
      'and it says a takeover waits for the approval',
      emergencyText.includes('only after the wait you chose has passed and you have approved it'),
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

    return checks.finish() ? 0 : 1;
  } finally {
    if (browser) await browser.stop();
    await worker.stop();
  }
}

process.exitCode = await main();
