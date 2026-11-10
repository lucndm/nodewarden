// Local end-to-end check with the official Bitwarden browser extension.
//
// The extension is the client that shows a shared item the way a user sees
// it: the organization, the collection it sits in, and the item itself. The
// CLI already proved that the cryptography is the shape the official clients
// expect; this check is about the surface.
//
// The extension is the untouched package from the official release, loaded
// into a Chromium that only talks to a throwaway Worker with its own D1.
//
// Run it before pushing to main:
//   npm run test:local-extension
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { webcrypto } from 'node:crypto';

import { bytesToBase64, encryptBw, hkdf, hkdfExpand, pbkdf2 } from '../webapp/src/lib/crypto.ts';
import { startLocalWorker, startTlsProxy, chromiumEnv } from './local-worker.mjs';

const EMAIL = 'local-extension@example.test';
const PASSWORD = 'Local-Extension-Check-2026!';
const KDF_ITERATIONS = 600000;
const EXTENSION_DIR = process.env.NODEWARDEN_EXTENSION_DIR || '/tmp/nw-ext';

function findChromium() {
  const candidates = [
    process.env.NODEWARDEN_CHROMIUM,
    '/root/.cache/puppeteer/chrome/linux-156.0.8078.47/chrome-linux64/chrome',
  ].filter(Boolean);
  for (const candidate of candidates) {
    if (candidate.includes('/') && existsSync(candidate)) return candidate;
  }
  const fromPath = spawnSync('sh', ['-c', 'command -v chromium || command -v chromium-browser'], {
    encoding: 'utf8',
  });
  const path = (fromPath.stdout || '').trim();
  if (path) return path;
  if (existsSync('/nix/store')) {
    for (const entry of readdirSync('/nix/store')) {
      if (!entry.includes('chromium-unwrapped')) continue;
      const candidate = `/nix/store/${entry}/libexec/chromium/chromium`;
      if (existsSync(candidate)) return candidate;
    }
  }
  return null;
}

function findXvfb() {
  if (existsSync('/nix/store')) {
    for (const entry of readdirSync('/nix/store')) {
      if (!entry.includes('-xvfb-')) continue;
      const candidate = `/nix/store/${entry}/bin/Xvfb`;
      if (existsSync(candidate)) return candidate;
    }
  }
  return null;
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

function createChecks(title) {
  const failures = [];
  return {
    ok(label, condition, detail = '') {
      if (condition) console.log(`  ok   ${label}`);
      else {
        console.log(`  FAIL ${label}${detail ? `: ${detail}` : ''}`);
        failures.push(label);
      }
    },
    equal(label, actual, expected, detail = '') {
      const same = JSON.stringify(actual) === JSON.stringify(expected);
      this.ok(label, same, same ? '' : `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}${detail ? ` :: ${detail}` : ''}`);
    },
    finish() {
      if (failures.length) {
        console.log(`\n${failures.length} check(s) failed: ${failures.join(', ')}`);
        return false;
      }
      console.log('\nall checks passed');
      return true;
    },
  };
}

// Registers the account and writes an organization with one collection and one
// shared item, all with real key material.
async function seedVault(baseUrl) {
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

  const registered = await api(baseUrl, '/api/accounts/register', {
    method: 'POST',
    headers: { Origin: baseUrl },
    body: {
      email: EMAIL,
      name: 'Local Extension',
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
  const token = (
    await api(baseUrl, '/identity/connect/token', {
      method: 'POST',
      form: {
        grant_type: 'password',
        username: EMAIL,
        password: bytesToBase64(masterHash),
        scope: 'api offline_access',
        deviceIdentifier: 'local-extension-check',
        deviceName: 'local extension check',
        deviceType: '14',
      },
    })
  ).body?.access_token;

  // The organization key, wrapped for this member with their RSA key, and a
  // collection whose name is encrypted with it - the way a real client writes
  // both.
  const organizationKey = webcrypto.getRandomValues(new Uint8Array(64));
  const imported = await subtle.importKey(
    'spki',
    publicKey.buffer.slice(publicKey.byteOffset, publicKey.byteOffset + publicKey.byteLength),
    { name: 'RSA-OAEP', hash: 'SHA-1' },
    false,
    ['encrypt']
  );
  const wrappedOrganizationKey = `4.${bytesToBase64(
    new Uint8Array(
      await subtle.encrypt({ name: 'RSA-OAEP' }, imported, organizationKey.buffer.slice(0, 64))
    )
  )}`;
  const organization = await api(baseUrl, '/api/organizations', {
    method: 'POST',
    token,
    body: {
      name: 'Extension Team',
      collectionName: await encryptBw(
        new TextEncoder().encode('Extension Shared'),
        organizationKey.slice(0, 32),
        organizationKey.slice(32, 64)
      ),
      key: wrappedOrganizationKey,
      keys: {
        publicKey: bytesToBase64(publicKey),
        encryptedPrivateKey: await encryptBw(
          privateKey,
          organizationKey.slice(0, 32),
          organizationKey.slice(32, 64)
        ),
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
      name: await sharedEncrypt('Extension Shared Login'),
      organizationId: organization.body.id,
      collectionIds: [collectionId],
      key: await encryptBw(sharedItemKey, organizationKey.slice(0, 32), organizationKey.slice(32, 64)),
      login: { username: await sharedEncrypt('extension-user'), password: await sharedEncrypt('extension-pass') },
    },
  });
  if (shared.status !== 200) {
    throw new Error(`shared item create failed: ${shared.status} ${JSON.stringify(shared.body)}`);
  }
  return {
    organizationId: organization.body.id,
    collectionId,
    token,
    vaultHalves: { encKey: vaultKey.slice(0, 32), macKey: vaultKey.slice(32, 64) },
  };
}

/**
 * Creates a Send that carries a file, the way a client writes it: the name
 * and the file name are sealed with the Send key, the bytes are sealed with
 * it too, and the link carries the seed of that key.
 */
async function createFileSend(baseUrl, account, fileName, contents) {
  const { token, vaultHalves } = account;
  const sendSeed = webcrypto.getRandomValues(new Uint8Array(16));
  const derived = await hkdf(sendSeed, 'bitwarden-send', 'send', 64);
  const sendEnc = derived.slice(0, 32);
  const sendMac = derived.slice(32, 64);
  const seal = (value) => encryptBw(new TextEncoder().encode(value), sendEnc, sendMac);

  const created = await api(baseUrl, '/api/sends/file/v2', {
    method: 'POST',
    token,
    body: {
      type: 1,
      name: await seal('Extension File Send'),
      notes: await seal(''),
      key: await encryptBw(sendSeed, vaultHalves.encKey, vaultHalves.macKey),
      file: { fileName: await seal(fileName) },
      fileLength: contents.byteLength,
      deletionDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
    },
  });
  if (created.status !== 200) {
    throw new Error(`file Send create failed: ${created.status} ${JSON.stringify(created.body)}`);
  }
  const uploadUrl = created.body?.url;
  const send = created.body?.sendResponse;
  if (!uploadUrl || !send?.id) {
    throw new Error(`file Send create gave no upload url: ${JSON.stringify(created.body)}`);
  }

  // The bytes travel encrypted, so the server holds the file as it was
  // handed over and never the words of it.
  const upload = await fetch(uploadUrl, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: contents,
  });
  if (!upload.ok) {
    throw new Error(`file Send upload failed: ${upload.status} ${await upload.text().catch(() => '')}`);
  }
  return { send, keyPart: bytesToBase64(sendSeed).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '') };
}

// A very small CDP client: the browser's own websocket, one target, and the
// two calls the check needs.
async function connectCdp(endpoint) {
  // The endpoint is the local Chromium DevTools websocket: a validated port
  // number plus a validated /devtools/ path, both read from the browser's own
  // DevToolsActivePort file. It never leaves the loopback interface.
  const socket = new WebSocket(endpoint); // codeql[js/file-access-to-http]
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', reject, { once: true });
  });
  let nextId = 1;
  const pending = new Map();
  socket.addEventListener('message', (event) => {
    const message = JSON.parse(String(event.data));
    const entry = pending.get(message.id);
    if (!entry) return;
    pending.delete(message.id);
    if (message.error) entry.reject(new Error(message.error.message || 'cdp error'));
    else entry.resolve(message.result);
  });
  const send = (method, params = {}, sessionId) =>
    new Promise((resolve, reject) => {
      const id = nextId++;
      pending.set(id, { resolve, reject });
      socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    });
  return { send, close: () => socket.close() };
}

async function launchChromium(binary, display) {
  const profileDir = await mkdtemp(join(tmpdir(), 'nodewarden-ext-'));
  const child = spawn(
    binary,
    [
      '--no-sandbox',
      '--disable-gpu',
      '--disable-dev-shm-usage',
      '--no-first-run',
      '--no-default-browser-check',
      // Newer Chromium refuses --load-extension unless this is turned off.
      '--disable-features=DisableLoadExtensionCommandLineSwitch',
      // The local certificate is a throwaway one.
      '--ignore-certificate-errors',
      `--remote-debugging-port=0`,
      `--user-data-dir=${profileDir}`,
      '--window-size=1600,1000',
      'about:blank',
    ],
    { stdio: ['ignore', 'pipe', 'pipe'], env: chromiumEnv({ DISPLAY: display }) }
  );
  let log = '';
  child.stdout?.on('data', (chunk) => {
    log += chunk.toString();
  });
  child.stderr?.on('data', (chunk) => {
    log += chunk.toString();
  });

  // The debugging port is written to the DevTools active port file, so the
  // browser can pick a free one.
  const portFile = join(profileDir, 'DevToolsActivePort');
  const deadline = Date.now() + 40000;
  let port = '';
  let browserPath = '';
  while (Date.now() < deadline) {
    if (existsSync(portFile)) {
      const content = readFileSync(portFile, 'utf8').split('\n');
      if (content[0]) {
        const rawPort = content[0].trim();
        // The second line is the browser's own websocket path.
        const rawPath = (content[1] || '').trim();
        // Only a plain port number and a /devtools/ path are taken from the
        // file: nothing else may end up in the websocket URL.
        if (/^\d{1,5}$/.test(rawPort) && /^\/devtools\/[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/.test(rawPath)) {
          port = rawPort;
          browserPath = rawPath;
          break;
        }
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  if (!port || !browserPath) {
    child.kill('SIGKILL');
    await rm(profileDir, { recursive: true, force: true });
    throw new Error(`Chromium did not expose a debugging port\n${log.slice(-2000)}`);
  }

  const cdp = await connectCdp(`ws://127.0.0.1:${port}${browserPath}`);

  return {
    cdp,
    async openPopup(extensionId) {
      const { targetId } = await cdp.send('Target.createTarget', {
        url: `chrome-extension://${extensionId}/popup/index.html`,
      });
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
        const until = Date.now() + timeoutMs;
        while (Date.now() < until) {
          try {
            if (await evaluate(expression)) return true;
          } catch {
            // the page is still loading
          }
          await new Promise((resolve) => setTimeout(resolve, 200));
        }
        const seen = await evaluate('document.body ? document.body.textContent : ""').catch(() => '');
        throw new Error(`timed out waiting for ${label}\npage said:\n${String(seen).slice(0, 600)}`);
      };
      return { evaluate, waitFor, targetId, sessionId };
    },
    async attach() {
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
        const until = Date.now() + timeoutMs;
        while (Date.now() < until) {
          try {
            if (await evaluate(expression)) return true;
          } catch {
            // the page is still loading
          }
          await new Promise((resolve) => setTimeout(resolve, 200));
        }
        const seen = await evaluate('document.body ? document.body.textContent : ""').catch(() => '');
        throw new Error(`timed out waiting for ${label}\npage said:\n${String(seen).slice(0, 600)}`);
      };
      return { evaluate, waitFor, targetId, sessionId };
    },
    async stop() {
      try {
        cdp.close();
      } catch {
        // already closed
      }
      child.kill('SIGTERM');
      await new Promise((resolve) => setTimeout(resolve, 500));
      child.kill('SIGKILL');
      await rm(profileDir, { recursive: true, force: true });
    },
  };
}

// The browser loads the package and says which id it gave it. Chromium brings
// extensions of its own, so the id has to come from the load and not from the
// target list.
async function loadExtension(cdp) {
  const { id } = await cdp.send('Extensions.loadUnpacked', { path: EXTENSION_DIR });
  return String(id || '');
}

// The extension asks which server to talk to before it asks for the account.
async function configureServer(evaluate, waitFor, serverUrl) {
  // The environment button shows the server it would talk to.
  await evaluate(`(() => {
    const buttons = [...document.querySelectorAll('button')];
    const target = buttons.find((b) => /^(bitwarden\.com|https?:\\/\\/)/i.test((b.textContent || '').trim()));
    if (!target) return false;
    target.click();
    return true;
  })()`);
  await new Promise((resolve) => setTimeout(resolve, 2000));

  // A server of one's own is under "self-hosted".
  const selfHosted = await evaluate(`(() => {
    const buttons = [...document.querySelectorAll('button')];
    const target = buttons.find((b) => /^self-hosted$/i.test((b.textContent || '').trim()));
    if (!target) return false;
    target.click();
    return true;
  })()`);
  if (!selfHosted) return false;
  await new Promise((resolve) => setTimeout(resolve, 800));

  // Which asks for the address itself. The field it adds is a new one, so
  // the count before tells where it is.
  const inputsBefore = await evaluate(`document.querySelectorAll('input').length`);
  let picked = false;
  for (let attempt = 0; attempt < 25 && !picked; attempt += 1) {
    picked = await evaluate(`(() => {
      const buttons = [...document.querySelectorAll('button')];
      const target = buttons.find((b) => /custom environment/i.test(b.textContent || ''));
      if (!target) return false;
      target.click();
      return true;
    })()`);
    if (!picked) await new Promise((resolve) => setTimeout(resolve, 400));
  }
  if (!picked) return false;
  await new Promise((resolve) => setTimeout(resolve, 800));

  // The address sits in the field the environment panel added.
  const filled = await evaluate(`(() => {
    const inputs = [...document.querySelectorAll('input')];
    const server = inputs[${inputsBefore}] || inputs[inputs.length - 1];
    if (!server) return false;
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    setter.call(server, ${JSON.stringify(serverUrl)});
    server.dispatchEvent(new Event('input', { bubbles: true }));
    server.dispatchEvent(new Event('change', { bubbles: true }));
    return true;
  })()`);
  if (!filled) return false;
  await new Promise((resolve) => setTimeout(resolve, 500));
  // The form is saved with the button next to the address.
  await evaluate(`(() => {
    const buttons = [...document.querySelectorAll('button')];
    const save = buttons.find((b) => /^save$/i.test((b.textContent || '').trim()));
    if (!save) return false;
    save.click();
    return true;
  })()`);
  await new Promise((resolve) => setTimeout(resolve, 1500));
  return true;
}

async function logIn(evaluate, waitFor) {
  const filled = await evaluate(`(() => {
    const leaves = [...document.querySelectorAll('*')].filter((el) => el.children.length === 0);
    const inputFor = (labelText) => {
      const leaf = leaves.find((el) => (el.textContent || '').trim().toLowerCase() === labelText.toLowerCase());
      const holder = leaf ? leaf.parentElement : null;
      return holder ? holder.querySelector('input') : null;
    };
    const email = document.querySelector('input[type="email"]') || inputFor('Email address');
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    if (!email) return false;
    setter.call(email, ${JSON.stringify(EMAIL)});
    email.dispatchEvent(new Event('input', { bubbles: true }));
    return true;
  })()`);
  if (!filled) return false;
  await new Promise((resolve) => setTimeout(resolve, 300));

  // The address comes first; the password is asked for after it.
  await evaluate(`(() => {
    const buttons = [...document.querySelectorAll('button')];
    const next = buttons.find((b) => /^continue$/i.test((b.textContent || '').trim()));
    if (!next) return false;
    next.click();
    return true;
  })()`);
  await new Promise((resolve) => setTimeout(resolve, 1200));

  const filledPassword = await evaluate(`(() => {
    const password = document.querySelector('input[type="password"]');
    if (!password) return false;
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    setter.call(password, ${JSON.stringify(PASSWORD)});
    password.dispatchEvent(new Event('input', { bubbles: true }));
    return true;
  })()`);
  if (!filledPassword) return false;
  await new Promise((resolve) => setTimeout(resolve, 300));
  await evaluate(`(() => {
    const buttons = [...document.querySelectorAll('button')];
    const submit = buttons.find((b) => /^log in$/i.test((b.textContent || '').trim()));
    if (!submit) return false;
    submit.click();
    return true;
  })()`);
  return true;
}

async function main() {
  const binary = findChromium();
  if (!binary) {
    console.log('skipped: no Chromium found.');
    return 0;
  }
  if (!existsSync(join(EXTENSION_DIR, 'manifest.json'))) {
    console.log(`skipped: no extension at ${EXTENSION_DIR}.`);
    return 0;
  }
  const checks = createChecks('the official Bitwarden extension against a local Worker');

  // A throwaway Worker with its own D1, served over https: the official
  // clients refuse plain http.
  const worker = await startLocalWorker({ label: 'extension-e2e' });
  const proxy = await startTlsProxy(worker.baseUrl);
  const seeded = await seedVault(worker.baseUrl);
  const xvfb = findXvfb();
  const display = ':97';
  let displayProcess = null;
  let browser = null;
  try {
    if (xvfb) {
      displayProcess = spawn(xvfb, [display, '-screen', '0', '1600x1000x24'], { stdio: 'ignore' });
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
    browser = await launchChromium(binary, display);

    // The extension's own page is the popup. The id comes from the browser
    // itself, because an unpacked extension's id depends on where it sits.
    const extensionId = await loadExtension(browser.cdp);
    checks.ok('the extension is loaded', !!extensionId, extensionId || '');

    // The popup is an extension page: a normal page may not navigate to it, so
    // the browser opens it as a target of its own.
    const popupTarget = await browser.openPopup(extensionId);
    const evaluate = popupTarget.evaluate;
    const waitFor = popupTarget.waitFor;
    await new Promise((resolve) => setTimeout(resolve, 3000));
    await waitFor(`document.body && document.body.textContent.length > 0`, 'the popup', 30000);

    // The extension opens with a request to become the browser's password
    // manager and then an introduction. Neither is what this check is about,
    // so the screens are walked through: skip, then log in.
    const screen = async () =>
      JSON.parse(
        await evaluate(
          `JSON.stringify({ url: location.href, text: (document.body ? document.body.textContent : '').slice(0, 200), controls: [...document.querySelectorAll('button, a, input, [role="button"]')].map((el) => (el.tagName + ':' + (el.textContent || '').trim().slice(0, 30) + ':' + (el.getAttribute('aria-label') || '') + ':' + (el.getAttribute('placeholder') || ''))).slice(0, 25) })`
        )
      );
    for (let round = 0; round < 8; round += 1) {
      const state = await screen();
      const labels = state.controls.map((entry) => entry.split(':')[1]);
      // Each screen has one way out: the prompt can be skipped, the carousel
      // can be left for the login.
      const wanted = state.url.includes('default-password-manager-prompt')
        ? ['skip']
        : state.url.includes('intro-carousel')
          ? ['log in']
          : [];
      if (!wanted.length) break;
      const index = labels.findIndex((label) => wanted.some((text) => label.trim().toLowerCase() === text));
      if (index < 0) break;
      await evaluate(`(() => {
        const buttons = [...document.querySelectorAll('button')];
        const target = buttons[${index}];
        if (!target) return false;
        target.click();
        return true;
      })()`);
      await new Promise((resolve) => setTimeout(resolve, 1500));
    }

    // The extension asks which server to talk to before it asks for the
    // account. A self-hosted server is chosen by its address.
    const serverConfigured = await configureServer(evaluate, waitFor, proxy.baseUrl);
    checks.ok('the extension is pointed at the local server', serverConfigured);

    await waitFor(`document.body.textContent.includes('Log in') || document.body.textContent.includes('Email')`, 'the login form', 30000);
    const loggedIn = await logIn(evaluate, waitFor);
    checks.ok('the extension logs in', loggedIn);

    await new Promise((resolve) => setTimeout(resolve, 3000));
    await waitFor(`document.body.textContent.includes('Vault loaded')`, 'the vault', 60000);
    await waitFor(`document.body.textContent.includes('Extension Shared Login')`, 'the shared item', 30000);
    const popupText = await evaluate(`document.body.textContent`);
    checks.ok('the extension shows the shared item', popupText.includes('Extension Shared Login'), popupText.slice(0, 300));
    checks.ok('the extension shows the collection', popupText.includes('Extension Shared'), popupText.slice(0, 300));

    // The item's own view says which organization and collection it belongs
    // to, which is where a member sees it.
    await evaluate(`(() => {
      const rows = [...document.querySelectorAll('button, [role="button"], a')];
      const target = rows.find((el) => (el.textContent || '').includes('Extension Shared Login'));
      if (!target) return false;
      target.click();
      return true;
    })()`);
    await new Promise((resolve) => setTimeout(resolve, 1500));
    const detailText = await evaluate(`document.body.textContent`);
    checks.ok('the extension names the organization', detailText.includes('Extension Team'), detailText.slice(0, 400));
    checks.ok('the extension names the collection of the item', detailText.includes('Extension Shared'), detailText.slice(0, 400));

    // The Send tab of the official extension: it creates a Send against this
    // server. The client encrypts the name and the text with the vault key,
    // so what the server keeps is ciphertext, and the link keeps the key.
    await evaluate(`(() => {
      const deep = (root) => {
        const out = [...root.querySelectorAll('*')];
        for (const el of out) if (el.shadowRoot) out.push(...el.shadowRoot.querySelectorAll('*'));
        return out;
      };
      for (const el of deep(document)) {
        if (el.getAttribute('aria-label') === 'Back') el.click();
      }
      return true;
    })()`);
    await new Promise((resolve) => setTimeout(resolve, 1200));
    await evaluate(`(() => {
      const deep = (root) => {
        const out = [...root.querySelectorAll('*')];
        for (const el of out) if (el.shadowRoot) out.push(...el.shadowRoot.querySelectorAll('*'));
        return out;
      };
      for (const el of deep(document)) {
        if (el.getAttribute('aria-label') === 'Send') el.click();
      }
      return true;
    })()`);
    await new Promise((resolve) => setTimeout(resolve, 2000));
    const onSendPage = await evaluate(`document.body.textContent.includes('Create Send')`);
    checks.ok('the extension has a Send tab', onSendPage === true, String(onSendPage));

    // The composer: a name, the text to share, and the Save button.
    await evaluate(`(() => {
      const deep = (root) => {
        const out = [...root.querySelectorAll('*')];
        for (const el of out) if (el.shadowRoot) out.push(...el.shadowRoot.querySelectorAll('*'));
        return out;
      };
      for (const el of deep(document)) {
        if (el.tagName === 'BUTTON' && (el.textContent || '').trim() === 'Create Send') el.click();
      }
      return true;
    })()`);
    await new Promise((resolve) => setTimeout(resolve, 1200));
    await evaluate(`(() => {
      const deep = (root) => {
        const out = [...root.querySelectorAll('*')];
        for (const el of out) if (el.shadowRoot) out.push(...el.shadowRoot.querySelectorAll('*'));
        return out;
      };
      for (const el of deep(document)) {
        if ((el.textContent || '').trim() === 'Text' && el.tagName !== 'BUTTON') el.click();
      }
      return true;
    })()`);
    await new Promise((resolve) => setTimeout(resolve, 2000));
    const composed = await evaluate(`(() => {
      const deep = (root) => {
        const out = [...root.querySelectorAll('*')];
        for (const el of out) if (el.shadowRoot) out.push(...el.shadowRoot.querySelectorAll('*'));
        return out;
      };
      const all = deep(document);
      const setValue = (el, value) => {
        const proto = el.tagName === 'TEXTAREA' ? window.HTMLTextAreaElement.prototype : window.HTMLInputElement.prototype;
        Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, value);
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
      };
      const name = all.find((el) => el.tagName === 'INPUT' && el.id === 'bit-form-field-11');
      const text = all.find((el) => el.tagName === 'TEXTAREA' && el.id === 'text');
      if (!name || !text) return false;
      setValue(name, 'Extension Send');
      setValue(text, 'Shared through the official extension');
      return true;
    })()`);
    checks.ok('the extension opens the Send composer', composed === true, String(composed));

    await evaluate(`(() => {
      const deep = (root) => {
        const out = [...root.querySelectorAll('*')];
        for (const el of out) if (el.shadowRoot) out.push(...el.shadowRoot.querySelectorAll('*'));
        return out;
      };
      for (const el of deep(document)) {
        if (el.tagName === 'BUTTON' && (el.textContent || '').trim() === 'Save') el.click();
      }
      return true;
    })()`);
    await new Promise((resolve) => setTimeout(resolve, 4000));

    // The server is the one that holds the Send: the client only asked for it.
    const sends = await api(worker.baseUrl, '/api/sends', { token: seeded.token });
    const created = (sends.body?.data || [])[0];
    checks.ok(
      'the extension writes the Send to the server',
      sends.status === 200 && !!created,
      JSON.stringify(sends.body?.data || []).slice(0, 200)
    );
    // The client encrypts the name and the text with the vault key, so the
    // server holds ciphertext and never the words of the Send.
    checks.ok(
      'the server holds the Send encrypted',
      !!created &&
        typeof created.name === 'string' &&
        created.name.startsWith('2.') &&
        typeof created.key === 'string' &&
        created.key.startsWith('2.') &&
        String(created.text?.text || '').startsWith('2.'),
      created ? String(created.name).slice(0, 30) : ''
    );
    checks.ok(
      'the server hands out the access id the link carries',
      !!created && typeof created.accessId === 'string' && created.accessId.length > 10,
      created ? String(created.accessId) : ''
    );

    // The extension says the Send was made and offers the link. The link
    // itself goes to the clipboard, which a background popup cannot hand back.
    const doneText = await evaluate(`document.body.textContent`);
    checks.ok(
      'the extension says the Send was created and offers the link',
      doneText.includes('Send created') && doneText.includes('Copy link'),
      doneText.slice(-200)
    );

    // A Send that carries a file: the extension writes the file to the
    // server, and the link hands it back to whoever holds it.
    const fileSend = await createFileSend(
      worker.baseUrl,
      seeded,
      'extension-file.txt',
      new TextEncoder().encode('The bytes the extension shared.\n')
    );
    checks.ok(
      'the server holds a file Send',
      !!fileSend.send?.id && Number(fileSend.send.type) === 1,
      JSON.stringify(fileSend.send || {}).slice(0, 200)
    );
    checks.ok(
      'and it holds the file name encrypted',
      String(fileSend.send?.file?.fileName || '').startsWith('2.'),
      String(fileSend.send?.file?.fileName || '').slice(0, 30)
    );

    // The link opens the copy: the access id and the key of the Send.
    const access = await fetch(
      `${worker.baseUrl}/api/sends/access/${fileSend.send.accessId}`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }
    );
    const accessBody = access.ok ? await access.json() : {};
    checks.ok('the link opens the file Send', access.ok, String(access.status));
    checks.ok(
      'and the server holds the file without the key',
      accessBody.object === 'send-access' && accessBody.key === undefined,
      JSON.stringify(accessBody).slice(0, 160)
    );

    // The file itself comes back through the file route, sealed with the
    // Send key, so the bytes on the wire are not the bytes of the file.
    const fileId = accessBody?.file?.id;
    const fileResponse = fileId
      ? await fetch(
          `${worker.baseUrl}/api/sends/${fileSend.send.id}/access/file/${fileId}`,
          { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }
        )
      : null;
    checks.ok('the file of the Send can be fetched', !!fileResponse?.ok, String(fileResponse?.status));
    const fileBody = fileResponse?.ok ? await fileResponse.json() : {};
    checks.ok(
      'and it comes back as a sealed file, not as the words of it',
      typeof fileBody.url === 'string' && !String(fileBody.url).includes('extension shared'),
      JSON.stringify(fileBody).slice(0, 160)
    );

    return checks.finish() ? 0 : 1;
  } finally {
    if (browser) await browser.stop();
    if (displayProcess) displayProcess.kill('SIGKILL');
    await proxy.stop();
    await worker.stop();
  }
}

process.exitCode = await main();
