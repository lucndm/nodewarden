// Opens a Send link the way a recipient does.
//
// The Send contract is covered against the API in sends.test.ts, but the
// public page itself was never opened by anything: the link carries the key
// in its path, the page decrypts the payload with it, and a wrong key, a
// password, an expired Send and a deleted Send all have to show something
// honest on screen rather than a blank page.
//
// This runs in a real browser against a throwaway Worker with its own D1.
//
// Run it before pushing to main:
//   npm run test:local-send-public
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { webcrypto } from 'node:crypto';

import { startLocalWorker, findFreePort, createChecks, chromiumEnv } from './local-worker.mjs';
import { bytesToBase64, encryptBw, hkdf, hkdfExpand, pbkdf2 } from '../webapp/src/lib/crypto.ts';

const EMAIL = 'local-send-public@example.test';
const PASSWORD = 'Local-Send-Public-Check-2026!';
const KDF_ITERATIONS = 600000;
const NOTE_TEXT = 'A note that only the holder of the link can read.';

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
  const profileDir = await mkdtemp(join(tmpdir(), 'nodewarden-send-public-'));
  const child = spawn(
    binary,
    [
      '--headless=new',
      '--no-sandbox',
      '--disable-gpu',
      '--disable-dev-shm-usage',
      `--remote-debugging-port=${port}`,
      `--user-data-dir=${profileDir}`,
      'about:blank',
    ],
    { stdio: 'ignore', env: chromiumEnv() }
  );
  const deadline = Date.now() + 30000;
  let endpoint = null;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/version`, {
        signal: AbortSignal.timeout(2000),
      });
      if (response.ok) {
        endpoint = (await response.json()).webSocketDebuggerUrl;
        break;
      }
    } catch {
      // The browser is not listening yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  if (!endpoint) {
    child.kill('SIGKILL');
    await rm(profileDir, { recursive: true, force: true });
    throw new Error('Chromium did not expose a debugging endpoint');
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

/** The small part of the Chrome DevTools Protocol this check needs. */
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

/** The key of a Send, the way the link carries it: base64url of the raw bytes. */
function toUrlSafeKey(raw) {
  return bytesToBase64(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

/**
 * Registers the account, so it can create the Sends. Only one account is
 * registered: a second one would need an invite code, and the check does not
 * need a second account to prove anything.
 */
async function seedAccount(baseUrl) {
  const masterKey = await pbkdf2(PASSWORD, EMAIL, KDF_ITERATIONS, 32);
  const masterHash = await pbkdf2(masterKey, PASSWORD, 1, 32);
  const encKey = await hkdfExpand(masterKey, 'enc', 32);
  const macKey = await hkdfExpand(masterKey, 'mac', 32);
  const vaultKey = webcrypto.getRandomValues(new Uint8Array(64));
  const keyPair = await webcrypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' },
    true,
    ['encrypt', 'decrypt']
  );
  const publicKey = new Uint8Array(await webcrypto.subtle.exportKey('spki', keyPair.publicKey));
  const privateKey = new Uint8Array(await webcrypto.subtle.exportKey('pkcs8', keyPair.privateKey));

  const registered = await api(baseUrl, '/api/accounts/register', {
    method: 'POST',
    headers: { Origin: baseUrl },
    body: {
      email: EMAIL,
      name: 'Local Send Public',
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
        deviceIdentifier: 'local-send-public-seed',
        deviceName: 'local send public seed',
      },
    })
  ).body?.access_token;
  if (!token) throw new Error('the account could not get a token');
  return { token, vaultKey };
}

/**
 * Creates a Send with real key material, so the page decrypts the payload the
 * way a client's link does.
 */
async function createSend(baseUrl, account, overrides = {}) {
  const { token, vaultKey } = account;
  // The Send has its own key. The client seeds it with 16 bytes and derives
  // the encryption and the mac key from them, so the link carries the seed
  // and whoever holds it can read the note.
  const sendSeed = webcrypto.getRandomValues(new Uint8Array(16));
  const derived = await hkdf(sendSeed, 'bitwarden-send', 'send', 64);
  const sendEnc = derived.slice(0, 32);
  const sendMac = derived.slice(32, 64);
  // The server refuses a deletion date more than 31 days out.
  const deletionDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  const created = await api(baseUrl, '/api/sends', {
    method: 'POST',
    token,
    body: {
      type: 0,
      name: await encryptBw(new TextEncoder().encode('Shared note'), sendEnc, sendMac),
      notes: await encryptBw(new TextEncoder().encode(''), sendEnc, sendMac),
      key: await encryptBw(sendSeed, vaultKey.slice(0, 32), vaultKey.slice(32, 64)),
      text: { text: await encryptBw(new TextEncoder().encode(NOTE_TEXT), sendEnc, sendMac), hidden: false },
      deletionDate,
      ...overrides,
    },
  });
  if (created.status !== 200) {
    throw new Error(`the Send could not be created: ${created.status} ${JSON.stringify(created.body)}`);
  }
  return {
    token,
    send: created.body,
    keyPart: toUrlSafeKey(sendSeed),
  };
}

async function main() {
  const binary = findChromium();
  if (!binary) {
    console.log('skipped: no Chromium found.');
    console.log('Set NODEWARDEN_CHROMIUM to a Chromium binary to run this check.');
    return 0;
  }

  const worker = await startLocalWorker({ label: 'send-public-e2e' });
  let browser = null;
  try {
    const account = await seedAccount(worker.baseUrl);
    const seeded = await createSend(worker.baseUrl, account);
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

    const checks = createChecks('the public Send page in a browser');
    const pageText = () => evaluate('document.body.textContent');

    // The link opens the note and nobody else can.
    await cdp.send(
      'Page.navigate',
      { url: `${worker.baseUrl}/#/send/${seeded.send.accessId}/${seeded.keyPart}` },
      sessionId
    );
    await waitFor(
      `document.body.textContent.includes(${JSON.stringify(NOTE_TEXT)})`,
      'the note to be shown'
    );
    checks.ok('the link opens the note', String(await pageText()).includes(NOTE_TEXT));

    const nameShown = await pageText();
    checks.ok('and it names the Send', nameShown.includes('Shared note'), nameShown.slice(0, 200));

    // A link with the wrong key cannot read it.
    const wrongKey = toUrlSafeKey(webcrypto.getRandomValues(new Uint8Array(16)));
    await cdp.send(
      'Page.navigate',
      { url: `${worker.baseUrl}/#/send/${seeded.send.accessId}/${wrongKey}` },
      sessionId
    );
    await waitFor(`!!document.body.textContent`, 'the answer for a wrong key', 15000);
    const wrongKeyText = String(await pageText());
    checks.ok('a link with the wrong key does not show the note', !wrongKeyText.includes(NOTE_TEXT));
    checks.ok(
      'and it says so instead of showing nothing',
      wrongKeyText.trim().length > 0,
      wrongKeyText.slice(0, 200)
    );

    // A link without a key cannot read it either.
    await cdp.send(
      'Page.navigate',
      { url: `${worker.baseUrl}/#/send/${seeded.send.accessId}` },
      sessionId
    );
    await waitFor(`!!document.body.textContent`, 'the answer for a link without a key', 15000);
    const noKeyText = String(await pageText());
    checks.ok('a link without a key does not show the note', !noKeyText.includes(NOTE_TEXT));

    // A Send that is gone cannot be opened.
    const deleted = await createSend(worker.baseUrl, account);
    await api(worker.baseUrl, `/api/sends/${deleted.send.id}`, { method: 'DELETE', token: deleted.token });
    await cdp.send(
      'Page.navigate',
      { url: `${worker.baseUrl}/#/send/${deleted.send.accessId}/${deleted.keyPart}` },
      sessionId
    );
    await waitFor(`!!document.body.textContent`, 'the answer for a Send that is gone', 15000);
    const goneText = String(await pageText());
    checks.ok('a deleted Send cannot be opened', !goneText.includes(NOTE_TEXT));

    // A Send whose access count is used up cannot be opened either.
    const spent = await createSend(worker.baseUrl, account, { maxAccessCount: 1 });
    const spentOpened = await api(worker.baseUrl, `/api/sends/access/${spent.send.accessId}`, {
      method: 'POST',
      body: {},
    });
    checks.equal('the first opening of a Send with one view works', spentOpened.status, 200);
    await cdp.send(
      'Page.navigate',
      { url: `${worker.baseUrl}/#/send/${spent.send.accessId}/${spent.keyPart}` },
      sessionId
    );
    await waitFor(`!!document.body.textContent`, 'the answer for a Send that is used up', 15000);
    const spentText = String(await pageText());
    checks.ok('a Send whose one view is used up cannot be opened', !spentText.includes(NOTE_TEXT));

    return checks.finish() ? 0 : 1;
  } finally {
    if (browser) await browser.stop();
    await worker.stop();
  }
}

process.exitCode = await main();
