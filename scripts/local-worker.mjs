// Boots a throwaway NodeWarden Worker with its own local D1.
//
// Used by the local end-to-end checks so a change can be verified against the
// real Worker, the real schema and the real HTTP surface before it reaches
// production. Nothing here talks to a remote database: the D1 lives in a temp
// directory that is removed afterwards.
import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdtemp, rm } from 'node:fs/promises';
import { existsSync, readdirSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { createServer as createTlsServer } from 'node:https';

export function findFreePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

// The official CLI refuses plain http, so the local check serves the Worker
// over https with a throwaway certificate the CLI is told to trust.
function findOpenssl() {
  const fromPath = spawnSync('sh', ['-c', 'command -v openssl'], { encoding: 'utf8' });
  const path = (fromPath.stdout || '').trim();
  if (path && existsSync(path)) return path;
  for (const entry of existsSync('/nix/store') ? readdirSync('/nix/store') : []) {
    if (!entry.includes('openssl')) continue;
    const candidate = `/nix/store/${entry}/bin/openssl`;
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

export async function startTlsProxy(targetBaseUrl) {
  const openssl = findOpenssl();
  if (!openssl) {
    throw new Error('openssl is required for the https check (the CLI refuses plain http)');
  }
  const dir = await mkdtemp(join(tmpdir(), 'nodewarden-tls-'));
  const certPath = join(dir, 'cert.pem');
  const keyPath = join(dir, 'key.pem');
  const generated = spawnSync(
    openssl,
    [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', keyPath, '-out', certPath, '-days', '2',
      '-subj', '/CN=127.0.0.1',
      '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost',
    ],
    { encoding: 'utf8' }
  );
  if (generated.status !== 0) {
    await rm(dir, { recursive: true, force: true });
    throw new Error(`openssl could not create a certificate: ${generated.stderr}`);
  }

  const target = new URL(targetBaseUrl);
  const port = await findFreePort();
  const server = createTlsServer(
    { key: await readFile(keyPath), cert: await readFile(certPath) },
    async (req, res) => {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      const headers = { ...req.headers, host: target.host };
      delete headers['accept-encoding'];
      delete headers.connection;
      delete headers['content-length'];
      if (body.length) headers['content-length'] = String(body.length);
      try {
        const upstream = await fetch(`${targetBaseUrl}${req.url}`, {
          method: req.method,
          headers,
          body: body.length ? body : undefined,
          redirect: 'manual',
        });
        const payload = Buffer.from(await upstream.arrayBuffer());
        const outHeaders = {};
        upstream.headers.forEach((value, key) => {
          if (['content-encoding', 'content-length', 'connection', 'transfer-encoding'].includes(key)) return;
          outHeaders[key] = value;
        });
        res.writeHead(upstream.status, outHeaders);
        res.end(payload);
      } catch (error) {
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: error instanceof Error ? error.message : 'proxy error' }));
      }
    }
  );

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });

  return {
    baseUrl: `https://127.0.0.1:${port}`,
    certPath,
    async stop() {
      await new Promise((resolve) => server.close(resolve));
      await rm(dir, { recursive: true, force: true });
    },
  };
}

async function waitForReady(baseUrl, child, timeoutMs = 180000) {
  const deadline = Date.now() + timeoutMs;
  let lastError = 'no response';
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`wrangler dev exited with code ${child.exitCode}`);
    }
    try {
      const response = await fetch(`${baseUrl}/api/version`, { signal: AbortSignal.timeout(5000) });
      if (response.ok) return;
      lastError = `status ${response.status}`;
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`local Worker did not become ready: ${lastError}`);
}

// Starts the Worker and returns the base URL plus a stop() that kills the
// process and removes the temporary D1 directory.
export async function startLocalWorker({ label = 'local' } = {}) {
  const port = await findFreePort();
  const persistDir = await mkdtemp(join(tmpdir(), `nodewarden-${label}-`));
  const jwtSecret = randomBytes(32).toString('hex');
  const child = spawn(
    'npx',
    [
      'wrangler',
      'dev',
      '-c',
      'wrangler.toml',
      '--local',
      '--persist-to',
      persistDir,
      '--ip',
      '127.0.0.1',
      '--port',
      String(port),
      '--var',
      `JWT_SECRET:${jwtSecret}`,
    ],
    { stdio: ['ignore', 'pipe', 'pipe'] }
  );

  let log = '';
  const collect = (chunk) => {
    log += chunk.toString();
    if (log.length > 8000) log = log.slice(-8000);
  };
  child.stdout?.on('data', collect);
  child.stderr?.on('data', collect);

  const baseUrl = `http://127.0.0.1:${port}`;
  try {
    await waitForReady(baseUrl, child);
  } catch (error) {
    child.kill('SIGKILL');
    await rm(persistDir, { recursive: true, force: true });
    throw new Error(`${error instanceof Error ? error.message : error}\n${log}`);
  }

  return {
    baseUrl,
    port,
    log: () => log,
    async stop() {
      child.kill('SIGTERM');
      await new Promise((resolve) => {
        if (child.exitCode !== null) {
          resolve();
          return;
        }
        child.once('exit', resolve);
        setTimeout(() => {
          child.kill('SIGKILL');
          resolve();
        }, 5000);
      });
      await rm(persistDir, { recursive: true, force: true });
    },
  };
}

// A tiny assertion logger: every check is reported, the run fails at the end.
export function createChecks(title) {
  const failures = [];
  console.log(`\n${title}`);
  return {
    ok(label, condition, detail = '') {
      if (condition) {
        console.log(`  ok   ${label}`);
      } else {
        console.log(`  FAIL ${label}${detail ? ` :: ${detail}` : ''}`);
        failures.push(label);
      }
      return condition;
    },
    equal(label, actual, expected, detail = '') {
      return this.ok(
        label,
        actual === expected,
        `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}${detail ? ` :: ${detail}` : ''}`
      );
    },
    finish() {
      if (failures.length) {
        console.log(`\n${failures.length} check(s) failed: ${failures.join(', ')}`);
        process.exitCode = 1;
        return false;
      }
      console.log('\nall checks passed');
      return true;
    },
  };
}
