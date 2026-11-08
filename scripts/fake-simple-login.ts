// A provider that speaks the SimpleLogin API, for the checks that need one.
//
// The alias feature talks to a provider outside this app, so the checks run
// against a stand-in that answers the same way: the aliases of the account,
// the toggle that turns one on or off, and the delete that removes it. The
// stand-in is deliberately strict about the API key, so a wrong key is
// answered the way a provider answers it.
import { spawnSync } from 'node:child_process';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { type AddressInfo } from 'node:net';
import { existsSync, readdirSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export interface FakeAlias {
  id: number;
  email: string;
  name: string | null;
  enabled: boolean;
  creation_timestamp: number;
  note: string | null;
  mailboxes: Array<{ id: number; email: string }>;
  nb_forward: number;
  nb_block: number;
  nb_reply: number;
}

export interface FakeSimpleLogin {
  url: string;
  apiKey: string;
  aliases: FakeAlias[];
  /** Every request the provider was asked for, as "METHOD /path". */
  requests: string[];
  /** How many connections the provider accepted, whatever they carried. */
  connections: number;
  /** The next answer is forced to this status, once. */
  failWith: number | null;
  close: () => Promise<void>;
}

export function defaultFakeAliases(): FakeAlias[] {
  return [
    {
      id: 3,
      email: 'shop.cat@sl.test',
      name: 'Shop',
      enabled: true,
      creation_timestamp: 1700000000,
      note: null,
      mailboxes: [{ id: 1, email: 'me@example.test' }],
      nb_forward: 4,
      nb_block: 0,
      nb_reply: 1,
    },
    {
      id: 4,
      email: 'news.letter@sl.test',
      name: null,
      enabled: false,
      creation_timestamp: 1700001000,
      note: 'newsletter',
      mailboxes: [
        { id: 1, email: 'me@example.test' },
        { id: 2, email: 'other@example.test' },
      ],
      nb_forward: 0,
      nb_block: 2,
      nb_reply: 0,
    },
  ];
}

/**
 * The provider answers over https when the check needs a browser to reach it:
 * the app's content security policy only lets a page connect to https
 * addresses, so a plain http stand-in would be blocked before it is asked.
 */
function findOpenssl(): string | null {
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

async function createCertificate(): Promise<{ key: string; cert: string; dir: string }> {
  const openssl = findOpenssl();
  if (!openssl) throw new Error('openssl is required for the https alias check');
  const dir = await mkdtemp(join(tmpdir(), 'nodewarden-provider-tls-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
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
  return { key: await readFile(keyPath, 'utf8'), cert: await readFile(certPath, 'utf8'), dir };
}

export async function startFakeSimpleLogin(
  options: { apiKey?: string; https?: boolean } = {},
): Promise<FakeSimpleLogin> {
  const state: FakeSimpleLogin = {
    url: '',
    apiKey: options.apiKey ?? 'test-api-key',
    aliases: defaultFakeAliases(),
    requests: [],
    connections: 0,
    failWith: null,
    close: async () => {},
  };

  const handle = (request: IncomingMessage, response: ServerResponse) => {
    state.connections += 1;
    const url = new URL(request.url || '/', 'http://provider.test');
    state.requests.push(`${request.method} ${url.pathname}`);

    // A browser calls the provider from another origin, so the answers carry
    // the headers a provider has to send for that to work at all.
    const cors = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Authentication, Content-Type',
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    };
    const answer = (status: number, body: unknown) => {
      response.writeHead(status, { 'Content-Type': 'application/json', ...cors });
      response.end(JSON.stringify(body));
    };

    if (request.method === 'OPTIONS') {
      response.writeHead(204, cors);
      response.end();
      return;
    }

    if (state.failWith !== null) {
      const status = state.failWith;
      state.failWith = null;
      answer(status, { error: 'forced failure' });
      return;
    }
    if (request.headers.authentication !== state.apiKey) {
      answer(401, { error: 'wrong api key' });
      return;
    }

    const aliasMatch = url.pathname.match(/^\/api\/aliases\/(\d+)(\/toggle)?$/);
    if (aliasMatch) {
      const alias = state.aliases.find((item) => item.id === Number(aliasMatch[1]));
      if (!alias) {
        answer(404, { error: 'alias not found' });
        return;
      }
      if (request.method === 'DELETE') {
        state.aliases = state.aliases.filter((item) => item.id !== alias.id);
        answer(200, { deleted: true });
        return;
      }
      if (request.method === 'POST' && aliasMatch[2] === '/toggle') {
        alias.enabled = !alias.enabled;
        answer(200, { enabled: alias.enabled });
        return;
      }
    }

    if (url.pathname === '/api/v2/aliases' && request.method === 'GET') {
      answer(200, { aliases: state.aliases });
      return;
    }

    answer(404, { error: 'not found' });
  };

  let certificateDir = '';
  let server: Server;
  if (options.https) {
    const certificate = await createCertificate();
    certificateDir = certificate.dir;
    server = createHttpsServer({ key: certificate.key, cert: certificate.cert }, handle);
  } else {
    server = createServer(handle);
  }

  const { promise: listening, resolve: onListening } = Promise.withResolvers<void>();
  server.listen(0, '127.0.0.1', onListening);
  await listening;
  const address = server.address() as AddressInfo;
  state.url = `${options.https ? 'https' : 'http'}://127.0.0.1:${address.port}`;
  state.close = async () => {
    const { promise, resolve } = Promise.withResolvers<void>();
    server.close(() => resolve());
    await promise;
    if (certificateDir) await rm(certificateDir, { recursive: true, force: true });
  };
  return state;
}
