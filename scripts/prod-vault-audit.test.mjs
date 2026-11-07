// Checks the production vault audit against a stand-in Cloudflare API.
//
// The audit reads production D1 over the Cloudflare API, so it is exercised
// here against a local server that answers with rows from a real backup
// archive: the clean archive must report clean, the archive that still holds
// the ciphertext-shaped tags must report them.
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { unzipSync } from 'fflate';
import assert from 'node:assert/strict';

const CLEAN_ARCHIVE = '/tmp/nodewarden_backup_20261107_084308_5124e.zip';
const DIRTY_ARCHIVE = '/tmp/nodewarden_backup_20261107_082540_4596d.zip';

function readArchive(path) {
  const zip = unzipSync(new Uint8Array(readFileSync(path)));
  const db = JSON.parse(Buffer.from(zip['db.json']).toString());
  const marker = (db.config || []).find((row) => String(row.key || '').startsWith('tags.legacy-repair.v1:'));
  return {
    folders: (db.folders || []).map((row) => ({
      id: row.id,
      user_id: row.user_id,
      name: row.name,
      tag_name: row.tag_name ?? null,
    })),
    ciphers: (db.ciphers || []).map((row) => ({
      id: row.id,
      user_id: row.user_id,
      folder_id: row.folder_id ?? null,
      data: row.data,
    })),
    users: (db.users || []).map((row) => ({ id: row.id, email: row.email, role: row.role, status: row.status })),
    revisions: db.user_revisions || [],
    markers: marker ? [{ key: marker.key, value: marker.value }] : [],
  };
}

/** Serves the rows of one archive behind the small part of the API the audit uses. */
function startStandIn(archive) {
  const server = createServer((request, response) => {
    const url = new URL(request.url, 'http://localhost');
    const send = (payload) => {
      response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify({ success: true, result: payload }));
    };
    if (url.pathname.endsWith('/d1/database')) {
      send([{ uuid: 'db-uuid', name: 'nodewarden-db' }]);
      return;
    }
    if (url.pathname.endsWith('/query')) {
      let body = '';
      request.on('data', (chunk) => {
        body += chunk;
      });
      request.on('end', () => {
        const sql = JSON.parse(body || '{}').sql || '';
        const rows = sql.includes('FROM folders')
          ? archive.folders
          : sql.includes('FROM ciphers')
            ? archive.ciphers
            : sql.includes('FROM users')
              ? archive.users
              : sql.includes('FROM user_revisions')
                ? archive.revisions
                : archive.markers;
        // The audit pages with LIMIT/OFFSET, so the stand-in has to page too.
        const limit = Number(/LIMIT\s+(\d+)/i.exec(sql)?.[1] || rows.length);
        const offset = Number(/OFFSET\s+(\d+)/i.exec(sql)?.[1] || 0);
        send([{ results: rows.slice(offset, offset + limit), success: true }]);
      });
      return;
    }
    response.writeHead(404);
    response.end('{}');
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

function runAudit(port) {
  return new Promise((resolve) => {
    execFile(
      'node',
      ['scripts/prod-vault-audit.mjs'],
      {
        cwd: process.cwd(),
        env: {
          ...process.env,
          CLOUDFLARE_API_TOKEN: 'test-token',
          CLOUDFLARE_ACCOUNT_ID: 'test-account',
          CLOUDFLARE_API_BASE: `http://127.0.0.1:${port}/client/v4`,
        },
      },
      (error, stdout, stderr) => resolve({ code: error?.code ?? 0, stdout, stderr })
    );
  });
}

const cleanArchive = readArchive(CLEAN_ARCHIVE);
const dirtyArchive = readArchive(DIRTY_ARCHIVE);

{
  const server = await startStandIn(cleanArchive);
  const port = server.address().port;
  const result = await runAudit(port);
  server.close();
  server.closeAllConnections?.();
  const summary = JSON.parse(result.stdout.slice(0, result.stdout.indexOf('\nCLEAN') >= 0 ? result.stdout.indexOf('\nCLEAN') : undefined));
  assert.equal(result.code, 0, `clean archive must pass: ${result.stderr}`);
  assert.equal(summary.folders, cleanArchive.folders.length);
  assert.equal(summary.items, cleanArchive.ciphers.length);
  assert.equal(summary.foldersWithPlainTextName, 0);
  assert.equal(summary.itemsWithCiphertextShapedTag, 0);
  assert.equal(summary.itemsWithoutFolder, 0);
  assert.equal(summary.itemsWithUnparsablePayload, 0);
  assert.equal(summary.legacyTagRepairMarker, 'done');
  console.log('ok   a clean vault reports clean');
}

{
  const server = await startStandIn(dirtyArchive);
  const port = server.address().port;
  const result = await runAudit(port);
  server.close();
  server.closeAllConnections?.();
  const summary = JSON.parse(result.stdout.slice(0, result.stdout.indexOf('\nCLEAN') >= 0 ? result.stdout.indexOf('\nCLEAN') : undefined));
  assert.equal(result.code, 1, 'a vault with ciphertext-shaped tags must fail');
  assert.equal(summary.itemsWithCiphertextShapedTag, 822);
  assert.equal(summary.foldersWithPlainTextName, 0);
  assert.match(result.stderr, /ciphertext-shaped tags/);
  console.log('ok   a vault with ciphertext-shaped tags is reported');
}

console.log('\nall checks passed');
