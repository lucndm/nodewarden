// Checks the production vault audit against a stand-in Cloudflare API.
//
// The audit reads production D1 over the Cloudflare API, so it is exercised
// here against a local server that answers with vault rows: a clean vault must
// report clean, and a vault that still holds the ciphertext-shaped tags must
// report them.
import { createServer } from 'node:http';
import { execFile } from 'node:child_process';
import assert from 'node:assert/strict';
import { vaultDigest } from './prod-vault-audit.mjs';

function encryptedName(seed) {
  // The shape of an encrypted string: a type, then base64 parts joined by '|'.
  const part = (text) => Buffer.from(text, 'utf8').toString('base64').replace(/=+$/, '');
  return `2.${part(seed)}|${part(`${seed}-mac`)}|${part(`${seed}-iv`)}`;
}

/** A vault that the audit has to accept. */
function cleanVault() {
  const userId = 'user-1';
  const folderId = 'folder-1';
  return {
    folders: [{ id: folderId, user_id: userId, name: encryptedName('folder'), tag_name: null }],
    ciphers: [
      { id: 'cipher-1', user_id: userId, folder_id: folderId, data: JSON.stringify({ login: {} }) },
      { id: 'cipher-2', user_id: userId, folder_id: null, data: JSON.stringify({ login: {} }) },
    ],
    users: [{ id: userId, email: 'owner@example.test', role: 'admin', status: 'active' }],
    revisions: [{ user_id: userId, revision_date: '2026-11-07T08:37:20.457Z' }],
    markers: [{ key: `tags.legacy-repair.v1:${userId}`, value: 'done' }],
  };
}

/** The same vault with the residue the old folder-to-tag backfill left behind. */
function dirtyVault() {
  const vault = cleanVault();
  vault.ciphers[0].data = JSON.stringify({ login: {}, tags: [encryptedName('folder')] });
  vault.markers = [];
  return vault;
}

/** Serves the rows of one vault behind the small part of the API the audit uses. */
async function startStandIn(vault) {
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
          ? vault.folders
          : sql.includes('FROM ciphers')
            ? vault.ciphers
            : sql.includes('FROM users')
              ? vault.users
              : sql.includes('FROM user_revisions')
                ? vault.revisions
                : vault.markers;
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
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return server;
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

function parseSummary(stdout) {
  const end = stdout.indexOf('\nCLEAN');
  return JSON.parse(end >= 0 ? stdout.slice(0, end) : stdout);
}

{
  const server = await startStandIn(cleanVault());
  const result = await runAudit(server.address().port);
  server.close();
  server.closeAllConnections?.();
  const summary = parseSummary(result.stdout);
  assert.equal(result.code, 0, `a clean vault must pass: ${result.stderr}`);
  assert.equal(summary.accounts, 1);
  assert.equal(summary.folders, 1);
  assert.equal(summary.items, 2);
  assert.equal(summary.itemsInAFolder, 1);
  assert.equal(summary.foldersWithPlainTextName, 0);
  assert.equal(summary.itemsWithCiphertextShapedTag, 0);
  assert.equal(summary.itemsWithoutFolder, 0);
  assert.equal(summary.legacyTagRepairMarker, 'done');
  console.log('ok   a clean vault reports clean');
}

{
  const server = await startStandIn(dirtyVault());
  const result = await runAudit(server.address().port);
  server.close();
  server.closeAllConnections?.();
  const summary = parseSummary(result.stdout);
  assert.equal(result.code, 1, 'a vault with ciphertext-shaped tags must fail');
  assert.equal(summary.itemsWithCiphertextShapedTag, 1);
  assert.match(result.stderr, /ciphertext-shaped tags/);
  assert.match(result.stderr, /legacy tag repair has not run/);
  console.log('ok   a vault with ciphertext-shaped tags is reported');
}

{
  // A folder name that is not an encrypted string is plain text: the server
  // can see that without the account key.
  const vault = cleanVault();
  vault.folders[0].name = 'Work';
  const server = await startStandIn(vault);
  const result = await runAudit(server.address().port);
  server.close();
  server.closeAllConnections?.();
  const summary = parseSummary(result.stdout);
  assert.equal(result.code, 1, 'a plain-text folder name must fail');
  assert.equal(summary.foldersWithPlainTextName, 1);
  assert.match(result.stderr, /plain-text folder names/);
  console.log('ok   a plain-text folder name is reported');
}

{
  // The digest is what ties an archive to the live vault, so it must depend
  // on the rows and on nothing else: the same rows in another order give the
  // same digest, and one changed row gives a different one.
  const vault = cleanVault();
  const digest = vaultDigest(vault);
  const reordered = {
    folders: [...vault.folders].reverse(),
    ciphers: [...vault.ciphers].reverse(),
    users: [...vault.users],
    revisions: [...vault.revisions],
  };
  assert.equal(vaultDigest(reordered), digest, 'the row order must not change the digest');
  const changed = cleanVault();
  changed.folders[0].tag_name = 'Work';
  assert.notEqual(vaultDigest(changed), digest, 'a changed folder must change the digest');
  const moved = cleanVault();
  moved.ciphers[0].folder_id = null;
  assert.notEqual(vaultDigest(moved), digest, 'an item moved out of its folder must change the digest');
  console.log('ok   the digest follows the rows that decide the layout');
}

console.log('\nall checks passed');
