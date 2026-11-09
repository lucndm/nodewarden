// Read-only audit of the production vault, straight from D1 over the
// Cloudflare API.
//
// The web vault's own answer to "is this vault clean?" needs the account key,
// which only the browser holds. The server can answer the same question from
// the rows it stores, because every Folder name and every cipher payload is
// ciphertext there: a Folder name that is not a cipher string is plain text,
// and a tag that is a cipher string can only be residue from the old
// folder-to-tag backfill.
//
// Nothing here writes, and nothing prints vault content: only counts and the
// repair marker are printed.
//
// Run it from a machine that holds the credentials, never from a CI runner.
// This repository is public, so a CI log is a public log: whatever the runner
// prints about the running vault is published with it.
//
// Environment:
//   CLOUDFLARE_API_TOKEN   Cloudflare API token with D1 read
//   CLOUDFLARE_ACCOUNT_ID  Cloudflare account id
//   CLOUDFLARE_D1_NAME     D1 database name (default: nodewarden-db)
import { createHash } from 'node:crypto';

const TOKEN = process.env.CLOUDFLARE_API_TOKEN || '';
const ACCOUNT_ID = process.env.CLOUDFLARE_ACCOUNT_ID || '';
// The tables the worker bootstraps, kept here so the audit can say what a
// running database is missing instead of failing on the first query.
const EXPECTED_TABLES = [
  'users',
  'config',
  'folders',
  'ciphers',
  'cipher_versions',
  'attachments',
  'organizations',
  'organization_users',
  'organization_policies',
  'collections',
  'collection_users',
  'collection_ciphers',
  'groups',
  'group_users',
  'sends',
  'audit_logs',
  'webauthn_credentials',
];

const DB_NAME = process.env.CLOUDFLARE_D1_NAME || 'nodewarden-db';
// The API host is fixed in production; the override exists so the script can
// be pointed at a stand-in server while it is being checked.
const API_BASE = process.env.CLOUDFLARE_API_BASE || 'https://api.cloudflare.com/client/v4';

// The same rule the web vault uses to recognise an encrypted string.
const CIPHER_STRING = /^\d+\.[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+(?:\|[A-Za-z0-9+/=]+)?$/;
const PAGE_SIZE = 500;

/** How many bytes a base64 segment carries, without decoding it. */
function base64Bytes(segment) {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(segment)) return null;
  const padding = segment.endsWith('==') ? 2 : segment.endsWith('=') ? 1 : 0;
  return (segment.length / 4) * 3 - padding;
}

/**
 * True when the value has the shape of an encrypted string and its segments
 * carry the byte counts their type fixes.
 *
 * The shape alone is not enough: "2.iv|data|mac" with a twelve character mac
 * has the right shape and the wrong bytes, so it never opens. The production
 * vault holds four folder names like that, and a check that only looked at
 * the shape called them encrypted and reported the vault clean.
 */
function isWholeCipherString(value) {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim();
  if (!CIPHER_STRING.test(trimmed)) return false;

  const dot = trimmed.indexOf('.');
  const type = Number(trimmed.slice(0, dot));
  const parts = trimmed.slice(dot + 1).split('|');
  const sizes = parts.map((part) => base64Bytes(part));
  if (sizes.some((size) => size === null)) return false;
  const [iv, data, mac] = sizes;

  if (type === 0 || type === 1) return iv === 16 && data > 0 && data % 16 === 0;
  if (type === 2) return iv === 16 && data > 0 && data % 16 === 0 && mac === 32;
  if (type === 4) return iv === 256;
  if (type === 5 || type === 6) return iv === 256 && data === 32;
  return true;
}

function api(path, init = {}) {
  return fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${TOKEN}`,
      'Content-Type': 'application/json',
      ...(init.headers || {}),
    },
  }).then(async (response) => {
    const body = await response.json().catch(() => ({}));
    if (!response.ok || body?.success === false) {
      const message = body?.errors?.[0]?.message || `HTTP ${response.status}`;
      throw new Error(message);
    }
    return body.result;
  });
}

async function query(databaseId, sql, params = []) {
  const result = await api(`/accounts/${ACCOUNT_ID}/d1/database/${databaseId}/query`, {
    method: 'POST',
    body: JSON.stringify({ sql, params }),
  });
  const first = Array.isArray(result) ? result[0] : result;
  return first?.results || [];
}

async function queryAll(databaseId, sql) {
  const rows = [];
  for (let offset = 0; ; offset += PAGE_SIZE) {
    const page = await query(databaseId, `${sql} LIMIT ${PAGE_SIZE} OFFSET ${offset}`);
    rows.push(...page);
    if (page.length < PAGE_SIZE) break;
  }
  return rows;
}

/**
 * The fields of an item that are still plain text.
 *
 * The server refuses to write an item whose name, notes or login fields are
 * not encrypted strings, so an item with plain text there is an item that
 * cannot be moved yet.
 */
export function plainTextFields(cipher) {
  const found = [];
  const check = (label, value) => {
    if (value == null || value === '') return;
    if (typeof value !== 'string' || !CIPHER_STRING.test(value.trim())) found.push(label);
  };
  check('name', cipher.name);
  check('notes', cipher.notes);
  let parsed;
  try {
    parsed = JSON.parse(cipher.data || '{}');
  } catch {
    return found;
  }
  const login = parsed?.login;
  if (login && typeof login === 'object') {
    check('login.username', login.username);
    check('login.password', login.password);
    check('login.totp', login.totp);
    for (const uri of Array.isArray(login.uris) ? login.uris : []) {
      check('login.uri', uri?.uri);
    }
  }
  return found;
}

function readTags(data) {
  let parsed;
  try {
    parsed = JSON.parse(data || '{}');
  } catch {
    return null;
  }
  const tags = parsed?.tags;
  return Array.isArray(tags) ? tags.map((tag) => String(tag)) : [];
}

/**
 * A digest of the vault rows that decide the layout: the folders with their
 * tag names, the items with their folder and payload, the accounts and the
 * revision. Two vaults with the same digest hold the same vault, so an
 * archive that passed the restore rehearsal can be tied to the live vault.
 */
export function vaultDigest(vault) {
  const folders = (vault.folders || [])
    .map((row) => [row.id, row.user_id, row.name, row.tag_name ?? null])
    .sort((a, b) => String(a[0]).localeCompare(String(b[0])));
  const ciphers = (vault.ciphers || [])
    .map((row) => [row.id, row.user_id, row.folder_id ?? null, row.data])
    .sort((a, b) => String(a[0]).localeCompare(String(b[0])));
  const users = (vault.users || [])
    .map((row) => [row.id, row.email, row.role, row.status])
    .sort((a, b) => String(a[0]).localeCompare(String(b[0])));
  const payload = JSON.stringify({
    folders,
    ciphers,
    users,
    revisions: (vault.revisions || [])
      .map((row) => [row.user_id, row.revision_date])
      .sort((a, b) => String(a[0]).localeCompare(String(b[0]))),
  });
  return createHash('sha256').update(payload).digest('hex');
}

async function main() {
  if (!TOKEN || !ACCOUNT_ID) {
    console.error('CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID are required.');
    process.exit(2);
  }

  const databases = await api(`/accounts/${ACCOUNT_ID}/d1/database?name=${encodeURIComponent(DB_NAME)}`);
  const database = (Array.isArray(databases) ? databases : [databases]).find((row) => row?.name === DB_NAME);
  if (!database?.uuid) {
    console.error(`D1 database ${DB_NAME} not found in this account.`);
    process.exit(2);
  }

  const folders = await queryAll(database.uuid, 'SELECT id, user_id, name, tag_name FROM folders');
  const ciphers = await queryAll(
    database.uuid,
    'SELECT id, user_id, folder_id, organization_id, name, notes, data FROM ciphers'
  );
  const users = await queryAll(database.uuid, 'SELECT id, email, role, status FROM users');
  const revisions = await queryAll(database.uuid, 'SELECT user_id, revision_date FROM user_revisions');
  const organizations = await queryAll(database.uuid, 'SELECT id, name FROM organizations');
  const organizationUsers = await queryAll(database.uuid, 'SELECT id, org_id, type, status FROM organization_users');
  const collections = await queryAll(database.uuid, 'SELECT id, org_id FROM collections');
  const markers = await queryAll(
    database.uuid,
    "SELECT key, value FROM config WHERE key LIKE 'tags.legacy-repair.v1:%'"
  );
  // The schema the running database actually has, read the way a migration
  // plan needs it: which version it claims, which tables the code expects,
  // and which of them are absent.
  const configValues = await queryAll(database.uuid, 'SELECT key, value FROM config');
  const schemaVersionRow = configValues.find((row) => row.key === 'schema.version');
  const schemaVersion = schemaVersionRow ? String(schemaVersionRow.value || '') : null;
  const tableRows = await queryAll(database.uuid, "SELECT name FROM sqlite_master WHERE type = 'table'");
  const tables = new Set(tableRows.map((row) => String(row.name || '')));
  const missingTables = EXPECTED_TABLES.filter((name) => !tables.has(name));
  // Items the migration must carry: a personal item's attachments and its
  // history are sealed with the item key, so moving the item to an
  // organization means re-sealing them too. The counts say how much is at
  // stake before anything is moved.
  const attachments = tables.has('attachments') ? await queryAll(database.uuid, 'SELECT id, cipher_id FROM attachments') : [];
  const versions = tables.has('cipher_versions') ? await queryAll(database.uuid, 'SELECT id, cipher_id FROM cipher_versions') : [];
  const sends = tables.has('sends') ? await queryAll(database.uuid, 'SELECT id FROM sends') : [];
  const attachmentCipherIds = new Set(attachments.map((row) => String(row.cipher_id || '')));
  const versionCipherIds = new Set(versions.map((row) => String(row.cipher_id || '')));
  const organizationPolicies = tables.has('organization_policies')
    ? await queryAll(database.uuid, 'SELECT id, org_id, type, enabled FROM organization_policies')
    : [];

  const plainTextFolders = folders.filter((folder) => {
    const name = String(folder.name || '');
    return name.trim() !== '' && !CIPHER_STRING.test(name.trim());
  });
  const namePerUser = new Map();
  for (const folder of folders) {
    const key = `${folder.user_id}|${folder.name}`;
    namePerUser.set(key, (namePerUser.get(key) || 0) + 1);
  }
  const duplicateFolderNames = [...namePerUser.values()].filter((count) => count > 1).length;
  // A folder with no name cannot become a collection: there would be nothing
  // to call it. Its items have to go somewhere else.
  const foldersWithoutName = folders.filter((folder) => !String(folder.name || '').trim()).length;
  const foldersWithoutTagName = folders.filter((folder) => folder.tag_name === null || folder.tag_name === '').length;
  // A folder whose name is an encrypted string of the right shape but the
  // wrong bytes never opens: the mac was cut short. Its items cannot go into
  // a collection of their own, they end up in the general one. A name that is
  // plain text is counted on its own, so it is left out here.
  const foldersWithBrokenName = folders.filter((folder) => {
    const name = String(folder.name || '').trim();
    return name !== '' && CIPHER_STRING.test(name) && !isWholeCipherString(name);
  }).length;

  const folderIds = new Set(folders.map((folder) => folder.id));
  const itemsWithoutFolder = ciphers.filter(
    (cipher) => cipher.folder_id && !folderIds.has(cipher.folder_id)
  ).length;
  const unparsablePayloads = ciphers.filter((cipher) => readTags(cipher.data) === null).length;
  const itemsWithTags = ciphers.filter((cipher) => (readTags(cipher.data) || []).length > 0).length;
  const junkTags = ciphers.filter((cipher) =>
    (readTags(cipher.data) || []).some((tag) => CIPHER_STRING.test(tag.trim()))
  ).length;
  const overlongTags = ciphers.filter((cipher) =>
    (readTags(cipher.data) || []).some((tag) => tag.length > 64)
  ).length;

  // An item whose own fields are still plain text cannot be written by the
  // server, so a move into an organization would refuse it. The count says
  // how many items that would be before the move, not after.
  const itemsWithPlainTextFields = ciphers.filter((cipher) => plainTextFields(cipher).length > 0);

  const marker = markers.find((row) => row.key.startsWith('tags.legacy-repair.v1:'));
  const repairMarker = marker ? String(marker.value || '') : 'missing';

  const summary = {
    database: DB_NAME,
    vaultDigest: vaultDigest({ folders, ciphers, users, revisions }),
    accounts: users.length,
    schemaVersion,
    missingTables,
    organizationPolicies: organizationPolicies.length,
    organizations: organizations.length,
    organizationMembers: organizationUsers.length,
    collections: collections.length,
    folders: folders.length,
    foldersWithPlainTextName: plainTextFolders.length,
    foldersWithBrokenName,
    foldersWithoutTagName,
    foldersWithoutName,
    duplicateFolderNames,
    items: ciphers.length,
    itemsInAFolder: ciphers.filter((cipher) => !!cipher.folder_id).length,
    itemsInAnOrganization: ciphers.filter((cipher) => !!cipher.organization_id).length,
    personalItems: ciphers.filter((cipher) => !cipher.organization_id).length,
    attachments: attachments.length,
    itemsWithAttachments: attachmentCipherIds.size,
    cipherVersions: versions.length,
    itemsWithHistory: versionCipherIds.size,
    sends: sends.length,
    itemsWithoutFolder,
    itemsWithTags,
    itemsWithPlainTextFields: itemsWithPlainTextFields.length,
    itemsWithCiphertextShapedTag: junkTags,
    itemsWithTagOver64Characters: overlongTags,
    itemsWithUnparsablePayload: unparsablePayloads,
    legacyTagRepairMarker: repairMarker,
    vaultRevision: revisions.map((row) => row.revision_date).sort().pop() || null,
  };

  console.log(JSON.stringify(summary, null, 2));

  const problems = [];
  if (summary.foldersWithPlainTextName > 0) problems.push('plain-text folder names');
  if (summary.foldersWithBrokenName > 0) problems.push('folder names that cannot be opened');
  if (summary.itemsWithCiphertextShapedTag > 0) problems.push('ciphertext-shaped tags');
  if (summary.duplicateFolderNames > 0) problems.push('duplicate folder names');
  if (summary.itemsWithoutFolder > 0) problems.push('items pointing at a missing folder');
  if (summary.itemsWithUnparsablePayload > 0) problems.push('unparsable cipher payloads');
  if (summary.itemsWithTagOver64Characters > 0) problems.push('tags over 64 characters');
  if (repairMarker !== 'done') problems.push('the legacy tag repair has not run');
// The tables are created by the worker on its first request after a deploy,
// so a missing table right after a deploy is expected until that request.
if (missingTables.length > 0) problems.push(`missing tables: ${missingTables.join(', ')}`);

  if (problems.length) {
    console.error(`NOT CLEAN: ${problems.join(', ')}`);
    process.exit(1);
  }
  console.log('CLEAN: no plain-text folder name, no ciphertext-shaped tag, repair applied.');
  if (itemsWithPlainTextFields.length) {
    // Not a damaged vault: a legacy one. The server refuses to write an item
    // whose fields are still plain text, so these items cannot be moved into
    // an organization until they are re-encrypted.
    console.log(
      `${itemsWithPlainTextFields.length} item(s) still carry plain-text fields and would be refused by a move into an organization.`
    );
  }
}

if (process.argv[1] && process.argv[1].endsWith('prod-vault-audit.mjs')) {
  process.exitCode = await main();
}
