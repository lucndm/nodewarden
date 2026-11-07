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
// Environment:
//   CLOUDFLARE_API_TOKEN   Cloudflare API token with D1 read
//   CLOUDFLARE_ACCOUNT_ID  Cloudflare account id
//   CLOUDFLARE_D1_NAME     D1 database name (default: nodewarden-db)
const TOKEN = process.env.CLOUDFLARE_API_TOKEN || '';
const ACCOUNT_ID = process.env.CLOUDFLARE_ACCOUNT_ID || '';
const DB_NAME = process.env.CLOUDFLARE_D1_NAME || 'nodewarden-db';
// The API host is fixed in production; the override exists so the script can
// be pointed at a stand-in server while it is being checked.
const API_BASE = process.env.CLOUDFLARE_API_BASE || 'https://api.cloudflare.com/client/v4';

// The same rule the web vault uses to recognise an encrypted string.
const CIPHER_STRING = /^\d+\.[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+(?:\|[A-Za-z0-9+/=]+)?$/;
const PAGE_SIZE = 500;

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
  const ciphers = await queryAll(database.uuid, 'SELECT id, user_id, folder_id, data FROM ciphers');
  const users = await queryAll(database.uuid, 'SELECT id, email, role, status FROM users');
  const revisions = await queryAll(database.uuid, 'SELECT user_id, revision_date FROM user_revisions');
  const markers = await queryAll(
    database.uuid,
    "SELECT key, value FROM config WHERE key LIKE 'tags.legacy-repair.v1:%'"
  );

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
  const foldersWithoutTagName = folders.filter((folder) => folder.tag_name === null || folder.tag_name === '').length;

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

  const marker = markers.find((row) => row.key.startsWith('tags.legacy-repair.v1:'));
  const repairMarker = marker ? String(marker.value || '') : 'missing';

  const summary = {
    database: DB_NAME,
    accounts: users.length,
    folders: folders.length,
    foldersWithPlainTextName: plainTextFolders.length,
    foldersWithoutTagName,
    duplicateFolderNames,
    items: ciphers.length,
    itemsInAFolder: ciphers.filter((cipher) => !!cipher.folder_id).length,
    itemsWithoutFolder,
    itemsWithTags,
    itemsWithCiphertextShapedTag: junkTags,
    itemsWithTagOver64Characters: overlongTags,
    itemsWithUnparsablePayload: unparsablePayloads,
    legacyTagRepairMarker: repairMarker,
    vaultRevision: revisions.map((row) => row.revision_date).sort().pop() || null,
  };

  console.log(JSON.stringify(summary, null, 2));

  const problems = [];
  if (summary.foldersWithPlainTextName > 0) problems.push('plain-text folder names');
  if (summary.itemsWithCiphertextShapedTag > 0) problems.push('ciphertext-shaped tags');
  if (summary.duplicateFolderNames > 0) problems.push('duplicate folder names');
  if (summary.itemsWithoutFolder > 0) problems.push('items pointing at a missing folder');
  if (summary.itemsWithUnparsablePayload > 0) problems.push('unparsable cipher payloads');
  if (summary.itemsWithTagOver64Characters > 0) problems.push('tags over 64 characters');
  if (repairMarker !== 'done') problems.push('the legacy tag repair has not run');

  if (problems.length) {
    console.error(`NOT CLEAN: ${problems.join(', ')}`);
    process.exit(1);
  }
  console.log('CLEAN: no plain-text folder name, no ciphertext-shaped tag, repair applied.');
}

process.exitCode = await main();
