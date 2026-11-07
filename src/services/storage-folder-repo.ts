import type { Folder } from '../types';
import { generateUUID } from '../utils/uuid';

function mapFolderRow(row: any): Folder {
  return {
    id: row.id,
    userId: row.user_id,
    name: row.name,
    tagName: row.tag_name ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function normalizeTagName(tag: unknown): string {
  return String(tag ?? '').trim();
}

function readCipherTags(data: Record<string, unknown>): string[] {
  const raw = data.tags;
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const tag of raw) {
    const name = normalizeTagName(tag);
    if (!name) continue;
    out.push(name);
  }
  return out;
}

function parseCipherData(raw: unknown): Record<string, unknown> {
  if (typeof raw !== 'string' || !raw) return {};
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

/**
 * Tag<->folder registry: the folders table doubles as the stable id registry
 * for tags. Official Bitwarden clients only know folders, so every tag is
 * exposed to them as a folder with the same id, and a cipher's first tag is
 * its folder position (ciphers.folder_id mirrors that id server-side).
 */

export async function getFolder(db: D1Database, id: string): Promise<Folder | null> {
  const row = await db
    .prepare('SELECT id, user_id, name, tag_name, created_at, updated_at FROM folders WHERE id = ?')
    .bind(id)
    .first<any>();
  if (!row) return null;
  return mapFolderRow(row);
}

export async function getFolderForUser(db: D1Database, id: string, userId: string): Promise<Folder | null> {
  const row = await db
    .prepare('SELECT id, user_id, name, tag_name, created_at, updated_at FROM folders WHERE id = ? AND user_id = ?')
    .bind(id, userId)
    .first<any>();
  if (!row) return null;
  return mapFolderRow(row);
}

export async function saveFolder(db: D1Database, folder: Folder): Promise<void> {
  await db
    .prepare(
      'INSERT INTO folders(id, user_id, name, tag_name, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(id) DO UPDATE SET name=excluded.name, tag_name=excluded.tag_name, updated_at=excluded.updated_at WHERE user_id=excluded.user_id'
    )
    .bind(folder.id, folder.userId, folder.name, folder.tagName ?? null, folder.createdAt, folder.updatedAt)
    .run();
}

export async function deleteFolder(db: D1Database, id: string, userId: string): Promise<void> {
  const folder = await getFolderForUser(db, id, userId);
  if (folder && !folder.tagName && /^\d+\.[^|]+\|/.test(folder.name)) {
    const rows = await db.prepare('SELECT id FROM ciphers WHERE user_id = ? AND folder_id = ?').bind(userId, id).all<{ id: string }>();
    await applyTagToCiphers(db, userId, (rows.results || []).map((row) => row.id), null);
  }
  await db.prepare('DELETE FROM folders WHERE id = ? AND user_id = ?').bind(id, userId).run();
}

/**
 * Makes sure every tag has a registry row (stable folder id) and returns the
 * tag-name -> folder-id map for the given tag list.
 */
export async function ensureFoldersForTags(db: D1Database, userId: string, tags: string[]): Promise<Map<string, string>> {
  const map = new Map<string, string>();
  for (const rawTag of tags) {
    const tag = normalizeTagName(rawTag);
    if (!tag || map.has(tag)) continue;
    const existing = await db
      .prepare('SELECT id FROM folders WHERE user_id = ? AND tag_name = ?')
      .bind(userId, tag)
      .first<{ id: string }>();
    const legacy = existing || await db.prepare('SELECT id FROM folders WHERE user_id = ? AND name = ? AND tag_name IS NULL').bind(userId, tag).first<{ id: string }>();
    if (legacy?.id) {
      map.set(tag, legacy.id);
      continue;
    }
    const id = generateUUID();
    const now = new Date().toISOString();
    await db
      .prepare('INSERT INTO folders(id, user_id, name, tag_name, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?)')
      .bind(id, userId, tag, tag, now, now)
      .run();
    map.set(tag, id);
  }
  return map;
}

interface MigratableCipherRow {
  id: string;
  folder_id: string | null;
  data: unknown;
}

/**
 * One-time-per-cipher backfill: legacy rows that only carry folder_id get the
 * folder name prepended to their tags. Registry rows (folders) are kept with
 * their ids, so official clients see no folder id/name churn. Idempotent;
 * returns true when any cipher row changed.
 */
export async function migrateFolderCiphersToTags(db: D1Database, userId: string, now: string): Promise<boolean> {
  const folders = await getAllFolders(db, userId);
  const nameById = new Map(folders.map((folder) => [folder.id, folder.tagName || (/^\d+\.[^|]+\|/.test(folder.name) ? '' : folder.name)]));
  const res = await db
    .prepare('SELECT id, folder_id, data FROM ciphers WHERE user_id = ?')
    .bind(userId)
    .all<MigratableCipherRow>();

  let changed = false;
  for (const row of res.results || []) {
    if (!row.folder_id) continue;
    const folderName = nameById.get(row.folder_id);
    const data = parseCipherData(row.data);
    const tags = readCipherTags(data);
    delete data.folderId;
    delete data.folder_id;

    if (!folderName) {
      // Without a plaintext tag name, an encrypted Bitwarden folder cannot be backfilled server-side.
      // Keep the folder id and existing tags until the Web Vault supplies its decrypted name.
      continue;
    }

    const remaining = tags.filter((tag) => tag.toLowerCase() !== folderName.toLowerCase());
    if (tags.length > 0 && tags[0].toLowerCase() === folderName.toLowerCase()) {
      continue; // already migrated and in sync with the registry
    }
    data.tags = [folderName, ...remaining];
    await db
      .prepare('UPDATE ciphers SET updated_at = ?, data = ? WHERE id = ?')
      .bind(now, JSON.stringify(data), row.id)
      .run();
    changed = true;
  }
  return changed;
}

/**
 * Renames a tag on every cipher carrying it. The registry row (folder id)
 * stays untouched, so clients keep their references.
 */
export async function renameTagOnCiphers(db: D1Database, userId: string, oldName: string, newName: string): Promise<void> {
  const oldKey = normalizeTagName(oldName).toLowerCase();
  const newKey = normalizeTagName(newName).toLowerCase();
  if (!oldKey || oldKey === newKey) return;
  const now = new Date().toISOString();
  const res = await db
    .prepare('SELECT id, folder_id, data FROM ciphers WHERE user_id = ?')
    .bind(userId)
    .all<MigratableCipherRow>();

  for (const row of res.results || []) {
    const data = parseCipherData(row.data);
    const tags = readCipherTags(data);
    if (!tags.some((tag) => tag.toLowerCase() === oldKey)) continue;

    const renamed = tags.map((tag) => (tag.toLowerCase() === oldKey ? normalizeTagName(newName) : tag));
    const seen = new Set<string>();
    const deduped: string[] = [];
    for (const tag of renamed) {
      const key = tag.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      deduped.push(tag);
    }
    data.tags = deduped.length ? deduped : undefined;
    if (!deduped.length) delete data.tags;

    const positionFolderId = deduped.length ? row.folder_id : null;
    await db
      .prepare('UPDATE ciphers SET folder_id = ?, updated_at = ?, data = ? WHERE id = ?')
      .bind(positionFolderId, now, JSON.stringify(data), row.id)
      .run();
  }
}

/**
 * Removes a tag from every cipher carrying it and re-points affected ciphers
 * to the folder of their new first tag.
 */
export async function removeTagFromCiphers(db: D1Database, userId: string, tagName: string): Promise<void> {
  const key = normalizeTagName(tagName).toLowerCase();
  if (!key) return;
  const now = new Date().toISOString();
  const res = await db
    .prepare('SELECT id, folder_id, data FROM ciphers WHERE user_id = ?')
    .bind(userId)
    .all<MigratableCipherRow>();

  const folderIdByTag = new Map<string, string>();
  for (const row of res.results || []) {
    const data = parseCipherData(row.data);
    const tags = readCipherTags(data);
    if (!tags.some((tag) => tag.toLowerCase() === key)) continue;

    const remaining = tags.filter((tag) => tag.toLowerCase() !== key);
    let positionFolderId: string | null = null;
    if (remaining.length) {
      const firstTag = remaining[0];
      if (!folderIdByTag.has(firstTag)) {
        const ensured = await ensureFoldersForTags(db, userId, [firstTag]);
        folderIdByTag.set(firstTag, ensured.get(firstTag) || '');
      }
      positionFolderId = folderIdByTag.get(firstTag) || null;
    }
    if (remaining.length) data.tags = remaining;
    else delete data.tags;

    await db
      .prepare('UPDATE ciphers SET folder_id = ?, updated_at = ?, data = ? WHERE id = ?')
      .bind(positionFolderId, now, JSON.stringify(data), row.id)
      .run();
  }
}

/**
 * Bulk folder move replaces the first tag with the destination; null removes
 * it and promotes the next tag to the Bitwarden folder position.
 */
export async function applyTagToCiphers(
  db: D1Database,
  userId: string,
  ids: string[],
  tagName: string | null | undefined,
  encryptedFolderId?: string
): Promise<{ changed: boolean; conflict: boolean }> {
  const sanitized = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
  if (!sanitized.length) return { changed: false, conflict: false };
  const now = new Date().toISOString();

  let folderIdForTag: string | null = null;
  if (tagName) {
    const ensured = await ensureFoldersForTags(db, userId, [tagName]);
    folderIdForTag = ensured.get(tagName) || null;
  }

  let changed = false;
  for (const id of sanitized) {
    const row = await db
      .prepare('SELECT data, folder_id, updated_at, name FROM ciphers WHERE id = ? AND user_id = ?')
      .bind(id, userId)
      .first<{ data: string; folder_id: string | null; updated_at: string; name: string | null }>();
    if (!row) continue;
    const data = parseCipherData(row.data);
    const current = readCipherTags(data);
    const previousFolder = row.folder_id ? await getFolderForUser(db, row.folder_id, userId) : null;
    const pendingFolderName = previousFolder && !previousFolder.tagName && /^\d+\.[^|]+\|/.test(previousFolder.name);
    const secondary = pendingFolderName ? current : current.slice(1);
    const next = tagName === undefined
      ? (row.folder_id === encryptedFolderId ? current : secondary)
      : tagName
        ? [tagName, ...secondary.filter((tag) => tag.toLowerCase() !== tagName.toLowerCase())]
        : secondary;
    if (next.length) data.tags = next;
    else delete data.tags;
    const positionFolderId = tagName === undefined ? encryptedFolderId! : next.length
      ? (tagName ? folderIdForTag : (await ensureFoldersForTags(db, userId, [next[0]])).get(next[0]) ?? null)
      : null;
    const result = await db
      .prepare('UPDATE ciphers SET folder_id = ?, updated_at = ?, data = ? WHERE id = ? AND user_id = ? AND data = ? AND updated_at = ? AND folder_id IS ? AND name IS ?')
      .bind(positionFolderId, now, JSON.stringify(data), id, userId, row.data, row.updated_at, row.folder_id, row.name)
      .run();
    if (result.meta.changes !== 1) return { changed, conflict: true };
    changed = true;
  }
  return { changed, conflict: false };
}

export async function getAllFolders(db: D1Database, userId: string): Promise<Folder[]> {
  const res = await db
    .prepare('SELECT id, user_id, name, tag_name, created_at, updated_at FROM folders WHERE user_id = ? ORDER BY updated_at DESC')
    .bind(userId)
    .all<any>();
  return (res.results || []).map((row) => mapFolderRow(row));
}

export async function getFoldersPage(db: D1Database, userId: string, limit: number, offset: number): Promise<Folder[]> {
  const res = await db
    .prepare('SELECT id, user_id, name, tag_name, created_at, updated_at FROM folders WHERE user_id = ? ORDER BY updated_at DESC LIMIT ? OFFSET ?')
    .bind(userId, limit, offset)
    .all<any>();
  return (res.results || []).map((row) => mapFolderRow(row));
}

export async function bulkDeleteFolders(
  db: D1Database,
  userId: string,
  ids: string[]
): Promise<void> {
  const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
  if (!uniqueIds.length) return;

  for (const id of uniqueIds) {
    const folder = await getFolderForUser(db, id, userId);
    if (!folder) continue;
    await removeTagFromCiphers(db, userId, folder.tagName || folder.name);
    await deleteFolder(db, id, userId);
  }
}
