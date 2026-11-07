import type { Cipher, CipherType, CipherUsage, CipherVersion } from '../types';

function normalizeOptionalId(value: unknown): string | null {
  if (value == null) return null;
  const normalized = String(value).trim();
  return normalized ? normalized : null;
}

type SafeBind = (stmt: D1PreparedStatement, ...values: any[]) => D1PreparedStatement;
type SqlChunkSize = (fixedBindCount: number) => number;
type UpdateRevisionDate = (userId: string) => Promise<string>;

interface CipherRow {
  id: string;
  user_id: string;
  type: number | null;
  folder_id: string | null;
  name: string | null;
  notes: string | null;
  favorite: number | null;
  data: string;
  reprompt: number | null;
  key: string | null;
  created_at: string;
  updated_at: string;
  archived_at: string | null;
  deleted_at: string | null;
  organization_id: string | null;
}

const CIPHER_SCALAR_DATA_KEYS = new Set([
  'id',
  'userId',
  'user_id',
  'type',
  'folderId',
  'folder_id',
  'name',
  'notes',
  'favorite',
  'reprompt',
  'key',
  'attachments',
  'Attachments',
  'attachments2',
  'Attachments2',
  'createdAt',
  'created_at',
  'creationDate',
  'updatedAt',
  'updated_at',
  'revisionDate',
  'lastKnownRevisionDate',
  'LastKnownRevisionDate',
  'archivedAt',
  'archived_at',
  'archivedDate',
  'deletedAt',
  'deleted_at',
  'deletedDate',
]);

function buildCipherData(cipher: Cipher, folderId: string | null): string {
  const payload: Record<string, unknown> = {
    ...cipher,
    folderId,
  };
  for (const key of CIPHER_SCALAR_DATA_KEYS) {
    delete payload[key];
  }
  return JSON.stringify(payload);
}

function parseCipherRow(row: CipherRow | null | undefined): Cipher | null {
  if (!row?.data) return null;
  try {
    const parsed = JSON.parse(row.data) as Cipher;
    const folderId = normalizeOptionalId(row.folder_id ?? parsed.folderId ?? null);
    return {
      ...parsed,
      id: row.id,
      userId: row.user_id,
      type: Number(row.type) || Number(parsed.type) || 1,
      folderId,
      name: row.name ?? parsed.name ?? null,
      notes: row.notes ?? parsed.notes ?? null,
      favorite: row.favorite != null ? !!row.favorite : !!parsed.favorite,
      reprompt: row.reprompt ?? parsed.reprompt ?? 0,
      key: row.key ?? parsed.key ?? null,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      archivedAt: row.archived_at ?? parsed.archivedAt ?? parsed.archivedDate ?? null,
      deletedAt: row.deleted_at ?? parsed.deletedAt ?? parsed.deletedDate ?? null,
      organizationId: row.organization_id ?? parsed.organizationId ?? null,
    };
  } catch {
    console.error('Corrupted cipher data, id:', row.id);
    return null;
  }
}

function selectCipherColumns(): string {
  return 'id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, archived_at, deleted_at, organization_id';
}

export async function getCipher(db: D1Database, id: string): Promise<Cipher | null> {
  const row = await db
    .prepare(`SELECT ${selectCipherColumns()} FROM ciphers WHERE id = ?`)
    .bind(id)
    .first<CipherRow>();
  return parseCipherRow(row);
}

export async function getCipherForUser(db: D1Database, id: string, userId: string): Promise<Cipher | null> {
  const row = await db
    .prepare(`SELECT ${selectCipherColumns()} FROM ciphers WHERE id = ? AND user_id = ?`)
    .bind(id, userId)
    .first<CipherRow>();
  return parseCipherRow(row);
}

export async function saveCipher(db: D1Database, safeBind: SafeBind, cipher: Cipher): Promise<void> {
  const folderId = normalizeOptionalId(cipher.folderId);
  const data = buildCipherData(cipher, folderId);
  const stmt = db.prepare(
    'INSERT INTO ciphers(id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, archived_at, deleted_at, organization_id) ' +
    'VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
    'ON CONFLICT(id) DO UPDATE SET ' +
    'type=excluded.type, folder_id=excluded.folder_id, name=excluded.name, notes=excluded.notes, favorite=excluded.favorite, data=excluded.data, reprompt=excluded.reprompt, key=excluded.key, updated_at=excluded.updated_at, archived_at=excluded.archived_at, deleted_at=excluded.deleted_at, organization_id=excluded.organization_id ' +
    'WHERE user_id=excluded.user_id'
  );
  await safeBind(
    stmt,
    cipher.id,
    cipher.userId,
    Number(cipher.type) || 1,
    folderId,
    cipher.name,
    cipher.notes,
    cipher.favorite ? 1 : 0,
    data,
    cipher.reprompt ?? 0,
    cipher.key,
    cipher.createdAt,
    cipher.updatedAt,
    cipher.archivedAt ?? null,
    cipher.deletedAt,
    normalizeOptionalId(cipher.organizationId)
  ).run();
}

// A single conditional UPDATE prevents a competing save or deletion between
// the handler's read and write from being overwritten (or resurrected).
// When a version is supplied, the snapshot of the superseded state is written
// in the same batch, guarded by the same revision check, so history and item
// can never disagree.
export async function updateCipherIfUnchanged(
  db: D1Database,
  safeBind: SafeBind,
  cipher: Cipher,
  expectedUpdatedAt: string,
  version?: CipherVersionInput | null
): Promise<boolean> {
  const folderId = normalizeOptionalId(cipher.folderId);
  const data = buildCipherData(cipher, folderId);
  const updateStatement = safeBind(
    db.prepare(
      'UPDATE ciphers SET type=?, folder_id=?, name=?, notes=?, favorite=?, data=?, reprompt=?, key=?, updated_at=?, archived_at=?, deleted_at=?, organization_id=? ' +
      'WHERE id=? AND user_id=? AND updated_at=?'
    ),
    Number(cipher.type) || 1, folderId, cipher.name, cipher.notes, cipher.favorite ? 1 : 0,
    data, cipher.reprompt ?? 0, cipher.key, cipher.updatedAt,
    cipher.archivedAt ?? null, cipher.deletedAt, normalizeOptionalId(cipher.organizationId),
    cipher.id, cipher.userId, expectedUpdatedAt
  );
  const statements: D1PreparedStatement[] = [updateStatement];
  if (version) statements.push(buildCipherVersionInsertStatement(db, safeBind, version, data));
  const results = await db.batch(statements);
  const result = results[0];
  return result.meta.changes === 1;
}

// Compares exactly the values the conditional UPDATE above would write, so a
// save that carries no real change can skip the cipher write, the user
// revision bump and the notification to the other clients. The updated-at
// timestamp is deliberately left out: it is always fresh for a write that
// happens.
export function isCipherWriteUnchanged(next: Cipher, current: Cipher): boolean {
  const nextFolderId = normalizeOptionalId(next.folderId);
  const currentFolderId = normalizeOptionalId(current.folderId);
  return (
    (Number(next.type) || 1) === (Number(current.type) || 1) &&
    nextFolderId === currentFolderId &&
    (next.name ?? null) === (current.name ?? null) &&
    (next.notes ?? null) === (current.notes ?? null) &&
    !!next.favorite === !!current.favorite &&
    (next.reprompt ?? 0) === (current.reprompt ?? 0) &&
    (next.key ?? null) === (current.key ?? null) &&
    (next.archivedAt ?? null) === (current.archivedAt ?? null) &&
    (next.deletedAt ?? null) === (current.deletedAt ?? null) &&
    buildCipherData(next, nextFolderId) === buildCipherData(current, currentFolderId)
  );
}

// --- Item history (cipher versions) ---

// How many superseded states are kept per cipher.
// ponytail: fixed per-item cap; add a vault-wide cap if storage becomes a problem.
export const CIPHER_VERSION_RETENTION = 20;

export interface CipherVersionInput {
  id: string;
  cipherId: string;
  userId: string;
  kind: 'created' | 'modified';
  revisionDate: string;
  createdAt: string;
  type: number;
  name: string | null;
  notes: string | null;
  key: string | null;
  reprompt: number;
  data: string;
  /** Cipher revision this write produces; the snapshot lands only when the cipher reaches it. */
  appliedUpdatedAt: string;
}

interface CipherVersionRow {
  id: string;
  cipher_id: string;
  user_id: string;
  kind: string;
  revision_date: string;
  created_at: string;
  type: number | null;
  name: string | null;
  notes: string | null;
  key: string | null;
  reprompt: number | null;
  data: string;
}

// The stored payload without the organization tags: tags say where the item
// sits in the folder tree, not what it holds. A folder move is therefore not a
// content change, and a restore never moves the item back to an old folder.
export function buildCipherVersionData(cipher: Cipher): string {
  const raw = buildCipherData(cipher, normalizeOptionalId(cipher.folderId));
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    delete parsed.tags;
    return JSON.stringify(parsed);
  } catch {
    return raw;
  }
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = canonicalize((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

// True when a write carries no change to what the item holds. Folder, favorite
// and archive moves are organization, not content, so they never produce a
// history entry.
export function isCipherContentUnchanged(next: Cipher, current: Cipher): boolean {
  return (
    (Number(next.type) || 1) === (Number(current.type) || 1) &&
    (next.name ?? null) === (current.name ?? null) &&
    (next.notes ?? null) === (current.notes ?? null) &&
    (next.key ?? null) === (current.key ?? null) &&
    (next.reprompt ?? 0) === (current.reprompt ?? 0) &&
    JSON.stringify(canonicalize(JSON.parse(buildCipherVersionData(next)))) ===
      JSON.stringify(canonicalize(JSON.parse(buildCipherVersionData(current))))
  );
}

function toCipherVersion(row: CipherVersionRow): CipherVersion {
  return {
    id: row.id,
    cipherId: row.cipher_id,
    userId: row.user_id,
    kind: row.kind === 'created' ? 'created' : 'modified',
    revisionDate: row.revision_date,
    createdAt: row.created_at,
    type: (Number(row.type) || 1) as CipherType,
    name: row.name ?? null,
    notes: row.notes ?? null,
    key: row.key ?? null,
    reprompt: Number(row.reprompt) || 0,
    data: row.data,
  };
}

// The version row is written in the same batch as the cipher write. Its guard
// asks for the cipher at the revision this write produces, so a write that was
// rejected or superseded never leaves a version behind.
function buildCipherVersionInsertStatement(
  db: D1Database,
  safeBind: SafeBind,
  version: CipherVersionInput,
  appliedData: string
): D1PreparedStatement {
  return safeBind(
    db.prepare(
      'INSERT INTO cipher_versions(id, cipher_id, user_id, kind, revision_date, created_at, type, name, notes, key, reprompt, data) ' +
      'SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? ' +
      'WHERE EXISTS (SELECT 1 FROM ciphers WHERE id = ? AND user_id = ? AND updated_at = ? AND data = ?)'
    ),
    version.id,
    version.cipherId,
    version.userId,
    version.kind,
    version.revisionDate,
    version.createdAt,
    version.type,
    version.name,
    version.notes,
    version.key,
    version.reprompt,
    version.data,
    version.cipherId,
    version.userId,
    version.appliedUpdatedAt,
    appliedData
  );
}

export async function listCipherVersions(
  db: D1Database,
  cipherId: string,
  userId: string
): Promise<CipherVersion[]> {
  const res = await db
    .prepare(
      'SELECT id, cipher_id, user_id, kind, revision_date, created_at, type, name, notes, key, reprompt, data ' +
      'FROM cipher_versions WHERE cipher_id = ? AND user_id = ? ORDER BY created_at DESC, id DESC'
    )
    .bind(cipherId, userId)
    .all<CipherVersionRow>();
  return (res.results || []).map(toCipherVersion);
}

export async function getCipherVersion(
  db: D1Database,
  versionId: string,
  cipherId: string,
  userId: string
): Promise<CipherVersion | null> {
  const row = await db
    .prepare(
      'SELECT id, cipher_id, user_id, kind, revision_date, created_at, type, name, notes, key, reprompt, data ' +
      'FROM cipher_versions WHERE id = ? AND cipher_id = ? AND user_id = ?'
    )
    .bind(versionId, cipherId, userId)
    .first<CipherVersionRow>();
  return row ? toCipherVersion(row) : null;
}

export async function deleteCipherVersionsForCipher(db: D1Database, cipherId: string): Promise<void> {
  await db.prepare('DELETE FROM cipher_versions WHERE cipher_id = ?').bind(cipherId).run();
}

// Retention: keep the newest states of an item, drop the older ones.
export async function pruneCipherVersions(
  db: D1Database,
  cipherId: string,
  limit: number = CIPHER_VERSION_RETENTION
): Promise<void> {
  const res = await db
    .prepare('SELECT id FROM cipher_versions WHERE cipher_id = ? ORDER BY created_at DESC, id DESC')
    .bind(cipherId)
    .all<{ id: string }>();
  const excess = (res.results || []).slice(limit);
  for (const row of excess) {
    await db.prepare('DELETE FROM cipher_versions WHERE id = ?').bind(row.id).run();
  }
}

function sanitizeIds(ids: string[]): string[] {
  return Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
}

export async function deleteCipher(db: D1Database, id: string, userId: string): Promise<void> {
  // A shared item may be destroyed by any member who may manage it; the caller
  // has already checked that, so the guard here only refuses another account's
  // personal item.
  await db.batch([
    db.prepare('DELETE FROM cipher_versions WHERE cipher_id = ?').bind(id),
    db.prepare('DELETE FROM ciphers WHERE id = ? AND (user_id = ? OR organization_id IS NOT NULL)').bind(id, userId),
    db.prepare('DELETE FROM collection_ciphers WHERE cipher_id = ?').bind(id),
  ]);
}

// Password-copy usage counters live in their own columns. They are written
// without touching updated_at or the user revision date, so recording a copy
// never produces a vault change or a sync notification.
export async function getCipherUsageMap(db: D1Database, userId: string): Promise<Record<string, CipherUsage>> {
  const res = await db
    .prepare('SELECT id, usage_count, last_used_at FROM ciphers WHERE user_id = ? AND usage_count > 0')
    .bind(userId)
    .all<{ id: string; usage_count: number | null; last_used_at: string | null }>();
  const usage: Record<string, CipherUsage> = {};
  for (const row of res.results || []) {
    usage[row.id] = {
      useCount: Number(row.usage_count) || 0,
      lastUsedAt: row.last_used_at ?? null,
    };
  }
  return usage;
}

// Only an owned, non-deleted, non-archived login cipher can be counted. The
// increment and the read-back share one transaction so the returned counter
// is the value this request wrote.
export async function incrementCipherUsage(
  db: D1Database,
  id: string,
  userId: string
): Promise<CipherUsage | null> {
  const now = new Date().toISOString();
  const [update, read] = await db.batch([
    db
      .prepare(
        'UPDATE ciphers SET usage_count = usage_count + 1, last_used_at = ? ' +
        'WHERE id = ? AND user_id = ? AND type = 1 ' +
        'AND deleted_at IS NULL AND archived_at IS NULL ' +
        "AND json_extract(data, '$.deletedAt') IS NULL AND json_extract(data, '$.deletedDate') IS NULL " +
        "AND json_extract(data, '$.archivedAt') IS NULL AND json_extract(data, '$.archivedDate') IS NULL"
      )
      .bind(now, id, userId),
    db.prepare('SELECT usage_count, last_used_at FROM ciphers WHERE id = ? AND user_id = ?').bind(id, userId),
  ]);
  if ((update.meta.changes ?? 0) !== 1) return null;
  const row = (read.results || [])[0] as
    | { usage_count?: number | null; last_used_at?: string | null }
    | undefined;
  if (!row) return null;
  return {
    useCount: Number(row.usage_count) || 0,
    lastUsedAt: row.last_used_at ?? null,
  };
}

export async function bulkSoftDeleteCiphers(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  if (ids.length === 0) return null;
  const uniqueIds = sanitizeIds(ids);
  if (!uniqueIds.length) return null;

  const now = new Date().toISOString();
  const chunkSize = sqlChunkSize(3);

  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    await db
      .prepare(
        `UPDATE ciphers
         SET deleted_at = ?, updated_at = ?,
             data = json_remove(data, '$.deletedAt', '$.deletedDate', '$.updatedAt', '$.revisionDate')
         WHERE id IN (${placeholders}) AND (user_id = ? OR organization_id IS NOT NULL)`
      )
      .bind(now, now, ...chunk, userId)
      .run();
  }

  return updateRevisionDate(userId);
}

export async function bulkRestoreCiphers(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  if (ids.length === 0) return null;
  const uniqueIds = sanitizeIds(ids);
  if (!uniqueIds.length) return null;

  const now = new Date().toISOString();
  const chunkSize = sqlChunkSize(2);

  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    await db
      .prepare(
        `UPDATE ciphers
         SET deleted_at = NULL, updated_at = ?,
             data = json_remove(data, '$.deletedAt', '$.deletedDate', '$.updatedAt', '$.revisionDate')
         WHERE id IN (${placeholders}) AND (user_id = ? OR organization_id IS NOT NULL)`
      )
      .bind(now, ...chunk, userId)
      .run();
  }

  return updateRevisionDate(userId);
}

export async function bulkDeleteCiphers(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  if (ids.length === 0) return null;
  const uniqueIds = sanitizeIds(ids);
  if (!uniqueIds.length) return null;

  const chunkSize = sqlChunkSize(1);
  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    await db.batch([
      db.prepare(`DELETE FROM cipher_versions WHERE cipher_id IN (${placeholders})`).bind(...chunk),
      db.prepare(`DELETE FROM ciphers WHERE id IN (${placeholders}) AND (user_id = ? OR organization_id IS NOT NULL)`).bind(...chunk, userId),
    ]);
  }

  return updateRevisionDate(userId);
}

export async function getAllCiphers(db: D1Database, userId: string): Promise<Cipher[]> {
  const res = await db
    .prepare(`SELECT ${selectCipherColumns()} FROM ciphers WHERE user_id = ? ORDER BY updated_at DESC`)
    .bind(userId)
    .all<CipherRow>();
  return (res.results || []).flatMap((row) => {
    const cipher = parseCipherRow(row);
    return cipher ? [cipher] : [];
  });
}

/**
 * The items a member may see: the ones they own, plus the ones they reach
 * through a collection of an organization they belong to.
 *
 * An owned item has no organization; a shared item has one and is reached
 * through a collection. The two are read apart in one query, the way the
 * official server reads them, so an item in an organization is never handed
 * out because the member happens to have created it.
 *
 * An owner or admin of an organization reaches every collection of it, which
 * is what the official server does when the organization allows admin access
 * to all collection items.
 */
/**
 * The items a member may read, as one set: their own plus the shared ones
 * reachable through a collection of an organization they belong to.
 *
 * The same rule backs the list, the sync and the paged read, so the three can
 * never disagree about what the member is allowed to see. Both placeholders
 * take the user id.
 */
function visibleCiphersSql(columns: string): string {
  const sharedColumns = columns.split(', ').map((name) => `C.${name}`).join(', ');
  return (
    `SELECT ${columns} FROM ciphers WHERE user_id = ? AND organization_id IS NULL ` +
    'UNION ALL ' +
    `SELECT ${sharedColumns} FROM ciphers C ` +
    'INNER JOIN collection_ciphers CC ON CC.cipher_id = C.id ' +
    'INNER JOIN collections COL ON COL.id = CC.collection_id ' +
    'INNER JOIN organization_users OU ON OU.org_id = COL.org_id AND OU.user_id = ? AND OU.status = 2 ' +
    'LEFT JOIN collection_users CU ON CU.collection_id = COL.id AND CU.org_user_id = OU.id ' +
    'LEFT JOIN group_users GU ON GU.org_user_id = OU.id ' +
    'LEFT JOIN collection_groups CG ON CG.collection_id = COL.id AND CG.group_id = GU.group_id ' +
    'WHERE CU.collection_id IS NOT NULL OR CG.collection_id IS NOT NULL OR OU.type <= 1'
  );
}

export async function getVisibleCiphers(db: D1Database, userId: string): Promise<Cipher[]> {
  const res = await db
    .prepare(`SELECT DISTINCT * FROM (${visibleCiphersSql(selectCipherColumns())})`)
    .bind(userId, userId)
    .all<CipherRow>();
  return (res.results || []).flatMap((row) => {
    const cipher = parseCipherRow(row);
    return cipher ? [cipher] : [];
  });
}


export async function getCiphersPage(
  db: D1Database,
  userId: string,
  includeDeleted: boolean,
  limit: number,
  offset: number
): Promise<Cipher[]> {
  const whereDeleted = includeDeleted
    ? ''
    : "WHERE deleted_at IS NULL AND json_extract(data, '$.deletedAt') IS NULL AND json_extract(data, '$.deletedDate') IS NULL";
  const res = await db
    .prepare(
      `SELECT DISTINCT * FROM (${visibleCiphersSql(selectCipherColumns())}) ${whereDeleted} ` +
        'ORDER BY updated_at DESC LIMIT ? OFFSET ?'
    )
    .bind(userId, userId, limit, offset)
    .all<CipherRow>();
  return (res.results || []).flatMap((row) => {
    const cipher = parseCipherRow(row);
    return cipher ? [cipher] : [];
  });
}

export async function getCiphersByIds(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  ids: string[],
  userId: string
): Promise<Cipher[]> {
  if (ids.length === 0) return [];
  const uniqueIds = sanitizeIds(ids);
  if (!uniqueIds.length) return [];

  const chunkSize = sqlChunkSize(1);
  const out: Cipher[] = [];
  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    const stmt = db.prepare(`SELECT ${selectCipherColumns()} FROM ciphers WHERE user_id = ? AND id IN (${placeholders})`);
    const res = await stmt.bind(userId, ...chunk).all<CipherRow>();
    out.push(
      ...(res.results || []).flatMap((row) => {
        const cipher = parseCipherRow(row);
        return cipher ? [cipher] : [];
      })
    );
  }
  return out;
}

export async function bulkArchiveCiphers(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  if (ids.length === 0) return null;
  const uniqueIds = sanitizeIds(ids);
  if (!uniqueIds.length) return null;

  const now = new Date().toISOString();
  const chunkSize = sqlChunkSize(3);

  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    await db
      .prepare(
        `UPDATE ciphers
         SET archived_at = ?, updated_at = ?,
             data = json_remove(data, '$.archivedAt', '$.archivedDate', '$.updatedAt', '$.revisionDate')
         WHERE id IN (${placeholders}) AND (user_id = ? OR organization_id IS NOT NULL)
           AND deleted_at IS NULL
           AND json_extract(data, '$.deletedAt') IS NULL
           AND json_extract(data, '$.deletedDate') IS NULL`
      )
      .bind(now, now, ...chunk, userId)
      .run();
  }

  return updateRevisionDate(userId);
}

export async function bulkUnarchiveCiphers(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  if (ids.length === 0) return null;
  const uniqueIds = sanitizeIds(ids);
  if (!uniqueIds.length) return null;

  const now = new Date().toISOString();
  const chunkSize = sqlChunkSize(2);

  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    await db
      .prepare(
        `UPDATE ciphers
         SET archived_at = NULL, updated_at = ?,
             data = json_remove(data, '$.archivedAt', '$.archivedDate', '$.updatedAt', '$.revisionDate')
         WHERE id IN (${placeholders}) AND (user_id = ? OR organization_id IS NOT NULL)`
      )
      .bind(now, ...chunk, userId)
      .run();
  }

  return updateRevisionDate(userId);
}
