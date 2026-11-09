// Storage adapter for the emergency_access table.
//
// CONTRACT:
// One account (the grantor) lets another person (the grantee) in when they
// cannot get in themselves. The row holds the grantor's wrapped key and the
// grantor's own email, so the server never holds a key it could open and
// never holds a grant that would work for somebody else.
//
// The columns and their meaning follow the upstream shape, so the official
// clients read a row written here.

/** What the grantee may do once the access is confirmed. */
export const EMERGENCY_ACCESS_TYPE_VIEW = 0;
export const EMERGENCY_ACCESS_TYPE_TAKEOVER = 1;

/** Where the grant stands. */
export const EMERGENCY_ACCESS_STATUS_INVITED = 0;
export const EMERGENCY_ACCESS_STATUS_ACCEPTED = 1;
export const EMERGENCY_ACCESS_STATUS_CONFIRMED = 2;
export const EMERGENCY_ACCESS_STATUS_RECOVERY_INITIATED = 3;
export const EMERGENCY_ACCESS_STATUS_RECOVERY_APPROVED = 4;

/** How long the grantee has to wait before the grantor can approve a takeover. */
export const EMERGENCY_ACCESS_MIN_WAIT_DAYS = 1;
export const EMERGENCY_ACCESS_MAX_WAIT_DAYS = 90;

export interface EmergencyAccessRow {
  id: string;
  grantorId: string;
  granteeId: string | null;
  email: string | null;
  wrappedKey: string | null;
  type: number;
  status: number;
  waitTimeDays: number;
  recoveryInitiatedAt: string | null;
  lastNotificationAt: string | null;
  createdAt: string;
  updatedAt: string;
}

interface RawRow {
  id: string;
  grantor_id: string;
  grantee_id: string | null;
  email: string | null;
  wrapped_key: string | null;
  type: number;
  status: number;
  wait_time_days: number;
  recovery_initiated_at: string | null;
  last_notification_at: string | null;
  created_at: string;
  updated_at: string;
}

const COLUMNS =
  'id, grantor_id, grantee_id, email, wrapped_key, type, status, wait_time_days, ' +
  'recovery_initiated_at, last_notification_at, created_at, updated_at';

function mapRow(row: RawRow): EmergencyAccessRow {
  return {
    id: String(row.id || ''),
    grantorId: String(row.grantor_id || ''),
    granteeId: row.grantee_id ? String(row.grantee_id) : null,
    email: row.email ? String(row.email) : null,
    wrappedKey: row.wrapped_key ? String(row.wrapped_key) : null,
    type: Number(row.type) || 0,
    status: Number(row.status) || 0,
    waitTimeDays: Number(row.wait_time_days) || 0,
    recoveryInitiatedAt: row.recovery_initiated_at ? String(row.recovery_initiated_at) : null,
    lastNotificationAt: row.last_notification_at ? String(row.last_notification_at) : null,
    createdAt: String(row.created_at || ''),
    updatedAt: String(row.updated_at || ''),
  };
}

/** True when the wait time is one the format allows. */
export function isValidEmergencyWaitDays(days: number): boolean {
  return Number.isInteger(days) && days >= EMERGENCY_ACCESS_MIN_WAIT_DAYS && days <= EMERGENCY_ACCESS_MAX_WAIT_DAYS;
}

/**
 * The day the wait is over, counted from the moment the recovery started.
 * It is null while the recovery has not started.
 */
export function emergencyAccessDeadline(row: EmergencyAccessRow): string | null {
  if (!row.recoveryInitiatedAt) return null;
  const started = new Date(row.recoveryInitiatedAt).getTime();
  if (!Number.isFinite(started)) return null;
  const days = isValidEmergencyWaitDays(row.waitTimeDays) ? row.waitTimeDays : 0;
  return new Date(started + days * 24 * 60 * 60 * 1000).toISOString();
}

/**
 * True when the wait is over, so the grantor may approve the recovery.
 * A row that never started a recovery has no deadline to pass.
 */
export function isEmergencyRecoveryAllowed(row: EmergencyAccessRow, now: number = Date.now()): boolean {
  const deadline = emergencyAccessDeadline(row);
  if (!deadline) return false;
  const time = new Date(deadline).getTime();
  if (!Number.isFinite(time)) return false;
  return time <= now;
}

/** The grants one account gave away. */
export async function listEmergencyAccessByGrantor(
  db: D1Database,
  grantorId: string
): Promise<EmergencyAccessRow[]> {
  const res = await db
    .prepare(`SELECT ${COLUMNS} FROM emergency_access WHERE grantor_id = ? ORDER BY created_at DESC`)
    .bind(grantorId)
    .all<RawRow>();
  return (res.results || []).map(mapRow);
}

/** The grants one account was given. */
export async function listEmergencyAccessByGrantee(
  db: D1Database,
  granteeId: string
): Promise<EmergencyAccessRow[]> {
  const res = await db
    .prepare(`SELECT ${COLUMNS} FROM emergency_access WHERE grantee_id = ? ORDER BY created_at DESC`)
    .bind(granteeId)
    .all<RawRow>();
  return (res.results || []).map(mapRow);
}

/** The grants that were addressed to an address, whether or not it was claimed yet. */
export async function listEmergencyAccessByEmail(
  db: D1Database,
  email: string
): Promise<EmergencyAccessRow[]> {
  const res = await db
    .prepare(`SELECT ${COLUMNS} FROM emergency_access WHERE email = ? ORDER BY created_at DESC`)
    .bind(email)
    .all<RawRow>();
  return (res.results || []).map(mapRow);
}

export async function getEmergencyAccess(db: D1Database, id: string): Promise<EmergencyAccessRow | null> {
  const row = await db
    .prepare(`SELECT ${COLUMNS} FROM emergency_access WHERE id = ?`)
    .bind(id)
    .first<RawRow>();
  return row ? mapRow(row) : null;
}

export async function createEmergencyAccess(
  db: D1Database,
  row: EmergencyAccessRow
): Promise<void> {
  await db
    .prepare(
      'INSERT INTO emergency_access (id, grantor_id, grantee_id, email, wrapped_key, type, status, wait_time_days, ' +
        'recovery_initiated_at, last_notification_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    )
    .bind(
      row.id,
      row.grantorId,
      row.granteeId,
      row.email,
      row.wrappedKey,
      row.type,
      row.status,
      row.waitTimeDays,
      row.recoveryInitiatedAt,
      row.lastNotificationAt,
      row.createdAt,
      row.updatedAt
    )
    .run();
}

/**
 * Writes the fields that change over the life of a grant. A field that is
 * not named keeps the value it had, so a step that only moves the status
 * cannot quietly reset the wait time.
 */
export async function updateEmergencyAccess(
  db: D1Database,
  id: string,
  changes: {
    granteeId?: string | null;
    email?: string | null;
    wrappedKey?: string | null;
    type?: number;
    status?: number;
    waitTimeDays?: number;
    recoveryInitiatedAt?: string | null;
    lastNotificationAt?: string | null;
    updatedAt: string;
  }
): Promise<void> {
  const current = await getEmergencyAccess(db, id);
  if (!current) return;
  await db
    .prepare(
      'UPDATE emergency_access SET grantee_id = ?, email = ?, wrapped_key = ?, type = ?, status = ?, wait_time_days = ?, ' +
        'recovery_initiated_at = ?, last_notification_at = ?, updated_at = ? WHERE id = ?'
    )
    .bind(
      'granteeId' in changes ? changes.granteeId ?? null : current.granteeId,
      'email' in changes ? changes.email ?? null : current.email,
      'wrappedKey' in changes ? changes.wrappedKey ?? null : current.wrappedKey,
      changes.type ?? current.type,
      changes.status ?? current.status,
      changes.waitTimeDays ?? current.waitTimeDays,
      'recoveryInitiatedAt' in changes ? changes.recoveryInitiatedAt ?? null : current.recoveryInitiatedAt,
      'lastNotificationAt' in changes ? changes.lastNotificationAt ?? null : current.lastNotificationAt,
      changes.updatedAt,
      id
    )
    .run();
}

export async function deleteEmergencyAccess(db: D1Database, id: string): Promise<void> {
  await db.prepare('DELETE FROM emergency_access WHERE id = ?').bind(id).run();
}
