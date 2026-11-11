// Storage adapter for the email_change_requests table.
//
// CONTRACT:
// One pending email change per account. The row holds the code as it was
// hashed, never the code itself, and how many wrong codes were tried, so the
// server can stop guessing. A new request replaces the pending one and
// starts the count over.

export interface StoredEmailChangeRequest {
  userId: string;
  newEmail: string;
  codeHash: string;
  expiresAt: number;
  attempts: number;
}

export async function putEmailChangeRequest(
  db: D1Database,
  input: { userId: string; newEmail: string; codeHash: string; expiresAt: number }
): Promise<void> {
  await db
    .prepare(
      'INSERT INTO email_change_requests(user_id, new_email, code_hash, expires_at, attempts) VALUES(?, ?, ?, ?, 0) ' +
        'ON CONFLICT(user_id) DO UPDATE SET new_email = excluded.new_email, code_hash = excluded.code_hash, ' +
        'expires_at = excluded.expires_at, attempts = 0'
    )
    .bind(input.userId, input.newEmail, input.codeHash, input.expiresAt)
    .run();
}

export async function getEmailChangeRequest(
  db: D1Database,
  userId: string
): Promise<StoredEmailChangeRequest | null> {
  const row = await db
    .prepare(
      'SELECT user_id, new_email, code_hash, expires_at, attempts FROM email_change_requests WHERE user_id = ?'
    )
    .bind(userId)
    .first<{
      user_id: string;
      new_email: string;
      code_hash: string;
      expires_at: number;
      attempts: number;
    }>();
  if (!row) return null;
  return {
    userId: String(row.user_id),
    newEmail: String(row.new_email),
    codeHash: String(row.code_hash),
    expiresAt: Number(row.expires_at),
    attempts: Number(row.attempts),
  };
}

/**
 * Counts one wrong code and answers with the number of wrong codes so far.
 *
 * The count is read back after the write, because the caller needs to know
 * whether this was the last try the request gets.
 */
export async function recordEmailChangeAttempt(db: D1Database, userId: string): Promise<number> {
  await db
    .prepare('UPDATE email_change_requests SET attempts = attempts + 1 WHERE user_id = ?')
    .bind(userId)
    .run();
  const row = await db
    .prepare('SELECT attempts FROM email_change_requests WHERE user_id = ?')
    .bind(userId)
    .first<{ attempts: number }>();
  return Number(row?.attempts ?? 0);
}

export async function deleteEmailChangeRequest(db: D1Database, userId: string): Promise<void> {
  await db.prepare('DELETE FROM email_change_requests WHERE user_id = ?').bind(userId).run();
}
