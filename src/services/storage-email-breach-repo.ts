// Storage adapter for the email_breach_cache table.
//
// CONTRACT:
// Derived per-account cache of Have I Been Pwned breach lookups, keyed by
// normalized (lowercased) account email. Rows are rebuildable at any time —
// this is a cache, not persistent user data, so it is excluded from the
// backup export contract.

export interface StoredEmailBreachCache {
  emailNorm: string;
  checkedAt: string;
  status: string;
  breachesJson: string;
}

export async function listActiveUserEmails(db: D1Database): Promise<string[]> {
  const res = await db
    .prepare('SELECT email FROM users WHERE status = ? ORDER BY created_at ASC')
    .bind('active')
    .all<{ email: string }>();
  return (res.results || []).map((row) => String(row.email || '').trim().toLowerCase()).filter(Boolean);
}

export async function getEmailBreachCache(
  db: D1Database,
  emailNorm: string
): Promise<StoredEmailBreachCache | null> {
  const row = await db
    .prepare('SELECT email_norm, checked_at, status, breaches_json FROM email_breach_cache WHERE email_norm = ?')
    .bind(emailNorm)
    .first<{ email_norm: string; checked_at: string; status: string; breaches_json: string }>();
  if (!row) return null;
  return {
    emailNorm: row.email_norm,
    checkedAt: row.checked_at,
    status: row.status,
    breachesJson: row.breaches_json,
  };
}

export async function upsertEmailBreachCache(
  db: D1Database,
  emailNorm: string,
  status: string,
  breachesJson: string,
  checkedAt: string
): Promise<void> {
  await db
    .prepare(
      'INSERT INTO email_breach_cache(email_norm, checked_at, status, breaches_json) VALUES(?, ?, ?, ?) ' +
        'ON CONFLICT(email_norm) DO UPDATE SET checked_at = excluded.checked_at, status = excluded.status, breaches_json = excluded.breaches_json'
    )
    .bind(emailNorm, checkedAt, status, breachesJson)
    .run();
}
