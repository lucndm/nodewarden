// Storage adapter for the generator_settings table.
//
// CONTRACT:
// Stores one opaque blob per user holding the username generator's forwarded
// email alias configuration. The blob is client-side encrypted with the
// user's symmetric key (Bitwarden cipher string format) before it reaches
// this layer — the server never sees the forwarder API key in plaintext.
export interface StoredGeneratorSettings {
  userId: string;
  data: string;
  updatedAt: string | null;
}

export async function getStoredGeneratorSettings(
  db: D1Database,
  userId: string
): Promise<StoredGeneratorSettings | null> {
  const row = await db
    .prepare('SELECT user_id, data, updated_at FROM generator_settings WHERE user_id = ?')
    .bind(userId)
    .first<{ user_id: string; data: string; updated_at: string | null }>();
  if (!row) return null;
  return { userId: row.user_id, data: row.data, updatedAt: row.updated_at || null };
}

export async function saveStoredGeneratorSettings(
  db: D1Database,
  userId: string,
  data: string
): Promise<void> {
  const now = new Date().toISOString();
  await db
    .prepare(
      'INSERT INTO generator_settings (user_id, data, updated_at) VALUES (?, ?, ?) ' +
        'ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at'
    )
    .bind(userId, data, now)
    .run();
}
