// Storage adapter for sso_authorization_codes.
//
// CONTRACT:
// Short-lived, single-use authorization codes for the Bitwarden client SSO
// flow. Only the SHA-256 hash of the code is stored; the plaintext code is
// returned to the client through the OAuth redirect and exchanged at the
// token endpoint together with its PKCE verifier.
export interface StoredSsoAuthorizationCode {
  userId: string;
  clientState: string | null;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  createdAt: string;
  expiresAt: string;
  consumedAt: string | null;
}

export async function putSsoAuthorizationCode(
  db: D1Database,
  codeHash: string,
  record: Omit<StoredSsoAuthorizationCode, 'consumedAt'>
): Promise<void> {
  await db
    .prepare(
      'INSERT INTO sso_authorization_codes (code_hash, user_id, client_state, redirect_uri, code_challenge, code_challenge_method, created_at, expires_at, consumed_at) ' +
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)'
    )
    .bind(
      codeHash,
      record.userId,
      record.clientState,
      record.redirectUri,
      record.codeChallenge,
      record.codeChallengeMethod,
      record.createdAt,
      record.expiresAt
    )
    .run();
}

export async function getSsoAuthorizationCode(
  db: D1Database,
  codeHash: string
): Promise<StoredSsoAuthorizationCode | null> {
  const row = await db
    .prepare('SELECT * FROM sso_authorization_codes WHERE code_hash = ?')
    .bind(codeHash)
    .first<{
      user_id: string;
      client_state: string | null;
      redirect_uri: string;
      code_challenge: string;
      code_challenge_method: string;
      created_at: string;
      expires_at: string;
      consumed_at: string | null;
    }>();
  if (!row) return null;
  return {
    userId: row.user_id,
    clientState: row.client_state,
    redirectUri: row.redirect_uri,
    codeChallenge: row.code_challenge,
    codeChallengeMethod: row.code_challenge_method,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    consumedAt: row.consumed_at,
  };
}

/** Marks the code consumed. Returns true only for the first successful call. */
export async function consumeSsoAuthorizationCode(
  db: D1Database,
  codeHash: string
): Promise<boolean> {
  const result = await db
    .prepare(
      'UPDATE sso_authorization_codes SET consumed_at = ? WHERE code_hash = ? AND consumed_at IS NULL'
    )
    .bind(new Date().toISOString(), codeHash)
    .run();
  return Number(result.meta?.changes ?? 0) > 0;
}

export async function deleteExpiredSsoAuthorizationCodes(
  db: D1Database,
  now: string = new Date().toISOString()
): Promise<void> {
  await db.prepare('DELETE FROM sso_authorization_codes WHERE expires_at < ?').bind(now).run();
}
