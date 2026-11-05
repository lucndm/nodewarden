/// <reference types="node" />
/// <reference types="@cloudflare/workers-types" />

// Integration coverage for the Telegram security alerts wired into the identity
// handler (src/handlers/identity.ts):
//   - a successful sign-in from an unrecognized client session reports once,
//     a known client never reports again;
//   - a failed sign-in never reports a new client session;
//   - the failed-login threshold reports the lockout transition once;
//   - a wrong second factor feeds the same lockout counter;
//   - refreshing a session never reports anything.
//
// The real alert service (src/services/security-alerts.ts) runs here: the test
// only replaces the outbound Telegram HTTP call.
import assert from 'node:assert/strict';
import test from 'node:test';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { handleToken } from '../src/handlers/identity';
import { StorageService } from '../src/services/storage';
import { createPasswordVerifier } from '../src/services/password-verifier';
import type { Env, User } from '../src/types';
import { MemoryD1, PRIMARY_KEY_BUILDERS } from './memory-d1';

// The alert service keeps its delivery cooldown in the strict-budget table.
PRIMARY_KEY_BUILDERS.rate_limit_buckets = (row) => String(row.bucket_key);

const PASKEY_CREDENTIAL_COLUMNS = [
  'id', 'user_id', 'purpose', 'name', 'public_key', 'credential_id', 'counter', 'type',
  'aa_guid', 'transports', 'encrypted_user_key', 'encrypted_public_key',
  'encrypted_private_key', 'supports_prf', 'created_at', 'updated_at',
];
const PASKEY_CHALLENGE_COLUMNS = ['challenge_hash', 'scope', 'user_id', 'expires_at', 'used_at', 'created_at'];

/**
 * The shared in-memory D1 shim does not model two things these flows use:
 * PRAGMA table_info(...) and the "attempts = attempts + 1" upsert of the login
 * attempt counter. This facade answers both and delegates the rest.
 */
class TestD1 {
  constructor(private readonly inner: MemoryD1) {}

  prepare(sql: string) {
    const normalized = sql.replace(/\s+/g, ' ').trim();
    if (/^pragma table_info/i.test(normalized)) return this.pragmaStatement(normalized);
    if (/^create /i.test(normalized)) return this.inner.prepare(sql);
    if (/login_attempts_ip/i.test(normalized)) return this.loginAttemptsStatement(normalized);
    if (/^update refresh_tokens/i.test(normalized) && /case/i.test(normalized)) {
      return this.refreshExpiryStatement();
    }
    return this.inner.prepare(sql);
  }

  /** Drops the alert cooldown buckets so the next report is not suppressed. */
  clearCooldowns(): void {
    this.inner.table('rate_limit_buckets').clear();
  }

  /** The sliding expiry update of a refresh token uses a CASE expression. */
  private refreshExpiryStatement() {
    const store = this.inner.table('refresh_tokens');
    let values: unknown[] = [];
    const statement = {
      bind: (...bound: unknown[]) => {
        values = bound;
        return statement;
      },
      first: async () => null,
      all: async () => ({ success: true, results: [] }),
      run: async () => {
        const tokenKey = String(values[3] ?? '');
        const nowMs = Number(values[4] ?? 0);
        const requested = Number(values[0] ?? 0);
        const row = store.get(tokenKey);
        if (!row) return { success: true, meta: { changes: 0 } };
        const absolute = row.absolute_expires_at == null ? null : Number(row.absolute_expires_at);
        if (Number(row.expires_at || 0) < nowMs || (absolute != null && absolute < nowMs)) {
          return { success: true, meta: { changes: 0 } };
        }
        store.set(tokenKey, {
          ...row,
          expires_at: absolute != null && absolute < requested ? absolute : requested,
          last_used_at: Number(values[2] ?? 0),
        });
        return { success: true, meta: { changes: 1 } };
      },
      raw: async () => [],
    };
    return statement;
  }

  private pragmaStatement(sql: string) {
    const table = /table_info\((\w+)\)/i.exec(sql)?.[1] || '';
    const columns = table === 'webauthn_challenges' ? PASKEY_CHALLENGE_COLUMNS : PASKEY_CREDENTIAL_COLUMNS;
    const statement = {
      bind: () => statement,
      first: async () => null,
      all: async () => ({ success: true, results: columns.map((name) => ({ name })) }),
      run: async () => ({ success: true, meta: { changes: 0 } }),
      raw: async () => [],
    };
    return statement;
  }

  private loginAttemptsStatement(sql: string) {
    const store = this.inner.table('login_attempts_ip');
    let values: unknown[] = [];
    const statement = {
      bind: (...bound: unknown[]) => {
        values = bound;
        return statement;
      },
      first: async () => {
        const row = store.get(String(values[0] ?? ''));
        if (!row) return null;
        const attempts = Number(row.attempts || 0);
        return /locked_until/i.test(sql)
          ? { attempts, locked_until: row.locked_until ?? null }
          : { attempts };
      },
      all: async () => ({ success: true, results: [] }),
      run: async () => {
        if (/^insert into/i.test(sql)) {
          const ip = String(values[0] ?? '');
          const existing = store.get(ip);
          store.set(ip, {
            ip,
            attempts: (existing ? Number(existing.attempts || 0) : 0) + 1,
            locked_until: existing?.locked_until ?? null,
            updated_at: Number(values[1] ?? 0),
          });
          return { success: true, meta: { changes: 1 } };
        }
        if (/^update /i.test(sql)) {
          const ip = String(values[2] ?? '');
          const row = store.get(ip);
          if (!row) return { success: true, meta: { changes: 0 } };
          store.set(ip, { ...row, locked_until: Number(values[0] ?? 0), updated_at: Number(values[1] ?? 0) });
          return { success: true, meta: { changes: 1 } };
        }
        if (/updated_at\s*</i.test(sql)) {
          const cutoff = Number(values[0] ?? 0);
          let changes = 0;
          for (const [ip, row] of store) {
            if (Number(row.updated_at || 0) < cutoff) {
              store.delete(ip);
              changes++;
            }
          }
          return { success: true, meta: { changes } };
        }
        const ip = String(values[0] ?? '');
        const changed = store.delete(ip);
        return { success: true, meta: { changes: changed ? 1 : 0 } };
      },
      raw: async () => [],
    };
    return statement;
  }
}

const JWT_SECRET = 'security-alerts-auth-test-secret-0123456789';
const VAULT_ORIGIN = 'https://vault.example.test';
const TELEGRAM_TOKEN = '123456789:fake-security-alerts-token';
const TELEGRAM_CHAT_ID = '123456';
const CLIENT_HASH = 'client-side-master-password-hash';
const LOGIN_MAX_ATTEMPTS = 10;

interface Delivery {
  url: string;
  text: string;
}

/** Replaces the outbound Telegram call and records what would be delivered. */
function installTelegramStub(): { deliveries: Delivery[]; restore: () => void } {
  const deliveries: Delivery[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input as RequestInfo, init);
    const body = JSON.parse(await request.text()) as { text?: string };
    deliveries.push({ url: request.url, text: String(body.text || '') });
    return Response.json({ ok: true });
  }) as typeof fetch;
  return { deliveries, restore: () => { globalThis.fetch = original; } };
}

function createEnv(db: TestD1): Env {
  return {
    DB: db as unknown as D1Database,
    JWT_SECRET,
    TELEGRAM_BOT_TOKEN: TELEGRAM_TOKEN,
    TELEGRAM_CHAT_ID: TELEGRAM_CHAT_ID,
  } as unknown as Env;
}

async function seedUser(db: TestD1, overrides: Partial<User> = {}): Promise<User> {
  const now = new Date().toISOString();
  const user: User = {
    id: overrides.id ?? '11111111-1111-4111-8111-111111111111',
    email: overrides.email ?? 'user@example.test',
    name: 'Security Alert User',
    masterPasswordHint: null,
    masterPasswordHash: await createPasswordVerifier(CLIENT_HASH),
    key: 'encrypted-user-key',
    privateKey: 'encrypted-private-key',
    publicKey: 'public-key',
    kdfType: 0,
    kdfIterations: 600000,
    kdfMemory: null,
    kdfParallelism: null,
    securityStamp: 'security-stamp-security-alerts',
    role: 'user',
    status: 'active',
    verifyDevices: false,
    totpSecret: null,
    totpRecoveryCode: null,
    yubikeyKey1: null,
    yubikeyKey2: null,
    yubikeyKey3: null,
    yubikeyKey4: null,
    yubikeyKey5: null,
    yubikeyNfc: false,
    apiKey: null,
    ssoSubject: null,
    userKeyId: null,
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
  await new StorageService(db as unknown as D1Database).saveUser(user);
  return user;
}

async function postToken(env: Env, params: Record<string, string>, ip: string): Promise<Response> {
  const body = new URLSearchParams({
    grant_type: 'password',
    client_id: 'cli',
    scope: 'api offline_access',
    ...params,
  });
  return handleToken(
    new Request(`${VAULT_ORIGIN}/identity/connect/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'CF-Connecting-IP': ip,
      },
      body: body.toString(),
    }),
    env
  );
}

function signInParams(user: User, deviceIdentifier: string): Record<string, string> {
  return {
    username: user.email,
    password: CLIENT_HASH,
    deviceIdentifier,
    deviceName: 'Test Device',
    deviceType: '0',
  };
}

test('an unrecognized client session reports once, a known client stays silent', async (t) => {
  const db = new TestD1(new MemoryD1());
  const env = createEnv(db);
  const user = await seedUser(db, { id: 'aaaaaaaa-1111-4111-8111-111111111111', email: 'new-client@example.test' });
  const telegram = installTelegramStub();
  t.after(() => telegram.restore());

  const first = await postToken(env, signInParams(user, 'device-alpha'), '203.0.113.10');
  assert.equal(first.status, 200);
  assert.equal(telegram.deliveries.length, 1, 'the first sign-in of a client must report');
  assert.match(telegram.deliveries[0].url, /api\.telegram\.org/);
  assert.match(telegram.deliveries[0].text, /unrecognized client session/);
  assert.match(telegram.deliveries[0].text, /Method: password/);
  // No credential, account address or device identifier may reach the channel.
  assert.ok(!telegram.deliveries[0].text.includes(user.email));
  assert.ok(!telegram.deliveries[0].text.includes(CLIENT_HASH));
  assert.ok(!telegram.deliveries[0].text.includes('device-alpha'));

  // The cooldown must not mask a broken "known client" check.
  db.clearCooldowns();
  const second = await postToken(env, signInParams(user, 'device-alpha'), '203.0.113.10');
  assert.equal(second.status, 200);
  assert.equal(telegram.deliveries.length, 1, 'a known client must not report again');

  // Refreshing the session is not a new sign-in and must stay silent.
  db.clearCooldowns();
  const body = await second.json() as { refresh_token?: string };
  const refreshed = await handleToken(
    new Request(`${VAULT_ORIGIN}/identity/connect/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'CF-Connecting-IP': '203.0.113.10',
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: 'cli',
        refresh_token: String(body.refresh_token || ''),
      }).toString(),
    }),
    env
  );
  assert.equal(refreshed.status, 200);
  assert.equal(telegram.deliveries.length, 1, 'a session refresh must not report');
});

test('a failed sign-in never reports a new client session', async (t) => {
  const db = new TestD1(new MemoryD1());
  const env = createEnv(db);
  const user = await seedUser(db, { id: 'bbbbbbbb-2222-4222-8222-222222222222', email: 'bad-password@example.test' });
  const telegram = installTelegramStub();
  t.after(() => telegram.restore());

  const response = await postToken(
    env,
    { ...signInParams(user, 'device-beta'), password: 'wrong-client-hash' },
    '203.0.113.20'
  );
  assert.equal(response.status, 400);
  assert.equal(telegram.deliveries.length, 0, 'an unverified client must not be reported');
});

test('the failed-login threshold reports the lockout once', async (t) => {
  const db = new TestD1(new MemoryD1());
  const env = createEnv(db);
  const user = await seedUser(db, { id: 'cccccccc-3333-4333-8333-333333333333', email: 'lockout@example.test' });
  const telegram = installTelegramStub();
  t.after(() => telegram.restore());

  for (let attempt = 1; attempt < LOGIN_MAX_ATTEMPTS; attempt++) {
    const response = await postToken(
      env,
      { ...signInParams(user, 'device-gamma'), password: 'wrong-client-hash' },
      '203.0.113.30'
    );
    assert.equal(response.status, 400, `attempt ${attempt} must stay a plain failure`);
  }
  assert.equal(telegram.deliveries.length, 0, 'no lockout happened yet');

  const locked = await postToken(
    env,
    { ...signInParams(user, 'device-gamma'), password: 'wrong-client-hash' },
    '203.0.113.30'
  );
  assert.equal(locked.status, 429);
  assert.equal(telegram.deliveries.length, 1, 'the lockout transition must be reported');
  assert.match(telegram.deliveries[0].text, /lockout/i);
  assert.match(telegram.deliveries[0].text, /Method: password/);
  assert.ok(!telegram.deliveries[0].text.includes(user.email));
});

test('a wrong second factor feeds the same lockout counter', async (t) => {
  const db = new TestD1(new MemoryD1());
  const env = createEnv(db);
  const user = await seedUser(db, {
    id: 'dddddddd-4444-4444-8444-444444444444',
    email: 'totp@example.test',
    totpSecret: 'JBSWY3DPEHPK3PXP',
  });
  const telegram = installTelegramStub();
  t.after(() => telegram.restore());

  // The challenge itself is not a failed login.
  const challenge = await postToken(env, signInParams(user, 'device-delta'), '203.0.113.40');
  assert.equal(challenge.status, 400);
  assert.equal(telegram.deliveries.length, 0);

  const wrongFactor = {
    ...signInParams(user, 'device-delta'),
    twoFactorProvider: '0',
    // Wrong length: it can never match the six digit code.
    twoFactorToken: '11111',
  };
  for (let attempt = 1; attempt < LOGIN_MAX_ATTEMPTS; attempt++) {
    const response = await postToken(env, wrongFactor, '203.0.113.40');
    assert.equal(response.status, 400, `attempt ${attempt} must stay a plain failure`);
  }
  assert.equal(telegram.deliveries.length, 0);

  const locked = await postToken(env, wrongFactor, '203.0.113.40');
  assert.equal(locked.status, 429);
  assert.equal(telegram.deliveries.length, 1, 'the second factor lockout must be reported');
  assert.match(telegram.deliveries[0].text, /lockout/i);
});