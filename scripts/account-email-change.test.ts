// Changing the email of an account.
//
// A user changes the address of the account: a code goes to the new address,
// and the change waits for that code. The old address is told afterwards, so
// the person who owned it learns that the account moved.
//
// These checks run through the real router: the code only reaches the new
// address, a wrong code is counted, the change ends every session, and the
// address the account no longer has stops working.
import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { installTestGlobals } from './test-env';
installTestGlobals();

import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { handlePublicRoute } from '../src/router-public';
import { AuthService } from '../src/services/auth';
import { StorageService } from '../src/services/storage';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { putEmailChangeRequest } from '../src/services/storage-email-change-repo';
import type { MailBinding } from '../src/services/mail';
import { sqliteD1 } from './sqlite-d1';
import type { Env, User } from '../src/types';

const USER_ID = '00000000-0000-4000-8000-0000000000c1';
const GRANTOR_ID = '00000000-0000-4000-8000-0000000000c2';
const NOW = '2026-11-11T00:00:00.000Z';
const EMAIL = 'owner@example.test';
const NEW_EMAIL = 'new-address@example.test';
const CLIENT_HASH = 'client-master-password-hash';
const JWT_SECRET = 'a-test-secret-that-is-long-enough-for-hmac-0123456789';
const NEW_KEY = '2.key|ciphertext|mac';

/** The mails the server handed to the binding. */
type SentMail = Parameters<MailBinding['send']>[0];

/** What the routes answer. */
interface ApiBody {
  error?: string;
  error_description?: string;
  data?: unknown[];
  [key: string]: unknown;
}

async function fixture(options: { mail?: boolean; failingMail?: boolean } = {}): Promise<{
  env: Env;
  storage: StorageService;
  sent: SentMail[];
}> {
  const db = new DatabaseSync(':memory:');
  // The mail keeps its budget in the strict-budget table. The rate limiter
  // only creates that table once per process, so a fresh database here has to
  // have the table already.
  db.exec(
    'CREATE TABLE IF NOT EXISTS rate_limit_buckets(bucket_key TEXT PRIMARY KEY, count INTEGER NOT NULL, expires_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)'
  );
  await ensureStorageSchema(sqliteD1(db));
  const base = { DB: sqliteD1(db), JWT_SECRET } as unknown as Env;
  const storage = new StorageService(base.DB);
  await storage.createUser({
    id: USER_ID,
    email: EMAIL,
    name: null,
    masterPasswordHint: null,
    masterPasswordHash: await new AuthService(base).hashPasswordServer(CLIENT_HASH),
    key: NEW_KEY,
    privateKey: null,
    publicKey: null,
    kdfType: 0,
    kdfIterations: 600000,
    kdfMemory: null,
    kdfParallelism: null,
    securityStamp: 'stamp',
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
    userKeyId: null,
    createdAt: NOW,
    updatedAt: NOW,
  } as never);
  await storage.createUser({
    id: GRANTOR_ID,
    email: 'grantor@example.test',
    name: null,
    masterPasswordHint: null,
    masterPasswordHash: await new AuthService(base).hashPasswordServer(CLIENT_HASH),
    key: 'key',
    privateKey: null,
    publicKey: null,
    kdfType: 0,
    kdfIterations: 600000,
    kdfMemory: null,
    kdfParallelism: null,
    securityStamp: 'stamp',
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
    userKeyId: null,
    createdAt: NOW,
    updatedAt: NOW,
  } as never);

  const sent: SentMail[] = [];
  if (options.mail === false) return { env: base, storage, sent };
  const EMAIL_BINDING: MailBinding = {
    async send(message) {
      if (options.failingMail) throw new Error('the mail could not be sent');
      sent.push(message);
      return { messageId: 'fake-message-id' };
    },
  };
  const env = {
    ...base,
    EMAIL: EMAIL_BINDING,
    MAIL_FROM: 'no-reply@pass.minhluc.info',
    MAIL_VAULT_URL: 'https://pass.minhluc.info',
  } as unknown as Env;
  return { env, storage, sent };
}

async function call(
  env: Env,
  storage: StorageService,
  method: string,
  path: string,
  body?: unknown,
  userId: string = USER_ID
): Promise<{ status: number; body: ApiBody | null }> {
  const request = new Request(`https://vault.example.test${path}`, {
    method,
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const user = await storage.getUserById(userId);
  const response = await handleAuthenticatedRoute(request, env, userId, (user ?? { id: userId }) as User, path, method);
  assert.ok(response, `no route answered ${method} ${path}`);
  const text = await response.text();
  return { status: response.status, body: text ? (JSON.parse(text) as ApiBody) : null };
}

/** A login with the password of the account. */
async function login(env: Env, email: string, password: string): Promise<Response> {
  const request = new Request('https://vault.example.test/identity/connect/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'CF-Connecting-IP': '203.0.113.9' },
    body: new URLSearchParams({
      grant_type: 'password',
      username: email,
      password,
      scope: 'api offline_access',
      deviceIdentifier: 'device-one',
      deviceName: 'a device',
      deviceType: '14',
    }).toString(),
  });
  const response = await handlePublicRoute(request, env, '/identity/connect/token', 'POST', async () => null);
  assert.ok(response, 'the token route answered');
  return response;
}

/** The mail that carries the code of the email change. */
function codeMail(sent: SentMail[]): SentMail {
  const mail = sent.find((item) => item.subject === 'Your email change code');
  assert.ok(mail, 'the code mail was sent');
  return mail;
}

/** The code the server mailed to the new address. */
function codeFrom(mail: SentMail): string {
  const match = mail.text.match(/\b(\d{6})\b/);
  assert.ok(match, mail.text);
  return match[1];
}

test('without mail both routes answer 501', async () => {
  const { env, storage } = await fixture({ mail: false });
  const token = await call(env, storage, 'POST', '/api/accounts/email-token', {
    masterPasswordHash: CLIENT_HASH,
    newEmail: NEW_EMAIL,
  });
  assert.equal(token.status, 501);
  assert.equal(token.body?.error, 'Email delivery is not supported by this server.');

  const change = await call(env, storage, 'POST', '/api/accounts/email', {
    masterPasswordHash: CLIENT_HASH,
    newEmail: NEW_EMAIL,
    newMasterPasswordHash: CLIENT_HASH,
    token: '123456',
    key: NEW_KEY,
  });
  assert.equal(change.status, 501);
  assert.equal(change.body?.error, 'Email delivery is not supported by this server.');
});

test('asking for a code mails it to the new address', async () => {
  const { env, storage, sent } = await fixture();
  const asked = await call(env, storage, 'POST', '/api/accounts/email-token', {
    masterPasswordHash: CLIENT_HASH,
    newEmail: NEW_EMAIL,
  });
  assert.equal(asked.status, 200, JSON.stringify(asked.body));

  assert.equal(sent.length, 1, 'one mail is sent');
  assert.equal(sent[0].to, NEW_EMAIL);
  const code = codeFrom(codeMail(sent));
  assert.match(code, /^\d{6}$/, code);

  const request = await storage.getEmailChangeRequest(USER_ID);
  assert.ok(request, 'the request is stored');
  assert.equal(request.newEmail, NEW_EMAIL);
  assert.notEqual(request.codeHash, code, 'the code is not stored as it is');
  assert.ok(!request.codeHash.includes(code), request.codeHash);
});

test('a wrong password gets no code', async () => {
  const { env, storage, sent } = await fixture();
  const asked = await call(env, storage, 'POST', '/api/accounts/email-token', {
    masterPasswordHash: 'the-wrong-hash',
    newEmail: NEW_EMAIL,
  });
  assert.equal(asked.status, 400);
  assert.equal(asked.body?.error, 'Invalid password');
  assert.equal(sent.length, 0, 'nothing is mailed');
  assert.equal(await storage.getEmailChangeRequest(USER_ID), null);
});

test('an address in use gets no code', async () => {
  const { env, storage, sent } = await fixture();
  const asked = await call(env, storage, 'POST', '/api/accounts/email-token', {
    masterPasswordHash: CLIENT_HASH,
    newEmail: 'grantor@example.test',
  });
  assert.equal(asked.status, 400);
  assert.equal(asked.body?.error, 'Email already in use');
  assert.equal(sent.length, 0, 'nothing is mailed');
});

test('the current email gets no code', async () => {
  const { env, storage, sent } = await fixture();
  const asked = await call(env, storage, 'POST', '/api/accounts/email-token', {
    masterPasswordHash: CLIENT_HASH,
    newEmail: EMAIL,
  });
  assert.equal(asked.status, 400);
  assert.equal(asked.body?.error, 'The new email is the current email');
  assert.equal(sent.length, 0, 'nothing is mailed');
});

test('the right code changes the email', async () => {
  const { env, storage, sent } = await fixture();
  await call(env, storage, 'POST', '/api/accounts/email-token', {
    masterPasswordHash: CLIENT_HASH,
    newEmail: NEW_EMAIL,
  });
  const code = codeFrom(codeMail(sent));

  const stampBefore = (await storage.getUserById(USER_ID))?.securityStamp;
  const changed = await call(env, storage, 'POST', '/api/accounts/email', {
    masterPasswordHash: CLIENT_HASH,
    newEmail: NEW_EMAIL,
    newMasterPasswordHash: CLIENT_HASH,
    token: code,
    key: NEW_KEY,
  });
  assert.equal(changed.status, 200, JSON.stringify(changed.body));

  const user = await storage.getUserById(USER_ID);
  assert.ok(user);
  assert.equal(user.email, NEW_EMAIL);
  assert.notEqual(user.securityStamp, stampBefore, 'the security stamp changed');
  assert.equal(await storage.getEmailChangeRequest(USER_ID), null, 'the request is gone');

  // The sessions of the account are gone.
  const sessions = await env.DB.prepare('SELECT COUNT(*) AS count FROM refresh_tokens WHERE user_id = ?')
    .bind(USER_ID)
    .first<{ count: number }>();
  assert.equal(Number(sessions?.count || 0), 0, 'the sessions are gone');

  // The old address is told, and it names the new one.
  const notice = sent.find((mail) => mail.to === EMAIL);
  assert.ok(notice, 'the old address is told');
  assert.ok(notice.text.includes(NEW_EMAIL), notice.text);

  // The new address works with the same password, the old one does not.
  const signedIn = await login(env, NEW_EMAIL, CLIENT_HASH);
  assert.equal(signedIn.status, 200, await signedIn.clone().text());
  const refused = await login(env, EMAIL, CLIENT_HASH);
  assert.notEqual(refused.status, 200, 'the old address does not sign in');
});

test('a wrong code counts, and the fifth ends the request', async () => {
  const { env, storage, sent } = await fixture();
  await call(env, storage, 'POST', '/api/accounts/email-token', {
    masterPasswordHash: CLIENT_HASH,
    newEmail: NEW_EMAIL,
  });
  const code = codeFrom(codeMail(sent));
  const wrong = code === '000000' ? '111111' : '000000';

  for (let attempt = 1; attempt <= 4; attempt += 1) {
    const refused = await call(env, storage, 'POST', '/api/accounts/email', {
      masterPasswordHash: CLIENT_HASH,
      newEmail: NEW_EMAIL,
      newMasterPasswordHash: CLIENT_HASH,
      token: wrong,
      key: NEW_KEY,
    });
    assert.equal(refused.status, 400, `attempt ${attempt}`);
    assert.equal(refused.body?.error, 'Token mismatch', `attempt ${attempt}`);
  }

  const last = await call(env, storage, 'POST', '/api/accounts/email', {
    masterPasswordHash: CLIENT_HASH,
    newEmail: NEW_EMAIL,
    newMasterPasswordHash: CLIENT_HASH,
    token: wrong,
    key: NEW_KEY,
  });
  assert.equal(last.status, 400);
  assert.equal(last.body?.error, 'Too many wrong codes; ask for a new one');
  assert.equal(await storage.getEmailChangeRequest(USER_ID), null, 'the request is gone');

  const tooLate = await call(env, storage, 'POST', '/api/accounts/email', {
    masterPasswordHash: CLIENT_HASH,
    newEmail: NEW_EMAIL,
    newMasterPasswordHash: CLIENT_HASH,
    token: code,
    key: NEW_KEY,
  });
  assert.equal(tooLate.status, 400);
  assert.equal(tooLate.body?.error, 'No email change pending');
});

test('an expired code is refused', async () => {
  const { env, storage, sent } = await fixture();
  await call(env, storage, 'POST', '/api/accounts/email-token', {
    masterPasswordHash: CLIENT_HASH,
    newEmail: NEW_EMAIL,
  });
  const code = codeFrom(codeMail(sent));
  const pending = await storage.getEmailChangeRequest(USER_ID);
  assert.ok(pending);

  await putEmailChangeRequest(env.DB, {
    userId: USER_ID,
    newEmail: NEW_EMAIL,
    codeHash: pending.codeHash,
    expiresAt: Date.now() - 1000,
  });

  const refused = await call(env, storage, 'POST', '/api/accounts/email', {
    masterPasswordHash: CLIENT_HASH,
    newEmail: NEW_EMAIL,
    newMasterPasswordHash: CLIENT_HASH,
    token: code,
    key: NEW_KEY,
  });
  assert.equal(refused.status, 400);
  assert.equal(refused.body?.error, 'The code has expired; ask for a new one');
  assert.equal(await storage.getEmailChangeRequest(USER_ID), null, 'the request is gone');
});

test('a code that was not delivered is not kept', async () => {
  const { env, storage } = await fixture({ failingMail: true });
  const asked = await call(env, storage, 'POST', '/api/accounts/email-token', {
    masterPasswordHash: CLIENT_HASH,
    newEmail: NEW_EMAIL,
  });
  assert.equal(asked.status, 429);
  assert.equal(asked.body?.error, 'The code could not be sent; try again later');
  assert.equal(await storage.getEmailChangeRequest(USER_ID), null, 'the request is gone');
});

test('an address that belongs to somebody else is refused at the change', async () => {
  const { env, storage, sent } = await fixture();
  await call(env, storage, 'POST', '/api/accounts/email-token', {
    masterPasswordHash: CLIENT_HASH,
    newEmail: NEW_EMAIL,
  });
  const code = codeFrom(codeMail(sent));

  // The address is taken between the code and the change.
  const grantor = await storage.getUserById(GRANTOR_ID);
  assert.ok(grantor);
  await storage.saveUser({ ...grantor, email: NEW_EMAIL });

  const refused = await call(env, storage, 'POST', '/api/accounts/email', {
    masterPasswordHash: CLIENT_HASH,
    newEmail: NEW_EMAIL,
    newMasterPasswordHash: CLIENT_HASH,
    token: code,
    key: NEW_KEY,
  });
  assert.equal(refused.status, 400);
  assert.equal(refused.body?.error, 'Email already in use');
  assert.equal((await storage.getUserById(USER_ID))?.email, EMAIL, 'the email did not change');
});

test('an email that does not match the request is refused', async () => {
  const { env, storage, sent } = await fixture();
  await call(env, storage, 'POST', '/api/accounts/email-token', {
    masterPasswordHash: CLIENT_HASH,
    newEmail: NEW_EMAIL,
  });
  const code = codeFrom(codeMail(sent));

  const refused = await call(env, storage, 'POST', '/api/accounts/email', {
    masterPasswordHash: CLIENT_HASH,
    newEmail: 'another@example.test',
    newMasterPasswordHash: CLIENT_HASH,
    token: code,
    key: NEW_KEY,
  });
  assert.equal(refused.status, 400);
  assert.equal(refused.body?.error, 'Email change mismatch');
});

test('a key that is not an encrypted string is refused', async () => {
  const { env, storage, sent } = await fixture();
  await call(env, storage, 'POST', '/api/accounts/email-token', {
    masterPasswordHash: CLIENT_HASH,
    newEmail: NEW_EMAIL,
  });
  const code = codeFrom(codeMail(sent));

  const refused = await call(env, storage, 'POST', '/api/accounts/email', {
    masterPasswordHash: CLIENT_HASH,
    newEmail: NEW_EMAIL,
    newMasterPasswordHash: CLIENT_HASH,
    token: code,
    key: 'not-an-encrypted-string',
  });
  assert.equal(refused.status, 400);
  assert.equal(refused.body?.error, 'key is not a valid encrypted string');
  assert.equal((await storage.getUserById(USER_ID))?.email, EMAIL, 'the email did not change');
});

test('a pending change of another account is not reachable', async () => {
  const { env, storage, sent } = await fixture();
  await call(env, storage, 'POST', '/api/accounts/email-token', {
    masterPasswordHash: CLIENT_HASH,
    newEmail: NEW_EMAIL,
  });
  const code = codeFrom(codeMail(sent));

  // The other account asks for a change of its own: the request of the first
  // account is not its request, so the code of the first account is no good.
  const other = await call(
    env,
    storage,
    'POST',
    '/api/accounts/email',
    {
      masterPasswordHash: CLIENT_HASH,
      newEmail: NEW_EMAIL,
      newMasterPasswordHash: CLIENT_HASH,
      token: code,
      key: NEW_KEY,
    },
    GRANTOR_ID
  );
  assert.equal(other.status, 400);
  assert.equal(other.body?.error, 'No email change pending');
  assert.equal((await storage.getUserById(USER_ID))?.email, EMAIL, 'the email did not change');
});

test('an invitation to the new address shows up after the change', async () => {
  const { env, storage, sent } = await fixture();
  const invited = await call(env, storage, 'POST', '/api/emergency-access/invite', {
    email: NEW_EMAIL,
    type: 0,
    waitTimeDays: 7,
  });
  assert.equal(invited.status, 200, JSON.stringify(invited.body));

  const before = await call(env, storage, 'GET', '/api/emergency-access/granted');
  assert.equal(before.body?.data?.length, 0, 'the invitation is not there yet');

  await call(env, storage, 'POST', '/api/accounts/email-token', {
    masterPasswordHash: CLIENT_HASH,
    newEmail: NEW_EMAIL,
  });
  const code = codeFrom(codeMail(sent));

  const changed = await call(env, storage, 'POST', '/api/accounts/email', {
    masterPasswordHash: CLIENT_HASH,
    newEmail: NEW_EMAIL,
    newMasterPasswordHash: CLIENT_HASH,
    token: code,
    key: NEW_KEY,
  });
  assert.equal(changed.status, 200, JSON.stringify(changed.body));

  const after = await call(env, storage, 'GET', '/api/emergency-access/granted');
  assert.equal(after.body?.data?.length, 1, 'the invitation is there now');
});
