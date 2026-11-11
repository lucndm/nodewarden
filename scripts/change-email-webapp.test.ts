// The email change of NodeWarden's web vault.
//
// The password of the account stays the same, but the address is the salt of
// the master key, so the master key changes with the address. The user key
// does not change: it is wrapped again with the new master key, and the
// server keeps the password it is given.
//
// These checks run the real WebCrypto calls, because the key that goes to
// the server has to open with the master key of the new address.
import assert from 'node:assert/strict';
import test from 'node:test';
import { webcrypto } from 'node:crypto';

import { changeEmail, requestEmailChangeCode } from '../webapp/src/lib/api/auth';
import { decryptBw, encryptBw, hkdfExpand, pbkdf2 } from '../webapp/src/lib/crypto';

const globals = globalThis as unknown as { crypto?: unknown; fetch?: unknown };
if (!globals.crypto) globals.crypto = webcrypto;

const PASSWORD = 'correct horse battery staple';
const EMAIL = 'owner@example.test';
const NEW_EMAIL = 'new-address@example.test';
const ITERATIONS = 1000;
const CODE = '123456';

/** The body a request carried. */
interface Captured {
  url: string;
  body: {
    masterPasswordHash?: string;
    newEmail?: string;
    newMasterPasswordHash?: string;
    token?: string;
    key?: string;
  };
}

/** The prelogin answer of the server, and the requests that were made. */
const captured: Captured[] = [];

globals.fetch = async (input: string): Promise<Response> => {
  if (String(input).includes('/identity/accounts/prelogin')) {
    return new Response(JSON.stringify({ kdf: 0, kdfIterations: ITERATIONS }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  throw new Error(`unexpected request: ${String(input)}`);
};

const authedFetch = async (input: string, init: RequestInit = {}): Promise<Response> => {
  captured.push({
    url: String(input),
    body: JSON.parse(String(init.body || '{}')) as Captured['body'],
  });
  return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
};

/** The account: the user key, wrapped with the master key of the address. */
async function account() {
  const masterKey = await pbkdf2(PASSWORD, EMAIL, ITERATIONS, 32);
  const enc = await hkdfExpand(masterKey, 'enc', 32);
  const mac = await hkdfExpand(masterKey, 'mac', 32);
  const userSym = new Uint8Array(64);
  for (let index = 0; index < userSym.length; index += 1) userSym[index] = index;
  const profileKey = await encryptBw(userSym, enc, mac);
  return { masterKey, userSym, profileKey };
}

test('the new key opens with the master key of the new email', async () => {
  const { userSym, profileKey } = await account();
  captured.length = 0;

  await changeEmail(authedFetch, {
    email: EMAIL,
    password: PASSWORD,
    currentIterations: ITERATIONS,
    profileKey,
    newEmail: NEW_EMAIL,
    code: CODE,
  });

  const request = captured[captured.length - 1];
  assert.ok(request.body.key, 'the new key is in the body');

  const newMasterKey = await pbkdf2(PASSWORD, NEW_EMAIL, ITERATIONS, 32);
  const opened = await decryptBw(
    request.body.key,
    await hkdfExpand(newMasterKey, 'enc', 32),
    await hkdfExpand(newMasterKey, 'mac', 32)
  );
  assert.deepEqual([...opened], [...userSym], 'the same user key comes back');
});

test('the hashes differ for the old and new email', async () => {
  const { profileKey } = await account();
  captured.length = 0;

  await changeEmail(authedFetch, {
    email: EMAIL,
    password: PASSWORD,
    currentIterations: ITERATIONS,
    profileKey,
    newEmail: NEW_EMAIL,
    code: CODE,
  });

  const request = captured[captured.length - 1];
  const oldHash = await pbkdf2(
    await pbkdf2(PASSWORD, EMAIL, ITERATIONS, 32),
    PASSWORD,
    1,
    32
  );
  assert.notEqual(request.body.masterPasswordHash, request.body.newMasterPasswordHash);
  assert.notEqual(
    Buffer.from(oldHash).toString('base64'),
    request.body.newMasterPasswordHash,
    'the hash of the new address is not the hash of the old one'
  );
});

test('the request goes to /api/accounts/email with the code as token', async () => {
  const { profileKey } = await account();
  captured.length = 0;

  await changeEmail(authedFetch, {
    email: EMAIL,
    password: PASSWORD,
    currentIterations: ITERATIONS,
    profileKey,
    newEmail: NEW_EMAIL,
    code: CODE,
  });

  const request = captured[captured.length - 1];
  assert.equal(request.url, '/api/accounts/email');
  assert.equal(request.body.token, CODE);
  assert.equal(request.body.newEmail, NEW_EMAIL);
});

test('the code is asked for at /api/accounts/email-token', async () => {
  captured.length = 0;

  await requestEmailChangeCode(authedFetch, {
    email: EMAIL,
    password: PASSWORD,
    currentIterations: ITERATIONS,
    newEmail: NEW_EMAIL,
  });

  const request = captured[captured.length - 1];
  assert.equal(request.url, '/api/accounts/email-token');
  assert.equal(request.body.newEmail, NEW_EMAIL);
  assert.ok(request.body.masterPasswordHash, 'the password proves who is asking');
});
