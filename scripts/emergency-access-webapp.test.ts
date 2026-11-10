// Wrapping the vault key for the person who was let in.
//
// The grantor hands over a key that only the grantee can open: their own
// vault key, encrypted with the public key of the grantee. The server never
// holds a key it could open, and the wrapped key travels as `4.<base64>`,
// the same shape the official clients send.
//
// These checks run the real WebCrypto calls, because the format has to match
// what the grantee's own client will decrypt.
import assert from 'node:assert/strict';
import test from 'node:test';
import { webcrypto } from 'node:crypto';

const globals = globalThis as unknown as { crypto?: unknown };
if (!globals.crypto) globals.crypto = webcrypto;

const { buildTakeoverPassword, openGrantorVaultKey, vaultKeyBytes, wrapVaultKeyForGrantee } = await import(
  '../webapp/src/lib/emergency-access-key'
);
const { decryptBw, encryptBw, hkdfExpand, pbkdf2 } = await import('../webapp/src/lib/crypto');

const HALVES = {
  symEncKey: Buffer.from('a'.repeat(32), 'utf8').toString('base64'),
  symMacKey: Buffer.from('b'.repeat(32), 'utf8').toString('base64'),
};

async function makeKeyPair() {
  const pair = await crypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' },
    true,
    ['encrypt', 'decrypt']
  );
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
  return { pair, spkiBase64: Buffer.from(spki).toString('base64') };
}

test('the vault key is the two halves in one piece', () => {
  const bytes = vaultKeyBytes(HALVES);
  assert.equal(bytes.length, 64);
  assert.equal(bytes[0], 'a'.charCodeAt(0));
  assert.equal(bytes[32], 'b'.charCodeAt(0));
});

test('a key that is not the right length is refused', () => {
  assert.throws(() => vaultKeyBytes({ symEncKey: 'AAAA', symMacKey: HALVES.symMacKey }));
});

test('the wrapped key is one the grantee can open', async () => {
  const { pair, spkiBase64 } = await makeKeyPair();
  const wrapped = await wrapVaultKeyForGrantee(HALVES, spkiBase64);

  assert.ok(wrapped.startsWith('4.'), 'the shape the clients read');
  const ciphertext = Buffer.from(wrapped.slice(2), 'base64');
  const opened = await crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    pair.privateKey,
    new Uint8Array(ciphertext)
  );
  const bytes = new Uint8Array(opened);
  assert.equal(bytes.length, 64, 'the whole vault key comes back');
  assert.equal(Buffer.from(bytes.subarray(0, 32)).toString('utf8'), 'a'.repeat(32));
  assert.equal(Buffer.from(bytes.subarray(32)).toString('utf8'), 'b'.repeat(32));
});

test('a public key that is not a key is refused', async () => {
  await assert.rejects(() => wrapVaultKeyForGrantee(HALVES, 'not-a-key'));
});

// The grantee's own vault key, and their private key stored encrypted with
// it, the way the profile carries it.
const GRANTEE_HALVES = {
  symEncKey: Buffer.from('c'.repeat(32), 'utf8').toString('base64'),
  symMacKey: Buffer.from('d'.repeat(32), 'utf8').toString('base64'),
};

async function granteeAccount() {
  const { pair, spkiBase64 } = await makeKeyPair();
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  const encryptedPrivateKey = await encryptBw(
    pkcs8,
    Buffer.from(GRANTEE_HALVES.symEncKey, 'base64'),
    Buffer.from(GRANTEE_HALVES.symMacKey, 'base64')
  );
  return { spkiBase64, encryptedPrivateKey };
}

test('the grantee opens the handed key with their own private key', async () => {
  const grantee = await granteeAccount();
  const wrapped = await wrapVaultKeyForGrantee(HALVES, grantee.spkiBase64);
  const opened = await openGrantorVaultKey(wrapped, grantee.encryptedPrivateKey, GRANTEE_HALVES);
  assert.deepEqual(Buffer.from(opened), Buffer.from(vaultKeyBytes(HALVES)));
});

test('a key not wrapped for this account does not open', async () => {
  const grantee = await granteeAccount();
  const other = await granteeAccount();
  const wrappedForOther = await wrapVaultKeyForGrantee(HALVES, other.spkiBase64);
  await assert.rejects(() => openGrantorVaultKey(wrappedForOther, grantee.encryptedPrivateKey, GRANTEE_HALVES));
  await assert.rejects(() => openGrantorVaultKey('2.not-rsa', grantee.encryptedPrivateKey, GRANTEE_HALVES));
});

test('after a takeover the new password opens the same vault key', async () => {
  const grantee = await granteeAccount();
  const wrapped = await wrapVaultKeyForGrantee(HALVES, grantee.spkiBase64);
  const grantorKey = await openGrantorVaultKey(wrapped, grantee.encryptedPrivateKey, GRANTEE_HALVES);
  const salt = 'grantor@example.test';
  const password = 'a new master password';
  const next = await buildTakeoverPassword(grantorKey, password, salt, 1000);

  // What the grantor's client does at the next login with the new password.
  const masterKey = await pbkdf2(password, salt, 1000, 32);
  assert.equal(next.masterPasswordHash, Buffer.from(await pbkdf2(masterKey, password, 1, 32)).toString('base64'));
  const unlocked = await decryptBw(next.key, await hkdfExpand(masterKey, 'enc', 32), await hkdfExpand(masterKey, 'mac', 32));
  assert.deepEqual(Buffer.from(unlocked), Buffer.from(vaultKeyBytes(HALVES)), 'the vault key did not change');
});
