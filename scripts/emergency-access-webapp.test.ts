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

const { vaultKeyBytes, wrapVaultKeyForGrantee } = await import(
  '../webapp/src/lib/emergency-access-key'
);

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
