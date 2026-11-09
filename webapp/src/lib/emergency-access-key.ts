// Wrapping the vault key for the person who was let in.
//
// The grantor hands over a key that only the grantee can open. It is the
// grantor's own vault key, encrypted with the public key of the grantee, so
// the server never holds a key it could open.
//
// The wrapped key travels as `4.<base64>`, the same shape the official
// clients send.

import { base64ToBytes, bytesToBase64 } from '@/lib/crypto';

/** The two halves of the vault key, as the session keeps them. */
export interface VaultKeyHalves {
  symEncKey: string;
  symMacKey: string;
}

/**
 * The vault key as one piece of bytes: the encryption half first, then the
 * authentication half.
 */
export function vaultKeyBytes(key: VaultKeyHalves): Uint8Array {
  const enc = base64ToBytes(key.symEncKey);
  const mac = base64ToBytes(key.symMacKey);
  if (enc.length !== 32 || mac.length !== 32) {
    throw new Error('The vault key is not the expected length');
  }
  const bytes = new Uint8Array(64);
  bytes.set(enc, 0);
  bytes.set(mac, 32);
  return bytes;
}

/**
 * Encrypts the vault key with the public key of the grantee.
 *
 * The public key is the base64 of an SPKI key, the way the server stores it.
 */
export async function wrapVaultKeyForGrantee(
  key: VaultKeyHalves,
  publicKeyBase64: string
): Promise<string> {
  const spki = base64ToBytes(publicKeyBase64);
  const publicKey = await crypto.subtle.importKey(
    'spki',
    spki as unknown as BufferSource,
    { name: 'RSA-OAEP', hash: 'SHA-1' },
    false,
    ['encrypt']
  );
  const encrypted = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    publicKey,
    vaultKeyBytes(key) as unknown as BufferSource
  );
  return `4.${bytesToBase64(new Uint8Array(encrypted))}`;
}
