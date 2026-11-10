// Wrapping the vault key for the person who was let in.
//
// The grantor hands over a key that only the grantee can open. It is the
// grantor's own vault key, encrypted with the public key of the grantee, so
// the server never holds a key it could open.
//
// The wrapped key travels as `4.<base64>`, the same shape the official
// clients send.

import { base64ToBytes, bytesToBase64, decryptBw, encryptBw, hkdfExpand, pbkdf2 } from '@/lib/crypto';

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

/**
 * Opens the grantor's vault key, wrapped for this account, with this
 * account's private key. The private key itself is stored encrypted with
 * this account's vault key, so the session keys open it first.
 *
 * Returns the 64 bytes of the grantor's vault key: encryption half, then
 * authentication half.
 */
export async function openGrantorVaultKey(
  keyEncrypted: string,
  encryptedPrivateKey: string,
  ownKey: VaultKeyHalves
): Promise<Uint8Array> {
  if (!keyEncrypted.startsWith('4.')) throw new Error('The grantor key is not wrapped for this account');
  const pkcs8 = await decryptBw(encryptedPrivateKey, base64ToBytes(ownKey.symEncKey), base64ToBytes(ownKey.symMacKey));
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    pkcs8 as unknown as BufferSource,
    { name: 'RSA-OAEP', hash: 'SHA-1' },
    false,
    ['decrypt']
  );
  const raw = new Uint8Array(
    await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, base64ToBytes(keyEncrypted.slice(2)) as unknown as BufferSource)
  );
  if (raw.length !== 64) throw new Error('The grantor key is not the expected length');
  return raw;
}

/**
 * The new master password of the grantor, as a takeover sets it: the hash
 * that logs in, and the grantor's own vault key wrapped with the new master
 * key. The vault key does not change, so no item is encrypted again.
 *
 * PBKDF2 only, the same as the web vault's own password change; the salt is
 * the grantor's address.
 */
export async function buildTakeoverPassword(
  grantorVaultKey: Uint8Array,
  newPassword: string,
  salt: string,
  iterations: number
): Promise<{ masterPasswordHash: string; key: string }> {
  const masterKey = await pbkdf2(newPassword, salt, iterations, 32);
  const hash = await pbkdf2(masterKey, newPassword, 1, 32);
  const enc = await hkdfExpand(masterKey, 'enc', 32);
  const mac = await hkdfExpand(masterKey, 'mac', 32);
  return {
    masterPasswordHash: bytesToBase64(hash),
    key: await encryptBw(grantorVaultKey, enc, mac),
  };
}
