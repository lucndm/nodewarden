// Sealing a backup archive with a passphrase.
//
// The archive carries what the server cannot read: the users' master password
// hashes, their wrapped keys and the organization keys. Left in plaintext on a
// remote, whoever holds the remote holds the key material of the vault.
//
// The passphrase never leaves the administrator. It becomes a key with
// PBKDF2, and the archive is sealed with AES-GCM. A wrong passphrase fails to
// open the archive, and the archive says so instead of importing rubbish.
//
// An archive without the header is an archive from before the passphrase
// existed. It is still importable, so a restore never depends on the feature.
//
// The container is:
//
//   "NWBA1"        five bytes, the marker
//   salt           sixteen bytes, one per archive
//   iv             twelve bytes, one per archive
//   ciphertext     the rest, with the AES-GCM tag appended
const MAGIC = 'NWBA1';
const MAGIC_BYTES = MAGIC.length;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const KEY_BYTES = 32;
// The current guidance for turning a passphrase into a key with PBKDF2. The
// work is native, so it does not eat into the worker's CPU budget.
const PBKDF2_ITERATIONS = 210000;

function toBufferSource(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

async function deriveArchiveKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: toBufferSource(salt), iterations: PBKDF2_ITERATIONS },
    keyMaterial,
    KEY_BYTES * 8
  );
  return crypto.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/** Whether these bytes are a sealed archive rather than a plain zip. */
export function isEncryptedBackupArchive(bytes: Uint8Array): boolean {
  if (bytes.length < MAGIC_BYTES + SALT_BYTES + IV_BYTES) return false;
  for (let index = 0; index < MAGIC_BYTES; index += 1) {
    if (bytes[index] !== MAGIC.charCodeAt(index)) return false;
  }
  return true;
}

/**
 * Seals the archive with the passphrase.
 *
 * The salt and the nonce are fresh for every archive, so two archives of the
 * same vault never share a key stream.
 */
export async function encryptBackupArchive(bytes: Uint8Array, passphrase: string): Promise<Uint8Array> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const key = await deriveArchiveKey(passphrase, salt);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: toBufferSource(iv) }, key, toBufferSource(bytes))
  );
  const out = new Uint8Array(MAGIC_BYTES + SALT_BYTES + IV_BYTES + ciphertext.length);
  for (let index = 0; index < MAGIC_BYTES; index += 1) out[index] = MAGIC.charCodeAt(index);
  out.set(salt, MAGIC_BYTES);
  out.set(iv, MAGIC_BYTES + SALT_BYTES);
  out.set(ciphertext, MAGIC_BYTES + SALT_BYTES + IV_BYTES);
  return out;
}

/**
 * Opens a sealed archive.
 *
 * A wrong passphrase fails the AES-GCM tag, which is what tells a wrong
 * passphrase apart from a damaged file.
 */
export async function decryptBackupArchive(bytes: Uint8Array, passphrase: string): Promise<Uint8Array> {
  if (!isEncryptedBackupArchive(bytes)) {
    throw new Error('This file is not a sealed backup archive');
  }
  const salt = bytes.slice(MAGIC_BYTES, MAGIC_BYTES + SALT_BYTES);
  const iv = bytes.slice(MAGIC_BYTES + SALT_BYTES, MAGIC_BYTES + SALT_BYTES + IV_BYTES);
  const ciphertext = bytes.slice(MAGIC_BYTES + SALT_BYTES + IV_BYTES);
  const key = await deriveArchiveKey(passphrase, salt);
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt({ name: 'AES-GCM', iv: toBufferSource(iv) }, key, toBufferSource(ciphertext))
    );
  } catch {
    throw new Error('The archive could not be opened with that passphrase');
  }
}
