import { base64ToBytes, decryptBw, decryptStr } from './crypto';
import { openOrganizationKey } from './organization-key-rotation';
import { deriveSendKeyParts, looksLikeCipherString } from './app-support';
import type { Cipher, Folder, Send } from './types';

export interface DecryptVaultCoreArgs {
  folders: Folder[];
  ciphers: Cipher[];
  symEncKeyB64: string;
  symMacKeyB64: string;
  /**
   * The organizations the member belongs to, with their key as the server
   * stores it for this member. Without them a shared item shows as an empty
   * name: its item key is protected by the organization key, not by the
   * member's own key.
   */
  organizations?: Array<{ id: string; key: string | null }>;
  /** The member's RSA private key, encrypted under their vault key. */
  encryptedPrivateKey?: string | null;
}

export interface DecryptVaultCoreResult {
  folders: Folder[];
  ciphers: Cipher[];
}

export interface DecryptSendsArgs {
  sends: Send[];
  symEncKeyB64: string;
  symMacKeyB64: string;
  origin: string;
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

async function decryptField(
  value: string | null | undefined,
  enc: Uint8Array,
  mac: Uint8Array
): Promise<string> {
  if (!value || typeof value !== 'string') return '';
  try {
    return await decryptStr(value, enc, mac);
  } catch {
    return looksLikeCipherString(value) ? '' : value;
  }
}

async function decryptCipherField(
  value: string | null | undefined,
  itemEnc: Uint8Array,
  itemMac: Uint8Array,
  userEnc: Uint8Array,
  userMac: Uint8Array,
  canFallbackToUserKey: boolean
): Promise<string> {
  if (!value || typeof value !== 'string') return '';
  try {
    return await decryptStr(value, itemEnc, itemMac);
  } catch {
    // Try the legacy user-key path for mixed key/field ciphers.
  }
  if (canFallbackToUserKey) {
    try {
      return await decryptStr(value, userEnc, userMac);
    } catch {
      // Preserve the old raw fallback for fields that are genuinely unreadable.
    }
  }
  return looksLikeCipherString(value) ? '' : value;
}

async function decryptCipherObjectFields<T extends Record<string, unknown>>(
  source: T | null | undefined,
  fields: readonly string[],
  itemEnc: Uint8Array,
  itemMac: Uint8Array,
  userEnc: Uint8Array,
  userMac: Uint8Array,
  canFallbackToUserKey: boolean
): Promise<T | null | undefined> {
  if (!source || typeof source !== 'object') return source;
  const next: Record<string, unknown> = { ...source };
  for (const field of fields) {
    const decKey = `dec${field.charAt(0).toUpperCase()}${field.slice(1)}`;
    next[decKey] = await decryptCipherField(
      source[field] as string | null | undefined,
      itemEnc,
      itemMac,
      userEnc,
      userMac,
      canFallbackToUserKey
    );
  }
  return next as T;
}

async function decryptFieldWithSource(
  value: string | null | undefined,
  itemEnc: Uint8Array,
  itemMac: Uint8Array,
  userEnc: Uint8Array,
  userMac: Uint8Array,
  canFallbackToUserKey: boolean
): Promise<{ text: string; source: 'item' | 'user' | 'plain' }> {
  const raw = String(value || '').trim();
  if (!raw) return { text: '', source: 'plain' };
  try {
    return { text: await decryptStr(raw, itemEnc, itemMac), source: 'item' };
  } catch {
    // Try legacy user-key fallback below.
  }
  if (canFallbackToUserKey) {
    try {
      return { text: await decryptStr(raw, userEnc, userMac), source: 'user' };
    } catch {
      // Keep plain fallback.
    }
  }
  return { text: looksLikeCipherString(raw) ? '' : raw, source: 'plain' };
}

/**
 * Opens the organization keys the member holds.
 *
 * The organization key is wrapped for the member with their RSA key, so
 * opening it takes the member's own key material: the server cannot help.
 * An organization whose key does not open here simply has none for this
 * member.
 */
export async function openOrganizationKeys(args: {
  organizations: Array<{ id: string; key: string | null }>;
  symEncKeyB64: string;
  symMacKeyB64: string;
  encryptedPrivateKey: string | null;
}): Promise<Map<string, { encKey: Uint8Array; macKey: Uint8Array }>> {
  const organizationKeys = new Map<string, { encKey: Uint8Array; macKey: Uint8Array }>();
  if (!args.encryptedPrivateKey) return organizationKeys;
  const userEnc = base64ToBytes(args.symEncKeyB64);
  const userMac = base64ToBytes(args.symMacKeyB64);
  for (const organization of args.organizations) {
    const wrapped = String(organization.key || '');
    if (!wrapped.startsWith('4.')) continue;
    try {
      const raw = await openOrganizationKey({
        encryptedPrivateKey: args.encryptedPrivateKey,
        userEncKey: userEnc,
        userMacKey: userMac,
        wrappedOrganizationKey: wrapped,
      });
      organizationKeys.set(organization.id, { encKey: raw.slice(0, 32), macKey: raw.slice(32, 64) });
    } catch {
      // A key wrapped for someone else simply does not open here.
    }
  }
  return organizationKeys;
}

/**
 * Reads the names of the collections.
 *
 * A collection name is encrypted with the organization key, exactly like a
 * shared item, so a collection created by an official client arrives as a
 * cipher string. A name that is not encrypted is shown as it is: an older
 * collection, or one this server let through in plain text.
 */
export async function decryptCollectionNames<T extends { organizationId: string; name: string }>(args: {
  collections: T[];
  organizations: Array<{ id: string; key: string | null }>;
  symEncKeyB64: string;
  symMacKeyB64: string;
  encryptedPrivateKey: string | null;
  /** The organization keys, when the caller has already opened them. */
  organizationKeys?: Map<string, { encKey: Uint8Array; macKey: Uint8Array }>;
}): Promise<T[]> {
  if (!args.collections.length) return [];

  const organizationKeys =
    args.organizationKeys ??
    (await openOrganizationKeys({
      organizations: args.organizations,
      symEncKeyB64: args.symEncKeyB64,
      symMacKeyB64: args.symMacKeyB64,
      encryptedPrivateKey: args.encryptedPrivateKey,
    }));

  return Promise.all(
    args.collections.map(async (collection) => {
      const raw = String(collection.name || '');
      if (!looksLikeCipherString(raw)) return collection;
      const key = organizationKeys.get(collection.organizationId);
      if (!key) return { ...collection, name: '' };
      try {
        return { ...collection, name: await decryptStr(raw, key.encKey, key.macKey) };
      } catch {
        return collection;
      }
    })
  );
}

export async function decryptVaultCore(args: DecryptVaultCoreArgs): Promise<DecryptVaultCoreResult> {
  const userEnc = base64ToBytes(args.symEncKeyB64);
  const userMac = base64ToBytes(args.symMacKeyB64);

  // A shared item's key is wrapped with the organization key, which is itself
  // wrapped for this member with their RSA key. Opening it once is enough for
  // every item of that organization.
  const organizationKeys = new Map<string, { encKey: Uint8Array; macKey: Uint8Array }>();
  if (args.organizations?.length && args.encryptedPrivateKey) {
    let privateKey: CryptoKey | null = null;
    try {
      const pkcs8 = await decryptBw(args.encryptedPrivateKey, userEnc, userMac);
      privateKey = await crypto.subtle.importKey(
        'pkcs8',
        pkcs8.buffer.slice(pkcs8.byteOffset, pkcs8.byteOffset + pkcs8.byteLength) as ArrayBuffer,
        { name: 'RSA-OAEP', hash: 'SHA-1' },
        false,
        ['decrypt']
      );
    } catch {
      privateKey = null;
    }
    if (privateKey) {
      for (const organization of args.organizations) {
        const wrapped = String(organization.key || '');
        if (!wrapped.startsWith('4.')) continue;
        try {
          const blob = base64ToBytes(wrapped.slice(2));
          const raw = new Uint8Array(
            await crypto.subtle.decrypt(
              { name: 'RSA-OAEP' },
              privateKey,
              blob.buffer.slice(blob.byteOffset, blob.byteOffset + blob.byteLength) as ArrayBuffer
            )
          );
          if (raw.length === 64) {
            organizationKeys.set(organization.id, { encKey: raw.slice(0, 32), macKey: raw.slice(32, 64) });
          }
        } catch {
          // A key wrapped for someone else simply does not open here.
        }
      }
    }
  }

  const folders = await Promise.all(
    args.folders.map(async (folder) => ({
      ...folder,
      decName: await decryptField(folder.name, userEnc, userMac),
    }))
  );

  const foldersById = new Map(folders.map((folder) => [folder.id, folder]));
  const ciphers = await Promise.all(
    args.ciphers.map(async (cipher) => {
      let itemEnc = userEnc;
      let itemMac = userMac;
      let usesItemKey = false;
      if (cipher.key) {
        try {
          // A shared item unwraps its key with the organization key; a personal
          // one with the member's own key.
          const organizationId = (cipher as { organizationId?: string | null }).organizationId;
          const keyOwner = (organizationId && organizationKeys.get(organizationId)) || { encKey: userEnc, macKey: userMac };
          const itemKey = await decryptBw(cipher.key, keyOwner.encKey, keyOwner.macKey);
          if (itemKey.length >= 64) {
            itemEnc = itemKey.slice(0, 32);
            itemMac = itemKey.slice(32, 64);
            usesItemKey = true;
          }
        } catch {
          // Keep user key fallback.
        }
      }

      const itemUsesUserKey = sameBytes(itemEnc, userEnc) && sameBytes(itemMac, userMac);
      const canFallbackToUserKey = usesItemKey;
      const nextCipher: Cipher = {
        ...cipher,
        decName: await decryptCipherField(cipher.name || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
        decNotes: await decryptCipherField(cipher.notes || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      };
      const folder = cipher.folderId ? foldersById.get(cipher.folderId) : undefined;
      const folderName = folder?.decName;
      if (folderName && nextCipher.tags?.[0] !== folderName) {
        const tags = nextCipher.tags || [];
        const secondary = folder.tagName && tags[0]?.toLowerCase() === folder.tagName.toLowerCase() ? tags.slice(1) : tags;
        nextCipher.tags = [folderName, ...secondary.filter((tag) => tag.toLowerCase() !== folderName.toLowerCase())];
      }

      if (cipher.login) {
        nextCipher.login = {
          ...cipher.login,
          decUsername: await decryptCipherField(cipher.login.username || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          decPassword: await decryptCipherField(cipher.login.password || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          decTotp: await decryptCipherField(cipher.login.totp || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          uris: await Promise.all(
            (cipher.login.uris || []).map(async (uri) => ({
              ...uri,
              decUri: await decryptCipherField(uri.uri || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
            }))
          ),
        };
      }

      if (Array.isArray(cipher.passwordHistory)) {
        nextCipher.passwordHistory = await Promise.all(
          cipher.passwordHistory.map(async (entry) => ({
            ...entry,
            decPassword: await decryptCipherField(entry?.password || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          }))
        );
      }

      if (cipher.card) {
        nextCipher.card = {
          ...cipher.card,
          decCardholderName: await decryptCipherField(cipher.card.cardholderName || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          decNumber: await decryptCipherField(cipher.card.number || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          decBrand: await decryptCipherField(cipher.card.brand || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          decExpMonth: await decryptCipherField(cipher.card.expMonth || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          decExpYear: await decryptCipherField(cipher.card.expYear || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          decCode: await decryptCipherField(cipher.card.code || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
        };
      }

      if (cipher.identity) {
        nextCipher.identity = {
          ...cipher.identity,
          decTitle: await decryptCipherField(cipher.identity.title || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          decFirstName: await decryptCipherField(cipher.identity.firstName || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          decMiddleName: await decryptCipherField(cipher.identity.middleName || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          decLastName: await decryptCipherField(cipher.identity.lastName || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          decUsername: await decryptCipherField(cipher.identity.username || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          decCompany: await decryptCipherField(cipher.identity.company || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          decSsn: await decryptCipherField(cipher.identity.ssn || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          decPassportNumber: await decryptCipherField(cipher.identity.passportNumber || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          decLicenseNumber: await decryptCipherField(cipher.identity.licenseNumber || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          decEmail: await decryptCipherField(cipher.identity.email || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          decPhone: await decryptCipherField(cipher.identity.phone || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          decAddress1: await decryptCipherField(cipher.identity.address1 || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          decAddress2: await decryptCipherField(cipher.identity.address2 || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          decAddress3: await decryptCipherField(cipher.identity.address3 || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          decCity: await decryptCipherField(cipher.identity.city || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          decState: await decryptCipherField(cipher.identity.state || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          decPostalCode: await decryptCipherField(cipher.identity.postalCode || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          decCountry: await decryptCipherField(cipher.identity.country || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
        };
      }

      if (cipher.sshKey) {
        const encryptedFingerprint = cipher.sshKey.keyFingerprint || cipher.sshKey.fingerprint || '';
        nextCipher.sshKey = {
          ...cipher.sshKey,
          decPrivateKey: await decryptCipherField(cipher.sshKey.privateKey || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          decPublicKey: await decryptCipherField(cipher.sshKey.publicKey || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          keyFingerprint: encryptedFingerprint || null,
          fingerprint: encryptedFingerprint || null,
          decFingerprint: await decryptCipherField(encryptedFingerprint, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
        };
      }

      if (cipher.bankAccount) {
        nextCipher.bankAccount = await decryptCipherObjectFields(
          cipher.bankAccount,
          ['bankName', 'nameOnAccount', 'accountType', 'accountNumber', 'routingNumber', 'branchNumber', 'pin', 'swiftCode', 'iban', 'bankContactPhone'],
          itemEnc,
          itemMac,
          userEnc,
          userMac,
          canFallbackToUserKey
        );
      }

      if (cipher.driversLicense) {
        nextCipher.driversLicense = await decryptCipherObjectFields(
          cipher.driversLicense,
          ['firstName', 'middleName', 'lastName', 'dateOfBirth', 'licenseNumber', 'issuingCountry', 'issuingState', 'issueDate', 'expirationDate', 'issuingAuthority', 'licenseClass'],
          itemEnc,
          itemMac,
          userEnc,
          userMac,
          canFallbackToUserKey
        );
      }

      if (cipher.passport) {
        nextCipher.passport = await decryptCipherObjectFields(
          cipher.passport,
          ['surname', 'givenName', 'dateOfBirth', 'sex', 'birthPlace', 'nationality', 'issuingCountry', 'passportNumber', 'passportType', 'nationalIdentificationNumber', 'issuingAuthority', 'issueDate', 'expirationDate'],
          itemEnc,
          itemMac,
          userEnc,
          userMac,
          canFallbackToUserKey
        );
      }

      if (cipher.fields) {
        nextCipher.fields = await Promise.all(
          cipher.fields.map(async (field) => ({
            ...field,
            decName: await decryptCipherField(field.name || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
            decValue: await decryptCipherField(field.value || '', itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
          }))
        );
      }

      if (Array.isArray(cipher.attachments)) {
        nextCipher.attachments = await Promise.all(
          cipher.attachments.map(async (attachment) => {
            const fileNameResult = await decryptFieldWithSource(
              attachment.fileName || '',
              itemEnc,
              itemMac,
              userEnc,
              userMac,
              !itemUsesUserKey
            );
            return {
              ...attachment,
              decFileName: fileNameResult.text,
            };
          })
        );
      }

      return nextCipher;
    })
  );

  return { folders, ciphers };
}

export async function decryptSends(args: DecryptSendsArgs): Promise<Send[]> {
  const userEnc = base64ToBytes(args.symEncKeyB64);
  const userMac = base64ToBytes(args.symMacKeyB64);
  return Promise.all(
    args.sends.map(async (send) => {
      const nextSend: Send = { ...send };
      try {
        if (send.key) {
          const sendKeyRaw = await decryptBw(send.key, userEnc, userMac);
          const derived = await deriveSendKeyParts(sendKeyRaw);
          nextSend.decName = await decryptField(send.name || '', derived.enc, derived.mac);
          nextSend.decNotes = await decryptField(send.notes || '', derived.enc, derived.mac);
          nextSend.decText = await decryptField(send.text?.text || '', derived.enc, derived.mac);
          if (send.file?.fileName) {
            const decFileName = await decryptField(send.file.fileName, derived.enc, derived.mac);
            nextSend.file = {
              ...(send.file || {}),
              fileName: decFileName || send.file.fileName,
            };
          }
          nextSend.decShareKey = btoa(String.fromCharCode(...sendKeyRaw))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/g, '');
          nextSend.shareUrl = `${args.origin}/#/send/${send.accessId}/${nextSend.decShareKey}`;
        } else {
          nextSend.decName = '';
          nextSend.decNotes = '';
          nextSend.decText = '';
        }
      } catch {
        nextSend.decName = 'Decrypt failed';
      }
      return nextSend;
    })
  );
}
