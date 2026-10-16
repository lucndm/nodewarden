import type { Env, ProfileResponse, User } from '../types';
import { buildAccountKeys } from './user-decryption';
import { isYubiKeyEnabled } from './yubico-otp';

// Official Bitwarden clients treat profile.masterPasswordHint as an EncString
// (encrypted with the user's key). NodeWarden historically stored plaintext
// hints written by the bundled web vault, which makes the official Rust SDK
// throw "EncString error, Invalid length" when parsing the /api/sync payload.
// We accept any value on write (web vault UX stays intact) but suppress
// anything that is not EncString-shaped on read so the SDK never sees garbage.
// ponytail: swallows pre-existing plaintext hints; upgrade path is to encrypt
// hints client-side in the web vault and switch storage to EncString.
export function looksLikeMasterPasswordHint(value: string | null | undefined): boolean {
  if (!value) return false;
  const firstDot = value.indexOf('.');
  if (firstDot <= 0 || firstDot === value.length - 1) return false;
  const parts = value.slice(firstDot + 1).split('|');
  return parts.length >= 2;
}

export function buildProfileResponse(user: User, env?: Env): ProfileResponse {
  void env;
  const organizations: any[] = [];
  const accountKeys = buildAccountKeys(user);

  const storedHint = user.masterPasswordHint;
  const masterPasswordHint =
    storedHint && looksLikeMasterPasswordHint(storedHint) ? storedHint : null;

  return {
    id: user.id,
    name: user.name,
    email: user.email,
    emailVerified: true,
    premium: true,
    premiumFromOrganization: false,
    usesKeyConnector: false,
    masterPasswordHint,
    culture: 'en-US',
    twoFactorEnabled: !!user.totpSecret || isYubiKeyEnabled(user),
    yubikeyEnabled: isYubiKeyEnabled(user),
    key: user.key,
    privateKey: user.privateKey,
    accountKeys,
    securityStamp: user.securityStamp || user.id,
    organizations,
    organizationsNew: organizations,
    providers: [],
    providerOrganizations: [],
    forcePasswordReset: false,
    avatarColor: null,
    creationDate: user.createdAt,
    // New-device verification is not supported without an email delivery channel.
    // Always report disabled so clients do not present a false security posture.
    verifyDevices: false,
    role: user.role,
    status: user.status,
    object: 'profile',
  };
}
