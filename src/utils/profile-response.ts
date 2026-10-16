import type { Env, ProfileResponse, User } from '../types';
import { buildAccountKeys } from './user-decryption';
import { isYubiKeyEnabled } from './yubico-otp';

// Master password hint storage is plaintext (the bundled web vault writes
// user-typed text and has no client-side encryption for it). The official
// Bitwarden clients parse profile.masterPasswordHint as an EncString and the
// Rust SDK throws "EncString error, Invalid length" when it sees raw text in
// the /api/sync payload.
//
// Suppression is therefore opt-in per caller:
//   - /api/sync (handleSync) sets suppressNonEncStringHint: true so the SDK
//     never sees a non-EncString value.
//   - /api/accounts/profile (handleGetProfile / handleUpdateProfile) does NOT
//     suppress: the bundled web vault reads profile.masterPasswordHint back to
//     prefill the Settings form, and that prefill path expects the stored
//     plaintext as-is. The official client also reads /api/accounts/profile,
//     but the Rust SDK only feeds masterPasswordHint through the EncString
//     parser when it arrives inside /api/sync, not when it is the dedicated
//     profile response.
//
// ponytail: only /api/sync is sanitized. Upgrade path is to encrypt hints
// client-side in the web vault (using the user's symmetric key) and switch
// storage to EncString; once that lands the suppression can be removed
// entirely.
export function looksLikeMasterPasswordHint(value: string | null | undefined): boolean {
  if (!value) return false;
  const firstDot = value.indexOf('.');
  if (firstDot <= 0 || firstDot === value.length - 1) return false;
  const parts = value.slice(firstDot + 1).split('|');
  return parts.length >= 2;
}

export interface BuildProfileResponseOptions {
  // When true, a stored masterPasswordHint that is not EncString-shaped is
  // replaced with null in the response. When false (default) the stored value
  // is returned as-is.
  suppressNonEncStringHint?: boolean;
}

export function buildProfileResponse(
  user: User,
  env?: Env,
  options: BuildProfileResponseOptions = {}
): ProfileResponse {
  void env;
  const organizations: any[] = [];
  const accountKeys = buildAccountKeys(user);

  const storedHint = user.masterPasswordHint;
  // Suppress only when the caller asked for it AND the stored value is not a
  // valid EncString (which includes null/empty). When the caller did not ask,
  // return the stored value verbatim so the bundled web vault can prefill
  // its Settings form.
  const masterPasswordHint =
    options.suppressNonEncStringHint && !looksLikeMasterPasswordHint(storedHint)
      ? null
      : storedHint;

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
