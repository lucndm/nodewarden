import type { Env, ProfileResponse, User } from '../types';
import { buildAccountKeys } from './user-decryption';
import { isYubiKeyEnabled } from './yubico-otp';

// Master password hint storage is plaintext (the bundled web vault writes
// user-typed text and has no client-side encryption for it). The official
// Bitwarden clients parse profile.masterPasswordHint as an EncString and the
// Rust SDK throws "EncString error, Invalid length" when it sees raw text in
// the /api/sync payload.
//
// /api/sync cannot distinguish a real EncString from plaintext by shape —
// any value matching "<type>.<b64>|<b64>|<b64>" syntax (e.g. "x.y|z|w" or
// even "a.b|c") looks EncString-shaped but is not a real EncString. A
// shape-based filter is fakable and leaves plaintext leaking into the SDK.
// Therefore /api/sync always reports null for masterPasswordHint regardless
// of the stored value: there is nothing left for the SDK to choke on.
//
// Suppression is therefore opt-in per caller:
//   - /api/sync (handleSync) sets suppressNonEncStringHint: true and always
//     receives null for masterPasswordHint.
//   - /api/accounts/profile (handleGetProfile / handleUpdateProfile) does NOT
//     suppress: the bundled web vault reads profile.masterPasswordHint back
//     to prefill the Settings form, and that prefill path expects the stored
//     plaintext as-is. The official client also reads /api/accounts/profile,
//     but the Rust SDK only feeds masterPasswordHint through the EncString
//     parser when it arrives inside /api/sync, not when it is the dedicated
//     profile response.
//
// ponytail: /api/sync always reports null. Upgrade path is to encrypt hints
// client-side in the web vault (using the user's symmetric key) and switch
// storage to EncString; once that lands the suppression can be removed
// entirely.

export interface BuildProfileResponseOptions {
  // When true, masterPasswordHint is always reported as null in the response
  // (used by /api/sync so the official SDK never tries to parse a stored
  // plaintext hint as an EncString). When false (default, used by
  // /api/accounts/profile) the stored value is returned as-is so the bundled
  // web vault can prefill its Settings form.
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
  // When the caller asked for suppression, always report null — there is no
  // shape check that cannot be faked, and a single missed leak crashes the
  // official SDK. When the caller did not ask, return the stored value
  // verbatim so the bundled web vault can prefill its Settings form.
  const masterPasswordHint = options.suppressNonEncStringHint ? null : storedHint;

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
