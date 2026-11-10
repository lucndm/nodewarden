import type { Env, User } from './types';
import { errorResponse, unsupportedResponse } from './utils/response';
import { handleGetGeneratorSettings, handleUpdateGeneratorSettings } from './handlers/generator-settings';
import { handleCollectEvents, handleListNotifications, handleNotificationNotFound } from './handlers/client-notifications';
import { handleSsoLinkStart, handleSsoStatus, handleSsoUnlink } from './handlers/identity';
import { handleGetEmailBreaches } from './handlers/email-breach';
import { handleGetUserPolicies, handleGetOrganizationPolicies, handleSetOrganizationPolicy } from './handlers/policies';
import {
  handleGetProfile,
  handleUpdateProfile,
  handleGetKeys,
  handleSetKeys,
    handleGetRevisionDate,
  handleSetUserKeyId,
  handleVerifyPassword,
  handlePutAvatar,
  handlePostSecurityStamp,
  handleChangePassword,
  handleSetVerifyDevices,
  handleGetTotpStatus,
  handleSetTotpStatus,
  handleGetTotpRecoveryCode,
  handleGetTwoFactorProviders,
  handleGetTwoFactorAuthenticator,
  handlePutTwoFactorAuthenticator,
  handleGetTwoFactorYubiKey,
  handlePutTwoFactorYubiKey,
  handlePutTwoFactorYubiKeyConfig,
  handleBootstrapTwoFactorYubiKeyConfig,
  handleGetDeviceVerificationSettings,
  handlePutDeviceVerificationSettings,
  handleDisableTwoFactorProvider,
  handleGetApiKey,
  handleRotateApiKey,
  handleGetUserPublicKey,
} from './handlers/accounts';
import { handleGetBillingSubscription } from './handlers/billing';
import {
  handleGetCiphers,
  handleGetCipher,
  handleCreateCipher,
  handleUpdateCipher,
  handleDeleteCipher,
  handleDeleteCipherCompat,
  handleSetCipherCollections,
  handleShareCipher,
  handlePermanentDeleteCipher,
  handleRestoreCipher,
  handleBulkArchiveCiphers,
  handlePartialUpdateCipher,
  handleBulkUnarchiveCiphers,
  handleBulkMoveCiphers,
  handleBulkDeleteCiphers,
  handleBulkPermanentDeleteCiphers,
  handleBulkRestoreCiphers,
  handleArchiveCipher,
  handleUnarchiveCipher,
  handleGetCipherUsage,
  handleRecordCipherUsage,
  handleDeleteScanExclusion,
  handleGetScanExclusions,
  handleSetScanExclusion,
} from './handlers/ciphers';
import {
  handleAcceptEmergencyAccess,
  handleConfirmEmergencyAccess,
  handleEmergencyAccessPolicies,
  handleReinviteEmergencyAccess,
  handleUpdateEmergencyAccess,
  handleViewEmergencyAccess,
  handleApproveEmergencyAccess,
  handleDeleteEmergencyAccess,
  handleEmergencyAccessPassword,
  handleGetEmergencyAccess,
  handleInitiateEmergencyAccess,
  handleInviteEmergencyAccess,
  handleListGrantedEmergencyAccess,
  handleListTrustedEmergencyAccess,
  handleRejectEmergencyAccess,
  handleTakeoverEmergencyAccess,
} from './handlers/emergency-access';
import {
  handleGetCipherVersion,
  handleGetCipherVersions,
  handleRestoreCipherVersion,
} from './handlers/cipher-versions';
import {
  handleGetFolders,
  handleGetFolder,
  handleCreateFolder,
  handleUpdateFolder,
  handleDeleteFolder,
  handleBulkDeleteFolders,
} from './handlers/folders';
import {
    handleGetSends,
  handleGetSend,
  handleCreateSend,
  handleCreateFileSendV2,
  handleGetSendFileUpload,
  handleUploadSendFile,
  handleUpdateSend,
  handleDeleteSend,
  handleBulkDeleteSends,
  handleRemoveSendPassword,
  handleRemoveSendAuth,
} from './handlers/sends';
import { handleSync } from './handlers/sync';
import { handleCiphersImport } from './handlers/import';
import {
  handleCreateAttachment,
  handleUploadAttachment,
  handleGetAttachment,
  handleUpdateAttachmentMetadata,
  handleDeleteAttachment,
} from './handlers/attachments';
import { handleAuthenticatedDeviceRoute } from './router-devices';
import { handleAdminRoute } from './router-admin';
import { handleGetDomains, handleUpdateDomains } from './handlers/domains';
import {
  handleCreateAccountPasskeyCredential,
  handleDeleteAccountPasskeyCredential,
  handleDeleteTwoFactorWebAuthn,
  handleGetAccountPasskeyAttestationOptions,
  handleGetAccountPasskeyCredentials,
  handleGetAccountPasskeyUpdateAssertionOptions,
  handleGetTwoFactorWebAuthn,
  handleGetTwoFactorWebAuthnChallenge,
  handlePutTwoFactorWebAuthn,
  handleUpdateAccountPasskeyEncryption,
} from './handlers/account-passkeys';
import {
  handleCreateAdminAuthRequest,
  handleGetAuthRequest,
  handleListAuthRequests,
  handleListPendingAuthRequests,
  handleUpdateAuthRequest,
} from './handlers/auth-requests';
import {
  handleConfirmOrganizationUser,
  handleCreateCollection,
  handleCreateOrganization,
  handleRemoveOrganizationUser,
  handleRotateOrganizationKey,
  handleUpdateOrganizationUser,
  handleGetCollections,
  handleGetMemberPublicKeys,
  handleAcceptOrganization,
  handleCreateOrganizationGroup,
  handleDeleteOrganizationGroup,
  handleGetOrganizationCollections,
  handleGetOrganizationGroups,
  handleUpdateOrganizationGroup,
  handleGetOrganizationRotationData,
  handleGetOrganizationUsers,
  handleGetOrganizations,
  handleGetOrganizationKeys,
  handleInviteOrganizationUser,
  handleLeaveOrganization,
  handleSetOrganizationKeys,
  handleUnsupportedOrganizationAction,
} from './handlers/organizations';

const TWO_FACTOR_TYPE_AUTHENTICATOR = 0;
const TWO_FACTOR_TYPE_YUBIKEY = 3;

export async function handleAuthenticatedRoute(
  request: Request,
  env: Env,
  userId: string,
  currentUser: User,
  path: string,
  method: string
): Promise<Response | null> {
  if (method === 'POST' || method === 'PUT' || method === 'DELETE') {
    const blockedAccountPaths = new Set([
      '/api/accounts/set-password',
      '/api/accounts/delete',
      '/api/accounts/delete-account',
      '/api/accounts/delete-vault',
    ]);
    if (blockedAccountPaths.has(path)) {
      return errorResponse('Not implemented', 501);
    }
  }

  if ((path === '/api/accounts/kdf' || path === '/accounts/kdf') && (method === 'POST' || method === 'PUT')) {
    return unsupportedResponse('KDF changes are not supported by this server.');
  }

  // Rotating the user key re-encrypts the whole vault in one request; like a
  // KDF change, it is not supported.
  if (path === '/api/accounts/key-management/rotate-user-account-keys' && method === 'POST') {
    return unsupportedResponse('Rotating the account encryption key is not supported by this server.');
  }

  // The official clients link SSO per organization. NodeWarden links one SSO
  // provider for the whole server on its own routes (/api/settings/sso).
  if (
    (path === '/api/accounts/sso/user-identifier' && method === 'GET') ||
    (/^\/api\/accounts\/sso\/[^/]+$/i.test(path) && method === 'DELETE')
  ) {
    return unsupportedResponse('Organization SSO is not supported by this server; manage SSO under Settings.');
  }

  if (path === '/api/notifications' && method === 'GET') {
    return handleListNotifications();
  }
  if (
    (/^\/api\/notifications\/[^/]+\/read$/i.test(path) && method === 'PATCH') ||
    (/^\/api\/notifications\/[^/]+\/delete$/i.test(path) && method === 'DELETE')
  ) {
    return handleNotificationNotFound();
  }
  if (path === '/events/collect' && method === 'POST') {
    return handleCollectEvents();
  }

  // Deleting the account is refused on every path, the official one included.
  if (path === '/api/accounts' && method === 'DELETE') {
    return errorResponse('Not implemented', 501);
  }

  const mailBackedAccountPaths = new Set([
    '/api/accounts/email-token',
    '/accounts/email-token',
    // Changing the email needs the code email-token sends, so it gets the same answer.
    '/api/accounts/email',
    '/accounts/email',
    '/api/accounts/verify-email',
    '/accounts/verify-email',
    '/api/accounts/verify-email-token',
    '/accounts/verify-email-token',
    '/api/accounts/request-otp',
    '/accounts/request-otp',
    '/api/accounts/verify-otp',
    '/accounts/verify-otp',
  ]);
  if (mailBackedAccountPaths.has(path) && (method === 'POST' || method === 'PUT')) {
    return unsupportedResponse('Email delivery is not supported by this server.');
  }

  const emailTwoFactorPaths = new Set([
    '/api/two-factor/get-email',
    '/two-factor/get-email',
    '/api/two-factor/send-email',
    '/two-factor/send-email',
    '/api/two-factor/send-email-login',
    '/two-factor/send-email-login',
    '/api/two-factor/email',
    '/two-factor/email',
  ]);
  if (emailTwoFactorPaths.has(path) && (method === 'POST' || method === 'PUT' || method === 'DELETE')) {
    return unsupportedResponse('Email two-step login is not supported by this server.');
  }

  if (path === '/api/accounts/profile') {
    if (method === 'GET') return handleGetProfile(request, env, userId);
    if (method === 'PUT') return handleUpdateProfile(request, env, userId);
    return errorResponse('Method not allowed', 405);
  }

  // Self-hosted clients (official Android 2026.9.1, others) hit this after
  // every vault unlock; returning 404 left a 4xx in the user's flight recorder.
  if (path === '/api/account/billing/vnext/subscription' && method === 'GET') {
    return handleGetBillingSubscription(request, env);
  }

  if ((path === '/api/accounts/password' || path === '/api/accounts/change-password') && (method === 'POST' || method === 'PUT')) {
    return handleChangePassword(request, env, userId);
  }

  if (path === '/api/accounts/keys') {
    if (method === 'GET') return handleGetKeys(request, env, userId);
    if (method === 'POST') return handleSetKeys(request, env, userId);
    return errorResponse('Method not allowed', 405);
  }

  if (path === '/api/accounts/totp') {
    if (method === 'GET') return handleGetTotpStatus(request, env, userId);
    if (method === 'PUT' || method === 'POST') return handleSetTotpStatus(request, env, userId);
    return null;
  }

  if ((path === '/api/accounts/totp/recovery-code' || path === '/api/two-factor/get-recover') && method === 'POST') {
    return handleGetTotpRecoveryCode(request, env, userId);
  }

  if (path === '/api/two-factor') {
    if (method === 'GET') return handleGetTwoFactorProviders(request, env, userId);
    return errorResponse('Method not allowed', 405);
  }

  if (path === '/api/two-factor/get-authenticator' && method === 'POST') {
    return handleGetTwoFactorAuthenticator(request, env, userId);
  }

  if ((path === '/api/two-factor/get-yubikey' || path === '/api/two-factor/get-yubi-key') && method === 'POST') {
    return handleGetTwoFactorYubiKey(request, env, userId);
  }

  if (path === '/api/two-factor/get-device-verification-settings' && method === 'POST') {
    return handleGetDeviceVerificationSettings(request, env, userId);
  }

  if (path === '/api/two-factor/device-verification-settings') {
    if (method === 'PUT' || method === 'POST') return handlePutDeviceVerificationSettings(request, env, userId);
    return errorResponse('Method not allowed', 405);
  }

  if (path === '/api/two-factor/get-webauthn' && method === 'POST') {
    return handleGetTwoFactorWebAuthn(request, env, userId, currentUser);
  }

  if (path === '/api/two-factor/get-webauthn-challenge' && method === 'POST') {
    return handleGetTwoFactorWebAuthnChallenge(request, env, userId, currentUser);
  }

  if (path === '/api/two-factor/authenticator') {
    if (method === 'PUT' || method === 'POST') return handlePutTwoFactorAuthenticator(request, env, userId);
    if (method === 'DELETE') return handleDisableTwoFactorProvider(request, env, userId, TWO_FACTOR_TYPE_AUTHENTICATOR);
    return errorResponse('Method not allowed', 405);
  }

  if ((path === '/api/two-factor/yubikey' || path === '/api/two-factor/yubi-key')) {
    if (method === 'PUT' || method === 'POST') return handlePutTwoFactorYubiKey(request, env, userId);
    // The path names the provider; without this a body with no `type` would
    // turn the authenticator off instead of the YubiKey.
    if (method === 'DELETE') return handleDisableTwoFactorProvider(request, env, userId, TWO_FACTOR_TYPE_YUBIKEY);
    return errorResponse('Method not allowed', 405);
  }

  if (path === '/api/two-factor/webauthn') {
    if (method === 'PUT' || method === 'POST') return handlePutTwoFactorWebAuthn(request, env, userId, currentUser);
    if (method === 'DELETE') return handleDeleteTwoFactorWebAuthn(request, env, userId, currentUser);
    return errorResponse('Method not allowed', 405);
  }

  if ((path === '/api/two-factor/yubikey/config' || path === '/api/two-factor/yubi-key/config') && (method === 'PUT' || method === 'POST')) {
    return handlePutTwoFactorYubiKeyConfig(request, env, userId);
  }

  if ((path === '/api/two-factor/yubikey/bootstrap' || path === '/api/two-factor/yubi-key/bootstrap') && method === 'POST') {
    return handleBootstrapTwoFactorYubiKeyConfig(request, env, userId);
  }

  if (path === '/api/two-factor/disable' && (method === 'PUT' || method === 'POST')) {
    return handleDisableTwoFactorProvider(request, env, userId);
  }

  if (path === '/api/accounts/revision-date' && method === 'GET') {
    return handleGetRevisionDate(request, env, userId);
  }

  if (path === '/api/accounts/key-management/user-key-id' && method === 'POST') {
    return handleSetUserKeyId(request, env, userId);
  }

  if (path === '/api/accounts/verify-password' && method === 'POST') {
    return handleVerifyPassword(request, env, userId);
  }

  if (path === '/api/accounts/avatar' && method === 'PUT') {
    return handlePutAvatar(request, env, userId);
  }

  if (path === '/api/accounts/security-stamp' && method === 'POST') {
    return handlePostSecurityStamp(request, env, userId);
  }

  if (path === '/api/accounts/verify-devices' && (method === 'PUT' || method === 'POST')) {
    return handleSetVerifyDevices(request, env, userId);
  }

  if ((path === '/api/accounts/api-key' || path === '/api/accounts/api_key') && method === 'POST') {
    return handleGetApiKey(request, env, userId);
  }

  if ((path === '/api/accounts/rotate-api-key' || path === '/api/accounts/rotate_api_key') && method === 'POST') {
    return handleRotateApiKey(request, env, userId);
  }

  if (path === '/api/webauthn' || path === '/webauthn') {
    if (method === 'GET') return handleGetAccountPasskeyCredentials(request, env, userId);
    if (method === 'POST') return handleCreateAccountPasskeyCredential(request, env, userId);
    if (method === 'PUT') return handleUpdateAccountPasskeyEncryption(request, env, userId);
    return errorResponse('Method not allowed', 405);
  }

  if ((path === '/api/webauthn/attestation-options' || path === '/webauthn/attestation-options') && method === 'POST') {
    return handleGetAccountPasskeyAttestationOptions(request, env, userId, currentUser);
  }

  if ((path === '/api/webauthn/assertion-options' || path === '/webauthn/assertion-options') && method === 'POST') {
    return handleGetAccountPasskeyUpdateAssertionOptions(request, env, userId, currentUser);
  }

  const accountPasskeyDeleteMatch =
    path.match(/^\/api\/webauthn\/([^/]+)\/delete$/i) ||
    path.match(/^\/webauthn\/([^/]+)\/delete$/i);
  if (accountPasskeyDeleteMatch && method === 'POST') {
    return handleDeleteAccountPasskeyCredential(request, env, userId, accountPasskeyDeleteMatch[1], currentUser);
  }

  if (path === '/api/sync' && method === 'GET') {
    return handleSync(request, env, userId);
  }

  if (path.startsWith('/notifications/')) {
    return errorResponse('Not found', 404);
  }

  if (path === '/api/ciphers' || path === '/api/ciphers/create') {
    if (method === 'GET') return handleGetCiphers(request, env, userId);
    if (method === 'POST') return handleCreateCipher(request, env, userId);
    if (path === '/api/ciphers' && method === 'DELETE') return handleBulkPermanentDeleteCiphers(request, env, userId);
    return null;
  }

  if (path === '/api/ciphers/import' && method === 'POST') {
    return handleCiphersImport(request, env, userId);
  }

  if (path === '/api/ciphers/usage' && method === 'GET') {
    return handleGetCipherUsage(request, env, userId);
  }

  // Which items the user does not want checked by the password scan.
  if (path === '/api/security/scan-exclusions' && method === 'GET') {
    return handleGetScanExclusions(request, env, userId);
  }

  const scanExclusionMatch = path.match(/^\/api\/security\/scan-exclusions\/([^/]+)$/i);
  if (scanExclusionMatch) {
    if (method === 'PUT' || method === 'POST') {
      return handleSetScanExclusion(request, env, userId, scanExclusionMatch[1]);
    }
    if (method === 'DELETE') {
      return handleDeleteScanExclusion(request, env, userId, scanExclusionMatch[1]);
    }
  }

  // Emergency access: one account lets another person in when they cannot
  // get in themselves. The key travels wrapped, so the server holds no key
  // it could open.
  // GET /api/users/:id/public-key — the key somebody wraps a vault key with.
  const userPublicKeyMatch = path.match(/^\/api\/users\/([^/]+)\/public-key$/i);
  if (userPublicKeyMatch && method === 'GET') {
    return handleGetUserPublicKey(request, env, userPublicKeyMatch[1]);
  }

  if (path === '/api/emergency-access/trusted' && method === 'GET') {
    return handleListTrustedEmergencyAccess(request, env, userId);
  }
  if (path === '/api/emergency-access/granted' && method === 'GET') {
    return handleListGrantedEmergencyAccess(request, env, userId);
  }
  if (path === '/api/emergency-access/invite' && method === 'POST') {
    return handleInviteEmergencyAccess(request, env, userId);
  }
  const emergencyAccessMatch = path.match(/^\/api\/emergency-access\/([^/]+)(?:\/([^/]+))?$/i);
  if (emergencyAccessMatch) {
    const emergencyId = emergencyAccessMatch[1];
    const action = emergencyAccessMatch[2]?.toLowerCase();
    if (!action && method === 'GET') {
      return handleGetEmergencyAccess(request, env, userId, emergencyId);
    }
    if (!action && (method === 'PUT' || method === 'POST')) {
      return handleUpdateEmergencyAccess(request, env, userId, emergencyId);
    }
    if (action === 'accept' && (method === 'PUT' || method === 'POST')) {
      return handleAcceptEmergencyAccess(request, env, userId, emergencyId);
    }
    if (action === 'reject' && (method === 'PUT' || method === 'POST')) {
      return handleRejectEmergencyAccess(request, env, userId, emergencyId);
    }
    if (action === 'confirm' && (method === 'PUT' || method === 'POST')) {
      return handleConfirmEmergencyAccess(request, env, userId, emergencyId);
    }
    if (action === 'reinvite' && (method === 'PUT' || method === 'POST')) {
      return handleReinviteEmergencyAccess(request, env, userId, emergencyId);
    }
    if (action === 'view' && (method === 'PUT' || method === 'POST')) {
      return handleViewEmergencyAccess(request, env, userId, emergencyId);
    }
    if (action === 'policies' && method === 'GET') {
      return handleEmergencyAccessPolicies(request, env, userId, emergencyId);
    }
    if (action === 'initiate' && (method === 'PUT' || method === 'POST')) {
      return handleInitiateEmergencyAccess(request, env, userId, emergencyId);
    }
    if (action === 'approve' && (method === 'PUT' || method === 'POST')) {
      return handleApproveEmergencyAccess(request, env, userId, emergencyId);
    }
    if (action === 'takeover' && (method === 'PUT' || method === 'POST')) {
      return handleTakeoverEmergencyAccess(request, env, userId, emergencyId);
    }
    if (action === 'password' && (method === 'PUT' || method === 'POST')) {
      return handleEmergencyAccessPassword(request, env, userId, emergencyId);
    }
    if (!action && method === 'DELETE') {
      return handleDeleteEmergencyAccess(request, env, userId, emergencyId);
    }
  }

  if (path === '/api/ciphers/delete' && (method === 'PUT' || method === 'POST')) {
    return handleBulkDeleteCiphers(request, env, userId);
  }

  if (path === '/api/ciphers/delete-permanent' && method === 'POST') {
    return handleBulkPermanentDeleteCiphers(request, env, userId);
  }

  if (path === '/api/ciphers/restore' && (method === 'PUT' || method === 'POST')) {
    return handleBulkRestoreCiphers(request, env, userId);
  }

  if (path === '/api/ciphers/archive' && (method === 'PUT' || method === 'POST')) {
    return handleBulkArchiveCiphers(request, env, userId);
  }

  if (path === '/api/ciphers/unarchive' && (method === 'PUT' || method === 'POST')) {
    return handleBulkUnarchiveCiphers(request, env, userId);
  }

  if (path === '/api/ciphers/move' && (method === 'POST' || method === 'PUT')) {
    return handleBulkMoveCiphers(request, env, userId);
  }

  const cipherMatch = path.match(/^\/api\/ciphers\/([a-f0-9-]+)(\/.*)?$/i);
  if (cipherMatch) {
    const cipherId = cipherMatch[1];
    const subPath = cipherMatch[2] || '';

    if (subPath === '' || subPath === '/') {
      if (method === 'GET') return handleGetCipher(request, env, userId, cipherId);
      if (method === 'PUT' || method === 'POST') return handleUpdateCipher(request, env, userId, cipherId);
      if (method === 'DELETE') return handleDeleteCipherCompat(request, env, userId, cipherId);
    }

    if (subPath === '/delete' && method === 'PUT') return handleDeleteCipher(request, env, userId, cipherId);
    if (subPath === '/delete' && (method === 'DELETE' || method === 'POST')) return handlePermanentDeleteCipher(request, env, userId, cipherId);
    if (subPath === '/restore' && method === 'PUT') return handleRestoreCipher(request, env, userId, cipherId);
    if (subPath === '/archive' && (method === 'PUT' || method === 'POST')) return handleArchiveCipher(request, env, userId, cipherId);
    if (subPath === '/unarchive' && (method === 'PUT' || method === 'POST')) return handleUnarchiveCipher(request, env, userId, cipherId);
    if (subPath === '/partial' && (method === 'PUT' || method === 'POST')) return handlePartialUpdateCipher(request, env, userId, cipherId);
    if (subPath === '/usage' && method === 'POST') return handleRecordCipherUsage(request, env, userId, cipherId);
    if (subPath === '/share' && method === 'PUT') return handleShareCipher(request, env, userId, cipherId);
    if (subPath === '/collections_v2' && (method === 'PUT' || method === 'POST')) {
      return handleSetCipherCollections(request, env, userId, cipherId);
    }
    if (subPath === '/share' && method === 'POST') return handleShareCipher(request, env, userId, cipherId);
    if (subPath === '/details' && method === 'GET') return handleGetCipher(request, env, userId, cipherId);
    if (subPath === '/attachment/v2' && method === 'POST') return handleCreateAttachment(request, env, userId, cipherId);
    if (subPath === '/attachment' && method === 'POST') return handleCreateAttachment(request, env, userId, cipherId);

    if (subPath === '/versions' && method === 'GET') return handleGetCipherVersions(request, env, userId, cipherId);
    const versionMatch = subPath.match(/^\/versions\/([a-f0-9-]+)(\/restore)?$/i);
    if (versionMatch) {
      const versionId = versionMatch[1];
      if (versionMatch[2] && (method === 'POST' || method === 'PUT')) {
        return handleRestoreCipherVersion(request, env, userId, cipherId, versionId);
      }
      if (!versionMatch[2] && method === 'GET') return handleGetCipherVersion(request, env, userId, cipherId, versionId);
    }

    const attachmentMatch = subPath.match(/^\/attachment\/([a-f0-9-]+)$/i);
    if (attachmentMatch) {
      const attachmentId = attachmentMatch[1];
      if (method === 'POST' || method === 'PUT') return handleUploadAttachment(request, env, userId, cipherId, attachmentId);
      if (method === 'GET') return handleGetAttachment(request, env, userId, cipherId, attachmentId);
      if (method === 'DELETE') return handleDeleteAttachment(request, env, userId, cipherId, attachmentId);
    }

    const attachmentMetadataMatch = subPath.match(/^\/attachment\/([a-f0-9-]+)\/metadata$/i);
    if (attachmentMetadataMatch && (method === 'POST' || method === 'PUT')) {
      return handleUpdateAttachmentMetadata(request, env, userId, cipherId, attachmentMetadataMatch[1]);
    }

    const attachmentDeleteMatch = subPath.match(/^\/attachment\/([a-f0-9-]+)\/delete$/i);
    if (attachmentDeleteMatch && method === 'POST') {
      return handleDeleteAttachment(request, env, userId, cipherId, attachmentDeleteMatch[1]);
    }
  }

  if (path === '/api/folders') {
    if (method === 'GET') return handleGetFolders(request, env, userId);
    if (method === 'POST') return handleCreateFolder(request, env, userId);
    return null;
  }

  if (path === '/api/folders/delete' && method === 'POST') {
    return handleBulkDeleteFolders(request, env, userId);
  }

  const folderMatch = path.match(/^\/api\/folders\/([a-f0-9-]+)$/i);
  if (folderMatch) {
    const folderId = folderMatch[1];
    if (method === 'GET') return handleGetFolder(request, env, userId, folderId);
    if (method === 'PUT') return handleUpdateFolder(request, env, userId, folderId);
    if (method === 'DELETE') return handleDeleteFolder(request, env, userId, folderId);
  }

  if (path === '/api/auth-requests' || path === '/api/auth-requests/' || path === '/auth-requests' || path === '/auth-requests/') {
    if (method === 'GET') return handleListAuthRequests(request, env, userId);
    return errorResponse('Method not allowed', 405);
  }

  if (path === '/api/auth-requests/pending' || path === '/auth-requests/pending') {
    if (method === 'GET') return handleListPendingAuthRequests(request, env, userId);
    return errorResponse('Method not allowed', 405);
  }

  if (path === '/api/auth-requests/admin-request' || path === '/auth-requests/admin-request') {
    if (method === 'POST') return handleCreateAdminAuthRequest(request, env, userId, currentUser.email);
    return errorResponse('Method not allowed', 405);
  }

  const authRequestMatch = path.match(/^\/(?:api\/)?auth-requests\/([a-f0-9-]+)$/i);
  if (authRequestMatch) {
    if (method === 'GET') return handleGetAuthRequest(request, env, userId, authRequestMatch[1]);
    if (method === 'PUT') return handleUpdateAuthRequest(request, env, userId, authRequestMatch[1]);
    return errorResponse('Method not allowed', 405);
  }

  if (path === '/api/collections' || path.startsWith('/api/collections/')) {
    if (path === '/api/collections' && method === 'GET') {
      return handleGetCollections(request, env, userId);
    }
    return handleUnsupportedOrganizationAction();
  }

  if (path === '/api/organizations' || path.startsWith('/api/organizations/')) {
    if (path === '/api/organizations') {
      if (method === 'GET') return handleGetOrganizations(request, env, userId);
      if (method === 'POST') return handleCreateOrganization(request, env, userId);
      return handleUnsupportedOrganizationAction();
    }

    // GET /api/organizations/:orgId/rotation-data — what a rotation needs.
    const rotationDataMatch = path.match(/^\/api\/organizations\/([^/]+)\/rotation-data$/i);
    if (rotationDataMatch) {
      if (method === 'GET') return handleGetOrganizationRotationData(request, env, userId, rotationDataMatch[1]);
      return handleUnsupportedOrganizationAction();
    }

    // POST /api/organizations/:orgId/accept — the invited member accepts.
    const acceptMatch = path.match(/^\/api\/organizations\/([^/]+)\/accept$/i);
    if (acceptMatch) {
      if (method === 'POST') return handleAcceptOrganization(request, env, userId, acceptMatch[1]);
      return handleUnsupportedOrganizationAction();
    }

    // GET and POST /api/organizations/:orgId/keys — the public key a member
    // reads, and the admin action that sets the key pair.
    const keysMatch = path.match(/^\/api\/organizations\/([^/]+)\/keys$/i);
    if (keysMatch) {
      if (method === 'GET') return handleGetOrganizationKeys(request, env, userId, keysMatch[1]);
      if (method === 'POST') return handleSetOrganizationKeys(request, env, userId, keysMatch[1]);
      return handleUnsupportedOrganizationAction();
    }

    // POST /api/organizations/:orgId/leave — the member leaves.
    const leaveMatch = path.match(/^\/api\/organizations\/([^/]+)\/leave$/i);
    if (leaveMatch) {
      if (method === 'POST') return handleLeaveOrganization(request, env, userId, leaveMatch[1]);
      return handleUnsupportedOrganizationAction();
    }

    // POST /api/organizations/:orgId/rotate-key — store the new key material.
    const rotateMatch = path.match(/^\/api\/organizations\/([^/]+)\/rotate-key$/i);
    if (rotateMatch) {
      if (method === 'POST') return handleRotateOrganizationKey(request, env, userId, rotateMatch[1]);
      return handleUnsupportedOrganizationAction();
    }

    // POST /api/organizations/:orgId/collections — create a collection.
    const collectionMatch = path.match(/^\/api\/organizations\/([^/]+)\/collections$/i);
    if (collectionMatch) {
      if (method === 'GET') return handleGetOrganizationCollections(request, env, userId, collectionMatch[1]);
      if (method === 'POST') {
        return handleCreateCollection(request, env, userId, collectionMatch[1]);
      }
      return handleUnsupportedOrganizationAction();
    }

    // POST /api/organizations/:orgId/users — invite one or more members.
    const inviteMatch = path.match(/^\/api\/organizations\/([^/]+)\/users$/i);
    if (inviteMatch) {
      // GET reads the member list, POST invites.
      if (method === 'GET') return handleGetOrganizationUsers(request, env, userId, inviteMatch[1]);
      if (method === 'POST') return handleInviteOrganizationUser(request, env, userId, inviteMatch[1]);
      return handleUnsupportedOrganizationAction();
    }

    // The policies of an organization: the decisions that bind its members.
    const orgPoliciesMatch = path.match(/^\/api\/organizations\/([^/]+)\/policies(?:\/(\d+))?$/i);
    if (orgPoliciesMatch) {
      const type = orgPoliciesMatch[2] === undefined ? null : Number(orgPoliciesMatch[2]);
      if (type === null && method === 'GET') {
        return handleGetOrganizationPolicies(request, env, userId, orgPoliciesMatch[1]);
      }
      if (type !== null && (method === 'PUT' || method === 'POST')) {
        return handleSetOrganizationPolicy(request, env, userId, orgPoliciesMatch[1], type);
      }
      return handleUnsupportedOrganizationAction();
    }

    // The groups of an organization: a shortcut that hands a set of
    // collections to a set of members in one go.
    const groupsMatch = path.match(/^\/api\/organizations\/([^/]+)\/groups$/i);
    if (groupsMatch) {
      if (method === 'GET') return handleGetOrganizationGroups(request, env, userId, groupsMatch[1]);
      if (method === 'POST') return handleCreateOrganizationGroup(request, env, userId, groupsMatch[1]);
      return handleUnsupportedOrganizationAction();
    }
    const groupMatch = path.match(/^\/api\/organizations\/([^/]+)\/groups\/([^/]+)$/i);
    if (groupMatch) {
      if (method === 'PUT' || method === 'POST') {
        return handleUpdateOrganizationGroup(request, env, userId, groupMatch[1], groupMatch[2]);
      }
      if (method === 'DELETE') {
        return handleDeleteOrganizationGroup(request, env, userId, groupMatch[1], groupMatch[2]);
      }
      return handleUnsupportedOrganizationAction();
    }

    // POST /api/organizations/:orgId/users/:membershipId/confirm — store the
    // organization key wrapped for that member and confirm the membership.
    const confirmMatch = path.match(/^\/api\/organizations\/([^/]+)\/users\/([^/]+)\/confirm$/i);
    if (confirmMatch) {
      if (method === 'POST') {
        return handleConfirmOrganizationUser(request, env, userId, confirmMatch[1], confirmMatch[2]);
      }
      return handleUnsupportedOrganizationAction();
    }

    // POST /api/organizations/:orgId/users/public-key — the public keys an
    // admin's client needs in order to wrap the organization key.
    const publicKeyMatch = path.match(/^\/api\/organizations\/([^/]+)\/users\/public-key$/i);
    if (publicKeyMatch) {
      if (method === 'POST') {
        let ids: string[] = [];
        try {
          const body = (await request.clone().json()) as { userIds?: unknown };
          if (Array.isArray(body.userIds)) {
            ids = body.userIds.filter((value): value is string => typeof value === 'string');
          }
        } catch {
          ids = [];
        }
        return handleGetMemberPublicKeys(request, env, userId, publicKeyMatch[1], ids);
      }
      return handleUnsupportedOrganizationAction();
    }

    // PUT /api/organizations/:orgId/users/:membershipId — role and collection rights.
    const memberMatch = path.match(/^\/api\/organizations\/([^/]+)\/users\/([^/]+)$/i);
    if (memberMatch) {
      if (method === 'PUT' || method === 'POST') {
        return handleUpdateOrganizationUser(request, env, userId, memberMatch[1], memberMatch[2]);
      }
      if (method === 'DELETE') {
        return handleRemoveOrganizationUser(request, env, userId, memberMatch[1], memberMatch[2]);
      }
      return handleUnsupportedOrganizationAction();
    }

    return handleUnsupportedOrganizationAction();
  }

  if (path === '/api/sends') {
    if (method === 'GET') return handleGetSends(request, env, userId);
    if (method === 'POST') return handleCreateSend(request, env, userId);
    return null;
  }

  if (path === '/api/sends/file/v2' && method === 'POST') {
    return handleCreateFileSendV2(request, env, userId);
  }

  if (path === '/api/sends/delete' && method === 'POST') {
    return handleBulkDeleteSends(request, env, userId);
  }

  const sendMatch = path.match(/^\/api\/sends\/([^/]+)(\/.*)?$/i);
  if (sendMatch) {
    const sendId = sendMatch[1];
    const subPath = sendMatch[2] || '';

    if (subPath === '' || subPath === '/') {
      if (method === 'GET') return handleGetSend(request, env, userId, sendId);
      if (method === 'PUT') return handleUpdateSend(request, env, userId, sendId);
      if (method === 'DELETE') return handleDeleteSend(request, env, userId, sendId);
    }

    if (subPath === '/remove-password' && (method === 'PUT' || method === 'POST')) {
      return handleRemoveSendPassword(request, env, userId, sendId);
    }

    if (subPath === '/remove-auth' && (method === 'PUT' || method === 'POST')) {
      return handleRemoveSendAuth(request, env, userId, sendId);
    }

    const sendFileUploadMatch = subPath.match(/^\/file\/([^/]+)\/?$/i);
    if (sendFileUploadMatch) {
      const fileId = sendFileUploadMatch[1];
      if (method === 'GET') return handleGetSendFileUpload(request, env, userId, sendId, fileId);
      if (method === 'POST' || method === 'PUT') return handleUploadSendFile(request, env, userId, sendId, fileId);
    }
  }

  if (path === '/api/policies' || path.startsWith('/api/policies/')) {
    if (method === 'GET') {
      return handleGetUserPolicies(request, env, userId);
    }
    return null;
  }

  if (path === '/api/settings/domains' || path === '/settings/domains') {
    if (method === 'GET') return handleGetDomains(env, userId);
    if (method === 'PUT' || method === 'POST') return handleUpdateDomains(request, env, userId);
    return null;
  }

  if (path === '/api/settings/generator' || path === '/settings/generator') {
    if (method === 'GET') return handleGetGeneratorSettings(env, userId);
    if (method === 'PUT' || method === 'POST') return handleUpdateGeneratorSettings(request, env, userId);
    return null;
  }

  if (path === '/api/settings/sso' || path === '/settings/sso') {
    if (method === 'GET') return handleSsoStatus(env, userId);
    if (method === 'DELETE') return handleSsoUnlink(request, env, userId);
    return null;
  }

  if (path === '/api/security/email-breaches' && method === 'GET') {
    return handleGetEmailBreaches(request, env, userId);
  }

  if ((path === '/api/settings/sso/link' || path === '/settings/sso/link') && method === 'POST') {
    return handleSsoLinkStart(request, env, userId);
  }

  const authenticatedDeviceResponse = await handleAuthenticatedDeviceRoute(request, env, userId, path, method);
  if (authenticatedDeviceResponse) return authenticatedDeviceResponse;

  const adminResponse = await handleAdminRoute(request, env, currentUser, path, method);
  if (adminResponse) return adminResponse;

  return null;
}
