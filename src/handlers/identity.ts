import { Env, TokenResponse, User } from '../types';
import { StorageService } from '../services/storage';
import { AuthService } from '../services/auth';
import { RateLimitService, getClientIdentifier } from '../services/ratelimit';
import { jsonResponse, errorResponse, identityErrorResponse } from '../utils/response';
import { getRefreshTokenSlidingTtlMs, LIMITS } from '../config/limits';
import { findMatchingTotpCounter, isTotpEnabled } from '../utils/totp';
import { createRefreshToken } from '../utils/jwt';
import { readAuthRequestDeviceInfo } from '../utils/device';
import { createRecoveryCode, recoveryCodeEquals } from '../utils/recovery-code';
import { generateUUID } from '../utils/uuid';
import { issueSendAccessToken } from './sends';
import { registerMobilePushDevice } from '../services/push-relay';
import {
  buildAccountKeys,
  buildUserDecryptionOptions,
} from '../utils/user-decryption';
import { auditRequestMetadata, safeWriteAuditEvent } from '../services/audit-events';
import {
  assertAccountPasskeyCredential,
  assertTwoFactorPasskeyCredential,
  buildAccountPasskeyTokenUserDecryptionOption,
  buildTwoFactorPasskeyAssertionOptions,
} from './account-passkeys';
import { isAuthRequestExpired } from '../services/storage-auth-request-repo';
import { createPasskeyUserVerificationToken } from '../utils/user-verification-token';
import { constantTimeEquals, verifyApiKey } from '../utils/api-key';
import { isYubiKeyEnabled, userYubiKeyPublicIds, verifyYubicoOtp, yubiKeyPublicIdFromOtp } from '../utils/yubico-otp';
import { getYubicoCredentials, initializeYubicoCredentialsOnce } from '../services/yubico-config';
import {
  buildAuthorizeUrl,
  createPkcePair,
  discoverOidc,
  exchangeAuthorizationCode,
  getOidcConfig,
  verifyIdToken,
} from '../lib/oidc';

const TWO_FACTOR_REMEMBER_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const TWO_FACTOR_PROVIDER_AUTHENTICATOR = 0;
const TWO_FACTOR_PROVIDER_YUBIKEY = 3;
const TWO_FACTOR_PROVIDER_REMEMBER = 5;
const TWO_FACTOR_PROVIDER_WEBAUTHN = 7;
const TWO_FACTOR_PROVIDER_RECOVERY_CODE = 8;
const WEB_REFRESH_COOKIE = 'nodewarden_web_refresh';
// Some UI surfaces use -1 for the recovery-code settings dialog. Login itself follows
// the official Identity provider enum (RecoveryCode = 8), while request parsing remains
// compatible with older/local provider values.
const TWO_FACTOR_PROVIDER_RECOVERY_CODE_RESPONSE = '-1';
const TWO_FACTOR_PROVIDER_RECOVERY_CODE_ANDROID_REQUEST = 100;

function identityJsonResponse(data: unknown, status: number = 200): Response {
  return jsonResponse(data, status, { 'Cache-Control': 'no-store', Pragma: 'no-cache' });
}

function resolveTotpSecret(userSecret: string | null): string | null {
  if (userSecret && isTotpEnabled(userSecret)) {
    return userSecret;
  }
  return null;
}

async function resolveDeviceSession(
  storage: StorageService,
  userId: string,
  deviceInfo: ReturnType<typeof readAuthRequestDeviceInfo>
): Promise<{ identifier: string; sessionStamp: string } | null> {
  if (!deviceInfo.deviceIdentifier) return null;
  const existingDevice = await storage.getDevice(userId, deviceInfo.deviceIdentifier);
  const sessionStamp = String(existingDevice?.sessionStamp || '').trim() || generateUUID();
  return { identifier: deviceInfo.deviceIdentifier, sessionStamp };
}

function resolveRefreshClientType(request: Request, body: Record<string, string>): string {
  if (shouldUseWebSession(request)) return 'web';
  const clientId = String(body.client_id || '').trim().toLowerCase();
  if (clientId === 'mobile') return 'mobile';
  if (clientId === 'browser' || clientId === 'desktop' || clientId === 'cli') return clientId;
  return clientId || 'other';
}

async function persistAndResolveDeviceSession(
  storage: StorageService,
  userId: string,
  deviceInfo: ReturnType<typeof readAuthRequestDeviceInfo>
): Promise<{ identifier: string; sessionStamp: string } | null> {
  const candidate = await resolveDeviceSession(storage, userId, deviceInfo);
  if (!candidate) return null;
  await storage.upsertDevice(
    userId,
    candidate.identifier,
    deviceInfo.deviceName,
    deviceInfo.deviceType,
    candidate.sessionStamp
  );
  const persisted = await storage.getDevice(userId, candidate.identifier);
  if (!persisted?.sessionStamp) throw new Error('Failed to persist device session');
  return { identifier: persisted.deviceIdentifier, sessionStamp: persisted.sessionStamp };
}

function readDevicePushToken(body: Record<string, string>): string {
  return String(readBodyValue(body, ['devicePushToken', 'DevicePushToken', 'device_push_token']) || '').trim();
}

async function persistIdentityDevicePushToken(
  env: Env,
  storage: StorageService,
  userId: string,
  deviceSession: { identifier: string; sessionStamp: string } | null,
  deviceType: number,
  body: Record<string, string>
): Promise<void> {
  if (!deviceSession) return;
  const pushToken = readDevicePushToken(body);
  if (!pushToken) return;

  const device = await storage.getDevice(userId, deviceSession.identifier);
  if (!device) return;

  const pushUuid = device.pushUuid || generateUUID();
  await storage.updateDevicePushToken(userId, deviceSession.identifier, pushUuid, pushToken);
  const registered = await registerMobilePushDevice(env, {
    userId,
    deviceIdentifier: deviceSession.identifier,
    type: device.type || deviceType,
    pushUuid,
    pushToken,
  });
  console.info('Mobile push token updated from identity token request', {
    userId,
    deviceIdentifier: deviceSession.identifier,
    deviceType: device.type || deviceType,
    pushUuid,
    pushTokenLength: pushToken.length,
    relayRegistered: registered,
  });
}

function shouldUseWebSession(request: Request): boolean {
  return String(request.headers.get('X-NodeWarden-Web-Session') || '').trim() === '1';
}

function parseCookieValue(request: Request, name: string): string | null {
  const rawCookie = String(request.headers.get('Cookie') || '').trim();
  if (!rawCookie) return null;
  for (const part of rawCookie.split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key !== name) continue;
    const value = rest.join('=').trim();
    return value ? decodeURIComponent(value) : null;
  }
  return null;
}

function readBodyValue(body: Record<string, string>, names: string[]): string | undefined {
  for (const name of names) {
    const value = body[name];
    if (value != null) return value;
  }
  return undefined;
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function loginRateLimitKey(clientIdentifier: string, grantType: string, subject: string): Promise<string> {
  const subjectHash = await sha256Hex(`${grantType}:${String(subject || '').trim() || 'unknown'}`);
  return `${clientIdentifier}:login:${grantType}:${subjectHash}`;
}

function buildRefreshCookie(
  request: Request,
  refreshToken: string,
  maxAgeSeconds: number,
  sameSite: 'Strict' | 'Lax' = 'Strict'
): string {
  const isHttps = new URL(request.url).protocol === 'https:';
  const parts = [
    `${WEB_REFRESH_COOKIE}=${encodeURIComponent(refreshToken)}`,
    'Path=/identity/connect',
    'HttpOnly',
    `SameSite=${sameSite}`,
    `Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}`,
  ];
  if (isHttps) parts.push('Secure');
  return parts.join('; ');
}

function buildClearedRefreshCookie(request: Request): string {
  return buildRefreshCookie(request, '', 0);
}

function withWebRefreshCookie(request: Request, response: Response, refreshToken: string | null): Response {
  const headers = new Headers(response.headers);
  headers.append(
    'Set-Cookie',
    refreshToken
      ? buildRefreshCookie(request, refreshToken, Math.floor(getRefreshTokenSlidingTtlMs('web') / 1000))
      : buildClearedRefreshCookie(request)
  );
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function buildPreloginResponse(
  email: string,
  kdfType: number,
  kdfIterations: number,
  kdfMemory: number | null,
  kdfParallelism: number | null,
  ssoRequired: boolean = false
): Record<string, unknown> {
  return {
    kdf: kdfType,
    kdfIterations,
    kdfMemory,
    kdfParallelism,
    // Current official servers expose the consolidated KDF model alongside
    // the legacy flat fields. Keep both shapes while clients migrate.
    kdfSettings: {
      kdfType,
      iterations: kdfIterations,
      memory: kdfMemory,
      parallelism: kdfParallelism,
    },
    salt: null,
    // Preserve the historic NodeWarden aliases for older integrations.
    KdfSettings: {
      KdfType: kdfType,
      Iterations: kdfIterations,
      Memory: kdfMemory,
      Parallelism: kdfParallelism,
    },
    Salt: email.toLowerCase(),
    // Clients use this to switch the email to the SSO button instead of the
    // password form. Note: like KDF parameters, this reveals for a known email
    // that the account is SSO-linked (accepted enumeration trade-off).
    ssoRequired,
  };
}

function masterPasswordPolicyResponse(): TokenResponse['MasterPasswordPolicy'] {
  return {
    minComplexity: 0,
    minLength: 0,
    requireUpper: false,
    requireLower: false,
    requireNumbers: false,
    requireSpecial: false,
    enforceOnLogin: false,
    Object: 'masterPasswordPolicy',
    object: 'masterPasswordPolicy',
  };
}

async function twoFactorRequiredResponse(
  request: Request,
  env: Env,
  storage: StorageService,
  user?: User,
  message: string = 'Two factor required.'
): Promise<Response> {
  // Match Bitwarden Identity: TwoFactorProviders2 lists enabled 2FA providers only.
  // Clients expose recovery-code entry points themselves; Android 2026.4 fails to
  // parse the challenge if an unknown recovery provider key such as "8" is included.
  const providers: string[] = [];
  let webAuthnOptions: Record<string, unknown> | null = null;
  if (!user || resolveTotpSecret(user.totpSecret)) providers.push(String(TWO_FACTOR_PROVIDER_AUTHENTICATOR));
  if (user && isYubiKeyEnabled(user)) providers.push(String(TWO_FACTOR_PROVIDER_YUBIKEY));
  if (user) {
    webAuthnOptions = await buildTwoFactorPasskeyAssertionOptions(request, env, storage, user) as Record<string, unknown> | null;
    if (webAuthnOptions) providers.push(String(TWO_FACTOR_PROVIDER_WEBAUTHN));
  }
  const providers2: Record<string, Record<string, unknown> | null> = {};
  for (const provider of providers) {
    providers2[provider] = provider === String(TWO_FACTOR_PROVIDER_YUBIKEY)
      ? { Nfc: user?.yubikeyNfc ?? false }
      : provider === String(TWO_FACTOR_PROVIDER_WEBAUTHN) && webAuthnOptions
        ? webAuthnOptions
        : null;
  }
  const customResponse = {
    TwoFactorProviders: providers,
    TwoFactorProviders2: providers2,
    SsoEmail2faSessionToken: null,
    MasterPasswordPolicy: masterPasswordPolicyResponse(),
  };

  // Bitwarden clients rely on these fields to trigger the 2FA UI flow.
  return identityJsonResponse(
    {
      error: 'invalid_grant',
      error_description: message,
      Error: 'invalid_grant',
      ErrorDescription: message,
      ErrorMessage: message,
      TwoFactorProviders: customResponse.TwoFactorProviders,
      TwoFactorProviders2: customResponse.TwoFactorProviders2,
      // Required by current Android parser (nullable value is acceptable).
      SsoEmail2faSessionToken: customResponse.SsoEmail2faSessionToken,
      MasterPasswordPolicy: customResponse.MasterPasswordPolicy,
      CustomResponse: customResponse,
      ErrorModel: {
        Message: message,
        Object: 'error',
      },
    },
    400
  );
}

async function recordFailedLoginAndBuildResponse(
  rateLimit: RateLimitService,
  loginIdentifier: string,
  message: string
): Promise<Response> {
  const result = await rateLimit.recordFailedLogin(loginIdentifier);
  if (result.locked) {
    return identityErrorResponse(
      `Too many failed login attempts. Account locked for ${Math.ceil(result.retryAfterSeconds! / 60)} minutes.`,
      'TooManyRequests',
      429
    );
  }
  return identityErrorResponse(message, 'invalid_grant', 400);
}

async function recordFailedTwoFactorAndBuildResponse(
  rateLimit: RateLimitService,
  loginIdentifier: string
): Promise<Response> {
  const failed = await rateLimit.recordFailedLogin(loginIdentifier);
  if (failed.locked) {
    return identityErrorResponse(
      `Too many failed login attempts. Account locked for ${Math.ceil(failed.retryAfterSeconds! / 60)} minutes.`,
      'TooManyRequests',
      429
    );
  }
  return identityErrorResponse('Two-step token is invalid. Try again.', 'invalid_grant', 400);
}

// POST /identity/connect/token
export async function handleToken(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const rateLimit = new RateLimitService(env.DB);

  let body: Record<string, string>;
  const contentType = request.headers.get('content-type') || '';
  try {
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const formData = await request.formData();
      body = Object.fromEntries(formData.entries()) as Record<string, string>;
    } else {
      body = await request.json();
    }
  } catch {
    return identityErrorResponse('Invalid request payload', 'invalid_request', 400);
  }

  const grantType = body.grant_type;
  const clientIdentifier = getClientIdentifier(request);
  if (!clientIdentifier && grantType !== 'refresh_token') {
    await safeWriteAuditEvent(env, {
      action: 'auth.client_ip.missing',
      category: 'auth',
      level: 'error',
      targetType: 'tokenEndpoint',
      metadata: { grantType, reason: 'client_ip_missing', ...auditRequestMetadata(request) },
    });
    return identityErrorResponse(
      'Authentication is temporarily unavailable',
      'temporarily_unavailable',
      503,
      { 'Retry-After': '5' }
    );
  }

  if (grantType === 'password') {
    // Login with password
    const email = body.username?.toLowerCase();
    const passwordHash = body.password;
    const authRequestId = readBodyValue(body, ['authRequest', 'AuthRequest']);
    const twoFactorToken = readBodyValue(body, ['twoFactorToken', 'TwoFactorToken']);
    const twoFactorProvider = readBodyValue(body, ['twoFactorProvider', 'TwoFactorProvider']);
    const twoFactorRemember = readBodyValue(body, ['twoFactorRemember', 'TwoFactorRemember']);
    const deviceInfo = readAuthRequestDeviceInfo(body, request);

    if (!email || !passwordHash) {
      // Bitwarden clients expect OAuth-style error fields.
      return identityErrorResponse('Email and password are required', 'invalid_request', 400);
    }
    const loginIdentifier = await loginRateLimitKey(clientIdentifier!, grantType, email);

    // Check login lockout before user lookup to reduce user-enumeration signal
    const loginCheck = await rateLimit.checkLoginAttempt(loginIdentifier);
    if (!loginCheck.allowed) {
      return identityErrorResponse(
        `Too many failed login attempts. Try again in ${Math.ceil(loginCheck.retryAfterSeconds! / 60)} minutes.`,
        'TooManyRequests',
        429
      );
    }

    const user = await storage.getUser(email);
    if (!user) {
      await rateLimit.recordFailedLogin(loginIdentifier);
      return identityErrorResponse('Username or password is incorrect. Try again', 'invalid_grant', 400);
    }
    if (user.status !== 'active') {
      await rateLimit.recordFailedLogin(loginIdentifier);
      await safeWriteAuditEvent(env, {
        actorUserId: user.id,
        action: 'auth.login.failed.user_inactive',
        category: 'auth',
        level: 'warn',
        targetType: 'user',
        targetId: user.id,
        metadata: {
          grantType,
          deviceIdentifier: deviceInfo.deviceIdentifier,
          ...auditRequestMetadata(request),
        },
      });
      return identityErrorResponse('Account is disabled', 'invalid_grant', 400);
    }
    if (isSsoLoginRequired(env, user) && !(await hasActiveWebSessionFor(request, env, user.id))) {
      await safeWriteAuditEvent(env, {
        actorUserId: user.id,
        action: 'auth.login.failed.sso_required',
        category: 'auth',
        level: 'warn',
        targetType: 'user',
        targetId: user.id,
        metadata: {
          grantType,
          deviceIdentifier: deviceInfo.deviceIdentifier,
          ...auditRequestMetadata(request),
        },
      });
      return identityErrorResponse('This account requires SSO sign-in', 'sso_required', 400);
    }

    let validatedAuthRequestId: string | null = null;
    let authRequestLoginKey: string | null = null;
    let valid = false;
    const normalizedAuthRequestId = String(authRequestId || '').trim();
    if (normalizedAuthRequestId) {
      const authRequest = await storage.getAuthRequestByIdForUser(normalizedAuthRequestId, user.id);
      valid = !!(
        authRequest &&
        authRequest.userId === user.id &&
        authRequest.type === 0 &&
        authRequest.approved === true &&
        authRequest.responseDate &&
        !authRequest.authenticationDate &&
        !isAuthRequestExpired(authRequest) &&
        !!authRequest.key &&
        constantTimeEquals(authRequest.accessCode, passwordHash)
      );
      if (valid) {
        validatedAuthRequestId = authRequest!.id;
        authRequestLoginKey = authRequest!.key;
      }
    } else {
      valid = await auth.verifyPassword(passwordHash, user.masterPasswordHash, user.email);
    }
    if (!valid) {
      await safeWriteAuditEvent(env, {
        actorUserId: user.id,
        action: normalizedAuthRequestId ? 'auth.login.failed.bad_auth_request' : 'auth.login.failed.bad_password',
        category: 'auth',
        level: 'warn',
        targetType: 'user',
        targetId: user.id,
        metadata: {
          grantType,
          deviceIdentifier: deviceInfo.deviceIdentifier,
          ...auditRequestMetadata(request),
        },
      });
      return recordFailedLoginAndBuildResponse(
        rateLimit,
        loginIdentifier,
        'Username or password is incorrect. Try again'
      );
    }

    // Optional 2FA: enabled by any supported per-user provider.
    let trustedTwoFactorTokenToReturn: string | undefined;
    const effectiveTotpSecret = resolveTotpSecret(user.totpSecret);
    const effectiveYubiKeyPublicIds = userYubiKeyPublicIds(user);
    const effectiveWebAuthnCredentials = await storage.getAccountPasskeyCredentialsByUserId(user.id, 'twoFactor');
    if (effectiveTotpSecret || effectiveYubiKeyPublicIds.length > 0 || effectiveWebAuthnCredentials.length > 0) {
      const normalizedTwoFactorProvider = String(twoFactorProvider ?? '').trim();
      const normalizedTwoFactorToken = String(twoFactorToken ?? '').trim();
      let rememberRequested = ['1', 'true', 'True', 'TRUE', 'on', 'yes', 'Yes', 'YES'].includes(String(twoFactorRemember || '').trim());
      const hasProvider = normalizedTwoFactorProvider.length > 0;
      const hasToken = normalizedTwoFactorToken.length > 0;

      // Upstream-compatible behavior: if 2FA is required and either provider or token is missing,
      // respond with a 2FA challenge payload.
      if (!hasProvider || !hasToken) {
        return await twoFactorRequiredResponse(request, env, storage, user, 'Two factor required.');
      }

      let passedByRememberToken = false;
      if (normalizedTwoFactorProvider === String(TWO_FACTOR_PROVIDER_REMEMBER)) {
        if (deviceInfo.deviceIdentifier) {
          const trustedUserId = await storage.getTrustedTwoFactorDeviceTokenUserId(
            normalizedTwoFactorToken,
            deviceInfo.deviceIdentifier
          );
          passedByRememberToken = trustedUserId === user.id;
        }

        // Remember token missing/invalid/expired should re-enter the 2FA challenge flow.
        if (!passedByRememberToken) {
          return await twoFactorRequiredResponse(request, env, storage, user, 'Two factor required.');
        }
      } else if (normalizedTwoFactorProvider === String(TWO_FACTOR_PROVIDER_AUTHENTICATOR)) {
        if (!effectiveTotpSecret) {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
        }
        const matchedCounter = await findMatchingTotpCounter(effectiveTotpSecret, normalizedTwoFactorToken);
        if (matchedCounter == null) {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
        }
        const consumed = await storage.consumeTotpLoginCounter(user.id, matchedCounter);
        if (!consumed) {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
        }
      } else if (normalizedTwoFactorProvider === String(TWO_FACTOR_PROVIDER_YUBIKEY)) {
        const publicId = yubiKeyPublicIdFromOtp(normalizedTwoFactorToken);
        if (!publicId || !effectiveYubiKeyPublicIds.includes(publicId)) {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
        }
        let credentials = await getYubicoCredentials(env.DB);
        let initializedWithCurrentOtp = false;
        if (!credentials) {
          const initialized = await initializeYubicoCredentialsOnce(env.DB, user.email, normalizedTwoFactorToken);
          if (!initialized) {
            return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
          }
          credentials = initialized.credentials;
          initializedWithCurrentOtp = initialized.created;
        }
        if (!initializedWithCurrentOtp && !await verifyYubicoOtp(env, normalizedTwoFactorToken, credentials)) {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
        }
      } else if (normalizedTwoFactorProvider === String(TWO_FACTOR_PROVIDER_WEBAUTHN)) {
        if (!effectiveWebAuthnCredentials.length) {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
        }
        let deviceResponse: unknown;
        try {
          deviceResponse = JSON.parse(normalizedTwoFactorToken);
        } catch {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
        }
        try {
          await assertTwoFactorPasskeyCredential(request, env, storage, user, deviceResponse);
        } catch {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
        }
      } else if (
        normalizedTwoFactorProvider === TWO_FACTOR_PROVIDER_RECOVERY_CODE_RESPONSE ||
        normalizedTwoFactorProvider === String(TWO_FACTOR_PROVIDER_RECOVERY_CODE) ||
        normalizedTwoFactorProvider === String(TWO_FACTOR_PROVIDER_RECOVERY_CODE_ANDROID_REQUEST)
      ) {
        if (!recoveryCodeEquals(normalizedTwoFactorToken, user.totpRecoveryCode)) {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
        }
        user.totpSecret = null;
        user.yubikeyKey1 = null;
        user.yubikeyKey2 = null;
        user.yubikeyKey3 = null;
        user.yubikeyKey4 = null;
        user.yubikeyKey5 = null;
        user.yubikeyNfc = false;
        for (const credential of effectiveWebAuthnCredentials) {
          await storage.deleteAccountPasskeyCredential(user.id, credential.id, 'twoFactor');
        }
        user.totpRecoveryCode = createRecoveryCode();
        user.securityStamp = generateUUID();
        user.updatedAt = new Date().toISOString();
        await storage.saveUser(user);
        await storage.deleteRefreshTokensByUserId(user.id);
        AuthService.invalidateUserCache(user.id);
        rememberRequested = false;
      } else {
        // Unsupported provider for this server profile behaves as an invalid 2FA attempt.
        return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
      }

      // Upstream behavior: do not issue a new remember token when auth itself used remember provider.
      if (rememberRequested && !passedByRememberToken && deviceInfo.deviceIdentifier) {
        trustedTwoFactorTokenToReturn = createRefreshToken();
        await storage.saveTrustedTwoFactorDeviceToken(
          trustedTwoFactorTokenToReturn,
          user.id,
          deviceInfo.deviceIdentifier,
          Date.now() + TWO_FACTOR_REMEMBER_TTL_MS
        );
      }
    }

    // Persist device only after successful password + (optional) 2FA verification.
    const deviceSession = await persistAndResolveDeviceSession(storage, user.id, deviceInfo);
    if (deviceSession) {
      await persistIdentityDevicePushToken(env, storage, user.id, deviceSession, deviceInfo.deviceType, body);
    }

    // Successful login - clear failed attempts
    await rateLimit.clearLoginAttempts(loginIdentifier);
    if (validatedAuthRequestId) {
      await storage.markAuthRequestAuthenticated(validatedAuthRequestId);
    }

    const accessToken = await auth.generateAccessToken(user, deviceSession);
    const refreshToken = await auth.generateRefreshToken(user, deviceSession, resolveRefreshClientType(request, body));
    const accountKeys = buildAccountKeys(user);
    const userDecryptionOptions = buildUserDecryptionOptions(user);
    await safeWriteAuditEvent(env, {
      actorUserId: user.id,
      action: 'auth.login.success',
      category: 'auth',
      level: 'info',
      targetType: 'user',
      targetId: user.id,
      metadata: {
        grantType,
        webSession: shouldUseWebSession(request),
        deviceIdentifier: deviceSession?.identifier ?? deviceInfo.deviceIdentifier,
        deviceType: deviceInfo.deviceType,
        ...auditRequestMetadata(request),
      },
    });

    const response: TokenResponse = {
      access_token: accessToken,
      expires_in: LIMITS.auth.accessTokenTtlSeconds,
      token_type: 'Bearer',
      ...(shouldUseWebSession(request) ? { web_session: true } : { refresh_token: refreshToken }),
      ...(trustedTwoFactorTokenToReturn ? { TwoFactorToken: trustedTwoFactorTokenToReturn } : {}),
      Key: authRequestLoginKey || user.key,
      PrivateKey: user.privateKey,
      AccountKeys: accountKeys,
      accountKeys: accountKeys,
      Kdf: user.kdfType,
      KdfIterations: user.kdfIterations,
      KdfMemory: user.kdfMemory,
      KdfParallelism: user.kdfParallelism,
      ForcePasswordReset: false,
      ResetMasterPassword: false,
      MasterPasswordPolicy: masterPasswordPolicyResponse(),
      ApiUseKeyConnector: false,
      scope: 'api offline_access',
      unofficialServer: true,
      UserDecryptionOptions: userDecryptionOptions,
      userDecryptionOptions: userDecryptionOptions,
    };

    const baseResponse = identityJsonResponse(response);
    return shouldUseWebSession(request)
      ? withWebRefreshCookie(request, baseResponse, refreshToken)
      : baseResponse;

  } else if (grantType === 'webauthn') {
    const token = String(body.token || '').trim();
    const loginIdentifier = await loginRateLimitKey(clientIdentifier!, grantType, token || 'missing-token');
    const loginCheck = await rateLimit.checkLoginAttempt(loginIdentifier);
    if (!loginCheck.allowed) {
      return identityErrorResponse(
        `Too many failed login attempts. Try again in ${Math.ceil(loginCheck.retryAfterSeconds! / 60)} minutes.`,
        'TooManyRequests',
        429
      );
    }

    let deviceResponse: unknown = body.deviceResponse;
    if (typeof deviceResponse === 'string') {
      try {
        deviceResponse = JSON.parse(deviceResponse);
      } catch {
        return identityErrorResponse('Invalid passkey response', 'invalid_request', 400);
      }
    }
    if (!token || !deviceResponse) {
      return identityErrorResponse('Passkey token and deviceResponse are required', 'invalid_request', 400);
    }

    let asserted: Awaited<ReturnType<typeof assertAccountPasskeyCredential>>;
    try {
      asserted = await assertAccountPasskeyCredential(request, env, storage, {
        token,
        deviceResponse,
        scope: 'Authentication',
      });
    } catch (error) {
      await rateLimit.recordFailedLogin(loginIdentifier);
      await safeWriteAuditEvent(env, {
        actorUserId: null,
        action: 'auth.passkey.login.failed',
        category: 'auth',
        level: 'warn',
        targetType: 'accountPasskey',
        targetId: null,
        metadata: {
          grantType,
          reason: error instanceof Error ? error.message : 'assertion_failed',
          ...auditRequestMetadata(request),
        },
      });
      return identityErrorResponse('Passkey is invalid. Try again', 'invalid_grant', 400);
    }

    const { user, credential } = asserted;
    if (user.status !== 'active') {
      await rateLimit.recordFailedLogin(loginIdentifier);
      return identityErrorResponse('Account is disabled', 'invalid_grant', 400);
    }
    if (isSsoLoginRequired(env, user) && !(await hasActiveWebSessionFor(request, env, user.id))) {
      await safeWriteAuditEvent(env, {
        actorUserId: user.id,
        action: 'auth.login.failed.sso_required',
        category: 'auth',
        level: 'warn',
        targetType: 'user',
        targetId: user.id,
        metadata: { grantType, ...auditRequestMetadata(request) },
      });
      return identityErrorResponse('This account requires SSO sign-in', 'sso_required', 400);
    }

    const deviceInfo = readAuthRequestDeviceInfo(body, request);
    const deviceSession = await persistAndResolveDeviceSession(storage, user.id, deviceInfo);
    if (deviceSession) {
      await persistIdentityDevicePushToken(env, storage, user.id, deviceSession, deviceInfo.deviceType, body);
    }

    await rateLimit.clearLoginAttempts(loginIdentifier);

    const accessToken = await auth.generateAccessToken(user, deviceSession);
    const refreshToken = await auth.generateRefreshToken(user, deviceSession, resolveRefreshClientType(request, body));
    const userVerificationToken = await createPasskeyUserVerificationToken(env, user.id, 'backup.settings.repair');
    const accountKeys = buildAccountKeys(user);
    const webAuthnPrfOption = buildAccountPasskeyTokenUserDecryptionOption(credential);
    const userDecryptionOptions = buildUserDecryptionOptions(user, webAuthnPrfOption);
    await safeWriteAuditEvent(env, {
      actorUserId: user.id,
      action: 'auth.passkey.login.success',
      category: 'auth',
      level: 'info',
      targetType: 'accountPasskey',
      targetId: credential.id,
      metadata: {
        grantType,
        webSession: shouldUseWebSession(request),
        deviceIdentifier: deviceSession?.identifier ?? deviceInfo.deviceIdentifier,
        deviceType: deviceInfo.deviceType,
        ...auditRequestMetadata(request),
      },
    });

    const response: TokenResponse = {
      access_token: accessToken,
      expires_in: LIMITS.auth.accessTokenTtlSeconds,
      token_type: 'Bearer',
      ...(shouldUseWebSession(request) ? { web_session: true } : { refresh_token: refreshToken }),
      Key: user.key,
      PrivateKey: user.privateKey,
      AccountKeys: accountKeys,
      accountKeys: accountKeys,
      Kdf: user.kdfType,
      KdfIterations: user.kdfIterations,
      KdfMemory: user.kdfMemory,
      KdfParallelism: user.kdfParallelism,
      ForcePasswordReset: false,
      ResetMasterPassword: false,
      MasterPasswordPolicy: masterPasswordPolicyResponse(),
      ApiUseKeyConnector: false,
      scope: 'api offline_access',
      unofficialServer: true,
      UserVerificationToken: userVerificationToken,
      userVerificationToken,
      UserDecryptionOptions: userDecryptionOptions,
      userDecryptionOptions: userDecryptionOptions,
    };

    const baseResponse = identityJsonResponse(response);
    return shouldUseWebSession(request)
      ? withWebRefreshCookie(request, baseResponse, refreshToken)
      : baseResponse;

  } else if (grantType === 'client_credentials') {
    // Login with client credentials
    const clientId = body.client_id;
    const clientSecret = body.client_secret;
    const scope = body.scope;
    const deviceInfo = readAuthRequestDeviceInfo(body, request);

    const parmValid = checkClientCredentialsParam(clientId, clientSecret, scope);
    if (!parmValid) {
      return identityErrorResponse('Parameter error', 'invalid_request', 400);
    }
    const uid = clientId.slice(5);
    const loginIdentifier = await loginRateLimitKey(clientIdentifier!, grantType, uid);

    // Check login lockout before user lookup to reduce user-enumeration signal
    const loginCheck = await rateLimit.checkLoginAttempt(loginIdentifier);
    if (!loginCheck.allowed) {
      return identityErrorResponse(
        `Too many failed login attempts. Try again in ${Math.ceil(loginCheck.retryAfterSeconds! / 60)} minutes.`,
        'TooManyRequests',
        429
      );
    }

    const user = await storage.getUserById(uid);
    if (!user) {
      await rateLimit.recordFailedLogin(loginIdentifier);
      return identityErrorResponse('ClientId or clientSecret is incorrect. Try again', 'invalid_grant', 400);
    }
    if (user.status !== 'active') {
      await rateLimit.recordFailedLogin(loginIdentifier);
      await safeWriteAuditEvent(env, {
        actorUserId: user.id,
        action: 'auth.login.failed.user_inactive',
        category: 'auth',
        level: 'warn',
        targetType: 'user',
        targetId: user.id,
        metadata: {
          grantType,
          deviceIdentifier: deviceInfo.deviceIdentifier,
          ...auditRequestMetadata(request),
        },
      });
      return identityErrorResponse('Account is disabled', 'invalid_grant', 400);
    }

    if (!user.apiKey || !(await verifyApiKey(clientSecret, user.apiKey))) {
      await rateLimit.recordFailedLogin(loginIdentifier);
      await safeWriteAuditEvent(env, {
        actorUserId: user.id,
        action: 'auth.login.failed.bad_api_key',
        category: 'auth',
        level: 'warn',
        targetType: 'user',
        targetId: user.id,
        metadata: {
          grantType,
          deviceIdentifier: deviceInfo.deviceIdentifier,
          ...auditRequestMetadata(request),
        },
      });
      return identityErrorResponse('ClientId or clientSecret is incorrect. Try again', 'invalid_grant', 400);
    }

    // Persist device only after successful client credential verification.
    const deviceSession = await persistAndResolveDeviceSession(storage, user.id, deviceInfo);
    if (deviceSession) {
      await persistIdentityDevicePushToken(env, storage, user.id, deviceSession, deviceInfo.deviceType, body);
    }

    // Successful login - clear failed attempts
    await rateLimit.clearLoginAttempts(loginIdentifier);

    const accessToken = await auth.generateAccessToken(user, deviceSession);
    const refreshToken = await auth.generateRefreshToken(user, deviceSession, resolveRefreshClientType(request, body));
    const accountKeys = buildAccountKeys(user);
    const userDecryptionOptions = buildUserDecryptionOptions(user);
    await safeWriteAuditEvent(env, {
      actorUserId: user.id,
      action: 'auth.login.success',
      category: 'auth',
      level: 'info',
      targetType: 'user',
      targetId: user.id,
      metadata: {
        grantType,
        webSession: shouldUseWebSession(request),
        deviceIdentifier: deviceSession?.identifier ?? deviceInfo.deviceIdentifier,
        deviceType: deviceInfo.deviceType,
        ...auditRequestMetadata(request),
      },
    });

    const response: TokenResponse = {
      access_token: accessToken,
      expires_in: LIMITS.auth.accessTokenTtlSeconds,
      token_type: 'Bearer',
      ...(shouldUseWebSession(request) ? { web_session: true } : { refresh_token: refreshToken }),
      Key: user.key,
      PrivateKey: user.privateKey,
      AccountKeys: accountKeys,
      accountKeys: accountKeys,
      Kdf: user.kdfType,
      KdfIterations: user.kdfIterations,
      KdfMemory: user.kdfMemory,
      KdfParallelism: user.kdfParallelism,
      ForcePasswordReset: false,
      ResetMasterPassword: false,
      MasterPasswordPolicy: masterPasswordPolicyResponse(),
      ApiUseKeyConnector: false,
      scope: 'api offline_access',
      unofficialServer: true,
      UserDecryptionOptions: userDecryptionOptions,
      userDecryptionOptions: userDecryptionOptions,
    };

    const baseResponse = identityJsonResponse(response);
    return shouldUseWebSession(request)
      ? withWebRefreshCookie(request, baseResponse, refreshToken)
      : baseResponse;

  } else if (grantType === 'authorization_code') {
    // Official Bitwarden client SSO: exchange the short-lived authorization
    // code (with its PKCE verifier) for tokens. The client then unlocks the
    // vault with the master password — no key escrow involved.
    const code = String(body.code || '').trim();
    const codeVerifier = String(body.code_verifier || body.codeVerifier || '').trim();
    const redirectUri = String(body.redirect_uri || body.redirectUri || '').trim();
    if (!code || !codeVerifier) {
      return identityErrorResponse('code and code_verifier are required', 'invalid_request', 400);
    }

    const ssoStorage = new StorageService(env.DB);
    const codeHash = await sha256Hex(code);
    const record = await ssoStorage.getSsoAuthorizationCode(codeHash);
    if (!record || record.consumedAt || new Date(record.expiresAt).getTime() < Date.now()) {
      await safeWriteAuditEvent(env, {
        action: 'auth.sso.client.exchange.failed',
        category: 'auth',
        level: 'warn',
        targetType: 'sso',
        metadata: { reason: 'invalid_or_expired_code', ...auditRequestMetadata(request) },
      });
      return identityErrorResponse('Invalid or expired authorization code', 'invalid_grant', 400);
    }
    if (redirectUri && redirectUri !== record.redirectUri) {
      return identityErrorResponse('redirect_uri mismatch', 'invalid_grant', 400);
    }
    const verifierDigest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
    if (base64UrlFromBytes(new Uint8Array(verifierDigest)) !== record.codeChallenge) {
      await safeWriteAuditEvent(env, {
        action: 'auth.sso.client.exchange.failed',
        category: 'auth',
        level: 'warn',
        targetType: 'sso',
        metadata: { reason: 'pkce_mismatch', ...auditRequestMetadata(request) },
      });
      return identityErrorResponse('PKCE verification failed', 'invalid_grant', 400);
    }
    if (!(await ssoStorage.consumeSsoAuthorizationCode(codeHash))) {
      return identityErrorResponse('Invalid or expired authorization code', 'invalid_grant', 400);
    }

    const ssoUser = await ssoStorage.getUserById(record.userId);
    if (!ssoUser || ssoUser.status !== 'active') {
      return identityErrorResponse('Account is not available', 'invalid_grant', 400);
    }

    const ssoDeviceInfo = readAuthRequestDeviceInfo(body, request);
    const ssoDeviceSession = await persistAndResolveDeviceSession(ssoStorage, ssoUser.id, ssoDeviceInfo);
    if (ssoDeviceSession) {
      await persistIdentityDevicePushToken(env, ssoStorage, ssoUser.id, ssoDeviceSession, ssoDeviceInfo.deviceType, body);
    }

    const ssoAccessToken = await auth.generateAccessToken(ssoUser, ssoDeviceSession);
    const ssoRefreshToken = await auth.generateRefreshToken(ssoUser, ssoDeviceSession, resolveRefreshClientType(request, body));
    const ssoAccountKeys = buildAccountKeys(ssoUser);
    const ssoUserDecryptionOptions = buildUserDecryptionOptions(ssoUser);
    await safeWriteAuditEvent(env, {
      actorUserId: ssoUser.id,
      action: 'auth.login.success',
      category: 'auth',
      level: 'info',
      targetType: 'user',
      targetId: ssoUser.id,
      metadata: {
        grantType,
        clientId: clientIdentifier,
        webSession: shouldUseWebSession(request),
        deviceIdentifier: ssoDeviceSession?.identifier ?? ssoDeviceInfo.deviceIdentifier,
        deviceType: ssoDeviceInfo.deviceType,
        ...auditRequestMetadata(request),
      },
    });

    const ssoResponse: TokenResponse = {
      access_token: ssoAccessToken,
      expires_in: LIMITS.auth.accessTokenTtlSeconds,
      token_type: 'Bearer',
      ...(shouldUseWebSession(request) ? { web_session: true } : { refresh_token: ssoRefreshToken }),
      Key: ssoUser.key,
      PrivateKey: ssoUser.privateKey,
      AccountKeys: ssoAccountKeys,
      accountKeys: ssoAccountKeys,
      Kdf: ssoUser.kdfType,
      KdfIterations: ssoUser.kdfIterations,
      KdfMemory: ssoUser.kdfMemory,
      KdfParallelism: ssoUser.kdfParallelism,
      ForcePasswordReset: false,
      ResetMasterPassword: false,
      MasterPasswordPolicy: masterPasswordPolicyResponse(),
      ApiUseKeyConnector: false,
      scope: 'api offline_access',
      unofficialServer: true,
      UserDecryptionOptions: ssoUserDecryptionOptions,
      userDecryptionOptions: ssoUserDecryptionOptions,
    };

    const ssoBaseResponse = identityJsonResponse(ssoResponse);
    return shouldUseWebSession(request)
      ? withWebRefreshCookie(request, ssoBaseResponse, ssoRefreshToken)
      : ssoBaseResponse;

  } else if (grantType === 'send_access') {
    const sendAccessLimit = await rateLimit.consumeBudget(`${clientIdentifier}:public`, LIMITS.rateLimit.publicRequestsPerMinute);
    if (!sendAccessLimit.allowed) {
      return identityErrorResponse(
        `Rate limit exceeded. Try again in ${sendAccessLimit.retryAfterSeconds} seconds.`,
        'TooManyRequests',
        429
      );
    }

    const sendId = String(body.send_id || body.sendId || '').trim();
    if (!sendId) {
      return identityJsonResponse(
        {
          error: 'invalid_request',
          error_description: 'send_id is required',
          send_access_error_type: 'invalid_send_id',
          ErrorModel: {
            Message: 'send_id is required',
            Object: 'error',
          },
        },
        400
      );
    }

    const passwordHashB64 = String(
      body.password_hash_b64 || body.passwordHashB64 || body.passwordHash || body.password_hash || ''
    ).trim() || null;
    const password = String(body.password || '').trim() || null;

    const result = await issueSendAccessToken(
      env,
      sendId,
      passwordHashB64,
      password,
      rateLimit,
      clientIdentifier || undefined
    );
    if ('error' in result) {
      return result.error;
    }

    return identityJsonResponse({
      access_token: result.token,
      expires_in: LIMITS.auth.sendAccessTokenTtlSeconds,
      token_type: 'Bearer',
      scope: 'api.send',
      unofficialServer: true,
    });
  } else if (grantType === 'refresh_token') {
    const refreshToken = String(body.refresh_token || '').trim() || (
      shouldUseWebSession(request)
        ? parseCookieValue(request, WEB_REFRESH_COOKIE)
        : null
    );
    if (!refreshToken) {
      return identityErrorResponse('Refresh token is required', 'invalid_request', 400);
    }

    const refreshTokenHash = await sha256Hex(refreshToken);
    try {
      const sessionLimit = await rateLimit.consumeBudget(
        `refresh-session:${refreshTokenHash}`,
        LIMITS.rateLimit.refreshTokenRequestsPerMinute
      );
      const ipLimit = clientIdentifier
        ? await rateLimit.consumeBudget(
            `refresh-ip:${clientIdentifier}`,
            LIMITS.rateLimit.refreshTokenRequestsPerIpMinute
          )
        : null;
      const rejected = !sessionLimit.allowed ? sessionLimit : (ipLimit && !ipLimit.allowed ? ipLimit : null);
      if (rejected) {
        const retryAfter = Math.max(1, rejected.retryAfterSeconds || 1);
        return identityErrorResponse(
          `Rate limit exceeded. Try again in ${retryAfter} seconds.`,
          'temporarily_unavailable',
          429,
          { 'Retry-After': String(retryAfter) }
        );
      }
    } catch (error) {
      await safeWriteAuditEvent(env, {
        action: 'auth.refresh.failed.rate_limit_unavailable',
        category: 'auth',
        level: 'error',
        targetType: 'refreshToken',
        metadata: { grantType, reason: 'rate_limit_unavailable', error: error instanceof Error ? error.message : String(error), ...auditRequestMetadata(request) },
      });
      return identityErrorResponse(
        'Session refresh is temporarily unavailable',
        'temporarily_unavailable',
        503,
        { 'Retry-After': '5' }
      );
    }

    if (!clientIdentifier) {
      await safeWriteAuditEvent(env, {
        action: 'auth.client_ip.missing',
        category: 'auth',
        level: 'warn',
        targetType: 'refreshToken',
        metadata: { grantType, reason: 'client_ip_missing', webSession: shouldUseWebSession(request), ...auditRequestMetadata(request) },
      });
    }

    let result: Awaited<ReturnType<AuthService['refreshAccessTokenDetailed']>>;
    try {
      result = await auth.refreshAccessTokenDetailed(refreshToken);
    } catch (error) {
      await safeWriteAuditEvent(env, {
        action: 'auth.refresh.failed.temporarily_unavailable',
        category: 'auth',
        level: 'error',
        targetType: 'refreshToken',
        metadata: { grantType, reason: 'storage_or_worker_error', error: error instanceof Error ? error.message : String(error), webSession: shouldUseWebSession(request), ...auditRequestMetadata(request) },
      });
      return identityErrorResponse(
        'Session refresh is temporarily unavailable',
        'temporarily_unavailable',
        503,
        { 'Retry-After': '5' }
      );
    }
    if (!result.ok) {
      await safeWriteAuditEvent(env, {
        actorUserId: result.userId ?? null,
        action: `auth.refresh.failed.${result.reason}`,
        category: 'auth',
        level: 'warn',
        targetType: result.deviceIdentifier ? 'device' : 'refreshToken',
        targetId: result.deviceIdentifier ?? null,
        metadata: {
          grantType,
          reason: result.reason,
          webSession: shouldUseWebSession(request),
          ...auditRequestMetadata(request),
        },
      });
      const invalidResponse = identityErrorResponse('Invalid refresh token', 'invalid_grant', 400);
      return shouldUseWebSession(request)
        ? withWebRefreshCookie(request, invalidResponse, null)
        : invalidResponse;
    }

    const { accessToken, user, device } = result;
    if (device?.identifier) {
      await storage.touchDeviceLastSeen(user.id, device.identifier);
    }
    const accountKeys = buildAccountKeys(user);
    const userDecryptionOptions = buildUserDecryptionOptions(user);

    const response: TokenResponse = {
      access_token: accessToken,
      expires_in: LIMITS.auth.accessTokenTtlSeconds,
      token_type: 'Bearer',
      ...(shouldUseWebSession(request) ? { web_session: true } : { refresh_token: refreshToken }),
      Key: user.key,
      PrivateKey: user.privateKey,
      AccountKeys: accountKeys,
      accountKeys: accountKeys,
      Kdf: user.kdfType,
      KdfIterations: user.kdfIterations,
      KdfMemory: user.kdfMemory,
      KdfParallelism: user.kdfParallelism,
      ForcePasswordReset: false,
      ResetMasterPassword: false,
      MasterPasswordPolicy: masterPasswordPolicyResponse(),
      ApiUseKeyConnector: false,
      scope: 'api offline_access',
      unofficialServer: true,
      UserDecryptionOptions: userDecryptionOptions,
      userDecryptionOptions: userDecryptionOptions,
    };

    const baseResponse = identityJsonResponse(response);
    return shouldUseWebSession(request)
      ? withWebRefreshCookie(request, baseResponse, refreshToken)
      : baseResponse;
  }

  return identityErrorResponse('Unsupported grant type', 'unsupported_grant_type', 400);
}

// POST /identity/accounts/prelogin
export async function handlePrelogin(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { email?: string };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const email = body.email?.toLowerCase();
  if (!email) {
    return errorResponse('Email is required', 400);
  }

  const user = await storage.getUser(email);

  // Return default KDF settings even if user doesn't exist (to prevent user enumeration)
  const kdfType = user?.kdfType ?? 0;
  const kdfIterations = user?.kdfIterations ?? LIMITS.auth.defaultKdfIterations;
  // Use ?? null so non-existent users return null (not undefined/omitted) for these fields,
  // matching the response shape of real PBKDF2 users and reducing enumeration signal.
  const kdfMemory = user?.kdfMemory ?? null;
  const kdfParallelism = user?.kdfParallelism ?? null;

  const ssoRequired = user != null && isSsoLoginRequired(env, user);
  return identityJsonResponse(buildPreloginResponse(email, kdfType, kdfIterations, kdfMemory, kdfParallelism, ssoRequired));
}

// POST /identity/connect/revocation
// Best-effort OAuth token revocation endpoint.
// RFC 7009 allows returning 200 even if token is unknown.
export async function handleRevocation(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);
  let body: Record<string, string>;
  const contentType = request.headers.get('content-type') || '';
  try {
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const formData = await request.formData();
      body = Object.fromEntries(formData.entries()) as Record<string, string>;
    } else {
      body = await request.json();
    }
  } catch {
    return new Response(null, { status: 200, headers: { 'Cache-Control': 'no-store', Pragma: 'no-cache' } });
  }

  const token = String(body.token || '').trim() || (
    shouldUseWebSession(request)
      ? (parseCookieValue(request, WEB_REFRESH_COOKIE) || '')
      : ''
  );
  if (token) {
    await storage.deleteRefreshToken(token);
  }

  const baseResponse = new Response(null, {
    status: 200,
    headers: { 'Cache-Control': 'no-store', Pragma: 'no-cache' },
  });
  return shouldUseWebSession(request)
    ? withWebRefreshCookie(request, baseResponse, null)
    : baseResponse;
}

// ─── Zitadel / OIDC SSO (web vault login) ───────────────────────────────────
// Design (Option 1): SSO authenticates the web session; the vault stays LOCKED
// and is still unlocked with the master password (or passkey PRF). No key
// escrow, no server-side decryption — zero-knowledge is preserved. Only
// pre-existing accounts can sign in (link-only, never auto-provisioned).

const SSO_STATE_COOKIE = 'nw_sso_state';
const SSO_STATE_TTL_SECONDS = 10 * 60;

interface SsoStatePayload {
  state: string;
  verifier: string;
  nonce: string;
  exp: number;
  purpose: 'login' | 'link' | 'client_sso';
  /** Set for purpose=link: the authenticated account that requested the bind. */
  userId?: string;
  /** Set for purpose=client_sso: the official Bitwarden client parameters. */
  clientId?: string;
  clientState?: string;
  clientRedirectUri?: string;
  clientCodeChallenge?: string;
  clientCodeChallengeMethod?: string;
  clientEmail?: string;
}

function base64UrlFromBytes(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

function bytesFromBase64Url(value: string): Uint8Array {
  const padded = value.replaceAll('-', '+').replaceAll('_', '/');
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

async function hmacBase64Url(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return base64UrlFromBytes(new Uint8Array(signature));
}

async function sealSsoState(payload: SsoStatePayload, secret: string): Promise<string> {
  const body = base64UrlFromBytes(new TextEncoder().encode(JSON.stringify(payload)));
  const signature = await hmacBase64Url(secret, body);
  return `${body}.${signature}`;
}

async function unsealSsoState(token: string, secret: string): Promise<SsoStatePayload | null> {
  const dot = token.indexOf('.');
  if (dot === -1) return null;
  const body = token.slice(0, dot);
  const signature = token.slice(dot + 1);
  const expected = await hmacBase64Url(secret, body);
  if (!constantTimeEquals(signature, expected)) return null;
  try {
    const payload = JSON.parse(new TextDecoder().decode(bytesFromBase64Url(body))) as Partial<SsoStatePayload>;
    if (!payload.state || !payload.verifier || !payload.nonce || typeof payload.exp !== 'number') return null;
    if (payload.purpose !== 'login' && payload.purpose !== 'link' && payload.purpose !== 'client_sso') {
      return null;
    }
    if (payload.purpose === 'link' && !payload.userId) return null;
    if (
      payload.purpose === 'client_sso' &&
      (!payload.clientRedirectUri || !payload.clientCodeChallenge || !payload.clientCodeChallengeMethod)
    ) {
      return null;
    }
    return payload as SsoStatePayload;
  } catch {
    return null;
  }
}

function buildSsoStateCookie(request: Request, sealed: string | null): string {
  const isHttps = new URL(request.url).protocol === 'https:';
  const parts = [
    `${SSO_STATE_COOKIE}=${sealed ? encodeURIComponent(sealed) : ''}`,
    'Path=/auth/sso',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${sealed ? SSO_STATE_TTL_SECONDS : 0}`,
  ];
  if (isHttps) parts.push('Secure');
  return parts.join('; ');
}

function ssoRedirect(location: string, request: Request, refreshToken?: string | null): Response {
  const headers = new Headers({
    Location: location,
    'Cache-Control': 'no-store',
    Pragma: 'no-cache',
  });
  headers.append('Set-Cookie', buildSsoStateCookie(request, null));
  // Only a successful SSO login refreshes the web session cookie. Error and
  // link-flow redirects must never clear an existing session: the callback is
  // a cross-site top-level redirect, and a Strict cookie would be rejected
  // there — Lax still withholds the cookie from cross-site POSTs, and the
  // token endpoint only accepts POSTs.
  if (refreshToken) {
    headers.append(
      'Set-Cookie',
      buildRefreshCookie(request, refreshToken, Math.floor(getRefreshTokenSlidingTtlMs('web') / 1000), 'Lax')
    );
  }
  return new Response(null, { status: 302, headers });
}

export function isSsoEnabled(env: Env): boolean {
  return getOidcConfig(env) !== null;
}

/**
 * SSO enforcement: once an account is linked to an identity provider, the
 * password and passkey login grants are closed for it — the IdP (with its MFA
 * and policies) becomes the only way to obtain a session. Vault unlock stays
 * local (master password / passkey PRF) and API keys keep working. Unsetting
 * the OIDC configuration restores password login (natural break-glass).
 */
export function isSsoLoginRequired(env: Env, user: Pick<User, 'ssoSubject'>): boolean {
  return getOidcConfig(env) !== null && Boolean(user.ssoSubject);
}

/**
 * True when the request carries a valid web refresh cookie for this user.
 * The webapp re-uses the password/webauthn grants to UNLOCK an existing
 * session (it re-sends the master password hash to obtain fresh tokens and
 * the profile). SSO enforcement must only block fresh sign-ins, not session
 * re-establishment, which is what this check distinguishes.
 */
async function hasActiveWebSessionFor(request: Request, env: Env, userId: string): Promise<boolean> {
  if (!shouldUseWebSession(request)) return false;
  const refreshToken = parseCookieValue(request, WEB_REFRESH_COOKIE);
  if (!refreshToken) return false;
  try {
    const result = await new AuthService(env).refreshAccessTokenDetailed(refreshToken);
    return result.ok === true && result.user.id === userId;
  } catch {
    return false;
  }
}

async function buildSsoAuthorize(
  request: Request,
  env: Env,
  purpose: 'login' | 'link' | 'client_sso',
  extras: Partial<SsoStatePayload> = {}
): Promise<{ authorizeUrl: string; stateCookie: string } | null> {
  const config = getOidcConfig(env);
  const secret = (env.JWT_SECRET || '').trim();
  if (!config || !secret) return null;

  const url = new URL(request.url);
  const redirectUri = `${url.origin}/auth/sso/callback`;
  const discovery = await discoverOidc(config.issuer);
  const pkce = await createPkcePair();
  const payload: SsoStatePayload = {
    state: base64UrlFromBytes(crypto.getRandomValues(new Uint8Array(16))),
    verifier: pkce.verifier,
    nonce: base64UrlFromBytes(crypto.getRandomValues(new Uint8Array(16))),
    exp: Date.now() + SSO_STATE_TTL_SECONDS * 1000,
    purpose,
    ...extras,
  };
  const sealed = await sealSsoState(payload, secret);
  return {
    authorizeUrl: buildAuthorizeUrl(config, discovery, {
      redirectUri,
      state: payload.state,
      nonce: payload.nonce,
      challenge: pkce.challenge,
    }),
    stateCookie: buildSsoStateCookie(request, sealed),
  };
}

export async function handleSsoStart(request: Request, env: Env): Promise<Response> {
  try {
    const built = await buildSsoAuthorize(request, env, 'login');
    if (!built) return errorResponse('SSO is not configured', 404);

    const headers = new Headers({
      Location: built.authorizeUrl,
      'Cache-Control': 'no-store',
      Pragma: 'no-cache',
    });
    headers.append('Set-Cookie', built.stateCookie);
    return new Response(null, { status: 302, headers });
  } catch (error) {
    await safeWriteAuditEvent(env, {
      action: 'auth.sso.start.failed',
      category: 'auth',
      level: 'error',
      targetType: 'sso',
      metadata: { reason: 'discovery_failed', error: error instanceof Error ? error.message : String(error), ...auditRequestMetadata(request) },
    });
    return ssoRedirect('/?sso_error=upstream_error', request);
  }
}

/**
 * POST /api/settings/sso/link (authenticated) — starts the explicit account
 * link flow. Binding is authorized by the caller's session, never by email.
 */
export async function handleSsoLinkStart(request: Request, env: Env, userId: string): Promise<Response> {
  try {
    const built = await buildSsoAuthorize(request, env, 'link', { userId });
    if (!built) return errorResponse('SSO is not configured', 404);
    const response = jsonResponse({ authorizeUrl: built.authorizeUrl });
    response.headers.append('Set-Cookie', built.stateCookie);
    return response;
  } catch (error) {
    await safeWriteAuditEvent(env, {
      action: 'auth.sso.link_start.failed',
      category: 'auth',
      level: 'error',
      targetType: 'user',
      targetId: userId,
      metadata: { error: error instanceof Error ? error.message : String(error), ...auditRequestMetadata(request) },
    });
    return errorResponse('Failed to start the SSO link flow', 502);
  }
}

// Bitwarden client SSO entry points -------------------------------------------------

const BITWARDEN_SSO_CLIENT_IDS = new Set(['web', 'cli', 'desktop', 'browser', 'mobile', 'sdk']);
const SSO_REDIRECT_SCHEME_RE = /^bitwarden[a-z-]*:\/\//i;

function isAllowedClientRedirectUri(redirectUri: string): boolean {
  if (redirectUri.startsWith('/') && !redirectUri.startsWith('//')) return true;
  return SSO_REDIRECT_SCHEME_RE.test(redirectUri);
}

/**
 * GET /identity/connect/authorize — front-channel entry of the official
 * Bitwarden client SSO flow. Validates the client request, seals it into the
 * SSO state and redirects to the identity provider (Zitadel).
 */
export async function handleSsoAuthorize(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const clientId = String(url.searchParams.get('client_id') || url.searchParams.get('clientId') || '').toLowerCase();
  const redirectUri = String(url.searchParams.get('redirect_uri') || url.searchParams.get('redirectUri') || '');
  const state = String(url.searchParams.get('state') || '');
  const codeChallenge = String(url.searchParams.get('code_challenge') || url.searchParams.get('codeChallenge') || '');
  const codeChallengeMethod = String(url.searchParams.get('code_challenge_method') || '').toUpperCase();
  const email = String(url.searchParams.get('email') || '').trim().toLowerCase();

  if (!BITWARDEN_SSO_CLIENT_IDS.has(clientId)) {
    return errorResponse('Unknown client_id', 400);
  }
  if (!redirectUri || !isAllowedClientRedirectUri(redirectUri)) {
    return errorResponse('Invalid redirect_uri', 400);
  }
  if (!state || !codeChallenge || codeChallengeMethod !== 'S256') {
    return errorResponse('PKCE code_challenge (S256) and state are required', 400);
  }

  try {
    const built = await buildSsoAuthorize(request, env, 'client_sso', {
      clientId,
      clientState: state,
      clientRedirectUri: redirectUri,
      clientCodeChallenge: codeChallenge,
      clientCodeChallengeMethod: codeChallengeMethod,
      ...(email ? { clientEmail: email } : {}),
    });
    if (!built) return errorResponse('SSO is not configured', 404);

    const headers = new Headers({
      Location: built.authorizeUrl,
      'Cache-Control': 'no-store',
      Pragma: 'no-cache',
    });
    headers.append('Set-Cookie', built.stateCookie);
    return new Response(null, { status: 302, headers });
  } catch (error) {
    await safeWriteAuditEvent(env, {
      action: 'auth.sso.client.authorize.failed',
      category: 'auth',
      level: 'error',
      targetType: 'sso',
      metadata: { error: error instanceof Error ? error.message : String(error), ...auditRequestMetadata(request) },
    });
    return errorResponse('Failed to start the SSO flow', 502);
  }
}

/**
 * GET/POST /api/sso/prevalidate — tells the SSO page whether the identity
 * provider is available for the submitted email domain.
 */
export async function handleSsoPrevalidate(request: Request, env: Env): Promise<Response> {
  let domain = new URL(request.url).searchParams.get('domain') || '';
  if (request.method === 'POST') {
    const body = (await request.json().catch(() => ({}))) as { domain?: string; email?: string };
    domain = body.domain || body.email || domain;
  }
  const normalized = String(domain || '').trim().toLowerCase();
  if (!normalized) return errorResponse('domain is required', 400);

  return identityJsonResponse({
    object: 'ssoPrevalidate',
    ssoAvailable: isSsoEnabled(env),
    ssoIdentifier: 'zitadel',
  });
}

/** GET /api/settings/sso — SSO configuration + link status for the account. */
export async function handleSsoStatus(env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);
  return identityJsonResponse({
    enabled: isSsoEnabled(env),
    linked: Boolean(user.ssoSubject),
    subjectPreview: user.ssoSubject ? `${user.ssoSubject.slice(0, 8)}…` : null,
  });
}

/**
 * DELETE /api/settings/sso — unlink, confirmed with the master password hash.
 * Unlinking re-opens password/passkey login for the account.
 */
export async function handleSsoUnlink(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);
  if (!user.ssoSubject) return errorResponse('SSO is not linked', 400);

  let body: Record<string, string | undefined>;
  try {
    body = (await request.json()) as Record<string, string | undefined>;
  } catch {
    return errorResponse('Invalid JSON', 400);
  }
  const providedHash = String(body.masterPasswordHash || body.master_password_hash || '').trim();
  if (!providedHash) return errorResponse('masterPasswordHash is required', 400);
  if (!(await auth.verifyPassword(providedHash, user.masterPasswordHash, user.email))) {
    return errorResponse('Invalid password', 400);
  }

  user.ssoSubject = null;
  user.updatedAt = new Date().toISOString();
  await storage.saveUser(user);
  AuthService.invalidateUserCache(user.id);
  await safeWriteAuditEvent(env, {
    action: 'auth.sso.unlink',
    category: 'auth',
    level: 'warn',
    targetType: 'user',
    targetId: user.id,
    metadata: { email: user.email, ...auditRequestMetadata(request) },
  });
  return jsonResponse({ ok: true });
}

export async function handleSsoCallback(request: Request, env: Env): Promise<Response> {
  const config = getOidcConfig(env);
  const secret = (env.JWT_SECRET || '').trim();
  if (!config || !secret) {
    return errorResponse('SSO is not configured', 404);
  }

  const url = new URL(request.url);
  const fail = async (reason: string, level: 'info' | 'warn' = 'info'): Promise<Response> => {
    await safeWriteAuditEvent(env, {
      action: `auth.sso.login.failed.${reason}`,
      category: 'auth',
      level,
      targetType: 'sso',
      metadata: { reason, ...auditRequestMetadata(request) },
    });
    return ssoRedirect(`/?sso_error=${encodeURIComponent(reason)}`, request);
  };

  if (url.searchParams.get('error')) return fail('denied');

  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  if (!code || !state) return fail('invalid_request');

  const sealed = parseCookieValue(request, SSO_STATE_COOKIE);
  const payload = sealed ? await unsealSsoState(sealed, secret) : null;
  if (!payload || payload.state !== state || payload.exp < Date.now()) {
    return fail('invalid_state', 'warn');
  }

  let claims: Awaited<ReturnType<typeof verifyIdToken>>;
  try {
    const discovery = await discoverOidc(config.issuer);
    const tokens = await exchangeAuthorizationCode(config, discovery, {
      code,
      redirectUri: `${url.origin}/auth/sso/callback`,
      verifier: payload.verifier,
    });
    claims = await verifyIdToken(config, discovery, tokens.id_token, payload.nonce);
  } catch (error) {
    await safeWriteAuditEvent(env, {
      action: 'auth.sso.login.failed.upstream_error',
      category: 'auth',
      level: 'warn',
      targetType: 'sso',
      metadata: { reason: 'token_exchange_or_verify', error: error instanceof Error ? error.message : String(error), ...auditRequestMetadata(request) },
    });
    return ssoRedirect('/?sso_error=upstream_error', request);
  }

  const storage = new StorageService(env.DB);

  // Official Bitwarden client SSO: resolve the linked account by subject and
  // hand the client a short-lived authorization code via its redirect URI.
  if (payload.purpose === 'client_sso') {
    const redirectUri = payload.clientRedirectUri!;
    const withRedirectParams = (params: Record<string, string>, error?: string) => {
      try {
        const target = new URL(redirectUri, 'https://placeholder.invalid');
        for (const [key, value] of Object.entries(params)) {
          if (value) target.searchParams.set(key, value);
        }
        if (error) target.searchParams.set('error', error);
        return target.toString().replace('https://placeholder.invalid', '') || target.toString();
      } catch {
        return null;
      }
    };
    const deny = async (code: string, reason: string, level: 'info' | 'warn' = 'warn'): Promise<Response> => {
      await safeWriteAuditEvent(env, {
        action: `auth.sso.client.failed.${reason}`,
        category: 'auth',
        level,
        targetType: 'sso',
        metadata: { reason, clientId: payload.clientId ?? null, ...auditRequestMetadata(request) },
      });
      const location = withRedirectParams({ state: payload.clientState ?? '' }, code);
      return location ? ssoRedirect(location, request) : fail(reason, level);
    };

    const user = await storage.getUserBySsoSubject(claims.sub);
    if (!user) return deny('access_denied', 'sso_not_linked');
    if (user.status !== 'active') return deny('access_denied', 'account_disabled');
    if (payload.clientEmail && payload.clientEmail.toLowerCase() !== user.email.toLowerCase()) {
      return deny('access_denied', 'email_mismatch');
    }

    const code = base64UrlFromBytes(crypto.getRandomValues(new Uint8Array(32)));
    const codeHash = await sha256Hex(code);
    const now = Date.now();
    await storage.putSsoAuthorizationCode(codeHash, {
      userId: user.id,
      clientState: payload.clientState ?? null,
      redirectUri,
      codeChallenge: payload.clientCodeChallenge!,
      codeChallengeMethod: payload.clientCodeChallengeMethod!,
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 5 * 60 * 1000).toISOString(),
    });
    await safeWriteAuditEvent(env, {
      action: 'auth.sso.client.code_issued',
      category: 'auth',
      level: 'info',
      targetType: 'user',
      targetId: user.id,
      metadata: { clientId: payload.clientId ?? null, ...auditRequestMetadata(request) },
    });

    const location = withRedirectParams({ code, state: payload.clientState ?? '' });
    if (!location) return deny('access_denied', 'invalid_redirect');
    return ssoRedirect(location, request);
  }

  // Explicit link flow: authorized by the session that started it, never by
  // the IdP email claim. Bind the immutable subject to that exact account.
  if (payload.purpose === 'link') {
    const user = await storage.getUserById(payload.userId!);
    if (!user) return fail('unknown_account', 'warn');
    if (user.status !== 'active') return fail('inactive', 'warn');
    const owner = await storage.getUserBySsoSubject(claims.sub);
    if (owner && owner.id !== user.id) return fail('subject_taken', 'warn');
    if (user.ssoSubject && user.ssoSubject !== claims.sub) {
      return fail('already_linked', 'warn');
    }
    if (user.ssoSubject !== claims.sub) {
      user.ssoSubject = claims.sub;
      user.updatedAt = new Date().toISOString();
      await storage.saveUser(user);
      AuthService.invalidateUserCache(user.id);
      await safeWriteAuditEvent(env, {
        action: 'auth.sso.link',
        category: 'auth',
        level: 'info',
        targetType: 'user',
        targetId: user.id,
        metadata: { email: user.email, subject: claims.sub, ...auditRequestMetadata(request) },
      });
    }
    return ssoRedirect('/?sso_linked=1', request);
  }

  // Login flow: only accounts explicitly linked to this subject may sign in.
  const user = await storage.getUserBySsoSubject(claims.sub);
  if (!user) return fail('sso_not_linked', 'warn');
  if (user.status !== 'active') return fail('inactive', 'warn');

  const deviceInfo = {
    deviceIdentifier: generateUUID(),
    deviceName: 'Zitadel SSO',
    deviceType: 14,
  };
  const deviceSession = await persistAndResolveDeviceSession(storage, user.id, deviceInfo);
  const auth = new AuthService(env);
  const refreshToken = await auth.generateRefreshToken(user, deviceSession, 'web');

  await safeWriteAuditEvent(env, {
    action: 'auth.login.success',
    category: 'auth',
    level: 'info',
    targetType: 'user',
    targetId: user.id,
    metadata: {
      grantType: 'sso_oidc',
      provider: 'zitadel',
      email: user.email,
      deviceIdentifier: deviceSession?.identifier ?? deviceInfo.deviceIdentifier,
      deviceType: deviceInfo.deviceType,
      ...auditRequestMetadata(request),
    },
  });

  return ssoRedirect('/', request, refreshToken);
}

export function checkClientCredentialsParam(clientId: string, clientSecret: string, scope: string): boolean {
  if (scope !== 'api') {
    return false;
  }
  if (!clientId.startsWith('user.')) {
    return false;
  }
  if (!clientSecret) {
    return false;
  }
  return true;
}
