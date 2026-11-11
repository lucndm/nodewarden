import { AuthService } from '../services/auth';
import { StorageService } from '../services/storage';
import { isAuthRequestExpired } from '../services/storage-auth-request-repo';
import type { Env, JWTPayload } from '../types';
import { errorResponse, jsonResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import {
  createWebSocketConnectionToken,
  verifyWebSocketConnectionToken,
} from '../utils/websocket-connection-token';

const WEBSOCKET_CONNECTION_TOKEN_TTL_MS = 60 * 1000;
const LOGGED_USER_AGENT_MAX_LENGTH = 120;

// The Durable Object would not take the ticket it was offered: the client is
// told to come back later, instead of seeing a server error.
class HubRefusedTicketError extends Error {
  readonly status: number;

  constructor(status: number) {
    super('The notifications hub refused the websocket connection token');
    this.status = status;
  }
}

function extractAccessToken(request: Request): string | null {
  const authHeader = String(request.headers.get('Authorization') || '').trim();
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  return match?.[1]?.trim() || null;
}

async function authenticateAccessToken(request: Request, env: Env): Promise<JWTPayload | null> {
  const accessToken = extractAccessToken(request);
  if (!accessToken) return null;

  const auth = new AuthService(env);
  return auth.verifyAccessToken(`Bearer ${accessToken}`);
}

async function issueWebSocketConnectionToken(payload: JWTPayload, env: Env): Promise<string> {
  const expiresAt = Date.now() + WEBSOCKET_CONNECTION_TOKEN_TTL_MS;
  const token = await createWebSocketConnectionToken(payload.sub, expiresAt, env.JWT_SECRET);
  const id = env.NOTIFICATIONS_HUB.idFromName(payload.sub);
  const stub = env.NOTIFICATIONS_HUB.get(id);
  const response = await stub.fetch('https://notifications/internal/ws-token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      token,
      userId: payload.sub,
      deviceIdentifier: payload.did || null,
      expiresAt,
    }),
  });
  if (!response.ok) {
    if (response.status === 400) throw new HubRefusedTicketError(response.status);
    throw new Error('Failed to issue websocket connection token');
  }
  return token;
}

async function consumeWebSocketConnectionToken(request: Request, env: Env): Promise<JWTPayload | null> {
  const token = String(new URL(request.url).searchParams.get('id') || '').trim();
  const claims = await verifyWebSocketConnectionToken(token, env.JWT_SECRET);
  if (!claims) return null;

  // Verify the signed routing claim before selecting a Durable Object. Otherwise an
  // attacker could activate arbitrary object names with forged token prefixes.
  const id = env.NOTIFICATIONS_HUB.idFromName(claims.userId);
  const stub = env.NOTIFICATIONS_HUB.get(id);
  const response = await stub.fetch('https://notifications/internal/ws-token/consume', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token }),
  });
  if (!response.ok) return null;

  const connection = (await response.json().catch(() => null)) as {
    userId?: string;
    deviceIdentifier?: string | null;
  } | null;
  if (connection?.userId !== claims.userId) return null;

  return {
    sub: claims.userId,
    did: String(connection.deviceIdentifier || '').trim() || undefined,
  } as JWTPayload;
}

async function authenticateNotificationsHub(request: Request, env: Env): Promise<JWTPayload | null> {
  if (request.headers.has('Authorization')) {
    return authenticateAccessToken(request, env);
  }
  // The official clients open the hub straight over WebSocket, without the
  // negotiate step, and a browser cannot set headers on a WebSocket: the
  // SignalR client puts the access token in the query, and vaultwarden
  // accepts it there. Query strings are redacted from the Worker's logs and
  // traces (wrangler.toml), and the token is dropped before the request goes
  // on to the Durable Object.
  const queryToken = String(new URL(request.url).searchParams.get('access_token') || '').trim();
  if (queryToken) {
    return new AuthService(env).verifyAccessToken(`Bearer ${queryToken}`);
  }
  return consumeWebSocketConnectionToken(request, env);
}

export async function handleNotificationsNegotiate(request: Request, env: Env): Promise<Response> {
  const payload = await authenticateAccessToken(request, env);
  if (!payload?.sub) return errorResponse('Unauthorized', 401);

  let connectionToken: string;
  try {
    connectionToken = await issueWebSocketConnectionToken(payload, env);
  } catch (error) {
    if (!(error instanceof HubRefusedTicketError)) throw error;
    // The client that keeps retrying shows up here; the ticket itself is
    // never written to the log.
    const userAgent = request.headers.get('User-Agent');
    console.warn('notifications.negotiate.refused', JSON.stringify({
      status: error.status,
      userAgent: userAgent ? userAgent.slice(0, LOGGED_USER_AGENT_MAX_LENGTH) : null,
    }));
    const unavailable = errorResponse('Notifications are temporarily unavailable', 503);
    unavailable.headers.set('Retry-After', '5');
    return unavailable;
  }

  return jsonResponse(
    {
      connectionId: generateUUID(),
      connectionToken,
      negotiateVersion: 1,
      availableTransports: [
        {
          transport: 'WebSockets',
          transferFormats: ['Text', 'Binary'],
        },
      ],
    },
    200,
    { 'Cache-Control': 'no-store' }
  );
}

export async function handleNotificationsHub(request: Request, env: Env): Promise<Response> {
  if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
    return errorResponse('Expected websocket', 426);
  }
  const payload = await authenticateNotificationsHub(request, env);
  if (!payload?.sub) return errorResponse('Unauthorized', 401);

  const userId = payload.sub;
  const id = env.NOTIFICATIONS_HUB.idFromName(userId);
  const stub = env.NOTIFICATIONS_HUB.get(id);
  const forwardedUrl = new URL(request.url);
  forwardedUrl.searchParams.delete('access_token');
  forwardedUrl.searchParams.set('nw_uid', userId);
  if (payload.did) {
    forwardedUrl.searchParams.set('nw_did', payload.did);
  }
  return stub.fetch(new Request(forwardedUrl.toString(), request));
}

export async function handleAnonymousNotificationsHub(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const authRequestId = String(url.searchParams.get('Token') || url.searchParams.get('token') || '').trim();
  if (!authRequestId) return errorResponse('Token is required', 400);
  if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
    return errorResponse('Expected websocket', 426);
  }

  const storage = new StorageService(env.DB);
  const authRequest = await storage.getAuthRequestById(authRequestId);
  if (!authRequest || isAuthRequestExpired(authRequest)) {
    return errorResponse('Not found', 404);
  }

  const id = env.NOTIFICATIONS_HUB.idFromName(authRequestId);
  const stub = env.NOTIFICATIONS_HUB.get(id);
  const forwardedUrl = new URL(request.url);
  forwardedUrl.searchParams.set('nw_auth_request_id', authRequestId);
  return stub.fetch(new Request(forwardedUrl.toString(), request));
}
