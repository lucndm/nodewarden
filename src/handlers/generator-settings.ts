import type { Env } from '../types';
import { StorageService } from '../services/storage';
import { errorResponse, jsonResponse } from '../utils/response';

// CONTRACT:
// The username generator's forwarded-email-alias configuration is stored as a
// single opaque blob that the web vault encrypts client-side with the user's
// symmetric key. The server never receives the forwarder API key in plaintext
// and treats `data` as an opaque string (same trust model as cipher data).
const MAX_GENERATOR_SETTINGS_BYTES = 16 * 1024;

export async function handleGetGeneratorSettings(env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const settings = await storage.getUserGeneratorSettings(userId);
  return jsonResponse({ data: settings?.data ?? null, updatedAt: settings?.updatedAt ?? null });
}

export async function handleUpdateGeneratorSettings(
  request: Request,
  env: Env,
  userId: string
): Promise<Response> {
  let payload: unknown;
  try {
    payload = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400);
  }
  const data = payload && typeof payload === 'object' && !Array.isArray(payload)
    ? (payload as Record<string, unknown>).data
    : undefined;
  if (typeof data !== 'string' || data.length === 0) {
    return errorResponse('data is required', 400);
  }
  if (data.length > MAX_GENERATOR_SETTINGS_BYTES) {
    return errorResponse('data is too large', 413);
  }

  const storage = new StorageService(env.DB);
  await storage.saveUserGeneratorSettings(userId, data);
  const settings = await storage.getUserGeneratorSettings(userId);
  return jsonResponse({ data: settings?.data ?? data, updatedAt: settings?.updatedAt ?? null });
}
