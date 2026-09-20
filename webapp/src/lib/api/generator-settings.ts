import { base64ToBytes, decryptStr, encryptBw } from '../crypto';
import { parseJson, type AuthedFetch } from './shared';
import type { SessionState } from '../types';

// Username generator settings that must survive devices: the forwarded-email
// alias account configuration (SimpleLogin-compatible server credentials).
// The payload is encrypted client-side with the user's symmetric key before
// it is stored on the server, mirroring how cipher data is protected. The
// API key never persists as plaintext in localStorage.
export interface ForwardedAliasAccountSettings {
  serverUrl?: string;
  apiKey?: string;
  aliasType?: 'word' | 'uuid' | 'custom';
  prefix?: string;
  note?: string;
}

export interface StoredGeneratorSettings {
  forwarders?: {
    simplelogin?: ForwardedAliasAccountSettings;
  };
}

interface GeneratorSettingsResponse {
  data: string | null;
  updatedAt: string | null;
}

function userKeyPair(session: SessionState): { encKey: Uint8Array; macKey: Uint8Array } | null {
  if (!session.symEncKey || !session.symMacKey) return null;
  return {
    encKey: base64ToBytes(session.symEncKey),
    macKey: base64ToBytes(session.symMacKey),
  };
}

export async function loadGeneratorSettings(
  authedFetch: AuthedFetch,
  session: SessionState,
): Promise<StoredGeneratorSettings | null> {
  const keys = userKeyPair(session);
  if (!keys) return null;
  const response = await authedFetch('/api/settings/generator');
  if (!response.ok) return null;
  const body = await parseJson<GeneratorSettingsResponse>(response);
  if (!body?.data) return null;
  try {
    const text = await decryptStr(body.data, keys.encKey, keys.macKey);
    const parsed = JSON.parse(text) as unknown;
    return parsed && typeof parsed === 'object' ? parsed as StoredGeneratorSettings : null;
  } catch (error) {
    console.warn('[generator-settings] hydrate failed', error);
    return null;
  }
}

export async function saveGeneratorSettings(
  authedFetch: AuthedFetch,
  session: SessionState,
  settings: StoredGeneratorSettings,
): Promise<boolean> {
  const keys = userKeyPair(session);
  if (!keys) return false;
  const data = await encryptBw(
    new TextEncoder().encode(JSON.stringify(settings)),
    keys.encKey,
    keys.macKey,
  );
  const response = await authedFetch('/api/settings/generator', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ data }),
  });
  return response.ok;
}
