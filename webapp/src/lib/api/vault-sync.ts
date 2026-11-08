import type { Cipher, Folder, Send } from '../types';
import { getVaultRevisionDate } from './auth';
import { clearCachedVaultCoreSnapshot, loadCachedVaultCoreSnapshot, saveCachedVaultCoreSnapshot, type VaultCoreSnapshot } from '../vault-cache';
import { parseJson, type AuthedFetch } from './shared';

interface VaultSyncResponse {
  ciphers?: Cipher[];
  folders?: Folder[];
  sends?: Send[];
  profile?: { organizations?: Array<{ id?: string; key?: string | null }> };
}

// The pending request is kept in a wrapper so that concurrent callers can
// share the same promise without comparing promises by identity.
interface PendingVaultCoreRequest {
  promise: Promise<VaultCoreSnapshot>;
}

const pendingVaultCoreRequests = new Map<string, PendingVaultCoreRequest>();
const memoryVaultCoreCache = new Map<string, { revisionStamp: number; snapshot: VaultCoreSnapshot }>();

function normalizeSnapshot(body: VaultSyncResponse | null | undefined): VaultCoreSnapshot {
  return {
    ciphers: Array.isArray(body?.ciphers) ? body!.ciphers! : [],
    folders: Array.isArray(body?.folders) ? body!.folders! : [],
    sends: Array.isArray(body?.sends) ? body!.sends! : [],
    organizations: Array.isArray(body?.profile?.organizations)
      ? body!.profile!.organizations!.map((organization) => ({
          id: String(organization?.id || ''),
          key: typeof organization?.key === 'string' ? organization.key : null,
        }))
      : [],
  };
}

function normalizeCachedSnapshot(snapshot: Partial<VaultCoreSnapshot> | null | undefined): VaultCoreSnapshot {
  return {
    ciphers: Array.isArray(snapshot?.ciphers) ? snapshot.ciphers : [],
    folders: Array.isArray(snapshot?.folders) ? snapshot.folders : [],
    sends: Array.isArray(snapshot?.sends) ? snapshot.sends : [],
    organizations: Array.isArray(snapshot?.organizations) ? snapshot.organizations : [],
  };
}

export async function getCachedVaultCoreSnapshot(cacheKey: string): Promise<VaultCoreSnapshot | null> {
  const normalizedKey = String(cacheKey || '').trim();
  if (!normalizedKey) return null;
  const memory = memoryVaultCoreCache.get(normalizedKey);
  if (memory) return memory.snapshot;
  const cached = await loadCachedVaultCoreSnapshot(normalizedKey);
  if (!cached?.snapshot) return null;
  const snapshot = normalizeCachedSnapshot(cached.snapshot);
  memoryVaultCoreCache.set(normalizedKey, {
    revisionStamp: cached.revisionStamp,
    snapshot,
  });
  return snapshot;
}

export async function invalidateVaultCoreSyncSnapshot(cacheKey: string): Promise<void> {
  const normalizedKey = String(cacheKey || '').trim();
  if (!normalizedKey) return;
  pendingVaultCoreRequests.delete(normalizedKey);
  memoryVaultCoreCache.delete(normalizedKey);
  await clearCachedVaultCoreSnapshot(normalizedKey);
}

export async function saveVaultCoreSyncSnapshot(
  cacheKey: string,
  snapshot: VaultCoreSnapshot,
  revisionStamp?: number | null
): Promise<void> {
  const normalizedKey = String(cacheKey || '').trim();
  if (!normalizedKey) return;

  const normalizedSnapshot = normalizeCachedSnapshot(snapshot);
  const currentMemory = memoryVaultCoreCache.get(normalizedKey);
  let nextRevisionStamp = Number(revisionStamp);
  if (!Number.isFinite(nextRevisionStamp) || nextRevisionStamp <= 0) {
    const cached = await loadCachedVaultCoreSnapshot(normalizedKey);
    nextRevisionStamp = currentMemory?.revisionStamp || cached?.revisionStamp || Date.now();
  }

  memoryVaultCoreCache.set(normalizedKey, {
    revisionStamp: nextRevisionStamp,
    snapshot: normalizedSnapshot,
  });
  await saveCachedVaultCoreSnapshot(normalizedKey, nextRevisionStamp, normalizedSnapshot);
}

export async function loadVaultCoreSyncSnapshot(authedFetch: AuthedFetch, cacheKey: string): Promise<VaultCoreSnapshot> {
  const normalizedKey = String(cacheKey || '').trim();
  if (!normalizedKey) return { ciphers: [], folders: [], sends: [] };

  const existing = pendingVaultCoreRequests.get(normalizedKey);
  if (existing) return existing.promise;

  const request = (async () => {
    const memory = memoryVaultCoreCache.get(normalizedKey);
    let cached = await loadCachedVaultCoreSnapshot(normalizedKey);
    if (!memory && cached?.snapshot) {
      const snapshot = normalizeCachedSnapshot(cached.snapshot);
      memoryVaultCoreCache.set(normalizedKey, {
        revisionStamp: cached.revisionStamp,
        snapshot,
      });
    }

    try {
      const revisionStamp = await getVaultRevisionDate(authedFetch);
      const currentMemory = memoryVaultCoreCache.get(normalizedKey);
      if (currentMemory?.revisionStamp === revisionStamp) {
        return currentMemory.snapshot;
      }

      if (!cached) {
        cached = await loadCachedVaultCoreSnapshot(normalizedKey);
      }
      if (cached?.revisionStamp === revisionStamp && cached.snapshot) {
        const snapshot = normalizeCachedSnapshot(cached.snapshot);
        memoryVaultCoreCache.set(normalizedKey, {
          revisionStamp,
          snapshot,
        });
        return snapshot;
      }

      const resp = await authedFetch('/api/sync', {
        cache: 'no-store',
        headers: {
          'Cache-Control': 'no-cache',
          Pragma: 'no-cache',
        },
      });
      if (!resp.ok) throw new Error('Failed to load vault');
      const body = await parseJson<VaultSyncResponse>(resp);
      const snapshot = normalizeSnapshot(body);
      memoryVaultCoreCache.set(normalizedKey, { revisionStamp, snapshot });
      void saveCachedVaultCoreSnapshot(normalizedKey, revisionStamp, snapshot);
      return snapshot;
    } catch (error) {
      const fallbackMemory = memoryVaultCoreCache.get(normalizedKey);
      if (fallbackMemory?.snapshot) return fallbackMemory.snapshot;
      if (cached?.snapshot) return normalizeCachedSnapshot(cached.snapshot);
      throw error;
    }
  })();

  const entry: PendingVaultCoreRequest = { promise: request };
  pendingVaultCoreRequests.set(normalizedKey, entry);
  try {
    return await request;
  } finally {
    if (pendingVaultCoreRequests.get(normalizedKey) === entry) {
      pendingVaultCoreRequests.delete(normalizedKey);
    }
  }
}
