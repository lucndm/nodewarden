import type { GeneratorMode } from '@/lib/password-generator';

// CONTRACT:
// Per-client generator history, mirroring Bitwarden's generator history:
// entries live in memory for the current application session and are cleared
// on logout. History is never synced to the server and never touches
// localStorage — a full page reload clears it, same as the official web vault.

export interface GeneratorHistoryEntry {
  id: string;
  mode: GeneratorMode;
  value: string;
  timestamp: number;
}

const MAX_HISTORY_ENTRIES = 50;

let entries: GeneratorHistoryEntry[] = [];

export function getGeneratorHistory(): readonly GeneratorHistoryEntry[] {
  return entries;
}

export function recordGenerated(mode: GeneratorMode, value: string): void {
  const trimmed = value.trim();
  if (!trimmed) return;
  if (entries[0]?.value === trimmed) return;
  entries = [
    { id: crypto.randomUUID(), mode, value: trimmed, timestamp: Date.now() },
    ...entries,
  ].slice(0, MAX_HISTORY_ENTRIES);
}

export function clearGeneratorHistory(): void {
  entries = [];
}
