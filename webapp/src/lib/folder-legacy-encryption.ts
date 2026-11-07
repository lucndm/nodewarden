// A folder row can carry a plain-text name: a Bitwarden JSON export stores
// folder names unencrypted, and older server builds wrote the tag name as-is.
// Official Bitwarden clients parse a folder name as an encrypted string, so such
// a folder shows up with an empty name there. The Web Vault still knows the
// plain text and holds the account key, so it can re-encrypt the name in place:
// the folder id, its tag and the items inside it stay exactly as they are.
//
// The inventory only reads the raw server name. A name that decrypts with the
// account key, or that still looks like an encrypted string, is never touched:
// re-encrypting it would destroy the only copy of that name.
import { base64ToBytes, decryptStr } from './crypto';
import { looksLikeCipherString } from './app-support';
import type { Folder } from './types';

// The server stores a tag name with at most 64 characters.
export const MAX_TAG_NAME_LENGTH = 64;

export type FolderNameState =
  | 'plaintext'
  | 'encrypted'
  | 'unreadable'
  | 'too_long'
  | 'padded'
  | 'empty';

export interface FolderNameEntry {
  id: string;
  /** The exact stored name, without trimming. */
  name: string;
  state: FolderNameState;
}

export interface FolderKeyParts {
  encB64: string;
  macB64: string;
}

/** Why a folder must not be rewritten. */
export type FolderSkipReason = 'tag_mismatch' | 'padded' | 'too_long';

export type FolderRewriteDecision =
  | { action: 'write' }
  | { action: 'skip'; reason: FolderSkipReason };

/**
 * Decides whether a folder name may be replaced by its encrypted form.
 *
 * The server keeps the tag of a folder in `tag_name` and falls back to the
 * stored name when it is empty. It also trims and truncates the tag name it
 * receives. A rewrite is therefore only safe when the tag that comes out is
 * the same tag that was there before:
 *
 * - a name with leading or trailing spaces would be trimmed into a different
 *   tag, and a name longer than a tag would be cut short - both rename the tag
 *   on every item that carries it;
 * - a folder whose tag already differs from its name keeps that tag: rewriting
 *   it would rename the tag.
 */
export function decideFolderRewrite(
  storedName: string,
  currentTag: string | null | undefined
): FolderRewriteDecision {
  const tag = String(currentTag || '').trim();
  if (storedName !== storedName.trim()) return { action: 'skip', reason: 'padded' };
  if (storedName.length > MAX_TAG_NAME_LENGTH) return { action: 'skip', reason: 'too_long' };
  if (tag && tag !== storedName) return { action: 'skip', reason: 'tag_mismatch' };
  return { action: 'write' };
}

/**
 * Lists the folders whose stored name is plain text. The name is taken from
 * the raw server field, never from a decrypted copy.
 */
export async function inspectFolderNames(
  folders: readonly Folder[],
  key?: FolderKeyParts | null
): Promise<FolderNameEntry[]> {
  const enc = key?.encB64 ? base64ToBytes(key.encB64) : null;
  const mac = key?.macB64 ? base64ToBytes(key.macB64) : null;
  const entries: FolderNameEntry[] = [];

  for (const folder of folders) {
    const raw = String(folder.name || '');
    if (!raw.trim()) {
      entries.push({ id: folder.id, name: raw, state: 'empty' });
      continue;
    }
    if (enc && mac) {
      try {
        await decryptStr(raw, enc, mac);
        entries.push({ id: folder.id, name: raw, state: 'encrypted' });
        continue;
      } catch {
        // Not decryptable with this key: fall through to the shape check.
      }
    }
    if (looksLikeCipherString(raw)) {
      entries.push({ id: folder.id, name: raw, state: 'unreadable' });
      continue;
    }
    if (raw !== raw.trim()) {
      entries.push({ id: folder.id, name: raw, state: 'padded' });
      continue;
    }
    if (raw.length > MAX_TAG_NAME_LENGTH) {
      entries.push({ id: folder.id, name: raw, state: 'too_long' });
      continue;
    }
    entries.push({ id: folder.id, name: raw, state: 'plaintext' });
  }

  return entries;
}

/** The folders that still hold a plain-text name. */
export function selectPlainTextFolders(entries: readonly FolderNameEntry[]): FolderNameEntry[] {
  return entries.filter(
    (entry) => entry.state === 'plaintext' || entry.state === 'too_long' || entry.state === 'padded'
  );
}

export interface FolderConversionOutcome {
  status: 'converted' | 'skipped';
  reason?: string;
}

export interface FolderConversionIssue {
  id: string;
  name: string;
  reason: string;
}

export interface FolderConversionResult {
  converted: number;
  skipped: FolderConversionIssue[];
  failed: FolderConversionIssue[];
}

/**
 * Converts every listed plain-text name on its own. One failure never stops the
 * rest, and a failed or skipped folder keeps its id, tag and name, so the run
 * can be retried without touching anything that already worked.
 */
export async function convertPlaintextFolderNames(
  entries: readonly FolderNameEntry[],
  convert: (entry: FolderNameEntry) => Promise<FolderConversionOutcome>
): Promise<FolderConversionResult> {
  const result: FolderConversionResult = { converted: 0, skipped: [], failed: [] };

  for (const entry of entries) {
    try {
      const outcome = await convert(entry);
      if (outcome.status === 'converted') {
        result.converted += 1;
      } else {
        result.skipped.push({ id: entry.id, name: entry.name, reason: outcome.reason || '' });
      }
    } catch (error) {
      result.failed.push({
        id: entry.id,
        name: entry.name,
        reason: error instanceof Error ? error.message : String(error || ''),
      });
    }
  }

  return result;
}
