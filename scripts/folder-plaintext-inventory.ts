// Cutover inventory: for an admin backup archive, list the folder names that
// are still stored as plain text, per account.
//
// A folder row can hold a plain-text name: a Bitwarden JSON export stores
// folder names unencrypted, and older server builds wrote the tag name as-is.
// Official Bitwarden clients parse a folder name as an encrypted string, so
// such a folder shows an empty name there. The Web Vault re-encrypts those
// names with the account key (Import & Export -> Folder compatibility); this
// script answers the question that has to come first: which accounts still
// need that conversion before a cutover.
//
// The archive is read offline. No server is contacted and nothing is uploaded.
// Names are taken from db.json exactly as the server stored them, and the
// classification is the Web Vault's own rule, so the list matches what the
// Folder compatibility page would offer to convert.
//
// Usage:
//   npx tsx scripts/folder-plaintext-inventory.ts <backup.zip> [more.zip ...]
import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import { pathToFileURL } from 'node:url';
import { unzipSync } from 'fflate';

import {
  inspectFolderNames,
  selectPlainTextFolders,
  type FolderNameEntry,
} from '../webapp/src/lib/folder-legacy-encryption';

interface FolderRow {
  id?: string;
  user_id?: string;
  name?: string;
  tag_name?: string | null;
}

interface UserRow {
  id?: string;
  email?: string;
}

export interface InventoryUser {
  id: string;
  email: string;
  folders: number;
  plain: FolderNameEntry[];
}

export interface InventorySummary {
  path: string;
  users: InventoryUser[];
  /** Folder rows whose user_id is not in the archive's users table. */
  orphans: FolderRow[];
  folderRows: number;
}

function readArchive(path: string): { users: UserRow[]; folders: FolderRow[] } {
  let entries: Record<string, Uint8Array>;
  try {
    entries = unzipSync(new Uint8Array(readFileSync(path)));
  } catch (error) {
    throw new Error(`${path}: not a readable backup archive (${error instanceof Error ? error.message : String(error)})`);
  }
  const dbBytes = entries['db.json'];
  if (!dbBytes) throw new Error(`${path}: archive has no db.json`);
  let db: { users?: UserRow[]; folders?: FolderRow[] };
  try {
    db = JSON.parse(new TextDecoder().decode(dbBytes));
  } catch (error) {
    throw new Error(`${path}: db.json is not valid JSON (${error instanceof Error ? error.message : String(error)})`);
  }
  return { users: db.users || [], folders: db.folders || [] };
}

export async function inventoryArchive(path: string): Promise<InventorySummary> {
  const { users, folders } = readArchive(path);

  const byUser = new Map<string, InventoryUser>();
  for (const user of users) {
    const id = String(user.id || '').trim();
    if (!id) continue;
    byUser.set(id, { id, email: String(user.email || '').trim() || '(no email)', folders: 0, plain: [] });
  }

  const orphans: FolderRow[] = [];
  for (const folder of folders) {
    const owner = byUser.get(String(folder.user_id || '').trim());
    if (!owner) {
      // Never drop a row silently: an unreported folder is an unreported
      // conversion, which is the failure this inventory exists to prevent.
      orphans.push(folder);
      continue;
    }
    owner.folders += 1;
    // Same rule as the Web Vault inventory. No account key is available
    // offline, so an encrypted-looking name stays classified by its shape.
    const [entry] = await inspectFolderNames([
      { id: String(folder.id || ''), name: String(folder.name || '') },
    ]);
    // Keep only the entries the Web Vault would offer to convert; encrypted,
    // unreadable and empty names are never candidates.
    if (entry && selectPlainTextFolders([entry]).length) owner.plain.push(entry);
  }

  return {
    path,
    users: [...byUser.values()].sort((a, b) => a.email.localeCompare(b.email)),
    orphans,
    folderRows: folders.length,
  };
}

export function formatInventory(summary: InventorySummary): string {
  const lines = [`${basename(summary.path)}`];
  lines.push(`  users: ${summary.users.length}, folder rows: ${summary.folderRows}`);

  let total = 0;
  for (const user of summary.users) {
    const flagged = user.plain;
    total += flagged.length;
    const suffix = flagged.length ? `  <-- ${flagged.length} need client-side conversion` : '';
    lines.push(`  ${user.email} (${user.id}): ${user.folders} folders, ${flagged.length} plain text${suffix}`);
    for (const entry of flagged) {
      const padded = entry.name !== entry.name.trim() ? ' (has surrounding whitespace)' : '';
      lines.push(`      ${JSON.stringify(entry.name)} [${entry.state}] id=${entry.id}${padded}`);
    }
  }

  if (summary.orphans.length) {
    lines.push(`  ${summary.orphans.length} folder row(s) reference a user missing from the archive:`);
    for (const folder of summary.orphans) {
      lines.push(`      ${JSON.stringify(String(folder.name || ''))} id=${folder.id} user=${folder.user_id}`);
    }
  }

  lines.push(
    total
      ? `  summary: ${total} plain-text folder name(s) across ${summary.users.length} account(s)`
      : '  summary: no plain-text folder names; nothing to convert'
  );
  return lines.join('\n');
}

async function main(paths: string[]): Promise<void> {
  if (!paths.length) {
    console.error('usage: npx tsx scripts/folder-plaintext-inventory.ts <backup.zip> [more.zip ...]');
    process.exitCode = 2;
    return;
  }
  for (const path of paths) {
    try {
      console.log(`\n${formatInventory(await inventoryArchive(path))}`);
    } catch (error) {
      console.error(`FAIL: ${error instanceof Error ? error.message : String(error)}`);
      process.exitCode = 1;
    }
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  await main(process.argv.slice(2));
}
