// The digest of a backup archive's vault rows, in the same shape the
// production audit prints.
//
// The audit reads the live vault and prints a digest of the rows that decide
// the layout. This prints the digest of the same rows in an archive, so the
// two can be compared: an archive whose digest matches the live vault holds
// the same vault, and an archive that passed the restore rehearsal can then
// be tied to the live vault.
//
// Usage:
//   node scripts/backup-archive-digest.mjs <backup.zip>
import { readFileSync } from 'node:fs';
import { unzipSync } from 'fflate';
import { vaultDigest } from './prod-vault-audit.mjs';

const archivePath = process.argv[2];
if (!archivePath) {
  console.error('usage: backup-archive-digest.mjs <backup.zip>');
  process.exit(2);
}

const zip = unzipSync(new Uint8Array(readFileSync(archivePath)));
const db = JSON.parse(Buffer.from(zip['db.json']).toString());
const manifest = JSON.parse(Buffer.from(zip['manifest.json']).toString());

const digest = vaultDigest({
  folders: (db.folders || []).map((row) => ({
    id: row.id,
    user_id: row.user_id,
    name: row.name,
    tag_name: row.tag_name ?? null,
  })),
  ciphers: (db.ciphers || []).map((row) => ({
    id: row.id,
    user_id: row.user_id,
    folder_id: row.folder_id ?? null,
    data: row.data,
  })),
  users: (db.users || []).map((row) => ({
    id: row.id,
    email: row.email,
    role: row.role,
    status: row.status,
  })),
  revisions: db.user_revisions || [],
});

console.log(
  JSON.stringify(
    {
      archive: archivePath,
      exportedAt: manifest.exportedAt,
      accounts: (db.users || []).length,
      folders: (db.folders || []).length,
      items: (db.ciphers || []).length,
      vaultDigest: digest,
    },
    null,
    2
  )
);
