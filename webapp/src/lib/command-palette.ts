// The command palette searches the pages of the app, the items of the vault
// and the fields of the items that match. The rules of the search live here,
// so the dialog only has to draw the results. A secret never reaches a label
// or a hint: the results carry the name of a field and never its value.
import { presentField } from '@/lib/field-display';
import { t } from '@/lib/i18n';
import { cipherCanSeeSecrets } from '@/lib/item-menu';
import type { Cipher } from '@/lib/types';

export type PaletteField =
  | { type: 'username' }
  | { type: 'password' }
  | { type: 'totp' }
  | { type: 'uri'; index: number }
  | { type: 'custom'; index: number }
  | { type: 'cardNumber' }
  | { type: 'cardCode' }
  | { type: 'notes' };

export interface PageEntry {
  id: string;
  label: string;
  hint?: string;
  href: string;
  /** The tab of the settings page the entry opens. */
  settingsSection?: string;
}

export type PaletteEntry =
  | ({ kind: 'page' } & PageEntry)
  | { kind: 'item'; id: string; cipherId: string; label: string; hint: string }
  | { kind: 'field'; id: string; cipherId: string; label: string; hint: string; field: PaletteField };

const PAGE_LIMIT = 8;
const ITEM_LIMIT = 20;
const FIELD_LIMIT = 30;

// The built-in fields of an item. The name is the English word of the field,
// so a search finds the field in every language.
const BUILT_IN_FIELDS: Record<'username' | 'password' | 'totp' | 'cardNumber' | 'cardCode' | 'notes', { key: string; name: string }> = {
  username: { key: 'txt_field_kind_username', name: 'username' },
  password: { key: 'txt_password', name: 'password' },
  totp: { key: 'txt_totp', name: 'totp' },
  cardNumber: { key: 'txt_number', name: 'card number' },
  cardCode: { key: 'txt_security_code', name: 'security code card code cvv' },
  notes: { key: 'txt_notes', name: 'notes note' },
};

// The order of the kinds decides which result comes first when two results
// match the search equally well.
const KIND_ORDER: Record<PaletteEntry['kind'], number> = { page: 0, item: 1, field: 2 };

interface Scored {
  score: number;
  entry: PaletteEntry;
}

interface FieldCandidate {
  label: string;
  search: string;
  field: PaletteField;
}

/** Lower case, without diacritics and with the spaces collapsed. */
export function normalizeQuery(text: string): string {
  return String(text ?? '')
    .toLowerCase()
    .replace(/đ/g, 'd')
    .normalize('NFD')
    .replace(/\p{M}/gu, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function hostOf(raw: string): string {
  const text = String(raw || '').trim();
  if (!text) return '';
  const withoutScheme = text.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  return withoutScheme.split(/[/?#]/)[0].trim();
}

function cipherName(cipher: Cipher): string {
  return String(cipher.decName ?? cipher.name ?? '').trim();
}

function cipherUsername(cipher: Cipher): string {
  return String(cipher.login?.decUsername ?? cipher.login?.username ?? '').trim();
}

function cipherHosts(cipher: Cipher): string[] {
  const uris = cipher.login?.uris;
  if (!Array.isArray(uris)) return [];
  return uris.map((uri) => hostOf(String(uri?.decUri ?? uri?.uri ?? ''))).filter(Boolean);
}

function builtInField(type: 'username' | 'password' | 'totp' | 'cardNumber' | 'cardCode' | 'notes'): { label: string; search: string } {
  const entry = BUILT_IN_FIELDS[type];
  const label = t(entry.key);
  return { label, search: normalizeQuery(`${entry.name} ${label}`) };
}

/**
 * The fields of an item that carry a value to copy. A boolean holds a flag
 * and has nothing to copy, so it is left out.
 */
function fieldCandidates(cipher: Cipher): FieldCandidate[] {
  const candidates: FieldCandidate[] = [];
  const login = cipher.login;
  if (login) {
    if (cipherUsername(cipher)) candidates.push({ ...builtInField('username'), field: { type: 'username' } });
    const canSeeSecrets = cipherCanSeeSecrets(cipher);
    if (canSeeSecrets && String(login.decPassword ?? login.password ?? '').trim()) {
      candidates.push({ ...builtInField('password'), field: { type: 'password' } });
    }
    if (canSeeSecrets && String(login.decTotp ?? login.totp ?? '').trim()) {
      candidates.push({ ...builtInField('totp'), field: { type: 'totp' } });
    }
    const uris = Array.isArray(login.uris) ? login.uris : [];
    uris.forEach((uri, index) => {
      const value = String(uri?.decUri ?? uri?.uri ?? '').trim();
      if (!value) return;
      const host = hostOf(value);
      candidates.push({
        label: host ? `${t('txt_website')} · ${host}` : t('txt_website'),
        search: normalizeQuery(`website url ${host}`),
        field: { type: 'uri', index },
      });
    });
  }

  const card = cipher.card;
  if (card) {
    if (String(card.decNumber ?? card.number ?? '').trim()) {
      candidates.push({ ...builtInField('cardNumber'), field: { type: 'cardNumber' } });
    }
    if (String(card.decCode ?? card.code ?? '').trim()) {
      candidates.push({ ...builtInField('cardCode'), field: { type: 'cardCode' } });
    }
  }

  const fields = Array.isArray(cipher.fields) ? cipher.fields : [];
  fields.forEach((field, index) => {
    const type = Number(field?.type) || 0;
    if (type === 2) return;
    const name = String(field?.decName ?? field?.name ?? '').trim();
    if (!name) return;
    // A field with a known kind is shown under its canonical name, a field
    // without one keeps the name it was stored with.
    const presented = presentField(name, type);
    const canonical = presented.labelKey ? t(presented.labelKey) : name;
    candidates.push({
      label: presented.labelKey ? canonical : name,
      search: normalizeQuery(`${name} ${canonical}`),
      field: { type: 'custom', index },
    });
  });

  if (String(cipher.decNotes ?? cipher.notes ?? '').trim()) {
    candidates.push({ ...builtInField('notes'), field: { type: 'notes' } });
  }

  return candidates;
}

/**
 * The score of a candidate: the label starts with the word (0), a word of the
 * label starts with it (1) or the word is somewhere in the text (2). Every
 * word of the query has to be found, otherwise the candidate does not match.
 */
function scoreOf(haystack: string, label: string, terms: string[]): number {
  if (terms.length === 0) return 0;
  const labelText = normalizeQuery(label);
  const labelWords = labelText.split(/[^a-z0-9]+/).filter(Boolean);
  let best = -1;
  for (const term of terms) {
    let score = -1;
    if (labelText.startsWith(term)) score = 0;
    else if (labelWords.some((word) => word.startsWith(term))) score = 1;
    else if (haystack.includes(term)) score = 2;
    if (score < 0) return -1;
    if (best < 0 || score < best) best = score;
  }
  return best;
}

/**
 * The results of a search. An empty query returns the pages only. The pages
 * come first, then the items, then the fields of the items that matched.
 */
export function searchPalette(
  query: string,
  pages: PageEntry[],
  ciphers: Cipher[],
  options?: { limit?: number }
): PaletteEntry[] {
  const terms = normalizeQuery(query).split(' ').filter(Boolean);
  const pageResults: Scored[] = [];
  const itemResults: Scored[] = [];
  const fieldResults: Scored[] = [];

  for (const page of pages) {
    const haystack = normalizeQuery(`${page.label} ${page.hint ?? ''}`);
    const score = scoreOf(haystack, page.label, terms);
    if (score < 0) continue;
    pageResults.push({ score, entry: { kind: 'page', ...page, id: `page:${page.id}` } });
  }

  if (terms.length > 0) {
    for (const cipher of ciphers) {
      // An item in the trash is gone from the vault.
      if (cipher.deletedDate) continue;
      const name = cipherName(cipher);
      const username = cipherUsername(cipher);
      const hosts = cipherHosts(cipher);
      // An item is found by its name, its username and the hosts of its links.
      const haystack = normalizeQuery([name, username, ...hosts].join(' '));
      const score = scoreOf(haystack, name, terms);
      if (score >= 0) {
        itemResults.push({
          score,
          entry: {
            kind: 'item',
            id: `item:${cipher.id}`,
            cipherId: cipher.id,
            label: name,
            hint: [username, hosts[0] || ''].filter(Boolean).join(' · '),
          },
        });
      }
      // The fields of an item the search found are listed, and a field may
      // also carry the word the item itself does not hold.
      if (score < 0 && !terms.some((term) => haystack.includes(term))) continue;
      fieldCandidates(cipher).forEach((candidate, index) => {
        const fieldHaystack = normalizeQuery(`${haystack} ${candidate.search}`);
        const fieldScore = scoreOf(fieldHaystack, candidate.label, terms);
        if (fieldScore < 0) return;
        fieldResults.push({
          score: fieldScore,
          entry: {
            kind: 'field',
            id: `field:${cipher.id}:${candidate.field.type}:${index}`,
            cipherId: cipher.id,
            label: candidate.label,
            hint: name,
            field: candidate.field,
          },
        });
      });
    }
  }

  const byKind = (a: Scored, b: Scored) => KIND_ORDER[a.entry.kind] - KIND_ORDER[b.entry.kind] || a.score - b.score;
  const entries = [
    ...pageResults.sort(byKind).slice(0, PAGE_LIMIT).map((result) => result.entry),
    ...itemResults.sort(byKind).slice(0, ITEM_LIMIT).map((result) => result.entry),
    ...fieldResults.sort(byKind).slice(0, FIELD_LIMIT).map((result) => result.entry),
  ];
  const limit = options?.limit;
  return typeof limit === 'number' && limit >= 0 ? entries.slice(0, limit) : entries;
}
