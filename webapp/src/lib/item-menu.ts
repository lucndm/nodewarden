// The actions the context menu of a list item offers. The list is built from
// the item itself, so the menu, the page and the tests agree on what an item
// can do.
import { usernameKind } from '@/lib/field-display';
import type { Cipher } from '@/lib/types';

export type ItemMenuAction =
  | 'copy-username'
  | 'copy-password'
  | 'copy-totp'
  | 'edit'
  | 'move-to-tag'
  | 'toggle-favorite'
  | 'view-history'
  | 'toggle-archive'
  | 'move-to-trash'
  | 'toggle-scan-exclusion'
  | 'restore'
  | 'delete-permanently';

export interface ItemMenuEntry {
  action: ItemMenuAction;
  labelKey: string;
  danger?: boolean;
}

/* Whether the member may change the item. A shared item the member may only
   read carries the flag from the server. */
export function cipherCanEdit(cipher: Cipher): boolean {
  if ('edit' in cipher && typeof cipher.edit === 'boolean') return cipher.edit;
  return true;
}

/* Whether the member may see the secrets of the item. */
export function cipherCanSeeSecrets(cipher: Cipher): boolean {
  if ('viewPassword' in cipher && typeof cipher.viewPassword === 'boolean') return cipher.viewPassword;
  return true;
}

/* Whether the item sits in the archive. */
export function cipherIsArchived(cipher: Cipher): boolean {
  if (cipher.archivedDate) return true;
  if ('archivedAt' in cipher && typeof cipher.archivedAt === 'string') return !!cipher.archivedAt;
  return false;
}

/**
 * The entries of the context menu of an item, grouped the way the menu shows
 * them: the copies, the actions on the item, and the rest.
 */
export function buildItemMenu(
  cipher: Cipher,
  options: { trash: boolean; canEdit: boolean; scanExcluded: boolean }
): ItemMenuEntry[][] {
  // An item in the trash can only come back or go away for good.
  if (options.trash) {
    return [
      [{ action: 'restore', labelKey: 'txt_restore' }],
      [{ action: 'delete-permanently', labelKey: 'txt_delete_permanently', danger: true }],
    ];
  }

  const groups: ItemMenuEntry[][] = [];

  // An item the member may only read never offers an action that changes it.
  const canEdit = options.canEdit && cipherCanEdit(cipher);

  const copies: ItemMenuEntry[] = [];
  const username = String(cipher.login?.decUsername || '').trim();
  if (username) {
    const kind = usernameKind(username);
    copies.push({
      action: 'copy-username',
      labelKey: kind === 'email' ? 'txt_copy_email' : kind === 'phone' ? 'txt_copy_phone' : 'txt_copy_username',
    });
  }
  // A field that was not decrypted holds no value to copy.
  const password = String(cipher.login?.decPassword || '').trim();
  const totp = String(cipher.login?.decTotp || '').trim();
  const maySeeSecrets = cipherCanSeeSecrets(cipher);
  if (maySeeSecrets && password) {
    copies.push({ action: 'copy-password', labelKey: 'txt_copy_password' });
  }
  if (maySeeSecrets && totp) {
    copies.push({ action: 'copy-totp', labelKey: 'txt_copy_verification_code' });
  }
  if (copies.length) groups.push(copies);

  const actions: ItemMenuEntry[] = [];
  if (canEdit) {
    actions.push({ action: 'edit', labelKey: 'txt_edit' });
    actions.push({ action: 'move-to-tag', labelKey: 'txt_move_to_tag' });
    actions.push({
      action: 'toggle-favorite',
      labelKey: cipher.favorite ? 'txt_remove_from_favorites' : 'txt_add_to_favorites',
    });
  }
  actions.push({ action: 'view-history', labelKey: 'txt_view_history' });
  groups.push(actions);

  const rest: ItemMenuEntry[] = [];
  if (canEdit) {
    rest.push({ action: 'toggle-archive', labelKey: cipherIsArchived(cipher) ? 'txt_unarchive' : 'txt_archive' });
    rest.push({ action: 'move-to-trash', labelKey: 'txt_move_to_trash', danger: true });
  }
  rest.push({
    action: 'toggle-scan-exclusion',
    labelKey: options.scanExcluded ? 'txt_scan_include_again' : 'txt_scan_exclude',
  });
  groups.push(rest);

  return groups;
}
