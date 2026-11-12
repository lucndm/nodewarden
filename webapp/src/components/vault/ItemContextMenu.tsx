import { Fragment } from 'preact';
import { createPortal } from 'preact/compat';
import { useEffect, useLayoutEffect, useRef, useState } from 'preact/hooks';
import {
  Archive,
  History,
  KeyRound,
  Lock,
  Mail,
  Pencil,
  Phone,
  RotateCcw,
  ShieldCheck,
  Star,
  Tag,
  Trash2,
  User,
} from 'lucide-preact';
import type { LucideIcon } from 'lucide-preact';
import { t } from '@/lib/i18n';
import { buildItemMenu, type ItemMenuAction, type ItemMenuEntry } from '@/lib/item-menu';
import { isPasswordSecurityExcluded } from '@/lib/password-security-exclusions';
import type { Cipher } from '@/lib/types';

export type { ItemMenuAction };

interface ItemContextMenuProps {
  cipher: Cipher;
  /** Where the pointer was, in viewport coordinates. */
  x: number;
  y: number;
  /** The item sits in the trash, so it can only be restored or removed. */
  trash: boolean;
  /** The member may change the item. */
  canEdit: boolean;
  onAction: (action: ItemMenuAction) => void;
  onClose: () => void;
}

/* The menu keeps a finger's width from the edge of the screen. */
const MENU_EDGE = 8;

const ACTION_ICONS: Record<ItemMenuAction, LucideIcon> = {
  'copy-username': User,
  'copy-password': KeyRound,
  'copy-totp': Lock,
  edit: Pencil,
  'move-to-tag': Tag,
  'toggle-favorite': Star,
  'view-history': History,
  'toggle-archive': Archive,
  'move-to-trash': Trash2,
  'toggle-scan-exclusion': ShieldCheck,
  restore: RotateCcw,
  'delete-permanently': Trash2,
};

/* The copy of a username says what it holds, so its icon says it too. */
function iconFor(entry: ItemMenuEntry): LucideIcon {
  if (entry.action === 'copy-username') {
    if (entry.labelKey === 'txt_copy_email') return Mail;
    if (entry.labelKey === 'txt_copy_phone') return Phone;
  }
  return ACTION_ICONS[entry.action];
}

export default function ItemContextMenu(props: ItemContextMenuProps) {
  const menuRef = useRef<HTMLDivElement | null>(null);
  const [position, setPosition] = useState({ left: props.x, top: props.y });

  const groups = buildItemMenu(props.cipher, {
    trash: props.trash,
    canEdit: props.canEdit,
    scanExcluded: isPasswordSecurityExcluded(props.cipher.id),
  });

  // The menu is measured once it is on the screen, so it can be pulled back
  // into the viewport when it would hang over an edge.
  useLayoutEffect(() => {
    const node = menuRef.current;
    if (!node) return;
    const rect = node.getBoundingClientRect();
    setPosition({
      left: Math.max(MENU_EDGE, Math.min(props.x, window.innerWidth - rect.width - MENU_EDGE)),
      top: Math.max(MENU_EDGE, Math.min(props.y, window.innerHeight - rect.height - MENU_EDGE)),
    });
  }, [props.x, props.y]);

  const menuItems = (): HTMLElement[] =>
    Array.from(menuRef.current?.querySelectorAll<HTMLElement>('[role="menuitem"]') ?? []);

  const focusItem = (index: number): void => {
    const items = menuItems();
    if (!items.length) return;
    items[(index + items.length) % items.length].focus();
  };

  // The first item takes the focus, so the keyboard can walk the menu.
  useEffect(() => {
    focusItem(0);
  }, []);

  // The menu closes when the user clicks away, scrolls the list or resizes the
  // window: the item it belongs to moves out of sight.
  useEffect(() => {
    const onPointerDown = (event: Event) => {
      const target = event.target as Node | null;
      if (target && menuRef.current?.contains(target)) return;
      props.onClose();
    };
    const onScroll = () => props.onClose();
    const onResize = () => props.onClose();
    document.addEventListener('pointerdown', onPointerDown, true);
    window.addEventListener('scroll', onScroll, true);
    window.addEventListener('resize', onResize);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown, true);
      window.removeEventListener('scroll', onScroll, true);
      window.removeEventListener('resize', onResize);
    };
  }, []);

  const onKeyDown = (event: KeyboardEvent) => {
    const items = menuItems();
    if (!items.length) return;
    const active = document.activeElement;
    const current = active instanceof HTMLElement ? items.indexOf(active) : -1;
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      focusItem(current < 0 ? 0 : current + 1);
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      focusItem(current < 0 ? items.length - 1 : current - 1);
    } else if (event.key === 'Home') {
      event.preventDefault();
      focusItem(0);
    } else if (event.key === 'End') {
      event.preventDefault();
      focusItem(items.length - 1);
    } else if (event.key === 'Escape') {
      event.preventDefault();
      props.onClose();
    }
  };

  return createPortal(
    <div
      ref={menuRef}
      className="sort-menu item-context-menu"
      role="menu"
      aria-label={t('txt_item_actions')}
      style={{ left: `${position.left}px`, top: `${position.top}px` }}
      onKeyDown={onKeyDown}
    >
      {groups.map((group, index) => (
        <Fragment key={index}>
          {index > 0 && <div role="separator" className="item-context-menu-sep" />}
          {group.map((entry) => {
            const Icon = iconFor(entry);
            return (
              <button
                key={entry.action}
                type="button"
                role="menuitem"
                className={`sort-menu-item item-context-menu-item ${entry.danger ? 'danger' : ''}`}
                onClick={() => props.onAction(entry.action)}
              >
                <span className="item-context-menu-item-main">
                  <Icon size={16} className="item-context-menu-item-icon" />
                  <span>{t(entry.labelKey)}</span>
                </span>
              </button>
            );
          })}
        </Fragment>
      ))}
    </div>,
    document.body
  );
}
