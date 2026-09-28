import { useMemo } from 'preact/hooks';
import {
  Archive,
  BookUser,
  Copy,
  CreditCard,
  Globe,
  IdCard,
  KeyRound,
  Landmark,
  LayoutGrid,
  Pencil,
  ShieldUser,
  ShieldCheck,
  Star,
  StickyNote,
  Tag,
  TagX,
  Trash2,
  X,
} from 'lucide-preact';
import { Link } from 'wouter';
import { t } from '@/lib/i18n';
import type { SidebarFilter } from '@/components/vault/vault-page-helpers';

export interface SidebarTag {
  tag: string;
  count: number;
  folderId: string;
}

interface VaultSidebarProps {
  tags: SidebarTag[];
  sidebarFilter: SidebarFilter;
  busy: boolean;
  isMobileLayout: boolean;
  mobileSidebarOpen: boolean;
  onCloseMobileSidebar: () => void;
  onChangeFilter: (filter: SidebarFilter) => void;
  onOpenDeleteAllTags: () => void;
  onOpenCreateTag: () => void;
  onOpenRenameTag: (tag: SidebarTag) => void;
  onOpenDeleteTag: (tag: SidebarTag) => void;
}

export default function VaultSidebar(props: VaultSidebarProps) {
  const nameCollator = useMemo(
    () => new Intl.Collator(undefined, { sensitivity: 'base', numeric: true }),
    []
  );
  const sortedTags = useMemo(() => {
    const sorted = [...props.tags];
    sorted.sort((a, b) => nameCollator.compare(a.tag, b.tag) || a.tag.localeCompare(b.tag));
    return sorted;
  }, [props.tags, nameCollator]);

  return (
    <aside className={`sidebar ${props.isMobileLayout ? 'mobile-sidebar-sheet' : ''} ${props.isMobileLayout && props.mobileSidebarOpen ? 'open' : ''}`}>
      {props.isMobileLayout && (
        <div className="mobile-sidebar-head">
          <div className="mobile-sidebar-title">{t('txt_tags')}</div>
          <button type="button" className="mobile-sidebar-close" onClick={props.onCloseMobileSidebar} aria-label={t('txt_close')}>
            <X size={16} />
          </button>
        </div>
      )}
      <div className="sidebar-block">
        <Link href="/security/password-health" className="tree-btn">
          <ShieldCheck size={14} className="tree-icon" /> <span className="tree-label">{t('nav_password_security')}</span>
        </Link>
        <button type="button" className={`tree-btn ${props.sidebarFilter.kind === 'all' ? 'active' : ''}`} onClick={() => props.onChangeFilter({ kind: 'all' })}>
          <LayoutGrid size={14} className="tree-icon" /> <span className="tree-label">{t('txt_all_items')}</span>
        </button>
        <button type="button" className={`tree-btn ${props.sidebarFilter.kind === 'favorite' ? 'active' : ''}`} onClick={() => props.onChangeFilter({ kind: 'favorite' })}>
          <Star size={14} className="tree-icon" /> <span className="tree-label">{t('txt_favorites')}</span>
        </button>
        <button type="button" className={`tree-btn ${props.sidebarFilter.kind === 'archive' ? 'active' : ''}`} onClick={() => props.onChangeFilter({ kind: 'archive' })}>
          <Archive size={14} className="tree-icon" /> <span className="tree-label">{t('txt_archive')}</span>
        </button>
        <button type="button" className={`tree-btn ${props.sidebarFilter.kind === 'trash' ? 'active' : ''}`} onClick={() => props.onChangeFilter({ kind: 'trash' })}>
          <Trash2 size={14} className="tree-icon" /> <span className="tree-label">{t('txt_trash')}</span>
        </button>
        <button type="button" className={`tree-btn ${props.sidebarFilter.kind === 'duplicates' ? 'active' : ''}`} onClick={() => props.onChangeFilter({ kind: 'duplicates' })}>
          <Copy size={14} className="tree-icon" /> <span className="tree-label">{t('txt_duplicates')}</span>
        </button>
      </div>

      <div className="sidebar-block">
        <div className="sidebar-title">{t('txt_type')}</div>
        <button type="button" className={`tree-btn ${props.sidebarFilter.kind === 'type' && props.sidebarFilter.value === 'login' ? 'active' : ''}`} onClick={() => props.onChangeFilter({ kind: 'type', value: 'login' })}>
          <Globe size={14} className="tree-icon" /> <span className="tree-label">{t('txt_login')}</span>
        </button>
        <button type="button" className={`tree-btn ${props.sidebarFilter.kind === 'type' && props.sidebarFilter.value === 'card' ? 'active' : ''}`} onClick={() => props.onChangeFilter({ kind: 'type', value: 'card' })}>
          <CreditCard size={14} className="tree-icon" /> <span className="tree-label">{t('txt_card')}</span>
        </button>
        <button type="button" className={`tree-btn ${props.sidebarFilter.kind === 'type' && props.sidebarFilter.value === 'bank' ? 'active' : ''}`} onClick={() => props.onChangeFilter({ kind: 'type', value: 'bank' })}>
          <Landmark size={14} className="tree-icon" /> <span className="tree-label">{t('txt_bank_account')}</span>
        </button>
        <button type="button" className={`tree-btn ${props.sidebarFilter.kind === 'type' && props.sidebarFilter.value === 'identity' ? 'active' : ''}`} onClick={() => props.onChangeFilter({ kind: 'type', value: 'identity' })}>
          <ShieldUser size={14} className="tree-icon" /> <span className="tree-label">{t('txt_identity')}</span>
        </button>
        <button type="button" className={`tree-btn ${props.sidebarFilter.kind === 'type' && props.sidebarFilter.value === 'license' ? 'active' : ''}`} onClick={() => props.onChangeFilter({ kind: 'type', value: 'license' })}>
          <IdCard size={14} className="tree-icon" /> <span className="tree-label">{t('txt_drivers_license')}</span>
        </button>
        <button type="button" className={`tree-btn ${props.sidebarFilter.kind === 'type' && props.sidebarFilter.value === 'passport' ? 'active' : ''}`} onClick={() => props.onChangeFilter({ kind: 'type', value: 'passport' })}>
          <BookUser size={14} className="tree-icon" /> <span className="tree-label">{t('txt_passport')}</span>
        </button>
        <button type="button" className={`tree-btn ${props.sidebarFilter.kind === 'type' && props.sidebarFilter.value === 'note' ? 'active' : ''}`} onClick={() => props.onChangeFilter({ kind: 'type', value: 'note' })}>
          <StickyNote size={14} className="tree-icon" /> <span className="tree-label">{t('txt_note')}</span>
        </button>
        <button type="button" className={`tree-btn ${props.sidebarFilter.kind === 'type' && props.sidebarFilter.value === 'ssh' ? 'active' : ''}`} onClick={() => props.onChangeFilter({ kind: 'type', value: 'ssh' })}>
          <KeyRound size={14} className="tree-icon" /> <span className="tree-label">{t('txt_ssh_key')}</span>
        </button>
      </div>

      <div className="sidebar-block">
        <div className="sidebar-title-row">
          <div className="sidebar-title">{t('txt_tags')}</div>
          <div className="folder-title-actions">
            <button
              type="button"
              className="folder-delete-btn"
              title={t('txt_delete_all_tags')}
              aria-label={t('txt_delete_all_tags')}
              disabled={props.busy || props.tags.length === 0}
              onClick={props.onOpenDeleteAllTags}
            >
              <X size={14} />
            </button>
            <button type="button" className="folder-add-btn" onClick={props.onOpenCreateTag}>
              <Tag size={14} />
            </button>
          </div>
        </div>
        <button
          type="button"
          className={`tree-btn ${props.sidebarFilter.kind === 'untagged' ? 'active' : ''}`}
          onClick={() => props.onChangeFilter({ kind: 'untagged' })}
        >
          <TagX size={14} className="tree-icon" /> <span className="tree-label">{t('txt_untagged')}</span>
        </button>
        {sortedTags.map(({ tag, count, folderId }) => (
          <div key={folderId || tag} className="folder-row">
            <button
              type="button"
              className={`tree-btn ${props.sidebarFilter.kind === 'tag' && props.sidebarFilter.tag === tag ? 'active' : ''}`}
              onClick={() => props.onChangeFilter({ kind: 'tag', tag })}
            >
              <Tag size={14} className="tree-icon" />
              <span className="tree-label" title={tag}>{tag}</span>
              <span className="tree-count">{count}</span>
            </button>
            <button
              type="button"
              className="folder-delete-btn folder-edit-btn"
              title={t('txt_edit')}
              aria-label={`${t('txt_edit')}: ${tag}`}
              disabled={props.busy || !folderId}
              onClick={(e) => {
                e.preventDefault();
                e.stopPropagation();
                props.onOpenRenameTag({ tag, count, folderId });
              }}
            >
              <Pencil size={12} />
            </button>
            <button
              type="button"
              className="folder-delete-btn"
              title={t('txt_delete')}
              aria-label={`${t('txt_delete')}: ${tag}`}
              disabled={props.busy || !folderId}
              onClick={(e) => {
                e.preventDefault();
                e.stopPropagation();
                props.onOpenDeleteTag({ tag, count, folderId });
              }}
            >
              <X size={12} />
            </button>
          </div>
        ))}
      </div>
    </aside>
  );
}
