import { createPortal } from 'preact/compat';
import type { ComponentChildren } from 'preact';
import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { Archive, BookOpen, Building2, Calendar, CalendarPlus, Clipboard, Contact, Copy, CreditCard, Database, Download, Eye, EyeOff, ExternalLink, FolderTree, Globe, Hash, History, IdCard, KeyRound, Landmark, List, Lock, Mail, MapPin, MoreVertical, Paperclip, Pencil, Phone, RefreshCw, RotateCcw, Server, ShieldCheck, Smartphone, Sparkles, StickyNote, Tag, Terminal, Trash2, User, X } from 'lucide-preact';
import type { LucideIcon } from 'lucide-preact';
import { useDialogLifecycle } from '@/components/ConfirmDialog';
import ItemHistoryDialog from '@/components/vault/ItemHistoryDialog';
import { looksLikeCipherString } from '@/lib/app-support';
import { parseNote, presentField, usernameKind } from '@/lib/field-display';
import type { FieldKind, FieldPresentation } from '@/lib/field-display';
import type { TotpCodeResult } from '@/lib/crypto';
import { checkPasswordLeaked, passwordHealthState } from '@/lib/password-security';
import {
  getPasswordSecurityFinding,
  recordPasswordBreachFinding,
  subscribePasswordSecurityState,
} from '@/lib/password-security-cache';
import type { CipherUsageEntry } from '@/lib/api/vault';
import type { ItemHistoryEntry, ItemHistoryVersion } from '@/lib/item-history';
import type { Cipher, CustomFieldType } from '@/lib/types';
import { t } from '@/lib/i18n';
import {
  CardBrandIcon,
  TOTP_RING_CIRCUMFERENCE,
  VaultListIcon,
  copyToClipboard,
  displayCardBrand,
  formatAttachmentSize,
  formatHistoryTime,
  formatTotp,
  isCipherDeleted,
  maskSecret,
  openUri,
  parseFieldType,
  toBooleanFieldValue,
  vaultDeleteAction,
} from '@/components/vault/vault-page-helpers';

function isAbortError(error: unknown): boolean {
  return !!error && typeof error === 'object' && 'name' in error && (error as { name?: string }).name === 'AbortError';
}

interface VaultDetailViewProps {
  selectedCipher: Cipher;
  repromptApprovedCipherId: string | null;
  showPassword: boolean;
  totpLive: TotpCodeResult | null;
  passkeyCreatedAt: string | null;
  usage: CipherUsageEntry | null;
  usageAvailable: boolean;
  usageError: boolean;
  onPasswordCopied: (cipherId: string) => void;
  /** The history of an item that has to be opened, with the moment it was asked for. */
  historyRequest?: { cipherId: string; nonce: number } | null;
  /** Whether the item is kept out of the password check. */
  scanExcluded: boolean;
  /** Keeps the item out of the password check, or puts it back in. */
  onToggleScanExclusion: (cipherId: string, exclude: boolean) => void;
  hiddenFieldVisibleMap: Record<number, boolean>;
  folderName: (id: string | null | undefined) => string;
  /** The organization and collections the item belongs to, when it is shared. */
  sharedWith?: { organizationName: string; collectionNames: string[] } | null;
  downloadingAttachmentKey: string;
  attachmentDownloadPercent: number | null;
  onOpenReprompt: () => void;
  onToggleShowPassword: () => void;
  onToggleHiddenField: (index: number) => void;
  onDownloadAttachment: (cipher: Cipher, attachmentId: string) => void;
  onLoadItemHistory: (cipherId: string) => Promise<ItemHistoryEntry[]>;
  onLoadItemHistoryVersion: (cipherId: string, versionId: string) => Promise<ItemHistoryVersion>;
  onRestoreItemHistoryVersion: (cipherId: string, versionId: string, expectedRevisionDate: string) => Promise<void>;
  onStartEdit: () => void;
  /** A save is still running; the item may not exist on the server yet, so it cannot be edited. */
  busy?: boolean;
  onDelete: (cipher: Cipher) => void;
  onMoveItem?: (cipher: Cipher) => void;
  onRestore: (cipher: Cipher) => void | Promise<void>;
  onArchive: (cipher: Cipher) => void | Promise<void>;
  onUnarchive: (cipher: Cipher) => void | Promise<void>;
}

function totpProgress(live: TotpCodeResult | null): number {
  const period = Math.max(1, live?.period || 30);
  return live ? Math.max(0, Math.min(period, live.remain)) / period : 0;
}

// The raw counterpart of a decrypted field is the encrypted blob, so a value
// that still looks like a cipher string never reaches the screen.
function plainValue(decrypted: string | null | undefined, raw: string | null | undefined): string {
  const dec = String(decrypted ?? '');
  if (dec && !looksLikeCipherString(dec)) return dec;
  const value = String(raw ?? '');
  return looksLikeCipherString(value) ? '' : value;
}

/* Every kind gets an icon that says what the field holds. */
const FIELD_KIND_ICONS: Record<FieldKind, LucideIcon> = {
  email: Mail,
  phone: Phone,
  username: User,
  fullName: User,
  firstName: User,
  lastName: User,
  birthDate: Calendar,
  address: MapPin,
  city: MapPin,
  country: Globe,
  postalCode: Hash,
  company: Building2,
  nationalId: IdCard,
  idIssueDate: Calendar,
  taxCode: Hash,
  socialInsurance: ShieldCheck,
  healthInsurance: ShieldCheck,
  hometown: MapPin,
  permanentAddress: MapPin,
  placeOfBirth: MapPin,
  server: Server,
  port: Hash,
  database: Database,
  path: FolderTree,
  website: Globe,
  oneTimeCode: KeyRound,
  other: List,
};

/* A value that can be copied is a click target: the row itself copies, so the
   copy button is only a hint that shows up while the row is hovered. */
function CopyTarget(props: { className: string; label: string; onCopy: () => void; children: ComponentChildren }) {
  return (
    <div
      className={`kv-copyable ${props.className}`}
      role="button"
      tabIndex={0}
      aria-label={t('txt_copy_field', { label: props.label })}
      onClick={props.onCopy}
      onKeyDown={(event) => {
        // A key press on a button inside the row belongs to that button.
        if (event.target !== event.currentTarget) return;
        if (event.key !== 'Enter' && event.key !== ' ') return;
        event.preventDefault();
        props.onCopy();
      }}
    >
      {props.children}
    </div>
  );
}

/* The copy hint is decorative: the row carries the accessible name. */
function CopyHint() {
  return (
    <span className="kv-copy-hint" aria-hidden="true">
      <Copy size={14} className="btn-icon" />
    </span>
  );
}

/* One stored field with everything the view needs to show it. */
interface CustomFieldEntry {
  index: number;
  type: CustomFieldType;
  name: string;
  value: string;
  presentation: FieldPresentation;
}

/* Every card in the detail column opens with the same tinted icon and title. */
function DetailSectionHead(props: { icon: ComponentChildren; title: string }) {
  return (
    <div className="detail-section-head">
      <span className="detail-section-icon" aria-hidden="true">
        {props.icon}
      </span>
      <h4>{props.title}</h4>
    </div>
  );
}

function PasswordHistoryDialog(props: {
  open: boolean;
  entries: Array<{ password: string; lastUsedDate: string | null }>;
  onClose: () => void;
}) {
  const [revealed, setRevealed] = useState<Record<number, boolean>>({});
  useDialogLifecycle(props.open, props.onClose);

  // Old passwords stay masked until the user asks for one, and the mask comes
  // back every time the dialog closes or the item changes.
  useEffect(() => {
    setRevealed({});
  }, [props.open, props.entries]);

  if (!props.open || typeof document === 'undefined') return null;
  return createPortal(
    <div className="dialog-mask open" onClick={(event) => event.target === event.currentTarget && props.onClose()}>
      <section className="dialog-card password-history-dialog open" role="dialog" aria-modal="true" aria-label={t('txt_password_history')}>
        <div className="password-history-head">
          <h3 className="dialog-title">{t('txt_password_history')}</h3>
          <button type="button" className="password-history-close" aria-label={t('txt_close')} onClick={props.onClose}>
            <X size={18} />
          </button>
        </div>
        <div className="password-history-list">
          {props.entries.map((entry, index) => {
            const isRevealed = !!revealed[index];
            const revealLabel = isRevealed ? t('txt_hide') : t('txt_reveal');
            return (
              <div key={`password-history-${index}-${entry.lastUsedDate || 'none'}`} className="password-history-item">
                <div className="password-history-copy">
                  <button
                    type="button"
                    className="btn btn-secondary small password-history-copy-btn"
                    aria-label={`${t('txt_copy')} ${t('txt_password')}`}
                    title={t('txt_copy')}
                    onClick={() => void copyToClipboard(entry.password)}
                  >
                    <Clipboard size={16} />
                  </button>
                  <button
                    type="button"
                    className="btn btn-secondary small password-history-copy-btn"
                    aria-label={`${revealLabel} ${t('txt_password')}`}
                    title={revealLabel}
                    onClick={() => setRevealed((prev) => ({ ...prev, [index]: !prev[index] }))}
                  >
                    {isRevealed ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
                <div className="password-history-value">{isRevealed ? entry.password : maskSecret(entry.password)}</div>
                <div className="password-history-time">{formatHistoryTime(entry.lastUsedDate)}</div>
              </div>
            );
          })}
        </div>
        <button type="button" className="btn btn-primary dialog-btn" onClick={props.onClose}>
          {t('txt_close')}
        </button>
      </section>
    </div>,
    document.body
  );
}

export default function VaultDetailView(props: VaultDetailViewProps) {
  const selectedAttachments = Array.isArray(props.selectedCipher.attachments) ? props.selectedCipher.attachments : [];
  const [showSshPrivateKey, setShowSshPrivateKey] = useState(false);
  const [revealedFields, setRevealedFields] = useState<Record<string, boolean>>({});
  const [overflowOpen, setOverflowOpen] = useState(false);
  const overflowRef = useRef<HTMLDivElement | null>(null);
  const itemHistoryRequestRef = useRef(0);
  const historyRequestNonceRef = useRef(0);
  const [passwordHistoryOpen, setPasswordHistoryOpen] = useState(false);
  const [itemHistoryOpen, setItemHistoryOpen] = useState(false);
  const [itemHistoryEntries, setItemHistoryEntries] = useState<ItemHistoryEntry[]>([]);
  const [itemHistoryVersion, setItemHistoryVersion] = useState<ItemHistoryVersion | null>(null);
  const [itemHistoryLoading, setItemHistoryLoading] = useState(false);
  const [itemHistoryVersionLoading, setItemHistoryVersionLoading] = useState(false);
  const [itemHistoryRestoring, setItemHistoryRestoring] = useState(false);
  const [itemHistoryError, setItemHistoryError] = useState('');
  const [checkingBreach, setCheckingBreach] = useState(false);
  // The password health of an item comes from the vault check, so the view has
  // to hear when that check finishes or when the item changes.
  const [securityTick, setSecurityTick] = useState(0);
  const breachControllerRef = useRef<AbortController | null>(null);
  const isArchived = !!(props.selectedCipher.archivedDate || (props.selectedCipher as { archivedAt?: string | null }).archivedAt);
  const isDeleted = isCipherDeleted(props.selectedCipher);
  const repromptLocked = Number(props.selectedCipher.reprompt || 0) === 1 && props.repromptApprovedCipherId !== props.selectedCipher.id;
  const deleteLabel = t(vaultDeleteAction(props.selectedCipher).labelKey);
  const passwordHistoryEntries = useMemo(
    () =>
      (props.selectedCipher.passwordHistory || [])
        .map((entry) => ({
          password: plainValue(entry?.decPassword, entry?.password),
          lastUsedDate: entry?.lastUsedDate ?? null,
        }))
        .filter((entry) => entry.password.trim()),
    [props.selectedCipher.passwordHistory]
  );
  const websiteValues = useMemo(
    () => (props.selectedCipher.login?.uris || []).map((uri) => plainValue(uri.decUri, uri.uri).trim()).filter((value) => !!value),
    [props.selectedCipher.login?.uris]
  );
  // The username says what it is: an address, a phone number or a name.
  const usernameValue = props.selectedCipher.login?.decUsername || '';
  const usernameKindValue = usernameKind(usernameValue);
  const usernameLabel = usernameKindValue === 'email' ? t('txt_email') : usernameKindValue === 'phone' ? t('txt_phone') : t('txt_username');
  const UsernameIcon = usernameKindValue === 'email' ? Mail : usernameKindValue === 'phone' ? Phone : User;
  // A note is not one blob of text: it may hold a key, a list of codes or
  // labelled lines, and each part is presented on its own.
  const noteText = plainValue(props.selectedCipher.decNotes, props.selectedCipher.notes);
  const noteBlocks = useMemo(() => parseNote(noteText), [noteText]);
  // The custom fields are sorted by what they are: the leftovers of a form go
  // to the collapsed area at the bottom, the rest stays in the card.
  const customFields = useMemo(() => {
    const entries = (props.selectedCipher.fields || [])
      .filter((field) => parseFieldType(field.type) !== 3)
      .map((field, index) => {
        const type = parseFieldType(field.type);
        const name = plainValue(field.decName, field.name);
        return {
          index,
          type,
          name,
          value: plainValue(field.decValue, field.value),
          presentation: presentField(name, type),
        };
      });
    return {
      visible: entries.filter((entry) => !entry.presentation.noise),
      noise: entries.filter((entry) => entry.presentation.noise),
    };
  }, [props.selectedCipher.fields]);
  // The password was replaced or the view was locked: what was revealed is
  // hidden again. Another item on screen is another view, mounted again, so
  // what is shown for an item does not have to be reset here: an effect that
  // lands after the user opened the history would close the history again.
  useEffect(() => {
    breachControllerRef.current?.abort();
    breachControllerRef.current = null;
    setShowSshPrivateKey(false);
    setRevealedFields({});
    setOverflowOpen(false);
    setCheckingBreach(false);
    return () => {
      breachControllerRef.current?.abort();
      breachControllerRef.current = null;
    };
  }, [props.selectedCipher.login?.decPassword, repromptLocked]);

  // The overflow menu closes on outside click and on Escape, like the other
  // menus in the vault.
  useEffect(() => {
    if (!overflowOpen) return;
    const onPointerDown = (event: Event) => {
      const target = event.target as Node | null;
      if (overflowRef.current && target && !overflowRef.current.contains(target)) setOverflowOpen(false);
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOverflowOpen(false);
    };
    document.addEventListener('pointerdown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [overflowOpen]);
  const checkBreach = async () => {
    const password = String(props.selectedCipher.login?.decPassword || '');
    if (!password) return;
    breachControllerRef.current?.abort();
    const controller = new AbortController();
    breachControllerRef.current = controller;
    setCheckingBreach(true);
    try {
      const result = await checkPasswordLeaked(password, fetch, controller.signal);
      if (controller.signal.aborted) return;
      recordPasswordBreachFinding(
        String(props.selectedCipher.id),
        String(props.selectedCipher.revisionDate || ''),
        result.available ? result.count : null
      );
    } catch (error) {
      if (controller.signal.aborted || isAbortError(error)) return;
      recordPasswordBreachFinding(
        String(props.selectedCipher.id),
        String(props.selectedCipher.revisionDate || ''),
        null
      );
    } finally {
      if (breachControllerRef.current === controller) {
        breachControllerRef.current = null;
        setCheckingBreach(false);
      }
    }
  };
  useEffect(() => subscribePasswordSecurityState(() => setSecurityTick((tick) => tick + 1)), []);
  // What may be said about the password of this item. Without a valid result
  // this is "unknown", and unknown is never shown as a clean password.
  const passwordHealth = useMemo(
    () =>
      passwordHealthState(
        getPasswordSecurityFinding(props.selectedCipher.id, props.selectedCipher.revisionDate)
      ),
    [props.selectedCipher.id, props.selectedCipher.revisionDate, securityTick]
  );
  const formatDownloadLabel = (attachmentId: string) => {
    const downloadKey = `${props.selectedCipher.id}:${attachmentId}`;
    if (props.downloadingAttachmentKey !== downloadKey) return t('txt_download');
    return props.attachmentDownloadPercent == null
      ? t('txt_downloading')
      : t('txt_downloading_percent', { percent: props.attachmentDownloadPercent });
  };

  // The versions are fetched and decrypted by the action layer, the view only
  // shows them and hands the restore back with the revision date it shows.
  const openItemHistory = async () => {
    const token = ++itemHistoryRequestRef.current;
    setItemHistoryOpen(true);
    setItemHistoryEntries([]);
    setItemHistoryVersion(null);
    setItemHistoryError('');
    setItemHistoryLoading(true);
    try {
      const entries = await props.onLoadItemHistory(props.selectedCipher.id);
      // A newer request or a different item won: the answer is stale.
      if (itemHistoryRequestRef.current !== token) return;
      setItemHistoryEntries(entries);
    } catch (error) {
      if (itemHistoryRequestRef.current !== token) return;
      setItemHistoryError(error instanceof Error ? error.message : t('txt_load_vault_failed'));
    } finally {
      if (itemHistoryRequestRef.current === token) setItemHistoryLoading(false);
    }
  };

  // The list asks for the history of an item, and the view opens it.
  useEffect(() => {
    const request = props.historyRequest;
    if (!request) return;
    if (request.cipherId !== props.selectedCipher.id) return;
    if (request.nonce === historyRequestNonceRef.current) return;
    historyRequestNonceRef.current = request.nonce;
    void openItemHistory();
  }, [props.historyRequest, props.selectedCipher.id]);

  const selectItemHistoryVersion = async (versionId: string) => {
    const token = ++itemHistoryRequestRef.current;
    setItemHistoryVersion(null);
    setItemHistoryVersionLoading(false);
    if (!versionId) return;
    setItemHistoryVersionLoading(true);
    setItemHistoryError('');
    try {
      const loaded = await props.onLoadItemHistoryVersion(props.selectedCipher.id, versionId);
      // A newer selection won the race: the late answer belongs to a version
      // the user already moved away from.
      if (itemHistoryRequestRef.current !== token) return;
      setItemHistoryVersion(loaded);
    } catch (error) {
      if (itemHistoryRequestRef.current !== token) return;
      setItemHistoryError(error instanceof Error ? error.message : t('txt_load_vault_failed'));
    } finally {
      if (itemHistoryRequestRef.current === token) setItemHistoryVersionLoading(false);
    }
  };

  const restoreItemHistoryVersion = async (versionId: string) => {
    setItemHistoryRestoring(true);
    try {
      await props.onRestoreItemHistoryVersion(props.selectedCipher.id, versionId, props.selectedCipher.revisionDate || '');
      setItemHistoryOpen(false);
    } catch (error) {
      setItemHistoryError(error instanceof Error ? error.message : t('txt_load_vault_failed'));
    } finally {
      setItemHistoryRestoring(false);
    }
  };

  // Only a copy that really reached the clipboard counts as a use. The reprompt
  // gate above already keeps a locked item from being copied at all.
  const copyLoginPassword = async () => {
    const copied = await copyToClipboard(props.selectedCipher.login?.decPassword || '');
    if (copied) props.onPasswordCopied(props.selectedCipher.id);
  };

  // Secrets stay masked until the user reveals that one field. The masked text
  // never carries the secret in a title or an aria label.
  const renderSecretLine = (key: string, label: string, value: string, copyable = false) => {
    const secret = value || '';
    const isRevealed = !!revealedFields[key];
    const revealLabel = isRevealed ? t('txt_hide') : t('txt_reveal');
    const body = (
      <>
        <span>{label}</span>
        <span className="kv-line-secret">
          <strong>{isRevealed ? secret : maskSecret(secret)}</strong>
          <button
            type="button"
            className="btn btn-secondary small"
            aria-label={`${revealLabel} ${label}`}
            title={revealLabel}
            onClick={(event) => {
              event.stopPropagation();
              setRevealedFields((prev) => ({ ...prev, [key]: !prev[key] }));
            }}
          >
            {isRevealed ? <EyeOff size={14} className="btn-icon" /> : <Eye size={14} className="btn-icon" />}
          </button>
          {copyable ? (
            <CopyHint />
          ) : (
            <button
              type="button"
              className="btn btn-secondary small"
              aria-label={`${t('txt_copy')} ${label}`}
              title={t('txt_copy')}
              onClick={() => void copyToClipboard(secret)}
            >
              <Clipboard size={14} className="btn-icon" />
            </button>
          )}
        </span>
      </>
    );
    if (!copyable) return <div className="kv-line">{body}</div>;
    return (
      <CopyTarget className="kv-line" label={label} onCopy={() => void copyToClipboard(secret)}>
        {body}
      </CopyTarget>
    );
  };

  // A custom field shows what it holds: a known name shows the canonical
  // label, and a field that only looks like a secret is masked like a hidden
  // one. The stored name stays available as the tooltip of the label.
  const renderCustomField = (entry: CustomFieldEntry) => {
    const { index, type, name, value, presentation } = entry;
    const labelKey = presentation.labelKey;
    const label = labelKey ? t(labelKey) : name || t('txt_field');
    const KindIcon = FIELD_KIND_ICONS[presentation.kind];
    const labelTitle = labelKey ? name : undefined;
    if (type === 2) {
      const checked = toBooleanFieldValue(value);
      return (
        <div key={`view-field-${index}`} className="kv-field custom-field-card">
          <span className="kv-field-icon" aria-hidden="true">
            <KindIcon size={13} />
          </span>
          <div className="kv-field-body">
            <span className="kv-field-label custom-field-label" title={labelTitle}>{label}</span>
            <div className="kv-field-value custom-field-value">
              <label className="check-line cf-check view custom-field-check">
                <input type="checkbox" checked={checked} disabled />
                <span className="boolean-text value-ellipsis" title={checked ? t('txt_checked') : t('txt_unchecked')}>
                  {checked ? t('txt_checked') : t('txt_unchecked')}
                </span>
              </label>
            </div>
          </div>
          <div className="kv-actions" />
        </div>
      );
    }
    const masked = presentation.secret;
    const revealed = !masked || !!props.hiddenFieldVisibleMap[index];
    return (
      <CopyTarget key={`view-field-${index}`} className="kv-field custom-field-card" label={label} onCopy={() => void copyToClipboard(value)}>
        <span className="kv-field-icon" aria-hidden="true">
          <KindIcon size={13} />
        </span>
        <div className="kv-field-body">
          <span className="kv-field-label custom-field-label" title={labelTitle}>{label}</span>
          <div className="kv-field-value custom-field-value">
            <strong
              className={masked && !revealed ? 'value-ellipsis' : 'custom-field-display'}
              title={masked && !revealed ? (type === 1 ? '' : t('txt_field_masked_hint')) : value}
            >
              {masked && !revealed ? maskSecret(value) : value}
            </strong>
          </div>
        </div>
        <div className="kv-actions">
          {masked && (
            <button
              type="button"
              className="btn btn-secondary small"
              onClick={(event) => {
                event.stopPropagation();
                props.onToggleHiddenField(index);
              }}
            >
              {revealed ? <EyeOff size={14} className="btn-icon" /> : <Eye size={14} className="btn-icon" />}
              {revealed ? t('txt_hide') : t('txt_reveal')}
            </button>
          )}
          <CopyHint />
        </div>
      </CopyTarget>
    );
  };

  return (
    <>
      {repromptLocked && (
        <div className="card">
          <h4>{t('txt_master_password_reprompt_2')}</h4>
          <div className="detail-sub">{t('txt_this_item_requires_master_password_every_time_before_viewing_details')}</div>
          <div className="actions detail-unlock-actions">
            <button type="button" className="btn btn-primary" onClick={props.onOpenReprompt}>
              <Eye size={14} className="btn-icon" /> {t('txt_unlock_details')}
            </button>
          </div>
        </div>
      )}
      {!repromptLocked && (
        <>
          <div className="card">
            <div className="detail-title-row">
              <span className="detail-title-icon" aria-hidden="true">
                <VaultListIcon cipher={props.selectedCipher} />
              </span>
              <div className="detail-title-main">
                <h3 className="detail-title detail-item-title">{props.selectedCipher.decName || t('txt_no_name')}</h3>
                <div className="detail-folder-line">
                  <Tag size={13} aria-hidden="true" />
                  <span>{props.folderName(props.selectedCipher.folderId)}</span>
                </div>
                {props.sharedWith && (
                  <div className="detail-folder-line detail-shared-line">
                    <Landmark size={13} aria-hidden="true" />
                    <span>
                      {props.sharedWith.organizationName}
                      {props.sharedWith.collectionNames.length
                        ? ` · ${props.sharedWith.collectionNames.join(', ')}`
                        : ''}
                    </span>
                    <span className="detail-shared-badge">{t('txt_shared_item')}</span>
                  </div>
                )}
              </div>
              <div className="detail-title-actions">
                {isDeleted ? (
                  <button
                    type="button"
                    className="detail-icon-action"
                    title={t('txt_restore')}
                    aria-label={t('txt_restore')}
                    onClick={() => void props.onRestore(props.selectedCipher)}
                  >
                    <RotateCcw size={16} />
                  </button>
                ) : (
                  <>
                    <button type="button" className="btn btn-secondary small" disabled={props.busy} onClick={props.onStartEdit}>
                      <Pencil size={14} className="btn-icon" /> {t('txt_edit')}
                    </button>
                    <div className="sort-menu-wrap" ref={overflowRef}>
                      <button
                        type="button"
                        className="detail-icon-action"
                        aria-haspopup="menu"
                        aria-expanded={overflowOpen}
                        aria-label={t('txt_actions')}
                        title={t('txt_actions')}
                        onClick={() => setOverflowOpen((open) => !open)}
                      >
                        <MoreVertical size={16} />
                      </button>
                      {overflowOpen && (
                        <div className="sort-menu" role="menu">
                          {props.onMoveItem && (
                            <button
                              type="button"
                              className="sort-menu-item"
                              role="menuitem"
                              onClick={() => {
                                setOverflowOpen(false);
                                props.onMoveItem?.(props.selectedCipher);
                              }}
                            >
                              <span>
                                <Tag size={14} /> {t('txt_move_to_tag')}
                              </span>
                            </button>
                          )}
                          <button
                            type="button"
                            className="sort-menu-item"
                            role="menuitem"
                            onClick={() => {
                              setOverflowOpen(false);
                              if (isArchived) void props.onUnarchive(props.selectedCipher);
                              else void props.onArchive(props.selectedCipher);
                            }}
                          >
                            <span>
                              {isArchived ? <RotateCcw size={14} /> : <Archive size={14} />} {isArchived ? t('txt_unarchive') : t('txt_archive')}
                            </span>
                          </button>
                          <button
                            type="button"
                            className="sort-menu-item"
                            role="menuitem"
                            onClick={() => {
                              setOverflowOpen(false);
                              props.onDelete(props.selectedCipher);
                            }}
                          >
                            <span>
                              <Trash2 size={14} /> {t('txt_move_to_trash')}
                            </span>
                          </button>
                        </div>
                      )}
                    </div>
                  </>
                )}
              </div>
            </div>
            {isArchived && <div className="list-badge archive-badge">{t('txt_archived')}</div>}
          </div>

          {props.selectedCipher.login && (
            <div className="card" role="group" aria-label={t('txt_login_credentials')}>
              <DetailSectionHead icon={<KeyRound size={15} />} title={t('txt_login_credentials')} />
              <CopyTarget className="kv-field" label={usernameLabel} onCopy={() => void copyToClipboard(usernameValue)}>
                <span className="kv-field-icon" aria-hidden="true">
                  <UsernameIcon size={15} />
                </span>
                <div className="kv-field-body">
                  <span className="kv-field-label">{usernameLabel}</span>
                  <div className="kv-field-value">
                    <strong className="value-ellipsis" title={usernameValue}>{usernameValue}</strong>
                  </div>
                </div>
                <div className="kv-actions">
                  <CopyHint />
                </div>
              </CopyTarget>
              <CopyTarget className="kv-field" label={t('txt_password')} onCopy={() => void copyLoginPassword()}>
                <span className="kv-field-icon" aria-hidden="true">
                  <KeyRound size={15} />
                </span>
                <div className="kv-field-body">
                  <span className="kv-field-label">{t('txt_password')}</span>
                  <div className="kv-field-value">
                    <strong>{props.showPassword ? props.selectedCipher.login.decPassword || '' : maskSecret(props.selectedCipher.login.decPassword || '')}</strong>
                  </div>
                </div>
                <div className="kv-actions">
                  <button
                    type="button"
                    className="btn btn-secondary small"
                    onClick={(event) => {
                      event.stopPropagation();
                      props.onToggleShowPassword();
                    }}
                  >
                    {props.showPassword ? <EyeOff size={14} className="btn-icon" /> : <Eye size={14} className="btn-icon" />}
                    {props.showPassword ? t('txt_hide') : t('txt_reveal')}
                  </button>
                  <CopyHint />
                </div>
              </CopyTarget>
              {!!props.selectedCipher.login.decTotp && (
                <CopyTarget className="kv-field" label={t('txt_totp')} onCopy={() => void copyToClipboard(props.totpLive?.code || '')}>
                  <span className="kv-field-icon" aria-hidden="true">
                    <Lock size={15} />
                  </span>
                  <div className="kv-field-body">
                    <span className="kv-field-label">{t('txt_totp')}</span>
                    <div className="kv-field-value">
                      <div className="totp-inline">
                        <strong>{props.totpLive ? formatTotp(props.totpLive.code) : t('txt_text_3')}</strong>
                        <div
                          className="totp-timer"
                          title={t('txt_refresh_in_seconds_s', { seconds: props.totpLive ? props.totpLive.remain : 0 })}
                          aria-label={t('txt_refresh_in_seconds_s', { seconds: props.totpLive ? props.totpLive.remain : 0 })}
                        >
                          <svg viewBox="0 0 36 36" className="totp-ring" role="presentation" aria-hidden="true">
                            <circle className="totp-ring-track" cx="18" cy="18" r="15.9155" />
                            <circle
                              className="totp-ring-progress"
                              cx="18"
                              cy="18"
                              r="15.9155"
                              style={{
                                strokeDasharray: `${TOTP_RING_CIRCUMFERENCE} ${TOTP_RING_CIRCUMFERENCE}`,
                                strokeDashoffset: String(
                                  TOTP_RING_CIRCUMFERENCE -
                                    TOTP_RING_CIRCUMFERENCE * totpProgress(props.totpLive)
                                ),
                              }}
                            />
                          </svg>
                          <span className="totp-timer-value">{props.totpLive ? props.totpLive.remain : 0}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="kv-actions">
                    <CopyHint />
                  </div>
                </CopyTarget>
              )}
              {!!props.passkeyCreatedAt && (
                <div className="kv-field">
                  <span className="kv-field-icon" aria-hidden="true">
                    <ShieldCheck size={15} />
                  </span>
                  <div className="kv-field-body">
                    <span className="kv-field-label">{t('txt_passkey')}</span>
                    <div className="kv-field-value">
                      <strong>{t('txt_passkey_created_at_value', { value: formatHistoryTime(props.passkeyCreatedAt) })}</strong>
                    </div>
                  </div>
                  <div className="kv-actions" />
                </div>
              )}
              <div className="detail-card-footer">
                {props.usageAvailable && (
                  <div className="detail-sub">{t('txt_password_copies')}: {t('txt_password_copied_count', { count: props.usage?.useCount || 0 })}</div>
                )}
                {props.usageError && (
                  <div className="detail-sub" role="status">{t('txt_usage_metrics_unavailable')}</div>
                )}
                <div className="password-security-badges" role="status">
                  {props.scanExcluded && (
                    <span className="risk-badge muted">{t('txt_scan_excluded_badge')}</span>
                  )}
                  {!props.scanExcluded && passwordHealth.kind === 'unknown' && (
                    <span className="risk-badge muted">
                      {passwordHealth.reason === 'unavailable'
                        ? t('txt_password_security_check_failed')
                        : t('txt_password_security_not_checked')}
                    </span>
                  )}
                  {!props.scanExcluded && passwordHealth.kind === 'breach-only' && passwordHealth.exposed && (
                    <span className="risk-badge danger">{t('txt_password_exposed_count', { count: passwordHealth.exposedCount })}</span>
                  )}
                  {!props.scanExcluded && passwordHealth.kind === 'breach-only' && !passwordHealth.exposed && (
                    <>
                      <span className="risk-badge muted">{t('txt_password_not_found_in_breaches')}</span>
                      <span className="detail-sub">{t('txt_password_health_breach_only')}</span>
                    </>
                  )}
                  {!props.scanExcluded && passwordHealth.kind === 'risks' && (
                    <>
                      {passwordHealth.exposedCount > 0 && (
                        <span className="risk-badge danger">{t('txt_password_security_exposed_short', { count: passwordHealth.exposedCount })}</span>
                      )}
                      {passwordHealth.weak && <span className="risk-badge weak">{t('txt_password_security_weak_short')}</span>}
                      {passwordHealth.reusedCount > 1 && <span className="risk-badge reused">{t('txt_password_security_reused_short')}</span>}
                    </>
                  )}
                  {!props.scanExcluded && passwordHealth.kind === 'clean' && (
                    <span className="risk-badge muted">{t('txt_no_password_risks')}</span>
                  )}
                </div>
                <div className="detail-card-actions">
                  <button
                    type="button"
                    className="btn btn-secondary small"
                    onClick={() => props.onToggleScanExclusion(props.selectedCipher.id, !props.scanExcluded)}
                  >
                    {props.scanExcluded ? t('txt_scan_include_again') : t('txt_scan_exclude')}
                  </button>
                  <button
                    type="button"
                    className="btn btn-secondary small"
                    // An item that is kept out of the check is not checked:
                    // the badge above says so, and the button to put it back
                    // in is next to it.
                    disabled={checkingBreach || !props.selectedCipher.login?.decPassword || props.scanExcluded}
                    onClick={() => void checkBreach()}
                  >
                    {checkingBreach ? <RefreshCw size={14} className="btn-icon spin" /> : <ShieldCheck size={14} className="btn-icon" />}
                    {checkingBreach ? t('txt_checking_password_security') : t('txt_check_password_breach')}
                  </button>
                </div>
              </div>
            </div>
          )}

          {websiteValues.length > 0 && (
            <div className="card" role="group" aria-label={t('txt_websites')}>
              <DetailSectionHead icon={<Globe size={15} />} title={t('txt_websites')} />
              <div className="detail-uri-list">
                {websiteValues.map((value, index) => {
                  // An Android app is not a page that can be opened: the row
                  // only carries the package name.
                  if (value.startsWith('androidapp://')) {
                    const appPackage = value.slice('androidapp://'.length);
                    return (
                      <CopyTarget key={`view-uri-${index}`} className="detail-uri-row" label={appPackage} onCopy={() => void copyToClipboard(appPackage)}>
                        <span className="detail-uri-app-icon" aria-hidden="true">
                          <Smartphone size={15} />
                        </span>
                        <div className="detail-uri-app-body">
                          <span className="detail-uri-app-label">{t('txt_android_app')}</span>
                          <strong className="detail-uri-app-value">{appPackage}</strong>
                        </div>
                        <div className="kv-actions">
                          <CopyHint />
                        </div>
                      </CopyTarget>
                    );
                  }
                  return (
                    <div key={`view-uri-${index}`} className="detail-uri-row">
                      <button type="button" className="detail-uri-link" title={value} onClick={() => openUri(value)}>
                        {value}
                      </button>
                      {value.startsWith('http://') && <span className="detail-uri-badge">{t('txt_not_secure')}</span>}
                      <div className="kv-actions">
                        <button type="button" className="btn btn-secondary small" title={t('txt_open')} onClick={() => openUri(value)}>
                          <ExternalLink size={14} className="btn-icon" /> {t('txt_open')}
                        </button>
                        <button
                          type="button"
                          className="btn btn-secondary small"
                          title={t('txt_copy')}
                          aria-label={t('txt_copy_field', { label: value })}
                          onClick={() => void copyToClipboard(value)}
                        >
                          <Copy size={14} className="btn-icon" />
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {props.selectedCipher.card && (
            <div className="card">
              <DetailSectionHead icon={<CreditCard size={15} />} title={t('txt_card_details')} />
              <CopyTarget className="kv-line" label={t('txt_cardholder_name')} onCopy={() => void copyToClipboard(props.selectedCipher.card?.decCardholderName || '')}>
                <span>{t('txt_cardholder_name')}</span>
                <strong>{props.selectedCipher.card.decCardholderName || ''}</strong>
                <CopyHint />
              </CopyTarget>
              {renderSecretLine('card-number', t('txt_number'), props.selectedCipher.card.decNumber || '', true)}
              <div className="kv-line">
                <span>{t('txt_brand')}</span>
                <strong className="card-brand-detail">
                  <CardBrandIcon brand={props.selectedCipher.card.decBrand} />
                  {displayCardBrand(props.selectedCipher.card.decBrand)}
                </strong>
              </div>
              <div className="kv-line"><span>{t('txt_expiry')}</span><strong>{`${props.selectedCipher.card.decExpMonth || ''}/${props.selectedCipher.card.decExpYear || ''}`}</strong></div>
              {renderSecretLine('card-code', t('txt_security_code'), props.selectedCipher.card.decCode || '', true)}
            </div>
          )}

          {props.selectedCipher.identity && (
            <div className="card">
              <DetailSectionHead icon={<Contact size={15} />} title={t('txt_identity_details')} />
              <div className="kv-line"><span>{t('txt_name')}</span><strong>{`${props.selectedCipher.identity.decFirstName || ''} ${props.selectedCipher.identity.decLastName || ''}`.trim()}</strong></div>
              <div className="kv-line"><span>{t('txt_username')}</span><strong>{props.selectedCipher.identity.decUsername || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_email')}</span><strong>{props.selectedCipher.identity.decEmail || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_phone')}</span><strong>{props.selectedCipher.identity.decPhone || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_company')}</span><strong>{props.selectedCipher.identity.decCompany || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_address')}</span><strong>{[props.selectedCipher.identity.decAddress1, props.selectedCipher.identity.decAddress2, props.selectedCipher.identity.decAddress3, props.selectedCipher.identity.decCity, props.selectedCipher.identity.decState, props.selectedCipher.identity.decPostalCode, props.selectedCipher.identity.decCountry].filter(Boolean).join(', ')}</strong></div>
            </div>
          )}

          {props.selectedCipher.sshKey && (
            <div className="card">
              <DetailSectionHead icon={<Terminal size={15} />} title={t('txt_ssh_key')} />
              <CopyTarget className="kv-field" label={t('txt_private_key')} onCopy={() => void copyToClipboard(props.selectedCipher.sshKey?.decPrivateKey || '')}>
                <span className="kv-field-icon" aria-hidden="true">
                  <KeyRound size={15} />
                </span>
                <div className="kv-field-body">
                  <span className="kv-field-label">{t('txt_private_key')}</span>
                  <div className="kv-field-value">
                    <strong
                      className="value-ellipsis"
                      title={showSshPrivateKey ? props.selectedCipher.sshKey.decPrivateKey || '' : maskSecret(props.selectedCipher.sshKey.decPrivateKey || '')}
                    >
                      {showSshPrivateKey ? props.selectedCipher.sshKey.decPrivateKey || '' : maskSecret(props.selectedCipher.sshKey.decPrivateKey || '')}
                    </strong>
                  </div>
                </div>
                <div className="kv-actions">
                  <button
                    type="button"
                    className="btn btn-secondary small"
                    onClick={(event) => {
                      event.stopPropagation();
                      setShowSshPrivateKey((value) => !value);
                    }}
                  >
                    {showSshPrivateKey ? <EyeOff size={14} className="btn-icon" /> : <Eye size={14} className="btn-icon" />}
                    {showSshPrivateKey ? t('txt_hide') : t('txt_reveal')}
                  </button>
                  <CopyHint />
                </div>
              </CopyTarget>
              <CopyTarget className="kv-field" label={t('txt_public_key')} onCopy={() => void copyToClipboard(props.selectedCipher.sshKey?.decPublicKey || '')}>
                <span className="kv-field-icon" aria-hidden="true">
                  <KeyRound size={15} />
                </span>
                <div className="kv-field-body">
                  <span className="kv-field-label">{t('txt_public_key')}</span>
                  <div className="kv-field-value">
                    <strong className="value-ellipsis" title={props.selectedCipher.sshKey.decPublicKey || ''}>
                      {props.selectedCipher.sshKey.decPublicKey || ''}
                    </strong>
                  </div>
                </div>
                <div className="kv-actions">
                  <CopyHint />
                </div>
              </CopyTarget>
              <CopyTarget className="kv-field" label={t('txt_fingerprint')} onCopy={() => void copyToClipboard(props.selectedCipher.sshKey?.decFingerprint || '')}>
                <span className="kv-field-icon" aria-hidden="true">
                  <List size={15} />
                </span>
                <div className="kv-field-body">
                  <span className="kv-field-label">{t('txt_fingerprint')}</span>
                  <div className="kv-field-value">
                    <strong className="value-ellipsis" title={props.selectedCipher.sshKey.decFingerprint || ''}>
                      {props.selectedCipher.sshKey.decFingerprint || ''}
                    </strong>
                  </div>
                </div>
                <div className="kv-actions">
                  <CopyHint />
                </div>
              </CopyTarget>
            </div>
          )}

          {props.selectedCipher.bankAccount && (
            <div className="card">
              <DetailSectionHead icon={<Landmark size={15} />} title={t('txt_bank_account_details')} />
              <div className="kv-line"><span>{t('txt_bank_name')}</span><strong>{props.selectedCipher.bankAccount.decBankName || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_name_on_account')}</span><strong>{props.selectedCipher.bankAccount.decNameOnAccount || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_account_type')}</span><strong>{props.selectedCipher.bankAccount.decAccountType || ''}</strong></div>
              {renderSecretLine('bank-account-number', t('txt_account_number'), props.selectedCipher.bankAccount.decAccountNumber || '')}
              {renderSecretLine('bank-routing-number', t('txt_routing_number'), props.selectedCipher.bankAccount.decRoutingNumber || '')}
              {renderSecretLine('bank-branch-number', t('txt_branch_number'), props.selectedCipher.bankAccount.decBranchNumber || '')}
              {renderSecretLine('bank-pin', t('txt_pin'), props.selectedCipher.bankAccount.decPin || '')}
              {renderSecretLine('bank-swift-code', t('txt_swift_code'), props.selectedCipher.bankAccount.decSwiftCode || '')}
              {renderSecretLine('bank-iban', t('txt_iban'), props.selectedCipher.bankAccount.decIban || '')}
              <div className="kv-line"><span>{t('txt_bank_contact_phone')}</span><strong>{props.selectedCipher.bankAccount.decBankContactPhone || ''}</strong></div>
            </div>
          )}

          {props.selectedCipher.driversLicense && (
            <div className="card">
              <DetailSectionHead icon={<IdCard size={15} />} title={t('txt_drivers_license_details')} />
              <div className="kv-line"><span>{t('txt_name')}</span><strong>{[props.selectedCipher.driversLicense.decFirstName, props.selectedCipher.driversLicense.decMiddleName, props.selectedCipher.driversLicense.decLastName].filter(Boolean).join(' ')}</strong></div>
              <div className="kv-line"><span>{t('txt_date_of_birth')}</span><strong>{props.selectedCipher.driversLicense.decDateOfBirth || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_license_number')}</span><strong>{props.selectedCipher.driversLicense.decLicenseNumber || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_issuing_country')}</span><strong>{props.selectedCipher.driversLicense.decIssuingCountry || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_issuing_state')}</span><strong>{props.selectedCipher.driversLicense.decIssuingState || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_issue_date')}</span><strong>{props.selectedCipher.driversLicense.decIssueDate || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_expiration_date')}</span><strong>{props.selectedCipher.driversLicense.decExpirationDate || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_issuing_authority')}</span><strong>{props.selectedCipher.driversLicense.decIssuingAuthority || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_license_class')}</span><strong>{props.selectedCipher.driversLicense.decLicenseClass || ''}</strong></div>
            </div>
          )}

          {props.selectedCipher.passport && (
            <div className="card">
              <DetailSectionHead icon={<BookOpen size={15} />} title={t('txt_passport_details')} />
              <div className="kv-line"><span>{t('txt_name')}</span><strong>{[props.selectedCipher.passport.decGivenName, props.selectedCipher.passport.decSurname].filter(Boolean).join(' ')}</strong></div>
              <div className="kv-line"><span>{t('txt_date_of_birth')}</span><strong>{props.selectedCipher.passport.decDateOfBirth || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_sex')}</span><strong>{props.selectedCipher.passport.decSex || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_birth_place')}</span><strong>{props.selectedCipher.passport.decBirthPlace || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_nationality')}</span><strong>{props.selectedCipher.passport.decNationality || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_issuing_country')}</span><strong>{props.selectedCipher.passport.decIssuingCountry || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_passport_number')}</span><strong>{props.selectedCipher.passport.decPassportNumber || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_passport_type')}</span><strong>{props.selectedCipher.passport.decPassportType || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_national_id_number')}</span><strong>{props.selectedCipher.passport.decNationalIdentificationNumber || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_issuing_authority')}</span><strong>{props.selectedCipher.passport.decIssuingAuthority || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_issue_date')}</span><strong>{props.selectedCipher.passport.decIssueDate || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_expiration_date')}</span><strong>{props.selectedCipher.passport.decExpirationDate || ''}</strong></div>
            </div>
          )}

          {!!noteText.trim() && (
            <div className="card">
              <DetailSectionHead icon={<StickyNote size={15} />} title={t('txt_notes')} />
              <div className="note-actions">
                <button type="button" className="btn btn-secondary small" onClick={() => void copyToClipboard(noteText)}>
                  <Clipboard size={14} className="btn-icon" /> {t('txt_copy_note')}
                </button>
              </div>
              {noteBlocks.map((block, index) => {
                if (block.kind === 'text') {
                  return <div key={`note-${index}`} className="notes">{block.text}</div>;
                }
                if (block.kind === 'pem') {
                  return (
                    <div key={`note-${index}`} className="note-block">
                      <div className="note-block-head">
                        <button type="button" className="btn btn-secondary small" onClick={() => void copyToClipboard(block.text)}>
                          <Clipboard size={14} className="btn-icon" /> {t('txt_copy_all')}
                        </button>
                      </div>
                      <pre className="note-pem">{block.text}</pre>
                    </div>
                  );
                }
                if (block.kind === 'recoveryCodes') {
                  return (
                    <div key={`note-${index}`} className="note-block">
                      <div className="note-block-head">
                        <button
                          type="button"
                          className="btn btn-secondary small"
                          onClick={() => void copyToClipboard(block.codes.join('\n'))}
                        >
                          <Clipboard size={14} className="btn-icon" /> {t('txt_copy_all')}
                        </button>
                      </div>
                      <div className="note-codes">
                        {block.codes.map((code, codeIndex) => (
                          <button
                            key={`note-code-${index}-${codeIndex}`}
                            type="button"
                            className="note-code"
                            onClick={() => void copyToClipboard(code)}
                          >
                            {code}
                          </button>
                        ))}
                      </div>
                    </div>
                  );
                }
                return (
                  <div key={`note-${index}`} className="note-pairs">
                    {block.pairs.map((pair, pairIndex) => {
                      const pairKey = `note-pair-${index}-${pairIndex}`;
                      const pairRevealed = !!revealedFields[pairKey];
                      const PairIcon = FIELD_KIND_ICONS[presentField(pair.label, 0).kind];
                      return (
                        <CopyTarget
                          key={pairKey}
                          className="kv-field"
                          label={pair.label}
                          onCopy={() => void copyToClipboard(pair.value)}
                        >
                          <span className="kv-field-icon" aria-hidden="true">
                            <PairIcon size={15} />
                          </span>
                          <div className="kv-field-body">
                            <span className="kv-field-label">{pair.label}</span>
                            <div className="kv-field-value">
                              <strong className="value-ellipsis" title={pair.secret && !pairRevealed ? '' : pair.value}>
                                {pair.secret && !pairRevealed ? maskSecret(pair.value) : pair.value}
                              </strong>
                            </div>
                          </div>
                          <div className="kv-actions">
                            {pair.secret && (
                              <button
                                type="button"
                                className="btn btn-secondary small"
                                aria-label={`${pairRevealed ? t('txt_hide') : t('txt_reveal')} ${pair.label}`}
                                title={pairRevealed ? t('txt_hide') : t('txt_reveal')}
                                onClick={(event) => {
                                  event.stopPropagation();
                                  setRevealedFields((prev) => ({ ...prev, [pairKey]: !prev[pairKey] }));
                                }}
                              >
                                {pairRevealed ? <EyeOff size={14} className="btn-icon" /> : <Eye size={14} className="btn-icon" />}
                              </button>
                            )}
                            <CopyHint />
                          </div>
                        </CopyTarget>
                      );
                    })}
                  </div>
                );
              })}
            </div>
          )}

          {customFields.visible.length > 0 && (
            <div className="card">
              <DetailSectionHead icon={<List size={15} />} title={t('txt_custom_fields')} />
              {customFields.visible.map((entry) => renderCustomField(entry))}
            </div>
          )}

          {customFields.noise.length > 0 && (
            <details className="card detail-more-info">
              <summary>{t('txt_more_info_count', { count: customFields.noise.length })}</summary>
              <div className="detail-more-info-body">
                {customFields.noise.map((entry) => renderCustomField(entry))}
              </div>
            </details>
          )}

          {selectedAttachments.some((attachment) => String(attachment?.id || '').trim()) && (
            <div className="card">
              <DetailSectionHead icon={<Paperclip size={15} />} title={t('txt_attachments')} />
              <div className="attachment-list">
                {selectedAttachments.map((attachment) => {
                  const attachmentId = String(attachment?.id || '').trim();
                  if (!attachmentId) return null;
                  const fileName = plainValue(attachment.decFileName, attachment.fileName).trim() || attachmentId;
                  return (
                    <div key={`view-attachment-${attachmentId}`} className="attachment-row">
                      <div className="attachment-main">
                        <Paperclip size={14} />
                        <div className="attachment-text">
                          <strong className="value-ellipsis" title={fileName}>{fileName}</strong>
                          <span>{formatAttachmentSize(attachment)}</span>
                        </div>
                      </div>
                      <div className="kv-actions">
                        <button
                          type="button"
                          className="btn btn-secondary small"
                          disabled={props.downloadingAttachmentKey === `${props.selectedCipher.id}:${attachmentId}`}
                          onClick={() => props.onDownloadAttachment(props.selectedCipher, attachmentId)}
                        >
                          <Download size={14} className="btn-icon" /> {formatDownloadLabel(attachmentId)}
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {(props.selectedCipher.creationDate || props.selectedCipher.revisionDate) && (
            <div className="card detail-meta-card">
              <DetailSectionHead icon={<History size={15} />} title={t('txt_item_information')} />
              <div className="detail-meta-group">
                {props.usageAvailable && (
                  <div className="detail-meta-row">
                    <span className="detail-meta-icon" aria-hidden="true"><Sparkles size={15} /></span>
                    <span className="detail-meta-text">
                      <span className="detail-meta-label">{t('txt_last_copied')}</span>
                      <span className="detail-meta-value">{formatHistoryTime(props.usage?.lastUsedAt)}</span>
                    </span>
                  </div>
                )}
                <div className="detail-meta-row">
                  <span className="detail-meta-icon" aria-hidden="true"><Pencil size={15} /></span>
                  <span className="detail-meta-text">
                    <span className="detail-meta-label">{t('txt_last_edited')}</span>
                    <span className="detail-meta-value">{formatHistoryTime(props.selectedCipher.revisionDate)}</span>
                  </span>
                </div>
                <div className="detail-meta-row">
                  <span className="detail-meta-icon" aria-hidden="true"><CalendarPlus size={15} /></span>
                  <span className="detail-meta-text">
                    <span className="detail-meta-label">{t('txt_created')}</span>
                    <span className="detail-meta-value">{formatHistoryTime(props.selectedCipher.creationDate)}</span>
                  </span>
                </div>
                {!!props.selectedCipher.login?.passwordRevisionDate && (
                  <div className="detail-meta-row">
                    <span className="detail-meta-icon" aria-hidden="true"><KeyRound size={15} /></span>
                    <span className="detail-meta-text">
                      <span className="detail-meta-label">{t('txt_password_updated')}</span>
                      <span className="detail-meta-value">{formatHistoryTime(props.selectedCipher.login.passwordRevisionDate)}</span>
                    </span>
                  </div>
                )}
              </div>
              <button type="button" className="detail-meta-link" onClick={() => void openItemHistory()}>
                {t('txt_item_history_view')}
              </button>
              {passwordHistoryEntries.length > 0 && (
                <button type="button" className="detail-meta-link" onClick={() => setPasswordHistoryOpen(true)}>
                  {t('txt_password_history')}
                </button>
              )}
            </div>
          )}

          {isDeleted && (
            <div className="detail-actions">
              <button type="button" className="btn btn-danger" onClick={() => props.onDelete(props.selectedCipher)}>
                <Trash2 size={14} className="btn-icon" /> {deleteLabel}
              </button>
            </div>
          )}
        </>
      )}
      <PasswordHistoryDialog
        open={passwordHistoryOpen && !repromptLocked}
        entries={passwordHistoryEntries}
        onClose={() => setPasswordHistoryOpen(false)}
      />
      <ItemHistoryDialog
        open={itemHistoryOpen && !repromptLocked}
        cipher={props.selectedCipher}
        entries={itemHistoryEntries}
        version={itemHistoryVersion}
        loading={itemHistoryLoading}
        versionLoading={itemHistoryVersionLoading}
        restoring={itemHistoryRestoring}
        error={itemHistoryError}
        onSelectVersion={(versionId) => void selectItemHistoryVersion(versionId)}
        onRestore={(versionId) => void restoreItemHistoryVersion(versionId)}
        onClose={() => setItemHistoryOpen(false)}
      />
    </>
  );
}
