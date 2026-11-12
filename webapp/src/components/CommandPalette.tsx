import { createPortal } from 'preact/compat';
import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { Copy, FileText, KeyRound, ListFilter, ListX } from 'lucide-preact';
import { useLocation } from 'wouter';
import { useDialogLifecycle } from '@/components/ConfirmDialog';
import { copyToClipboard } from '@/components/vault/vault-page-helpers';
import { searchPalette, withListFilter, type PageEntry, type PaletteEntry, type PaletteField } from '@/lib/command-palette';
import { calcTotpNow } from '@/lib/crypto';
import { presentField } from '@/lib/field-display';
import { t } from '@/lib/i18n';
import type { Cipher } from '@/lib/types';

interface CommandPaletteProps {
  open: boolean;
  pages: PageEntry[];
  ciphers: Cipher[];
  /** Rises every time the shortcut is pressed, so the input takes the focus again. */
  focusSignal: number;
  /** The text the input starts with. */
  initialQuery?: string;
  /** The list of the vault can be filtered from the palette. */
  listFilterAvailable?: boolean;
  /** Where the row that filters the list goes: in front of the results or behind them. */
  listFilterPlacement?: 'first' | 'last';
  onClose: () => void;
  onTrackPasswordCopy?: (cipherId: string) => void;
}

let paletteIdCounter = 0;

/** The value a field holds. A secret only reaches the clipboard here. */
async function fieldValue(cipher: Cipher, field: PaletteField): Promise<string> {
  switch (field.type) {
    case 'username':
      return String(cipher.login?.decUsername ?? cipher.login?.username ?? '');
    case 'password':
      return String(cipher.login?.decPassword ?? cipher.login?.password ?? '');
    case 'totp': {
      const code = await calcTotpNow(String(cipher.login?.decTotp || ''));
      return code?.code || '';
    }
    case 'uri':
      return String(cipher.login?.uris?.[field.index]?.decUri ?? cipher.login?.uris?.[field.index]?.uri ?? '');
    case 'custom':
      return String(cipher.fields?.[field.index]?.decValue ?? cipher.fields?.[field.index]?.value ?? '');
    case 'cardNumber':
      return String(cipher.card?.decNumber ?? cipher.card?.number ?? '');
    case 'cardCode':
      return String(cipher.card?.decCode ?? cipher.card?.code ?? '');
    case 'notes':
      return String(cipher.decNotes ?? cipher.notes ?? '');
  }
}

/** A field the item hides behind the master password. */
function isSecretField(cipher: Cipher, field: PaletteField): boolean {
  if (field.type === 'password' || field.type === 'totp') return true;
  if (field.type !== 'custom') return false;
  const stored = cipher.fields?.[field.index];
  if (!stored) return false;
  return presentField(String(stored.decName ?? stored.name ?? ''), Number(stored.type) || 0).secret;
}

export default function CommandPalette(props: CommandPaletteProps) {
  const [, navigate] = useLocation();
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const restoreFocusRef = useRef<HTMLElement | null>(null);
  const listboxId = useMemo(() => `command-palette-listbox-${++paletteIdCounter}`, []);

  // The search only runs while the palette is open.
  const results = useMemo(
    () => (props.open
      ? withListFilter(searchPalette(query, props.pages, props.ciphers), query, {
        listFilterAvailable: !!props.listFilterAvailable,
        activeFilter: props.initialQuery ?? '',
        placement: props.listFilterPlacement ?? 'first',
      })
      : []),
    [props.open, query, props.pages, props.ciphers, props.listFilterAvailable, props.initialQuery, props.listFilterPlacement]
  );
  const cipherById = useMemo(() => new Map(props.ciphers.map((cipher) => [cipher.id, cipher])), [props.ciphers]);

  const filters = results.filter((entry): entry is Extract<PaletteEntry, { kind: 'filter' }> => entry.kind === 'filter');
  const pages = results.filter((entry): entry is Extract<PaletteEntry, { kind: 'page' }> => entry.kind === 'page');
  const items = results.filter((entry): entry is Extract<PaletteEntry, { kind: 'item' }> => entry.kind === 'item');
  const fields = results.filter((entry): entry is Extract<PaletteEntry, { kind: 'field' }> => entry.kind === 'field');
  // The group of the filter row keeps the place the placement gives it: the
  // group is drawn in front of the results or behind them. The offset of a
  // group is the place of its first row in the list of the results.
  const groupsInOrder = props.listFilterPlacement === 'last'
    ? [
      { kind: 'page' as const, title: t('txt_palette_pages'), entries: pages },
      { kind: 'item' as const, title: t('txt_palette_items'), entries: items },
      { kind: 'field' as const, title: t('txt_palette_fields'), entries: fields },
      { kind: 'filter' as const, title: t('txt_palette_filter'), entries: filters },
    ]
    : [
      { kind: 'filter' as const, title: t('txt_palette_filter'), entries: filters },
      { kind: 'page' as const, title: t('txt_palette_pages'), entries: pages },
      { kind: 'item' as const, title: t('txt_palette_items'), entries: items },
      { kind: 'field' as const, title: t('txt_palette_fields'), entries: fields },
    ];
  let groupOffset = 0;
  const groups = groupsInOrder.map((group) => {
    const offset = groupOffset;
    groupOffset += group.entries.length;
    return { ...group, offset };
  });
  const active = results.length > 0 ? Math.min(activeIndex, results.length - 1) : -1;

  useDialogLifecycle(props.open, props.onClose);

  useEffect(() => {
    if (!props.open) return;
    // The palette starts with the text it was opened with.
    setQuery(props.initialQuery ?? '');
    setActiveIndex(0);
  }, [props.open]);

  useEffect(() => {
    if (!props.open || typeof document === 'undefined') return;
    const focused = document.activeElement;
    restoreFocusRef.current = focused instanceof HTMLElement ? focused : null;
    const frame = window.requestAnimationFrame(() => {
      inputRef.current?.focus({ preventScroll: true });
      // The text of the palette is selected, so typing replaces it.
      inputRef.current?.select();
    });
    return () => {
      window.cancelAnimationFrame(frame);
      const previous = restoreFocusRef.current;
      restoreFocusRef.current = null;
      if (previous && document.contains(previous)) previous.focus({ preventScroll: true });
    };
  }, [props.open]);

  useEffect(() => {
    if (!props.open) return;
    inputRef.current?.focus({ preventScroll: true });
    inputRef.current?.select();
  }, [props.focusSignal, props.open]);

  function move(step: number): void {
    if (results.length === 0) return;
    setActiveIndex((current) => (Math.min(current, results.length - 1) + step + results.length) % results.length);
  }

  function openItem(cipherId: string): void {
    // The URL names the item to open. The page reads it, so the item opens
    // whenever the page reads the URL.
    navigate(`/vault?cipher=${encodeURIComponent(cipherId)}`);
    props.onClose();
  }

  async function select(entry: PaletteEntry): Promise<void> {
    if (entry.kind === 'filter') {
      // The list of the vault is filtered by the text of the palette.
      window.dispatchEvent(new CustomEvent('nodewarden:vault-filter', {
        detail: entry.id === 'filter-clear' ? '' : query.trim(),
      }));
      props.onClose();
      return;
    }
    if (entry.kind === 'page') {
      // The URL names the tab of the settings page to open. The page reads
      // it, so the tab opens whenever the page reads the URL.
      const target = entry.settingsSection
        ? `${entry.href}?section=${encodeURIComponent(entry.settingsSection)}`
        : entry.href;
      navigate(target);
      props.onClose();
      return;
    }
    if (entry.kind === 'item') {
      openItem(entry.cipherId);
      return;
    }

    const cipher = cipherById.get(entry.cipherId);
    if (!cipher) return;
    // An item behind the master password opens in the vault, where the vault
    // asks for the password itself.
    if (Number(cipher.reprompt || 0) === 1 && isSecretField(cipher, entry.field)) {
      openItem(entry.cipherId);
      return;
    }
    const value = await fieldValue(cipher, entry.field);
    if (!value) return;
    const copied = await copyToClipboard(value);
    if (copied && entry.field.type === 'password') props.onTrackPasswordCopy?.(entry.cipherId);
    props.onClose();
  }

  function handleKeyDown(event: KeyboardEvent): void {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      move(1);
      return;
    }
    if (event.key === 'ArrowUp') {
      event.preventDefault();
      move(-1);
      return;
    }
    if (event.key === 'Enter') {
      event.preventDefault();
      if (active >= 0) void select(results[active]);
    }
  }

  if (!props.open || typeof document === 'undefined') return null;

  return createPortal(
    <div className="palette-mask" onClick={(event) => { if (event.target === event.currentTarget) props.onClose(); }}>
      <div
        className="palette-card"
        role="dialog"
        aria-modal="true"
        aria-label={t('txt_command_palette')}
        onKeyDown={(event) => {
          // The dialog holds the input only, so the focus stays inside it.
          if (event.key !== 'Tab') return;
          event.preventDefault();
          inputRef.current?.focus({ preventScroll: true });
        }}
      >
        <input
          ref={inputRef}
          className="palette-input"
          type="text"
          role="combobox"
          aria-expanded={results.length > 0}
          aria-controls={listboxId}
          aria-activedescendant={active >= 0 ? `${listboxId}-${active}` : undefined}
          aria-label={t('txt_command_palette')}
          placeholder={t('txt_command_palette')}
          value={query}
          onInput={(event) => {
            setQuery(event.currentTarget.value);
            setActiveIndex(0);
          }}
          onKeyDown={handleKeyDown}
        />
        <div className="palette-list" role="listbox" id={listboxId} aria-label={t('txt_command_palette')}>
          {groups.map((group) => group.entries.length === 0 ? null : (
            <div role="group" aria-label={group.title} key={group.kind}>
              <div className="palette-group-title" aria-hidden="true">{group.title}</div>
              {group.entries.map((entry, index) => {
                const optionIndex = group.offset + index;
                const selected = optionIndex === active;
                return (
                  <div
                    key={entry.id}
                    id={`${listboxId}-${optionIndex}`}
                    role="option"
                    aria-selected={selected}
                    className={`palette-row ${selected ? 'active' : ''}`}
                    onMouseEnter={() => setActiveIndex(optionIndex)}
                    onClick={() => void select(entry)}
                  >
                    <span className="palette-row-icon" aria-hidden="true">
                      {entry.kind === 'page'
                        ? <FileText size={16} />
                        : entry.kind === 'item'
                          ? <KeyRound size={16} />
                          : entry.kind === 'filter'
                            ? entry.id === 'filter-clear' ? <ListX size={16} /> : <ListFilter size={16} />
                            : <Copy size={16} />}
                    </span>
                    <span className="palette-row-label">{entry.label}</span>
                    {entry.hint && <span className="palette-row-hint">{entry.hint}</span>}
                    {entry.kind === 'field' && <span className="palette-row-copy">{t('txt_copy')}</span>}
                  </div>
                );
              })}
            </div>
          ))}
          {results.length === 0 && <div className="palette-empty">{t('txt_palette_no_results')}</div>}
        </div>
        <div className="palette-footer">{t('txt_palette_hint')}</div>
      </div>
    </div>,
    document.body
  );
}
