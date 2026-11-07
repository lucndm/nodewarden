import { createPortal } from 'preact/compat';
import { useEffect, useMemo, useState } from 'preact/hooks';
import { History, X } from 'lucide-preact';
import { useDialogLifecycle } from '@/components/ConfirmDialog';
import { formatHistoryTime } from '@/components/vault/vault-page-helpers';
import {
  ITEM_HISTORY_FIELDS,
  cipherHistoryValues,
  diffItemHistory,
  versionHistoryValues,
  type ItemHistoryEntry,
  type ItemHistoryVersion,
} from '@/lib/item-history';
import { t } from '@/lib/i18n';
import type { Cipher } from '@/lib/types';

interface ItemHistoryDialogProps {
  open: boolean;
  cipher: Cipher;
  entries: ItemHistoryEntry[];
  version: ItemHistoryVersion | null;
  loading: boolean;
  versionLoading: boolean;
  restoring: boolean;
  error: string;
  onSelectVersion: (versionId: string) => void;
  onRestore: (versionId: string) => void;
  onClose: () => void;
}

const CURRENT_VERSION_ID = '';

export default function ItemHistoryDialog(props: ItemHistoryDialogProps) {
  const [selectedId, setSelectedId] = useState(CURRENT_VERSION_ID);
  const [confirming, setConfirming] = useState(false);
  useDialogLifecycle(props.open, props.onClose);

  // Every opening starts on the live item, and a new selection always drops a
  // pending restore confirmation.
  useEffect(() => {
    if (!props.open) return;
    setSelectedId(CURRENT_VERSION_ID);
    setConfirming(false);
  }, [props.open, props.cipher.id]);

  const select = (versionId: string) => {
    setSelectedId(versionId);
    setConfirming(false);
    props.onSelectVersion(versionId);
  };

  const isCurrent = selectedId === CURRENT_VERSION_ID;
  const values = useMemo(
    () => (isCurrent || !props.version ? cipherHistoryValues(props.cipher) : versionHistoryValues(props.version)),
    [isCurrent, props.cipher, props.version]
  );
  const changes = useMemo(
    () => (isCurrent || !props.version ? [] : diffItemHistory(props.cipher, props.version)),
    [isCurrent, props.cipher, props.version]
  );

  if (!props.open || typeof document === 'undefined') return null;
  return createPortal(
    <div className="dialog-mask open" onClick={(event) => event.target === event.currentTarget && props.onClose()}>
      <section className="dialog-card item-history-dialog open" role="dialog" aria-modal="true" aria-label={t('txt_item_history')}>
        <div className="item-history-head">
          <h3 className="dialog-title">{t('txt_item_history')}</h3>
          <button type="button" className="item-history-close" aria-label={t('txt_close')} onClick={props.onClose}>
            <X size={18} />
          </button>
        </div>

        <div className="item-history-body">
          <div className="item-history-timeline">
            <button
              type="button"
              className={`item-history-row${isCurrent ? ' active' : ''}`}
              onClick={() => select(CURRENT_VERSION_ID)}
            >
              <span className="item-history-row-kind">{t('txt_item_history_current')}</span>
              <span className="item-history-row-name">{props.cipher.decName || t('txt_no_name')}</span>
              <span className="item-history-row-time">{formatHistoryTime(props.cipher.revisionDate)}</span>
            </button>

            {props.entries.map((entry) => (
              <button
                key={entry.id}
                type="button"
                className={`item-history-row${selectedId === entry.id ? ' active' : ''}`}
                onClick={() => select(entry.id)}
              >
                <span className="item-history-row-kind">
                  {entry.kind === 'created' ? t('txt_item_history_created') : t('txt_item_history_modified')}
                </span>
                <span className="item-history-row-name">{entry.name || t('txt_no_name')}</span>
                <span className="item-history-row-time">{formatHistoryTime(entry.createdAt)}</span>
              </button>
            ))}

            {!props.loading && !props.entries.length && (
              <p className="item-history-empty">{t('txt_item_history_empty')}</p>
            )}
          </div>

          <div className="item-history-detail">
            {props.error && <p className="item-history-error">{props.error}</p>}

            {!isCurrent && props.versionLoading && <p className="item-history-empty">{t('txt_loading')}</p>}

            {isCurrent && (
              <>
                <div className="item-history-fields">
                  {ITEM_HISTORY_FIELDS.map((field) => {
                    const value = values[field.key];
                    if (!value) return null;
                    return (
                      <div key={field.key} className="kv-line">
                        <span>{t(field.labelKey)}</span>
                        <strong>{value}</strong>
                      </div>
                    );
                  })}
                </div>
                <div className="item-history-diff">
                  <strong>{t('txt_item_history_compare')}</strong>
                  <p className="item-history-empty">{t('txt_item_history_no_changes')}</p>
                </div>
              </>
            )}

            {!isCurrent && !props.versionLoading && props.version && (
              <>
                <div className="item-history-fields">
                  {ITEM_HISTORY_FIELDS.map((field) => {
                    const value = values[field.key];
                    if (!value) return null;
                    return (
                      <div key={field.key} className="kv-line">
                        <span>{t(field.labelKey)}</span>
                        <strong>{value}</strong>
                      </div>
                    );
                  })}
                </div>

                <div className="item-history-diff">
                  <strong>{t('txt_item_history_compare')}</strong>
                  {changes.length ? (
                    <>
                      <span className="item-history-diff-label">{t('txt_item_history_changed')}</span>
                      {changes.map((change) => (
                        <div key={change.key} className="item-history-diff-row">
                          <span className="item-history-diff-label">{t(change.labelKey)}</span>
                          <span className="item-history-diff-value">
                            {change.previous || '—'} → <strong>{change.current || '—'}</strong>
                          </span>
                        </div>
                      ))}
                    </>
                  ) : (
                    <p className="item-history-empty">{t('txt_item_history_no_changes')}</p>
                  )}
                </div>

                <div className="item-history-actions">
                  {confirming ? (
                    <>
                      <span className="item-history-diff-label">{t('txt_item_history_restore')}</span>
                      <div className="item-history-action-row">
                        <button
                          type="button"
                          className="btn btn-primary small"
                          disabled={props.restoring}
                          onClick={() => props.onRestore(props.version?.id || '')}
                        >
                          {t('txt_item_history_restore_confirm')}
                        </button>
                        <button type="button" className="btn btn-secondary small" disabled={props.restoring} onClick={() => setConfirming(false)}>
                          {t('txt_cancel')}
                        </button>
                      </div>
                    </>
                  ) : (
                    <button type="button" className="btn btn-secondary small" onClick={() => setConfirming(true)}>
                      <History size={14} className="btn-icon" /> {t('txt_item_history_restore')}
                    </button>
                  )}
                </div>
              </>
            )}
          </div>
        </div>
      </section>
    </div>,
    document.body
  );
}
