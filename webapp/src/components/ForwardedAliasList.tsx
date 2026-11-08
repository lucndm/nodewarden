import { useCallback, useEffect, useState } from 'preact/hooks';
import { LoaderCircle, RefreshCw, Trash2 } from 'lucide-preact';

import ConfirmDialog from '@/components/ConfirmDialog';
import { t } from '@/lib/i18n';
import type { ForwarderAccountConfig } from '@/lib/password-generator';
import {
  deleteAlias,
  ForwarderError,
  listAliases,
  setAliasEnabled,
  type ForwarderErrorKind,
  type SlAliasRecord,
} from '@/lib/simplelogin-forwarder';

/** The message that tells the user what went wrong with the provider. */
export function forwardedErrorKey(kind: ForwarderErrorKind): string {
  const keys: Record<ForwarderErrorKind, string> = {
    config: 'txt_generator_forwarded_error_config',
    network: 'txt_generator_forwarded_error_network',
    auth: 'txt_generator_forwarded_error_auth',
    quota: 'txt_generator_forwarded_error_quota',
    server: 'txt_generator_forwarded_error_generic',
  };
  return keys[kind];
}

function providerErrorMessage(cause: unknown): string {
  if (cause instanceof ForwarderError) return t(forwardedErrorKey(cause.kind));
  return t('txt_generator_forwarded_error_generic');
}

/**
 * The aliases the provider holds for this account.
 *
 * The generator creates real aliases at the provider. Once one exists it
 * keeps receiving mail until it is turned off there, so it has to be
 * visible and revocable from here - and the state shown is the one the
 * provider answers with, never one that was assumed.
 */
export function ForwardedAliasList(props: { account: ForwarderAccountConfig }) {
  const serverUrl = props.account.serverUrl.trim();
  const apiKey = props.account.apiKey.trim();
  const configured = !!serverUrl && !!apiKey;

  const [aliases, setAliases] = useState<SlAliasRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [pendingId, setPendingId] = useState<number | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<SlAliasRecord | null>(null);

  const load = useCallback(async () => {
    if (!configured) return;
    setLoading(true);
    setError('');
    try {
      setAliases(await listAliases({ serverUrl, apiKey }));
    } catch (cause) {
      setError(providerErrorMessage(cause));
    } finally {
      setLoading(false);
    }
  }, [configured, serverUrl, apiKey]);

  useEffect(() => {
    void load();
  }, [load]);

  const toggle = async (alias: SlAliasRecord) => {
    setPendingId(alias.id);
    setError('');
    try {
      const enabled = await setAliasEnabled({ serverUrl, apiKey }, alias.id);
      setAliases((rows) => rows.map((row) => (row.id === alias.id ? { ...row, enabled } : row)));
    } catch (cause) {
      setError(providerErrorMessage(cause));
    } finally {
      setPendingId(null);
    }
  };

  const remove = async (alias: SlAliasRecord) => {
    setPendingId(alias.id);
    setError('');
    try {
      await deleteAlias({ serverUrl, apiKey }, alias.id);
      setAliases((rows) => rows.filter((row) => row.id !== alias.id));
    } catch (cause) {
      setError(providerErrorMessage(cause));
    } finally {
      setPendingId(null);
      setDeleteTarget(null);
    }
  };

  if (!configured) {
    return <p className="generator-options-note">{t('txt_generator_aliases_configure')}</p>;
  }

  return (
    <section className="generator-alias-section">
      <div className="generator-alias-toolbar">
        <strong>{t('txt_generator_aliases_title')}</strong>
        <button type="button" className="btn btn-secondary small" disabled={loading} onClick={() => void load()}>
          {loading ? <LoaderCircle size={14} className="btn-icon spin" /> : <RefreshCw size={14} className="btn-icon" />}
          {t('txt_refresh')}
        </button>
      </div>

      {error && <p className="generator-alias-error" role="alert">{error}</p>}
      {loading && !aliases.length && <p className="generator-options-note">{t('txt_loading')}</p>}
      {!loading && !aliases.length && !error && <p className="generator-options-note">{t('txt_generator_aliases_empty')}</p>}

      <div className="generator-alias-list">
        {aliases.map((alias) => (
          <article className="generator-alias-row" key={alias.id}>
            <div className="generator-alias-main">
              <span className="generator-alias-address">{alias.email}</span>
              <span className="generator-alias-meta">
                {alias.enabled ? t('txt_generator_aliases_active') : t('txt_generator_aliases_disabled')}
                {alias.mailboxes.length > 0
                  ? ` · ${t('txt_generator_aliases_forwarded', { value: alias.mailboxes.map((box) => box.email).join(', ') })}`
                  : ''}
              </span>
            </div>
            <div className="generator-alias-actions">
              <button
                type="button"
                className="btn btn-secondary small"
                disabled={pendingId === alias.id}
                onClick={() => void toggle(alias)}
              >
                {alias.enabled ? t('txt_generator_aliases_disable') : t('txt_generator_aliases_enable')}
              </button>
              <button
                type="button"
                className="btn btn-secondary small"
                disabled={pendingId === alias.id}
                onClick={() => setDeleteTarget(alias)}
              >
                <Trash2 size={14} className="btn-icon" /> {t('txt_delete')}
              </button>
            </div>
          </article>
        ))}
      </div>

      <ConfirmDialog
        open={deleteTarget !== null}
        title={t('txt_delete')}
        message={t('txt_generator_aliases_delete_confirm')}
        danger
        confirmText={t('txt_delete')}
        cancelText={t('txt_cancel')}
        onConfirm={() => {
          if (deleteTarget) void remove(deleteTarget);
        }}
        onCancel={() => setDeleteTarget(null)}
      />
    </section>
  );
}
