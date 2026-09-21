import { useState } from 'preact/hooks';
import { LogIn } from 'lucide-preact';
import { t } from '@/lib/i18n';
import StandalonePageFrame from '@/components/StandalonePageFrame';

// Entry page of the official Bitwarden client SSO flow. Desktop, mobile,
// browser-extension and CLI clients open `{server}/#/sso?...` and wait for a
// redirect back to their own redirect URI with an authorization code.

export interface SsoEntryParams {
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  email: string;
  ssoIdentifier: string;
  /** Present when the connector handed the web flow back with an authorization code. */
  code?: string;
}

export default function SsoEntryPage(props: { params: SsoEntryParams }) {
  const params = props.params;
  const clientFlowValid = Boolean(params.clientId && params.redirectUri && params.state && params.codeChallenge);
  const webCompleted = Boolean(params.code && params.state);
  const [email, setEmail] = useState(params.email);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function submit(e: Event): Promise<void> {
    e.preventDefault();
    const trimmed = email.trim().toLowerCase();
    const domain = trimmed.includes('@') ? trimmed.split('@')[1] : '';
    if (!trimmed || !domain) {
      setError(t('txt_sso_error_invalid_email'));
      return;
    }
    setBusy(true);
    setError('');
    try {
      const response = await fetch(`/api/sso/prevalidate?domain=${encodeURIComponent(domain)}`, {
        headers: { Accept: 'application/json' },
      });
      const data = (await response.json().catch(() => ({}))) as { ssoAvailable?: boolean; ssoIdentifier?: string };
      if (!response.ok || data.ssoAvailable !== true) {
        setError(t('txt_sso_unavailable'));
        return;
      }
      const url = new URL('/identity/connect/authorize', window.location.origin);
      url.searchParams.set('client_id', params.clientId);
      url.searchParams.set('redirect_uri', params.redirectUri);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('scope', 'api offline_access');
      url.searchParams.set('state', params.state);
      url.searchParams.set('code_challenge', params.codeChallenge);
      url.searchParams.set('code_challenge_method', params.codeChallengeMethod || 'S256');
      url.searchParams.set('email', trimmed);
      url.searchParams.set('ssoIdentifier', params.ssoIdentifier || data.ssoIdentifier || 'zitadel');
      window.location.href = url.toString();
    } catch {
      setError(t('txt_sso_error_generic'));
    } finally {
      setBusy(false);
    }
  }

  return (
    <StandalonePageFrame title={t('txt_sso_page_title')}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void submit(e);
        }}
      >
        {webCompleted ? (
          <p className="muted standalone-muted" role="status">{t('txt_sso_web_completed')}</p>
        ) : !clientFlowValid ? (
          <p className="muted standalone-muted" role="alert">{t('txt_sso_client_only')}</p>
        ) : (
          <>
            <p className="muted standalone-muted">{t('txt_sso_page_description')}</p>
            <label className="field">
              <span>{t('txt_email')}</span>
              <input
                className="input"
                type="email"
                value={email}
                autoComplete="username"
                placeholder="you@example.com"
                autoFocus
                onInput={(e) => setEmail((e.currentTarget as HTMLInputElement).value)}
              />
            </label>
            {error ? (
              <p className="muted standalone-muted" role="alert">{error}</p>
            ) : null}
            <button type="submit" className="btn btn-primary full" disabled={busy}>
              <LogIn size={16} className="btn-icon" />
              {busy ? t('txt_unlocking') : t('txt_sso_continue')}
            </button>
          </>
        )}
      </form>
    </StandalonePageFrame>
  );
}
