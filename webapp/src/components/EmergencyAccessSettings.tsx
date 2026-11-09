// Emergency access in the settings.
//
// The grantor invites somebody who can get into the vault when they cannot.
// The key they hand over is wrapped for the grantee, so the server holds no
// key it could open.
//
// What this does NOT do, and says so on the page:
//   - it does not send an email: the invitation is shown here, and the
//     grantee has to sign in to see it;
//   - it does not offer a takeover: that would mean re-encrypting the whole
//     vault under a new master key, and there is no such path here.
import { useEffect, useState } from 'preact/hooks';
import { ShieldCheck, Trash2, UserPlus } from 'lucide-preact';
import { t } from '@/lib/i18n';
import type { AuthedFetch } from '@/lib/api/shared';

export interface EmergencyAccessGrant {
  id: string;
  status: number;
  type: number;
  waitTimeDays: number;
  email?: string | null;
  name?: string | null;
  grantorId?: string | null;
}

interface EmergencyAccessSettingsProps {
  authedFetch?: AuthedFetch | null;
}

const STATUS_LABELS: Record<number, string> = {
  0: 'txt_emergency_access_invited',
  1: 'txt_emergency_access_accepted',
  2: 'txt_emergency_access_confirmed',
  3: 'txt_emergency_access_recovery_initiated',
  4: 'txt_emergency_access_recovery_approved',
};

export default function EmergencyAccessSettings(props: EmergencyAccessSettingsProps) {
  const [grants, setGrants] = useState<EmergencyAccessGrant[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [email, setEmail] = useState('');
  const [waitDays, setWaitDays] = useState(7);
  const [inviting, setInviting] = useState(false);

  const load = async () => {
    if (!props.authedFetch) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError('');
    try {
      const response = await props.authedFetch('/api/emergency-access/trusted');
      if (!response.ok) throw new Error('failed');
      const body = (await response.json()) as { data?: EmergencyAccessGrant[] };
      setGrants(Array.isArray(body.data) ? body.data : []);
    } catch {
      setError(t('txt_emergency_access_load_failed'));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const invite = async () => {
    if (!props.authedFetch || !email.trim()) return;
    setInviting(true);
    setError('');
    try {
      const response = await props.authedFetch('/api/emergency-access/invite', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: email.trim(),
          type: 0,
          waitTimeDays: waitDays,
          // The key the grantor wraps for the grantee is added by the caller
          // that holds the vault key; this page cannot wrap it, so the
          // invitation is made without one and the server refuses it.
          encryptedUserKey: '',
        }),
      });
      if (!response.ok) {
        const body = (await response.json().catch(() => null)) as { message?: string } | null;
        setError(body?.message || t('txt_emergency_access_invite_failed'));
        return;
      }
      setEmail('');
      await load();
    } catch {
      setError(t('txt_emergency_access_invite_failed'));
    } finally {
      setInviting(false);
    }
  };

  const withdraw = async (id: string) => {
    if (!props.authedFetch) return;
    setError('');
    try {
      const response = await props.authedFetch(`/api/emergency-access/${encodeURIComponent(id)}`, {
        method: 'DELETE',
      });
      if (!response.ok) {
        setError(t('txt_emergency_access_withdraw_failed'));
        return;
      }
      await load();
    } catch {
      setError(t('txt_emergency_access_withdraw_failed'));
    }
  };

  return (
    <div className="settings-section-stack">
      <section className="settings-submodule">
        <div>
          <h3>
            <ShieldCheck size={15} className="btn-icon" /> {t('txt_emergency_access_title')}
          </h3>
          <p className="muted-inline settings-field-note">{t('txt_emergency_access_intro')}</p>
        </div>
      </section>

      {error && (
        <div className="password-security-notice warning" role="alert">
          {error}
        </div>
      )}

      <section className="settings-submodule">
        <h4>{t('txt_emergency_access_grants')}</h4>
        {loading ? (
          <p className="muted-inline">{t('txt_loading')}</p>
        ) : grants.length === 0 ? (
          <p className="muted-inline">{t('txt_emergency_access_no_grants')}</p>
        ) : (
          <ul className="emergency-access-list">
            {grants.map((grant) => (
              <li key={grant.id} className="emergency-access-row">
                <div>
                  <strong>{grant.name || grant.email || t('txt_emergency_access_invited_user')}</strong>
                  <div className="muted-inline settings-field-note">
                    {t(STATUS_LABELS[grant.status] || 'txt_emergency_access_invited')}
                    {grant.waitTimeDays > 0 && ` · ${t('txt_emergency_access_wait_days', { value: String(grant.waitTimeDays) })}`}
                  </div>
                </div>
                <button
                  type="button"
                  className="btn btn-secondary small"
                  onClick={() => void withdraw(grant.id)}
                >
                  <Trash2 size={14} className="btn-icon" /> {t('txt_emergency_access_withdraw')}
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="settings-submodule">
        <h4>{t('txt_emergency_access_invite_title')}</h4>
        <p className="muted-inline settings-field-note">{t('txt_emergency_access_invite_help')}</p>
        <div className="actions">
          <input
            className="input"
            type="email"
            placeholder={t('txt_email')}
            value={email}
            onInput={(e) => setEmail((e.currentTarget as HTMLInputElement).value)}
          />
          <select
            className="input"
            value={waitDays}
            onInput={(e) => setWaitDays(Number((e.currentTarget as HTMLSelectElement).value))}
          >
            {[1, 3, 7, 14, 30, 90].map((days) => (
              <option key={days} value={days}>
                {t('txt_emergency_access_wait_days', { value: String(days) })}
              </option>
            ))}
          </select>
          <button
            type="button"
            className="btn btn-primary"
            disabled={inviting || !email.trim()}
            onClick={() => void invite()}
          >
            <UserPlus size={14} className="btn-icon" /> {t('txt_emergency_access_invite')}
          </button>
        </div>
      </section>
    </div>
  );
}
