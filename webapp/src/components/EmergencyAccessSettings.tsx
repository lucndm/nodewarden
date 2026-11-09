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
import {
  acceptEmergencyAccess,
  approveEmergencyAccess,
  getGrantedEmergencyAccess,
  getTrustedEmergencyAccess,
  initiateEmergencyAccess,
  inviteEmergencyAccess,
  rejectEmergencyAccess,
  withdrawEmergencyAccess,
  type EmergencyAccessGranteeDetails,
  type EmergencyAccessGrantorDetails,
} from '@/lib/api/emergency-access';

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

// A view grant lets the other person read; a takeover grant lets them replace
// the master password once the wait has passed and the grantor approves.
const TYPE_LABELS: Record<number, string> = {
  0: 'txt_emergency_access_type_view',
  1: 'txt_emergency_access_type_takeover',
};

export default function EmergencyAccessSettings(props: EmergencyAccessSettingsProps) {
  const [grants, setGrants] = useState<EmergencyAccessGranteeDetails[]>([]);
  const [received, setReceived] = useState<EmergencyAccessGrantorDetails[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [email, setEmail] = useState('');
  const [waitDays, setWaitDays] = useState(7);
  const [grantType, setGrantType] = useState(0);
  const [inviting, setInviting] = useState(false);

  const load = async () => {
    if (!props.authedFetch) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError('');
    try {
      // One of the two lists failing must not hide the other: the grants this
      // account gave and the ones it was given are separate things.
      const [given, got] = await Promise.all([
        getTrustedEmergencyAccess(props.authedFetch).catch(() => [] as EmergencyAccessGranteeDetails[]),
        getGrantedEmergencyAccess(props.authedFetch).catch(() => [] as EmergencyAccessGrantorDetails[]),
      ]);
      setGrants(given);
      setReceived(got);
    } catch {
      setError(t('txt_emergency_access_load_failed'));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const recover = async (id: string, action: 'initiate' | 'approve') => {
    if (!props.authedFetch) return;
    setError('');
    try {
      if (action === 'initiate') await initiateEmergencyAccess(props.authedFetch, id);
      else await approveEmergencyAccess(props.authedFetch, id);
      await load();
    } catch {
      setError(
        action === 'initiate'
          ? t('txt_emergency_access_initiate_failed')
          : t('txt_emergency_access_approve_failed')
      );
    }
  };

  const answer = async (id: string, action: 'accept' | 'reject') => {
    if (!props.authedFetch) return;
    setError('');
    try {
      if (action === 'accept') await acceptEmergencyAccess(props.authedFetch, id);
      else await rejectEmergencyAccess(props.authedFetch, id);
      await load();
    } catch {
      setError(
        action === 'accept'
          ? t('txt_emergency_access_accept_failed')
          : t('txt_emergency_access_reject_failed')
      );
    }
  };

  const invite = async () => {
    if (!props.authedFetch || !email.trim()) return;
    setInviting(true);
    setError('');
    try {
      await inviteEmergencyAccess(props.authedFetch, {
        email: email.trim(),
        type: grantType,
        waitTimeDays: waitDays,
        // The key the grantor wraps for the grantee is made by the caller
        // that holds the vault key. This page does not hold it, so the
        // invitation goes without one and the server refuses it rather than
        // storing a grant that could never be opened.
        encryptedUserKey: '',
      });
      setEmail('');
      await load();
    } catch (error) {
      setError(error instanceof Error && error.message ? error.message : t('txt_emergency_access_invite_failed'));
    } finally {
      setInviting(false);
    }
  };

  const withdraw = async (id: string) => {
    if (!props.authedFetch) return;
    setError('');
    try {
      await withdrawEmergencyAccess(props.authedFetch, id);
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
                    {t(TYPE_LABELS[grant.type] || 'txt_emergency_access_type_view')}
                    {' · '}
                    {t(STATUS_LABELS[grant.status] || 'txt_emergency_access_invited')}
                    {grant.waitTimeDays > 0 && ` · ${t('txt_emergency_access_wait_days', { value: String(grant.waitTimeDays) })}`}
                  </div>
                </div>
                <div className="actions">
                  {grant.type === 1 && grant.status === 3 && (
                    <button
                      type="button"
                      className="btn btn-primary small"
                      onClick={() => void recover(grant.id, 'approve')}
                    >
                      {t('txt_emergency_access_approve')}
                    </button>
                  )}
                  <button
                    type="button"
                    className="btn btn-secondary small"
                    onClick={() => void withdraw(grant.id)}
                  >
                    <Trash2 size={14} className="btn-icon" /> {t('txt_emergency_access_withdraw')}
                  </button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="settings-submodule">
        <h4>{t('txt_emergency_access_received_title')}</h4>
        <p className="muted-inline settings-field-note">{t('txt_emergency_access_received_help')}</p>
        {loading ? (
          <p className="muted-inline">{t('txt_loading')}</p>
        ) : received.length === 0 ? (
          <p className="muted-inline">{t('txt_emergency_access_no_received')}</p>
        ) : (
          <ul className="emergency-access-list">
            {received.map((grant) => (
              <li key={grant.id} className="emergency-access-row">
                <div>
                  <strong>{grant.name || grant.email || t('txt_emergency_access_grantor')}</strong>
                  <div className="muted-inline settings-field-note">
                    {t(STATUS_LABELS[grant.status] || 'txt_emergency_access_invited')}
                  </div>
                </div>
                {grant.status < 2 && (
                  <div className="actions">
                    <button
                      type="button"
                      className="btn btn-primary small"
                      onClick={() => void answer(grant.id, 'accept')}
                    >
                      {t('txt_emergency_access_accept')}
                    </button>
                    <button
                      type="button"
                      className="btn btn-secondary small"
                      onClick={() => void answer(grant.id, 'reject')}
                    >
                      {t('txt_emergency_access_reject')}
                    </button>
                  </div>
                )}
                {grant.status === 2 && grant.type === 1 && (
                  <div className="actions">
                    <button
                      type="button"
                      className="btn btn-secondary small"
                      onClick={() => void recover(grant.id, 'initiate')}
                    >
                      {t('txt_emergency_access_start_wait')}
                    </button>
                  </div>
                )}
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
            value={grantType}
            onInput={(e) => setGrantType(Number((e.currentTarget as HTMLSelectElement).value))}
          >
            <option value={0}>{t('txt_emergency_access_type_view')}</option>
            <option value={1}>{t('txt_emergency_access_type_takeover')}</option>
          </select>
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
