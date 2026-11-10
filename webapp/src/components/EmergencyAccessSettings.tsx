// Emergency access in the settings.
//
// The grantor invites somebody who can get into the vault when they cannot.
// The key they hand over is wrapped for the grantee, so the server holds no
// key it could open.
//
// The whole path runs here, for both kinds of grant:
//   - the grantor confirms (hands over the key), approves or turns down a
//     recovery, and withdraws;
//   - the grantee accepts or declines, starts the wait, and once the grant is
//     approved either reads the vault (view) or sets a new master password
//     (takeover). Both open the grantor's key in this browser, with the
//     grantee's own private key.
//
// What this does NOT do, and says so on the page:
//   - it does not send an email: the invitation is shown here, and the
//     grantee has to sign in to see it.
//
// A takeover does not re-encrypt the vault: the vault key stays the same and
// only the password that opens it is replaced.
import { useEffect, useState } from 'preact/hooks';
import { Eye, KeyRound, ShieldCheck, Trash2, UserPlus, X } from 'lucide-preact';
import { t, translateServerError } from '@/lib/i18n';
import type { AuthedFetch } from '@/lib/api/shared';
import { buildTakeoverPassword, openGrantorVaultKey, wrapVaultKeyForGrantee } from '@/lib/emergency-access-key';
import { decryptSingleCipher } from '@/lib/decrypt-cipher';
import type { Cipher, SessionState } from '@/lib/types';
import {
  acceptEmergencyAccess,
  approveEmergencyAccess,
  confirmEmergencyAccess,
  getEmergencyAccessTakeover,
  getGrantedEmergencyAccess,
  getTrustedEmergencyAccess,
  getUserPublicKey,
  PublicKeyUnavailableError,
  initiateEmergencyAccess,
  inviteEmergencyAccess,
  rejectEmergencyAccess,
  setEmergencyAccessPassword,
  viewEmergencyAccess,
  withdrawEmergencyAccess,
  type EmergencyAccessGranteeDetails,
  type EmergencyAccessGrantorDetails,
} from '@/lib/api/emergency-access';

interface EmergencyAccessSettingsProps {
  authedFetch?: AuthedFetch | null;
  /** The session holds the vault key, which is what gets wrapped for the grantee. */
  session?: SessionState | null;
  /** This account's address, so it is not invited as its own contact. */
  email?: string | null;
  /** This account's private key, encrypted with its vault key; it opens a key handed to this account. */
  encryptedPrivateKey?: string | null;
}

// The status as the grantor reads it.
const STATUS_LABELS: Record<number, string> = {
  0: 'txt_emergency_access_invited',
  1: 'txt_emergency_access_accepted',
  2: 'txt_emergency_access_confirmed',
  3: 'txt_emergency_access_recovery_initiated',
  4: 'txt_emergency_access_recovery_approved',
};

// The status as the grantee reads it: status 3 waits on the other person.
const RECEIVED_STATUS_LABELS: Record<number, string> = {
  ...STATUS_LABELS,
  3: 'txt_emergency_access_waiting_for_grantor',
};

// A view grant lets the other person read; a takeover grant lets them replace
// the master password once the wait has passed and the grantor approves.
const TYPE_LABELS: Record<number, string> = {
  0: 'txt_emergency_access_type_view',
  1: 'txt_emergency_access_type_takeover',
};

const MIN_PASSWORD_LENGTH = 12;

/** When access opens on its own, unless the grantor turns the recovery down first. */
function accessOpensAt(recoveryInitiatedDate: string | null, waitTimeDays: number): string {
  if (!recoveryInitiatedDate) return '';
  const started = new Date(recoveryInitiatedDate).getTime();
  if (!Number.isFinite(started)) return '';
  return new Date(started + waitTimeDays * 24 * 60 * 60 * 1000).toLocaleString();
}

function errorText(error: unknown, fallbackKey: string): string {
  return translateServerError(error instanceof Error ? error.message : '', t(fallbackKey));
}

interface OpenedVault {
  grantName: string;
  items: Cipher[];
}

interface TakeoverForm {
  grant: EmergencyAccessGrantorDetails;
  password: string;
  password2: string;
  saving: boolean;
}

export default function EmergencyAccessSettings(props: EmergencyAccessSettingsProps) {
  const [grants, setGrants] = useState<EmergencyAccessGranteeDetails[]>([]);
  const [received, setReceived] = useState<EmergencyAccessGrantorDetails[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [email, setEmail] = useState('');
  const [waitDays, setWaitDays] = useState(7);
  const [grantType, setGrantType] = useState(0);
  const [inviting, setInviting] = useState(false);
  const [busyId, setBusyId] = useState('');
  const [opened, setOpened] = useState<OpenedVault | null>(null);
  const [shownPasswords, setShownPasswords] = useState<Set<string>>(new Set());
  const [takeover, setTakeover] = useState<TakeoverForm | null>(null);

  const load = async () => {
    if (!props.authedFetch) {
      setLoading(false);
      return;
    }
    setLoading(true);
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

  // Runs one action on a grant, shows the server's reason when it fails, and
  // reloads both lists when it succeeds.
  const act = async (id: string, fallbackKey: string, run: (authedFetch: AuthedFetch) => Promise<void>) => {
    if (!props.authedFetch) return;
    setError('');
    setNotice('');
    setBusyId(id);
    try {
      await run(props.authedFetch);
      await load();
    } catch (err) {
      setError(errorText(err, fallbackKey));
    } finally {
      setBusyId('');
    }
  };

  // The grantee accepted, so the grantor hands over the vault key, wrapped
  // with the public key of the grantee. The server never sees a key it could
  // open.
  const confirmGrant = async (grant: EmergencyAccessGranteeDetails) => {
    const session = props.session;
    if (!session?.symEncKey || !session?.symMacKey) {
      setError(t('txt_emergency_access_confirm_no_key'));
      return;
    }
    if (!grant.granteeId) {
      setError(t('txt_emergency_access_confirm_failed'));
      return;
    }
    const granteeId = grant.granteeId;
    await act(grant.id, 'txt_emergency_access_confirm_failed', async (authedFetch) => {
      let publicKey: string;
      try {
        publicKey = await getUserPublicKey(authedFetch, granteeId);
      } catch (err) {
        if (err instanceof PublicKeyUnavailableError) throw new Error(t('txt_emergency_access_confirm_no_public_key'));
        throw err;
      }
      const wrapped = await wrapVaultKeyForGrantee(
        { symEncKey: session.symEncKey as string, symMacKey: session.symMacKey as string },
        publicKey
      );
      await confirmEmergencyAccess(authedFetch, grant.id, wrapped);
    });
  };

  // The key handed to this account, opened with this account's private key.
  const openHandedKey = async (keyEncrypted: string): Promise<Uint8Array> => {
    const session = props.session;
    if (!session?.symEncKey || !session?.symMacKey || !props.encryptedPrivateKey) {
      throw new Error(t('txt_emergency_access_no_private_key'));
    }
    return openGrantorVaultKey(keyEncrypted, props.encryptedPrivateKey, {
      symEncKey: session.symEncKey,
      symMacKey: session.symMacKey,
    });
  };

  const viewVault = async (grant: EmergencyAccessGrantorDetails) => {
    if (!props.authedFetch) return;
    setError('');
    setNotice('');
    setBusyId(grant.id);
    try {
      const view = await viewEmergencyAccess(props.authedFetch, grant.id);
      const key = await openHandedKey(view.keyEncrypted);
      const enc = key.slice(0, 32);
      const mac = key.slice(32, 64);
      // Only the grantor's own items: shared items belong to organizations
      // this account is not a member of, and their keys are not handed over.
      const own = view.ciphers.filter(
        (cipher) => !(cipher as Cipher & { organizationId?: string | null }).organizationId && !cipher.deletedDate
      );
      const items = await Promise.all(own.map((cipher) => decryptSingleCipher(cipher, enc, mac)));
      items.sort((a, b) => String(a.decName || '').localeCompare(String(b.decName || '')));
      setShownPasswords(new Set());
      setOpened({ grantName: grant.name || grant.email || t('txt_emergency_access_grantor'), items });
    } catch (err) {
      setError(errorText(err, 'txt_emergency_access_view_failed'));
    } finally {
      setBusyId('');
    }
  };

  const submitTakeover = async () => {
    if (!props.authedFetch || !takeover) return;
    const { grant, password, password2 } = takeover;
    setError('');
    setNotice('');
    if (password.length < MIN_PASSWORD_LENGTH) {
      setError(t('txt_new_password_must_be_at_least_12_chars'));
      return;
    }
    if (password !== password2) {
      setError(t('txt_new_passwords_do_not_match'));
      return;
    }
    setTakeover({ ...takeover, saving: true });
    try {
      const details = await getEmergencyAccessTakeover(props.authedFetch, grant.id);
      // The web vault derives master keys with PBKDF2 only, as in its own
      // password change; another derivation would set a password that never
      // opens the account.
      if (details.kdf !== 0 || details.kdfIterations <= 0 || !details.salt) {
        throw new Error(t('txt_emergency_access_takeover_kdf_unsupported'));
      }
      const key = await openHandedKey(details.keyEncrypted);
      const next = await buildTakeoverPassword(key, password, details.salt, details.kdfIterations);
      await setEmergencyAccessPassword(props.authedFetch, grant.id, {
        salt: details.salt,
        kdfIterations: details.kdfIterations,
        masterPasswordHash: next.masterPasswordHash,
        key: next.key,
      });
      setTakeover(null);
      setNotice(t('txt_emergency_access_takeover_done'));
      await load();
    } catch (err) {
      setTakeover((current) => (current ? { ...current, saving: false } : current));
      setError(errorText(err, 'txt_emergency_access_takeover_failed'));
    }
  };

  const invite = async () => {
    if (!props.authedFetch || !email.trim()) return;
    const address = email.trim();
    if (props.email && address.toLowerCase() === props.email.trim().toLowerCase()) {
      setError(t('txt_emergency_access_invite_self'));
      return;
    }
    setInviting(true);
    setError('');
    setNotice('');
    try {
      await inviteEmergencyAccess(props.authedFetch, {
        email: address,
        type: grantType,
        waitTimeDays: waitDays,
        // The key for the grantee is wrapped when the grantee has accepted
        // and the grantor hands it over, because only then is the public key
        // of the grantee known.
        encryptedUserKey: '',
      });
      setEmail('');
      await load();
    } catch (err) {
      setError(errorText(err, 'txt_emergency_access_invite_failed'));
    } finally {
      setInviting(false);
    }
  };

  const togglePassword = (id: string) => {
    setShownPasswords((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
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
      {notice && (
        <div className="password-security-notice" role="status">
          {notice}
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
                  {grant.status === 3 && grant.recoveryInitiatedDate && (
                    <div className="muted-inline settings-field-note">
                      {t('txt_emergency_access_opens_on', {
                        date: accessOpensAt(grant.recoveryInitiatedDate, grant.waitTimeDays),
                      })}
                    </div>
                  )}
                </div>
                <div className="actions">
                  {grant.status === 1 && (
                    <button
                      type="button"
                      className="btn btn-primary small"
                      disabled={busyId === grant.id}
                      onClick={() => void confirmGrant(grant)}
                    >
                      {t('txt_emergency_access_confirm')}
                    </button>
                  )}
                  {grant.status === 3 && (
                    <button
                      type="button"
                      className="btn btn-primary small"
                      disabled={busyId === grant.id}
                      onClick={() =>
                        void act(grant.id, 'txt_emergency_access_approve_failed', (f) => approveEmergencyAccess(f, grant.id))
                      }
                    >
                      {t('txt_emergency_access_approve')}
                    </button>
                  )}
                  {(grant.status === 3 || grant.status === 4) && (
                    <button
                      type="button"
                      className="btn btn-secondary small"
                      disabled={busyId === grant.id}
                      onClick={() =>
                        void act(grant.id, 'txt_emergency_access_reject_recovery_failed', (f) => rejectEmergencyAccess(f, grant.id))
                      }
                    >
                      {t('txt_emergency_access_reject_recovery')}
                    </button>
                  )}
                  <button
                    type="button"
                    className="btn btn-secondary small"
                    disabled={busyId === grant.id}
                    onClick={() =>
                      void act(grant.id, 'txt_emergency_access_withdraw_failed', (f) => withdrawEmergencyAccess(f, grant.id))
                    }
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
                    {t(TYPE_LABELS[grant.type] || 'txt_emergency_access_type_view')}
                    {' · '}
                    {t(RECEIVED_STATUS_LABELS[grant.status] || 'txt_emergency_access_invited')}
                    {grant.waitTimeDays > 0 && ` · ${t('txt_emergency_access_wait_days', { value: String(grant.waitTimeDays) })}`}
                  </div>
                  {grant.status === 3 && grant.recoveryInitiatedDate && (
                    <div className="muted-inline settings-field-note">
                      {t('txt_emergency_access_opens_on', {
                        date: accessOpensAt(grant.recoveryInitiatedDate, grant.waitTimeDays),
                      })}
                    </div>
                  )}
                </div>
                <div className="actions">
                  {grant.status < 2 && (
                    <>
                      <button
                        type="button"
                        className="btn btn-primary small"
                        disabled={busyId === grant.id}
                        onClick={() =>
                          void act(grant.id, 'txt_emergency_access_accept_failed', (f) => acceptEmergencyAccess(f, grant.id))
                        }
                      >
                        {t('txt_emergency_access_accept')}
                      </button>
                      <button
                        type="button"
                        className="btn btn-secondary small"
                        disabled={busyId === grant.id}
                        onClick={() =>
                          void act(grant.id, 'txt_emergency_access_reject_failed', (f) => rejectEmergencyAccess(f, grant.id))
                        }
                      >
                        {t('txt_emergency_access_reject')}
                      </button>
                    </>
                  )}
                  {grant.status === 2 && (
                    <button
                      type="button"
                      className="btn btn-secondary small"
                      disabled={busyId === grant.id}
                      onClick={() =>
                        void act(grant.id, 'txt_emergency_access_initiate_failed', (f) => initiateEmergencyAccess(f, grant.id))
                      }
                    >
                      {t('txt_emergency_access_start_wait')}
                    </button>
                  )}
                  {grant.status === 4 && grant.type === 0 && (
                    <button
                      type="button"
                      className="btn btn-primary small"
                      disabled={busyId === grant.id}
                      onClick={() => void viewVault(grant)}
                    >
                      <Eye size={14} className="btn-icon" /> {t('txt_emergency_access_view_vault')}
                    </button>
                  )}
                  {grant.status === 4 && grant.type === 1 && (
                    <button
                      type="button"
                      className="btn btn-primary small"
                      disabled={busyId === grant.id || !!takeover}
                      onClick={() => {
                        setError('');
                        setNotice('');
                        setTakeover({ grant, password: '', password2: '', saving: false });
                      }}
                    >
                      <KeyRound size={14} className="btn-icon" /> {t('txt_emergency_access_takeover')}
                    </button>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      {takeover && (
        <section className="settings-submodule emergency-access-takeover">
          <h4>
            {t('txt_emergency_access_takeover_title', {
              name: takeover.grant.name || takeover.grant.email || t('txt_emergency_access_grantor'),
            })}
          </h4>
          <p className="muted-inline settings-field-note">{t('txt_emergency_access_takeover_help')}</p>
          <div className="actions">
            <input
              className="input"
              type="password"
              autoComplete="new-password"
              placeholder={t('txt_new_password')}
              value={takeover.password}
              onInput={(e) => setTakeover({ ...takeover, password: (e.currentTarget as HTMLInputElement).value })}
            />
            <input
              className="input"
              type="password"
              autoComplete="new-password"
              placeholder={t('txt_emergency_access_repeat_password')}
              value={takeover.password2}
              onInput={(e) => setTakeover({ ...takeover, password2: (e.currentTarget as HTMLInputElement).value })}
            />
            <button
              type="button"
              className="btn btn-danger"
              disabled={takeover.saving || !takeover.password || !takeover.password2}
              onClick={() => void submitTakeover()}
            >
              {t('txt_emergency_access_set_password')}
            </button>
            <button type="button" className="btn btn-secondary" disabled={takeover.saving} onClick={() => setTakeover(null)}>
              {t('txt_cancel')}
            </button>
          </div>
        </section>
      )}

      {opened && (
        <section className="settings-submodule emergency-access-view">
          <div className="actions">
            <h4>{t('txt_emergency_access_view_title', { name: opened.grantName })}</h4>
            <button type="button" className="btn btn-secondary small" onClick={() => setOpened(null)}>
              <X size={14} className="btn-icon" /> {t('txt_close')}
            </button>
          </div>
          {opened.items.length === 0 ? (
            <p className="muted-inline">{t('txt_emergency_access_view_empty')}</p>
          ) : (
            <ul className="emergency-access-list">
              {opened.items.map((item) => (
                <li key={item.id} className="emergency-access-row emergency-access-item">
                  <div>
                    <strong>{item.decName || '—'}</strong>
                    {item.login?.decUsername && (
                      <div className="settings-field-note">
                        {t('txt_username')}: {item.login.decUsername}
                      </div>
                    )}
                    {item.login?.decPassword && (
                      <div className="settings-field-note">
                        {t('txt_password')}:{' '}
                        <code>{shownPasswords.has(item.id) ? item.login.decPassword : '••••••••'}</code>{' '}
                        <button type="button" className="btn btn-secondary small" onClick={() => togglePassword(item.id)}>
                          {shownPasswords.has(item.id) ? t('txt_hide') : t('txt_reveal')}
                        </button>
                      </div>
                    )}
                    {(item.login?.uris || []).filter((u) => u.decUri).map((u, index) => (
                      <div key={index} className="settings-field-note">
                        {t('txt_website')}: {u.decUri}
                      </div>
                    ))}
                    {item.card?.decNumber && (
                      <div className="settings-field-note">
                        {item.card.decCardholderName} {item.card.decNumber}
                      </div>
                    )}
                    {item.decNotes && (
                      <div className="settings-field-note">
                        {t('txt_notes')}: {item.decNotes}
                      </div>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

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
