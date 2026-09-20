import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { Check, Copy, Download, LoaderCircle, Minus, Plus, RefreshCw, ShieldCheck } from 'lucide-preact';
import { copyTextToClipboard } from '@/lib/clipboard';
import { t } from '@/lib/i18n';
import {
  clampInteger,
  defaultGeneratorSettings,
  estimateStrength,
  generateValue,
  normalizeGeneratorSettings,
  type EmailMode,
  type EmailOptions,
  type ForwardedAliasType,
  type ForwardedEmailOptions,
  type ForwarderAccountConfig,
  type GeneratorMode,
  type GeneratorSettings,
  type PassphraseOptions,
  type PasswordOptions,
  type PinOptions,
  type SshKeyOptions,
  type UsernameOptions,
} from '@/lib/password-generator';
import { ForwarderError, generateForwardedEmail, type ForwarderErrorKind } from '@/lib/simplelogin-forwarder';
import { generateSshKey, type GeneratedSshKey } from '@/lib/ssh-key-generator';
import { loadGeneratorSettings, saveGeneratorSettings, type ForwardedAliasAccountSettings } from '@/lib/api/generator-settings';
import type { AuthedFetch } from '@/lib/api/shared';
import type { SessionState } from '@/lib/types';
import { clearGeneratorHistory, getGeneratorHistory, recordGenerated, type GeneratorHistoryEntry } from '@/lib/generator-history';

const SETTINGS_KEY = 'nodewarden.passwordGenerator.settings.v2';

interface PasswordGeneratorPageProps {
  authedFetch?: AuthedFetch | null;
  session?: SessionState | null;
}

function readSettings(): GeneratorSettings {
  try {
    const current = localStorage.getItem(SETTINGS_KEY);
    if (current) return normalizeGeneratorSettings(JSON.parse(current));

    // Preserve compatible options for users upgrading from the original generator.
    const legacy = JSON.parse(localStorage.getItem('nodewarden.passwordGenerator.settings.v1') || '{}');
    return normalizeGeneratorSettings(legacy);
  } catch {
    return defaultGeneratorSettings;
  }
}

// The forwarder API key is stored server-side encrypted with the user key;
// only the non-secret parts stay in localStorage.
function settingsWithoutSecrets(settings: GeneratorSettings): GeneratorSettings {
  return {
    ...settings,
    forwarded: {
      ...settings.forwarded,
      simplelogin: { ...settings.forwarded.simplelogin, apiKey: '' },
    },
  };
}

export default function PasswordGeneratorPage(props: PasswordGeneratorPageProps = {}) {
  const initial = useMemo(readSettings, []);
  const [settings, setSettings] = useState<GeneratorSettings>(initial);
  const [seed, setSeed] = useState(0);
  const [copied, setCopied] = useState(false);
  const [sshKey, setSshKey] = useState<GeneratedSshKey | null>(null);
  const [sshKeyError, setSshKeyError] = useState('');
  const [sshKeyLoading, setSshKeyLoading] = useState(false);
  const [forwardedValue, setForwardedValue] = useState('');
  const [forwardedError, setForwardedError] = useState('');
  const [forwardedLoading, setForwardedLoading] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [history, setHistory] = useState<readonly GeneratorHistoryEntry[]>(() => getGeneratorHistory());
  const forwardedMode = settings.mode === 'email' && settings.email.type === 'forwarded';
  const serverSettingsReady = props.authedFetch && props.session?.symEncKey && props.session?.symMacKey;

  const generated = useMemo(() => {
    if (settings.mode === 'sshKey') return sshKey?.fingerprint || '';
    if (forwardedMode) return forwardedValue;
    return generateValue(settings);
  }, [settings, seed, sshKey, forwardedMode, forwardedValue]);
  const strength = useMemo(
    () => estimateStrength(settings.mode, generated, settings.mode === 'passphrase' ? settings.passphrase.words : undefined),
    [generated, settings.mode, settings.passphrase.words],
  );
  const strengthLabel = strength
    ? t(['txt_password_strength_weak', 'txt_password_strength_fair', 'txt_password_strength_good', 'txt_password_strength_strong'][strength - 1])
    : '';

  useEffect(() => {
    try {
      localStorage.setItem(SETTINGS_KEY, JSON.stringify(settingsWithoutSecrets(settings)));
    } catch {
      // The generator remains fully usable when browser storage is unavailable.
    }
  }, [settings]);

  // Hydrate the forwarded alias account config (incl. the API key) from the
  // user-key-encrypted server copy once session keys become available.
  const [serverSettingsHydrated, setServerSettingsHydrated] = useState(false);
  const lastSavedForwarderRef = useRef('');
  useEffect(() => {
    if (!props.authedFetch || !props.session) return;
    let cancelled = false;
    void loadGeneratorSettings(props.authedFetch, props.session)
      .then((stored) => {
        if (cancelled) return;
        const account = stored?.forwarders?.simplelogin;
        if (account) {
          setSettings((current) => ({
            ...current,
            forwarded: { ...current.forwarded, simplelogin: { ...current.forwarded.simplelogin, ...normalizeAccount(account) } },
          }));
        }
        lastSavedForwarderRef.current = JSON.stringify(account ? normalizeAccount(account) : null);
        setServerSettingsHydrated(true);
      })
      .catch(() => {
        if (!cancelled) setServerSettingsHydrated(true);
      });
    return () => { cancelled = true; };
  }, [props.authedFetch, props.session?.symEncKey, props.session?.symMacKey]);

  // Persist forwarder account changes back to the server (encrypted, debounced).
  useEffect(() => {
    if (!serverSettingsHydrated || !props.authedFetch || !props.session) return;
    const account: ForwardedAliasAccountSettings = settings.forwarded.simplelogin;
    const serialized = JSON.stringify(account);
    if (serialized === lastSavedForwarderRef.current) return;
    const timer = window.setTimeout(() => {
      lastSavedForwarderRef.current = serialized;
      void saveGeneratorSettings(props.authedFetch!, props.session!, { forwarders: { simplelogin: account } }).catch(() => { /* retried on next change */ });
    }, 800);
    return () => window.clearTimeout(timer);
  }, [settings.forwarded.simplelogin, serverSettingsHydrated, props.authedFetch, props.session]);

  useEffect(() => {
    if (settings.mode !== 'sshKey') return;
    let cancelled = false;
    setSshKeyLoading(true);
    setSshKeyError('');
    void generateSshKey({ ...settings.sshKey, comment: '' })
      .then((value) => { if (!cancelled) setSshKey(value); })
      .catch(() => { if (!cancelled) { setSshKey(null); setSshKeyError(t('txt_generator_ssh_error')); } })
      .finally(() => { if (!cancelled) setSshKeyLoading(false); });
    return () => { cancelled = true; };
  }, [settings.mode, settings.sshKey.type, settings.sshKey.rsaLength, seed]);

  const forwardedTriggerRef = useRef<{ seed: number; aliasType: ForwardedAliasType } | null>(null);
  useEffect(() => {
    if (!forwardedMode) return;
    const trigger = { seed, aliasType: settings.forwarded.simplelogin.aliasType };
    const previous = forwardedTriggerRef.current;
    forwardedTriggerRef.current = trigger;
    // Visiting the page must not create a real alias: generation only runs on
    // explicit Regenerate or an alias type change.
    if (previous === null && seed === 0) return;
    // Generating a forwarded alias contacts the remote provider and creates a
    // real alias, so it only runs on Regenerate, mode/type switches and alias
    // type changes — deliberately not on every keystroke in the fields.
    let cancelled = false;
    setForwardedLoading(true);
    setForwardedError('');
    setForwardedValue('');
    generateForwardedEmail(settings.forwarded)
      .then((value) => {
        if (cancelled) return;
        recordAndSync('email', value);
        setForwardedValue(value);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setForwardedValue('');
        const kind = error instanceof ForwarderError ? error.kind : 'server' satisfies ForwarderErrorKind;
        setForwardedError(forwardedErrorKey(kind));
      })
      .finally(() => { if (!cancelled) setForwardedLoading(false); });
    return () => { cancelled = true; };
  }, [forwardedMode, settings.forwarded.provider, settings.forwarded.simplelogin.aliasType, seed]);

  const recordAndSync = (mode: GeneratorMode, value: string) => {
    recordGenerated(mode, value);
    setHistory(getGeneratorHistory());
  };

  const regenerate = () => {
    setCopied(false);
    // Sync modes compute their next value immediately; forwarded aliases are
    // recorded when the provider call resolves (see the effect below).
    if (!forwardedMode && settings.mode !== 'sshKey') {
      recordAndSync(settings.mode, generateValue(settings));
    }
    setSeed((value) => value + 1);
  };

  const copy = async () => {
    const value = settings.mode === 'sshKey' && sshKey ? publicKeyWithComment(sshKey.publicKey, settings.sshKey.comment) : generated;
    await copyTextToClipboard(value, { onSuccess: () => setCopied(true), onError: () => setCopied(false) });
    window.setTimeout(() => setCopied(false), 1600);
  };

  const changeMode = (mode: GeneratorMode) => {
    setSettings((current) => ({ ...current, mode }));
    setCopied(false);
  };

  const changePasswordOption = <K extends keyof PasswordOptions>(key: K, value: PasswordOptions[K]) => {
    setSettings((current) => ({ ...current, password: { ...current.password, [key]: value } }));
    setCopied(false);
  };

  const changeCharacterType = (key: 'uppercase' | 'lowercase' | 'numbers' | 'special', checked: boolean) => {
    const enabled = ['uppercase', 'lowercase', 'numbers', 'special'].filter((item) => settings.password[item as 'uppercase']);
    if (!checked && enabled.length === 1 && enabled[0] === key) return;
    changePasswordOption(key, checked);
  };

  const changePassphraseOption = <K extends keyof PassphraseOptions>(key: K, value: PassphraseOptions[K]) => {
    setSettings((current) => ({ ...current, passphrase: { ...current.passphrase, [key]: value } }));
    setCopied(false);
  };

  const changePinOption = <K extends keyof PinOptions>(key: K, value: PinOptions[K]) => {
    setSettings((current) => ({ ...current, pin: { ...current.pin, [key]: value } }));
    setCopied(false);
  };

  const changeUsernameOption = <K extends keyof UsernameOptions>(key: K, value: UsernameOptions[K]) => {
    setSettings((current) => ({ ...current, username: { ...current.username, [key]: value } }));
    setCopied(false);
  };

  const changeEmailOption = <K extends keyof EmailOptions>(key: K, value: EmailOptions[K]) => {
    setSettings((current) => ({ ...current, email: { ...current.email, [key]: value } }));
    setCopied(false);
  };

  const changeForwardedOption = <K extends keyof ForwardedEmailOptions>(key: K, value: ForwardedEmailOptions[K]) => {
    setSettings((current) => ({ ...current, forwarded: { ...current.forwarded, [key]: value } }));
    setCopied(false);
  };

  const changeForwardedAccountOption = <K extends keyof ForwarderAccountConfig>(key: K, value: ForwarderAccountConfig[K]) => {
    setSettings((current) => ({ ...current, forwarded: { ...current.forwarded, simplelogin: { ...current.forwarded.simplelogin, [key]: value } } }));
    setCopied(false);
  };

  const changeSshKeyOption = <K extends keyof SshKeyOptions>(key: K, value: SshKeyOptions[K]) => {
    setSettings((current) => ({ ...current, sshKey: { ...current.sshKey, [key]: value } }));
    setCopied(false);
  };

  return (
    <section className="generator-page" aria-label={t('txt_password_generator')}>
      <div className="generator-layout">
        <section className="generator-output-card" aria-live="polite">
          <div className="settings-category-tabs generator-mode-tabs" role="tablist" aria-label={t('txt_generator_type')}>
            {([
              ['password', 'txt_password'],
              ['passphrase', 'txt_passphrase'],
              ['pin', 'txt_generator_pin'],
              ['username', 'txt_generator_username'],
              ['email', 'txt_generator_email_alias'],
              ['sshKey', 'txt_generator_ssh_key'],
            ] as const).map(([mode, label]) => (
              <button key={mode} type="button" role="tab" aria-selected={settings.mode === mode} className={`settings-category-tab ${settings.mode === mode ? 'active' : ''}`} onClick={() => changeMode(mode)}>{t(label)}</button>
            ))}
          </div>
          {settings.mode === 'sshKey' ? (
            <SshKeyOutput value={sshKey} loading={sshKeyLoading} error={sshKeyError} comment={settings.sshKey.comment} />
          ) : <output className={`generator-value ${generated ? '' : 'empty'}`} aria-label={t('txt_generated_value')}>{forwardedMode && forwardedError ? t(forwardedError) : generated || t('txt_generator_email_required_hint')}</output>}
          {settings.mode !== 'sshKey' && <div className="generator-meta-row">
            {strength > 0 ? (
              <>
                <div className="generator-strength" aria-label={`${t('txt_password_strength')}: ${strengthLabel}`}>
                  {[1, 2, 3, 4].map((level) => <span key={level} className={level <= strength ? `active level-${strength}` : ''} />)}
                </div>
                <span><ShieldCheck size={15} /> {strengthLabel}</span>
              </>
            ) : <span />}
            <span>{t('txt_generator_character_count', { count: generated.length })}</span>
          </div>}
          <div className="actions generator-actions">
            <button type="button" className="btn btn-primary" disabled={sshKeyLoading || forwardedLoading} onClick={regenerate}>{sshKeyLoading || forwardedLoading ? <LoaderCircle size={16} className="btn-icon generator-spinner" /> : <RefreshCw size={16} className="btn-icon" />}{t('txt_regenerate')}</button>
            <button type="button" className="btn btn-secondary" disabled={(settings.mode === 'sshKey' && !sshKey) || !generated} onClick={() => void copy()}><Copy size={16} className="btn-icon" />{copied ? t('txt_copied') : settings.mode === 'sshKey' ? t('txt_generator_copy_public_key') : t('txt_copy')}</button>
          </div>
          <p className="generator-security-note"><Check size={15} />{t(settings.mode === 'sshKey' ? 'txt_generator_ssh_security_note' : 'txt_generator_security_note')}</p>
          <div className="generator-history">
            <button type="button" className="btn-link generator-history-toggle" aria-expanded={historyOpen} onClick={() => { setHistoryOpen((open) => !open); setHistory(getGeneratorHistory()); }}>{t('txt_generator_history')}</button>
            {historyOpen && (
              <div className="generator-history-panel">
                <div className="generator-history-toolbar">
                  <button type="button" className="btn btn-secondary small" disabled={history.length === 0} onClick={() => { clearGeneratorHistory(); setHistory(getGeneratorHistory()); }}>{t('txt_generator_history_clear')}</button>
                </div>
                {history.length === 0 ? (
                  <p className="generator-options-note">{t('txt_generator_history_empty')}</p>
                ) : (
                  <ul className="generator-history-list">
                    {history.map((entry) => (
                      <li key={entry.id} className="generator-history-item">
                        <code className="generator-history-value" title={entry.value}>{entry.value}</code>
                        <span className="generator-history-meta">{modeLabel(entry.mode)} · {new Date(entry.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                        <button type="button" className="btn btn-secondary small" onClick={() => void copyTextToClipboard(entry.value)}>{t('txt_copy')}</button>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>
        </section>

        <section className="generator-options-card" aria-labelledby="generator-options-title">
          <h2 id="generator-options-title">{t('txt_options')}</h2>
          {settings.mode === 'password' && (
            <PasswordOptionFields options={settings.password} onChange={changePasswordOption} onCharacterTypeChange={changeCharacterType} />
          )}
          {settings.mode === 'passphrase' && (
            <>
              <GeneratorNumberStepper id="words" label={t('txt_generator_words')} value={settings.passphrase.words} minimum={3} maximum={20} fallback={6} onChange={(value) => changePassphraseOption('words', value)} />
              <label className="generator-select-field" htmlFor="generator-word-list"><span>{t('txt_generator_word_list')}</span><select id="generator-word-list" className="input" value={settings.passphrase.wordList} onChange={(event) => changePassphraseOption('wordList', event.currentTarget.value as 'eff' | 'custom')}><option value="eff">{t('txt_generator_eff_word_list')}</option><option value="custom">{t('txt_generator_custom_word_list')}</option></select></label>
              {settings.passphrase.wordList === 'custom' && <label className="generator-text-field" htmlFor="generator-custom-words"><span>{t('txt_generator_custom_words')}</span><textarea id="generator-custom-words" className="input generator-word-list-input" rows={6} spellcheck={false} placeholder={t('txt_generator_custom_words_placeholder')} value={settings.passphrase.customWords} onInput={(event) => changePassphraseOption('customWords', event.currentTarget.value)} /></label>}
              <label className="generator-number-field" htmlFor="generator-separator"><span>{t('txt_generator_separator')}</span><input id="generator-separator" className="input" type="text" maxLength={1} value={settings.passphrase.separator} onInput={(event) => changePassphraseOption('separator', event.currentTarget.value.slice(0, 1))} /></label>
              <div className="generator-option-group">
                <GeneratorToggle checked={settings.passphrase.capitalize} onChange={(checked) => changePassphraseOption('capitalize', checked)} label={t('txt_generator_capitalize')} />
                <GeneratorToggle checked={settings.passphrase.includeNumber} onChange={(checked) => changePassphraseOption('includeNumber', checked)} label={t('txt_generator_include_number')} />
              </div>
            </>
          )}
          {settings.mode === 'pin' && (
            <>
              <GeneratorNumberStepper id="pin-length" label={t('txt_generator_length')} value={settings.pin.length} minimum={3} maximum={64} fallback={6} onChange={(value) => changePinOption('length', value)} />
              <p className="generator-options-note">{t('txt_generator_pin_description')}</p>
            </>
          )}
          {settings.mode === 'username' && (
            <UsernameOptionFields options={settings.username} onChange={changeUsernameOption} />
          )}
          {settings.mode === 'email' && (
            <EmailOptionFields
              options={settings.email}
              onChange={changeEmailOption}
              forwarded={settings.forwarded}
              onForwardedChange={changeForwardedOption}
              onForwardedAccountChange={changeForwardedAccountOption}
            />
          )}
          {settings.mode === 'sshKey' && (
            <SshKeyOptionFields options={settings.sshKey} onChange={changeSshKeyOption} />
          )}
        </section>
      </div>
    </section>
  );
}

function PasswordOptionFields(props: { options: PasswordOptions; onChange: <K extends keyof PasswordOptions>(key: K, value: PasswordOptions[K]) => void; onCharacterTypeChange: (key: 'uppercase' | 'lowercase' | 'numbers' | 'special', checked: boolean) => void }) {
  const { options } = props;
  return (
    <>
      <GeneratorNumberStepper id="length" label={t('txt_generator_length')} value={options.length} minimum={5} maximum={128} fallback={16} onChange={(value) => props.onChange('length', value)} />
      <fieldset className="generator-option-group"><legend>{t('txt_generator_character_types')}</legend>
        <GeneratorToggle checked={options.uppercase} onChange={(checked) => props.onCharacterTypeChange('uppercase', checked)} label={t('txt_generator_uppercase')} />
        {options.uppercase && <GeneratorNumberStepper id="min-uppercase" compact label={t('txt_generator_minimum')} value={options.minUppercase} minimum={0} maximum={9} fallback={1} onChange={(value) => props.onChange('minUppercase', value)} />}
        <GeneratorToggle checked={options.lowercase} onChange={(checked) => props.onCharacterTypeChange('lowercase', checked)} label={t('txt_generator_lowercase')} />
        {options.lowercase && <GeneratorNumberStepper id="min-lowercase" compact label={t('txt_generator_minimum')} value={options.minLowercase} minimum={0} maximum={9} fallback={1} onChange={(value) => props.onChange('minLowercase', value)} />}
        <GeneratorToggle checked={options.numbers} onChange={(checked) => props.onCharacterTypeChange('numbers', checked)} label={t('txt_generator_numbers')} />
        {options.numbers && <GeneratorNumberStepper id="min-numbers" compact label={t('txt_generator_minimum')} value={options.minNumbers} minimum={0} maximum={9} fallback={1} onChange={(value) => props.onChange('minNumbers', value)} />}
        <GeneratorToggle checked={options.special} onChange={(checked) => props.onCharacterTypeChange('special', checked)} label={t('txt_generator_special')} />
        {options.special && <GeneratorNumberStepper id="min-special" compact label={t('txt_generator_minimum')} value={options.minSpecial} minimum={0} maximum={9} fallback={1} onChange={(value) => props.onChange('minSpecial', value)} />}
      </fieldset>
      <GeneratorToggle checked={options.avoidAmbiguous} onChange={(checked) => props.onChange('avoidAmbiguous', checked)} label={t('txt_generator_avoid_ambiguous')} />
    </>
  );
}

function UsernameOptionFields(props: { options: UsernameOptions; onChange: <K extends keyof UsernameOptions>(key: K, value: UsernameOptions[K]) => void }) {
  return (
    <>
      <GeneratorNumberStepper id="username-words" label={t('txt_generator_words')} value={props.options.words} minimum={1} maximum={10} fallback={2} onChange={(value) => props.onChange('words', value)} />
      <div className="generator-option-group">
        <GeneratorToggle checked={props.options.capitalize} onChange={(checked) => props.onChange('capitalize', checked)} label={t('txt_generator_capitalize')} />
        <GeneratorToggle checked={props.options.includeNumber} onChange={(checked) => props.onChange('includeNumber', checked)} label={t('txt_generator_include_number')} />
      </div>
      <label className="generator-select-field" htmlFor="generator-username-word-list"><span>{t('txt_generator_word_list')}</span><select id="generator-username-word-list" className="input" value={props.options.wordList} onChange={(event) => props.onChange('wordList', event.currentTarget.value as 'eff' | 'custom')}><option value="eff">{t('txt_generator_eff_word_list')}</option><option value="custom">{t('txt_generator_custom_word_list')}</option></select></label>
      {props.options.wordList === 'custom' && <label className="generator-text-field" htmlFor="generator-username-custom-words"><span>{t('txt_generator_custom_words')}</span><textarea id="generator-username-custom-words" className="input generator-word-list-input" rows={6} spellcheck={false} placeholder={t('txt_generator_custom_words_placeholder')} value={props.options.customWords} onInput={(event) => props.onChange('customWords', event.currentTarget.value)} /></label>}
      <label className="generator-text-field" htmlFor="generator-username-custom-word"><span>{t('txt_generator_custom_word')}</span><input id="generator-username-custom-word" className="input" type="text" autocomplete="off" maxLength={128} value={props.options.customWord} onInput={(event) => props.onChange('customWord', event.currentTarget.value)} /></label>
      <label className="generator-text-field" htmlFor="generator-username-delimiter"><span>{t('txt_generator_separator')}</span><input id="generator-username-delimiter" className="input" type="text" autocomplete="off" maxLength={8} value={props.options.delimiter} onInput={(event) => props.onChange('delimiter', event.currentTarget.value.slice(0, 8))} /></label>
      <p className="generator-options-note">{t('txt_generator_long_word_username_description')}</p>
    </>
  );
}

function EmailOptionFields(props: {
  options: EmailOptions;
  onChange: <K extends keyof EmailOptions>(key: K, value: EmailOptions[K]) => void;
  forwarded: ForwardedEmailOptions;
  onForwardedChange: <K extends keyof ForwardedEmailOptions>(key: K, value: ForwardedEmailOptions[K]) => void;
  onForwardedAccountChange: <K extends keyof ForwarderAccountConfig>(key: K, value: ForwarderAccountConfig[K]) => void;
}) {
  const types: Array<[EmailMode, string]> = [
    ['plusAddressed', 'txt_generator_plus_addressed_email'],
    ['catchAll', 'txt_generator_catch_all_email'],
    ['subdomain', 'txt_generator_subdomain_email'],
    ['forwarded', 'txt_generator_forwarded_email'],
  ];
  const providers: Array<[ForwardedEmailOptions['provider'], string]> = [
    ['simplelogin', 'txt_generator_provider_simplelogin'],
  ];
  return (
    <>
      <label className="generator-select-field" htmlFor="generator-email-type"><span>{t('txt_generator_email_type')}</span><select id="generator-email-type" className="input" value={props.options.type} onChange={(event) => props.onChange('type', event.currentTarget.value as EmailMode)}>{types.map(([value, label]) => <option key={value} value={value}>{t(label)}</option>)}</select></label>
      {props.options.type === 'catchAll'
        ? <label className="generator-text-field" htmlFor="generator-domain"><span>{t('txt_generator_domain')}</span><input id="generator-domain" className="input" type="text" autocomplete="off" value={props.options.domain} onInput={(event) => props.onChange('domain', event.currentTarget.value)} /></label>
        : props.options.type === 'forwarded'
          ? <>
              <label className="generator-select-field" htmlFor="generator-forwarded-provider"><span>{t('txt_generator_provider')}</span><select id="generator-forwarded-provider" className="input" value={props.forwarded.provider} onChange={(event) => props.onForwardedChange('provider', event.currentTarget.value as ForwardedEmailOptions['provider'])}>{providers.map(([value, label]) => <option key={value} value={value}>{t(label)}</option>)}</select></label>
              <ForwardedEmailFields options={props.forwarded.simplelogin} onChange={props.onForwardedAccountChange} />
            </>
          : <label className="generator-text-field" htmlFor="generator-email"><span>{t('txt_generator_email')}</span><input id="generator-email" className="input" type="email" autocomplete="off" value={props.options.email} onInput={(event) => props.onChange('email', event.currentTarget.value)} /></label>}
      <p className="generator-options-note">{t(props.options.type === 'forwarded' ? 'txt_generator_forwarded_description' : 'txt_generator_email_description')}</p>
    </>
  );
}

function ForwardedEmailFields(props: { options: ForwarderAccountConfig; onChange: <K extends keyof ForwarderAccountConfig>(key: K, value: ForwarderAccountConfig[K]) => void }) {
  const aliasTypes: Array<[ForwardedAliasType, string]> = [
    ['word', 'txt_generator_alias_type_word'],
    ['uuid', 'txt_generator_alias_type_uuid'],
    ['custom', 'txt_generator_alias_type_custom'],
  ];
  return (
    <>
      <label className="generator-text-field" htmlFor="generator-forwarded-server"><span>{t('txt_generator_server_url')}</span><input id="generator-forwarded-server" className="input" type="url" inputmode="url" autocomplete="off" placeholder="https://mailpal.example.com" value={props.options.serverUrl} onInput={(event) => props.onChange('serverUrl', event.currentTarget.value)} /></label>
      <label className="generator-text-field" htmlFor="generator-forwarded-api-key"><span>{t('txt_generator_api_key')}</span><input id="generator-forwarded-api-key" className="input" type="password" autocomplete="off" value={props.options.apiKey} onInput={(event) => props.onChange('apiKey', event.currentTarget.value)} /></label>
      <label className="generator-select-field" htmlFor="generator-forwarded-alias-type"><span>{t('txt_generator_alias_type')}</span><select id="generator-forwarded-alias-type" className="input" value={props.options.aliasType} onChange={(event) => props.onChange('aliasType', event.currentTarget.value as ForwardedAliasType)}>{aliasTypes.map(([value, label]) => <option key={value} value={value}>{t(label)}</option>)}</select></label>
      {props.options.aliasType === 'custom' && <label className="generator-text-field" htmlFor="generator-forwarded-prefix"><span>{t('txt_generator_prefix')}</span><input id="generator-forwarded-prefix" className="input" type="text" autocomplete="off" maxLength={64} value={props.options.prefix} onInput={(event) => props.onChange('prefix', event.currentTarget.value)} /></label>}
    </>
  );
}

function publicKeyWithComment(publicKey: string, comment: string): string {
  const base = publicKey.trim().split(/\s+/).slice(0, 2).join(' ');
  const safeComment = comment.replace(/[\r\n]+/g, ' ').trim();
  return safeComment ? `${base} ${safeComment}` : base;
}

function forwardedErrorKey(kind: ForwarderErrorKind): string {
  const keys: Record<ForwarderErrorKind, string> = {
    config: 'txt_generator_forwarded_error_config',
    network: 'txt_generator_forwarded_error_network',
    auth: 'txt_generator_forwarded_error_auth',
    quota: 'txt_generator_forwarded_error_quota',
    server: 'txt_generator_forwarded_error_generic',
  };
  return keys[kind];
}

function normalizeAccount(value: ForwardedAliasAccountSettings): ForwardedAliasAccountSettings {
  return {
    serverUrl: typeof value.serverUrl === 'string' ? value.serverUrl : '',
    apiKey: typeof value.apiKey === 'string' ? value.apiKey : '',
    aliasType: value.aliasType === 'uuid' || value.aliasType === 'custom' ? value.aliasType : 'word',
    prefix: typeof value.prefix === 'string' ? value.prefix : '',
    note: typeof value.note === 'string' ? value.note : '',
  };
}

function modeLabel(mode: GeneratorMode): string {
  const keys: Record<GeneratorMode, string> = {
    password: 'txt_password',
    passphrase: 'txt_passphrase',
    pin: 'txt_generator_pin',
    username: 'txt_generator_username',
    email: 'txt_generator_email_alias',
    sshKey: 'txt_generator_ssh_key',
  };
  return t(keys[mode]);
}

function downloadText(filename: string, value: string): void {
  const url = URL.createObjectURL(new Blob([value], { type: 'text/plain;charset=utf-8' }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.style.display = 'none';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function SshKeyOutput(props: { value: GeneratedSshKey | null; loading: boolean; error: string; comment: string }) {
  if (props.loading) return <div className="generator-key-status"><LoaderCircle size={24} className="generator-spinner" /><span>{t('txt_generator_ssh_generating')}</span></div>;
  if (props.error) return <div className="generator-key-status error">{props.error}</div>;
  if (!props.value) return null;
  const publicKey = publicKeyWithComment(props.value.publicKey, props.comment);
  const copyField = (value: string) => void copyTextToClipboard(value);
  return (
    <div className="generator-key-output">
      <div className="generator-key-summary"><strong>{props.value.type}{props.value.type === 'RSA' ? ` ${props.value.bits}` : ''}</strong><code>{props.value.fingerprint}</code></div>
      <div className="generator-key-field"><span>{t('txt_generator_public_key')}</span><code>{publicKey}</code><div className="generator-key-field-actions"><button type="button" className="btn btn-secondary small" onClick={() => copyField(publicKey)}><Copy size={14} />{t('txt_copy')}</button><button type="button" className="btn btn-secondary small" onClick={() => downloadText('id_nodewarden.pub', `${publicKey}\n`)}><Download size={14} />{t('txt_download')}</button></div></div>
      <details className="generator-private-key"><summary>{t('txt_generator_private_key')}</summary><code>{props.value.privateKey}</code><div className="generator-key-field-actions"><button type="button" className="btn btn-secondary small" onClick={() => copyField(props.value!.privateKey)}><Copy size={14} />{t('txt_copy')}</button><button type="button" className="btn btn-secondary small" onClick={() => downloadText('id_nodewarden', props.value!.privateKey)}><Download size={14} />{t('txt_download')}</button></div></details>
    </div>
  );
}

function SshKeyOptionFields(props: { options: SshKeyOptions; onChange: <K extends keyof SshKeyOptions>(key: K, value: SshKeyOptions[K]) => void }) {
  return (
    <>
      <label className="generator-select-field" htmlFor="generator-ssh-type"><span>{t('txt_generator_ssh_algorithm')}</span><select id="generator-ssh-type" className="input" value={props.options.type} onChange={(event) => props.onChange('type', event.currentTarget.value as SshKeyOptions['type'])}><option value="ed25519">Ed25519</option><option value="rsa">RSA</option></select></label>
      {props.options.type === 'rsa' && <label className="generator-select-field" htmlFor="generator-rsa-length"><span>{t('txt_generator_key_length')}</span><select id="generator-rsa-length" className="input" value={props.options.rsaLength} onChange={(event) => props.onChange('rsaLength', Number(event.currentTarget.value) as SshKeyOptions['rsaLength'])}><option value={2048}>2048</option><option value={3072}>3072</option><option value={4096}>4096</option></select></label>}
      <label className="generator-text-field" htmlFor="generator-ssh-comment"><span>{t('txt_generator_ssh_comment')}</span><input id="generator-ssh-comment" className="input" type="text" autocomplete="off" maxLength={256} placeholder="user@example.com" value={props.options.comment} onInput={(event) => props.onChange('comment', event.currentTarget.value)} /></label>
      <p className="generator-options-note">{t(props.options.type === 'rsa' ? 'txt_generator_ssh_rsa_description' : 'txt_generator_ssh_ed25519_description')}</p>
    </>
  );
}

function GeneratorToggle(props: { checked: boolean; label: string; onChange: (checked: boolean) => void }) {
  return <label className="generator-toggle"><input type="checkbox" checked={props.checked} onChange={(event) => props.onChange(event.currentTarget.checked)} /><span aria-hidden="true" /><strong>{props.label}</strong></label>;
}

function GeneratorNumberStepper(props: { id: string; label: string; value: number; minimum: number; maximum: number; fallback: number; compact?: boolean; onChange: (value: number) => void }) {
  const id = `generator-stepper-${props.id}`;
  const setValue = (value: number) => props.onChange(clampInteger(value, props.minimum, props.maximum, props.fallback));
  return (
    <div className={`generator-number-field ${props.compact ? 'compact' : ''}`}>
      <label htmlFor={id}>{props.label}</label>
      <div className="generator-stepper">
        <button type="button" aria-label={`${props.label} -`} disabled={props.value <= props.minimum} onClick={() => setValue(props.value - 1)}><Minus size={15} /></button>
        <input id={id} className="input" type="text" inputMode="numeric" pattern="[0-9]*" value={props.value} onInput={(event) => setValue(Number(event.currentTarget.value))} />
        <button type="button" aria-label={`${props.label} +`} disabled={props.value >= props.maximum} onClick={() => setValue(props.value + 1)}><Plus size={15} /></button>
      </div>
    </div>
  );
}
