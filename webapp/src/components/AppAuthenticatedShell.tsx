import { ChevronDown, Clock3, Folder as FolderIcon, KeyRound, Lock, LogOut, Send as SendIcon, Settings as SettingsIcon, ShieldUser, Sparkles } from 'lucide-preact';
import type { ComponentChildren } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import { Link } from 'wouter';
import AppMainRoutes from '@/components/AppMainRoutes';
import CommandPalette from '@/components/CommandPalette';
import NetworkStatusBadge from '@/components/NetworkStatusBadge';
import ThemeSwitch from '@/components/ThemeSwitch';
import type { AppMainRoutesProps } from '@/components/AppMainRoutes';
import type { PageEntry } from '@/lib/command-palette';
import { t } from '@/lib/i18n';
import type { Cipher, Profile } from '@/lib/types';

interface AppAuthenticatedShellProps {
  profile: Profile | null;
  location: string;
  mobilePrimaryRoute: string;
  currentPageTitle: string;
  showSidebarToggle: boolean;
  sidebarToggleTitle: string;
  settingsAccountRoute: string;
  importRoute: string;
  isImportRoute: boolean;
  darkMode: boolean;
  themeToggleTitle: string;
  onLock: () => void;
  onLogout: () => void;
  onToggleTheme: () => void;
  onToggleMobileSidebar: () => void;
  /** The items the palette searches. */
  paletteCiphers: Cipher[];
  onTrackPasswordCopy?: (cipherId: string) => void;
  mainRoutesProps: AppMainRoutesProps;
}

const NAV_GROUPS_STORAGE_KEY = 'nodewarden.navGroups';

const DEFAULT_EXPANDED_GROUPS = {
  tools: true,
  settings: true,
  management: true,
};

type NavGroup = keyof typeof DEFAULT_EXPANDED_GROUPS;
type ExpandedGroups = Record<NavGroup, boolean>;

function readExpandedGroups(): ExpandedGroups {
  if (typeof window === 'undefined') return DEFAULT_EXPANDED_GROUPS;
  try {
    const saved = window.localStorage.getItem(NAV_GROUPS_STORAGE_KEY);
    if (!saved) return DEFAULT_EXPANDED_GROUPS;
    const parsed = JSON.parse(saved) as Partial<ExpandedGroups>;
    return {
      tools: typeof parsed.tools === 'boolean' ? parsed.tools : DEFAULT_EXPANDED_GROUPS.tools,
      settings: typeof parsed.settings === 'boolean' ? parsed.settings : DEFAULT_EXPANDED_GROUPS.settings,
      management: typeof parsed.management === 'boolean' ? parsed.management : DEFAULT_EXPANDED_GROUPS.management,
    };
  } catch {
    // Ignore local preference read failures.
  }
  return DEFAULT_EXPANDED_GROUPS;
}

function isAdminProfile(profile: Profile | null): boolean {
  return String(profile?.role || '').toLowerCase() === 'admin';
}

const DEVICE_MANAGEMENT_ROUTE = '/settings/security/device-management';
const LEGACY_DEVICE_MANAGEMENT_ROUTE = '/security/devices';

export default function AppAuthenticatedShell(props: AppAuthenticatedShellProps) {
  const routeAnimationKey = props.isImportRoute ? props.importRoute : props.location;
  const isDomainRulesRoute = props.location === '/settings/domain-rules';
  const isLogRoute = props.location === '/logs';
  const isAdmin = isAdminProfile(props.profile);
  const deviceManagementActive = props.location === DEVICE_MANAGEMENT_ROUTE || props.location === LEGACY_DEVICE_MANAGEMENT_ROUTE;
  const [expandedGroups, setExpandedGroups] = useState<ExpandedGroups>(readExpandedGroups);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [paletteSignal, setPaletteSignal] = useState(0);
  const [paletteQuery, setPaletteQuery] = useState('');
  // The palette that opens from the search bar filters the list of the vault,
  // so its filter row comes first. The palette that opens with the shortcut
  // searches the app, so its filter row comes last and the first result
  // stays the chosen one.
  const [palettePlacement, setPalettePlacement] = useState<'first' | 'last'>('last');

  // The pages of the palette follow the menu: only the destinations the
  // member may open are listed, and the tabs of the settings page lead to
  // their section.
  const settingsLabel = t('nav_account_settings');
  const palettePages: PageEntry[] = [
    { id: 'vault', label: t('nav_vault_items'), href: '/vault' },
    { id: 'sends', label: t('nav_sends'), href: '/sends' },
    { id: 'verification-code', label: t('txt_verification_code'), href: '/vault/totp' },
    { id: 'generator', label: t('nav_generator'), href: '/generator' },
    { id: 'password-security', label: t('nav_password_security'), href: '/security/password-health' },
    { id: 'import-export', label: t('nav_import_export'), href: props.importRoute },
    { id: 'account-settings', label: settingsLabel, href: props.settingsAccountRoute },
    { id: 'device-management', label: t('nav_device_management'), href: DEVICE_MANAGEMENT_ROUTE },
    { id: 'domain-rules', label: t('nav_domain_rules'), href: '/settings/domain-rules' },
  ];
  if (isAdmin) {
    palettePages.push(
      { id: 'cloud-backup', label: t('nav_backup_strategy'), href: '/backup' },
      { id: 'admin-panel', label: t('nav_admin_panel'), href: '/admin' },
      { id: 'log-center', label: t('nav_log_center'), href: '/logs' },
    );
  }
  palettePages.push(
    { id: 'settings-appearance', label: t('txt_settings_appearance'), hint: settingsLabel, href: props.settingsAccountRoute, settingsSection: 'appearance' },
    { id: 'settings-session', label: t('txt_session_timeout'), hint: settingsLabel, href: props.settingsAccountRoute, settingsSection: 'session' },
    { id: 'settings-master-password', label: t('txt_master_password'), hint: settingsLabel, href: props.settingsAccountRoute, settingsSection: 'masterPassword' },
    { id: 'settings-two-step', label: t('txt_two_step_login'), hint: settingsLabel, href: props.settingsAccountRoute, settingsSection: 'twoStep' },
    { id: 'settings-keys', label: t('txt_keys'), hint: settingsLabel, href: props.settingsAccountRoute, settingsSection: 'keys' },
    { id: 'settings-sso', label: t('txt_sso_account_title'), hint: settingsLabel, href: props.settingsAccountRoute, settingsSection: 'sso' },
    { id: 'settings-emergency-access', label: t('txt_emergency_access_title'), hint: settingsLabel, href: props.settingsAccountRoute, settingsSection: 'emergencyAccess' },
  );

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent): void => {
      if (event.defaultPrevented) return;
      if (!event.ctrlKey && !event.metaKey) return;
      if (event.altKey || event.shiftKey) return;
      if (event.key.toLowerCase() !== 'p') return;
      // Another dialog is open: the shortcut belongs to that dialog.
      if (document.querySelector('[role="dialog"][aria-modal="true"]:not(.palette-card)')) return;
      event.preventDefault();
      setPaletteQuery('');
      setPalettePlacement('last');
      setPaletteOpen(true);
      setPaletteSignal((signal) => signal + 1);
    };
    window.addEventListener('keydown', handleKeyDown, true);
    return () => window.removeEventListener('keydown', handleKeyDown, true);
  }, []);

  // The search bar of the vault opens the palette with the filter it holds.
  useEffect(() => {
    const openPalette = (event: Event): void => {
      const detail = (event as CustomEvent<{ query?: string }>).detail;
      setPaletteQuery(String(detail?.query ?? ''));
      setPalettePlacement('first');
      setPaletteOpen(true);
      setPaletteSignal((signal) => signal + 1);
    };
    window.addEventListener('nodewarden:open-palette', openPalette);
    return () => window.removeEventListener('nodewarden:open-palette', openPalette);
  }, []);

  function toggleGroup(group: NavGroup): void {
    setExpandedGroups((current) => {
      const next = { ...current, [group]: !current[group] };
      try {
        window.localStorage.setItem(NAV_GROUPS_STORAGE_KEY, JSON.stringify(next));
      } catch {
        // Ignore local preference write failures.
      }
      return next;
    });
  }

  function renderSideLink(href: string, active: boolean, icon: ComponentChildren, label: string) {
    return (
      <Link href={href} className={`side-link ${active ? 'active' : ''}`}>
        {icon}
        <span>{label}</span>
      </Link>
    );
  }

  function renderSubLink(href: string, active: boolean, label: string) {
    return (
      <Link href={href} className={`side-sub-link ${active ? 'active' : ''}`}>
        <span>{label}</span>
      </Link>
    );
  }

  function renderNavGroup(
    group: NavGroup,
    title: string,
    icon: ComponentChildren,
    children: ComponentChildren
  ) {
    const open = expandedGroups[group];
    return (
      <div className={`side-nav-group ${open ? 'open' : ''}`}>
        <button
          type="button"
          className="side-group-trigger"
          aria-expanded={open}
          onClick={() => toggleGroup(group)}
        >
          {icon}
          <span>{title}</span>
          <ChevronDown size={15} className="side-group-chevron" />
        </button>
        <div className={`side-subnav ${open ? 'open' : ''}`}>
          <div className="side-subnav-inner">
            {children}
          </div>
        </div>
      </div>
    );
  }

  const groupedNav = (
    <>
      {renderSideLink('/vault', props.location === '/vault', <KeyRound size={16} />, t('nav_vault_items'))}
      {renderSideLink('/sends', props.location === '/sends', <SendIcon size={16} />, t('nav_sends'))}
      {renderNavGroup(
        'tools',
        t('nav_group_tools'),
        <Sparkles size={16} />,
        <>
          {renderSubLink('/vault/totp', props.location === '/vault/totp', t('txt_verification_code'))}
          {renderSubLink('/generator', props.location === '/generator', t('nav_generator'))}
          {renderSubLink('/security/password-health', props.location === '/security/password-health', t('nav_password_security'))}
          {renderSubLink(props.importRoute, props.isImportRoute, t('nav_import_export'))}
        </>
      )}
      {renderNavGroup(
        'settings',
        t('txt_settings'),
        <SettingsIcon size={16} />,
        <>
          {renderSubLink(props.settingsAccountRoute, props.location === props.settingsAccountRoute, t('nav_account_settings'))}
          {renderSubLink(DEVICE_MANAGEMENT_ROUTE, deviceManagementActive, t('nav_device_management'))}
          {renderSubLink('/settings/domain-rules', props.location === '/settings/domain-rules', t('nav_domain_rules'))}
        </>
      )}
      {isAdmin &&
        renderNavGroup(
          'management',
          t('nav_group_system_management'),
          <ShieldUser size={16} />,
          <>
            {renderSubLink('/backup', props.location === '/backup', t('nav_backup_strategy'))}
            {renderSubLink('/admin', props.location === '/admin', t('nav_admin_panel'))}
            {renderSubLink('/logs', props.location === '/logs', t('nav_log_center'))}
          </>
        )}
    </>
  );

  return (
    <div className="app-page">
      <CommandPalette
        open={paletteOpen}
        pages={palettePages}
        ciphers={props.paletteCiphers}
        focusSignal={paletteSignal}
        initialQuery={paletteQuery}
        listFilterAvailable={props.location === '/vault'}
        listFilterPlacement={palettePlacement}
        onClose={() => setPaletteOpen(false)}
        onTrackPasswordCopy={props.onTrackPasswordCopy}
      />
      <div className={`app-shell ${props.location === '/vault' ? 'vault-route' : ''}`}>
        <header className="topbar">
          <div className="brand">
            <span className="brand-wordmark">Vault</span>
            <span className="mobile-page-title">{props.currentPageTitle}</span>
          </div>
          <div className="topbar-actions">
            <NetworkStatusBadge />
            <div className="user-chip">
              <ShieldUser size={16} />
              <span>{props.profile?.email}</span>
            </div>
            <ThemeSwitch checked={props.darkMode} title={props.themeToggleTitle} onToggle={props.onToggleTheme} />
            <button type="button" className="btn btn-secondary small" onClick={props.onLock}>
              <Lock size={14} className="btn-icon" /> {t('txt_lock')}
            </button>
            {props.showSidebarToggle && (
              <button
                type="button"
                className="btn btn-secondary small mobile-sidebar-toggle"
                aria-label={props.sidebarToggleTitle}
                title={props.sidebarToggleTitle}
                onClick={props.onToggleMobileSidebar}
              >
                <FolderIcon size={16} className="btn-icon" />
              </button>
            )}
            <div className="mobile-theme-btn">
              <ThemeSwitch checked={props.darkMode} title={props.themeToggleTitle} onToggle={props.onToggleTheme} />
            </div>
            <button type="button" className="btn btn-secondary small mobile-lock-btn" aria-label={t('txt_lock')} title={t('txt_lock')} onClick={props.onLock}>
              <Lock size={14} className="btn-icon" />
            </button>
            <button type="button" className="btn btn-secondary small" onClick={props.onLogout}>
              <LogOut size={14} className="btn-icon" /> {t('txt_sign_out')}
            </button>
          </div>
        </header>

        <div className="app-main">
          <aside className="app-side">
            <div className="side-nav-main">
              {groupedNav}
            </div>
          </aside>
          {props.location === '/vault' && (
            <aside className="vault-filter-column" aria-label={t('txt_filter')}>
              <div id="vault-sidebar-slot" />
            </aside>
          )}
          <main className="content">
            <div key={routeAnimationKey} className={`route-stage ${isDomainRulesRoute ? 'route-stage-fixed' : ''} ${isLogRoute ? 'route-stage-log-fixed' : ''}`}>
              <AppMainRoutes {...props.mainRoutesProps} />
            </div>
          </main>
        </div>

        <nav className="mobile-tabbar" aria-label={t('txt_menu')}>
          <Link href="/vault" className={`mobile-tab ${props.mobilePrimaryRoute === '/vault' ? 'active' : ''}`}>
            <KeyRound size={18} />
            <span>{t('nav_my_vault')}</span>
          </Link>
          <Link href="/vault/totp" className={`mobile-tab ${props.mobilePrimaryRoute === '/vault/totp' ? 'active' : ''}`}>
            <Clock3 size={18} />
            <span>{t('txt_verification_code')}</span>
          </Link>
          <Link href="/generator" className={`mobile-tab ${props.mobilePrimaryRoute === '/generator' ? 'active' : ''}`}>
            <Sparkles size={18} />
            <span>{t('nav_generator')}</span>
          </Link>
          <Link href="/sends" className={`mobile-tab ${props.mobilePrimaryRoute === '/sends' ? 'active' : ''}`}>
            <SendIcon size={18} />
            <span>{t('nav_sends')}</span>
          </Link>
          <Link href="/settings" className={`mobile-tab ${props.mobilePrimaryRoute === '/settings' ? 'active' : ''}`}>
            <SettingsIcon size={18} />
            <span>{t('txt_settings')}</span>
          </Link>
        </nav>
      </div>
    </div>
  );
}