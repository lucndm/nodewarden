// CONTRACT:
// The names of the device types the server knows. The web vault shows them
// on the device list and in the log center, so both read them from here.
//
// The names of the products are the products and stay as they are; only the
// kinds of device that every platform names the same way are translated.
import { t } from '@/lib/i18n';

export function deviceTypeName(type: number): string {
  switch (type) {
    case 0: return t('txt_android');
    case 1: return t('txt_ios');
    case 2: return t('txt_chrome_extension');
    case 3: return t('txt_firefox_extension');
    case 4: return t('txt_opera_extension');
    case 5: return t('txt_edge_extension');
    case 6: return t('txt_windows_desktop');
    case 7: return t('txt_macos_desktop');
    case 8: return t('txt_linux_desktop');
    case 9: return t('txt_chrome_browser');
    case 10: return t('txt_firefox_browser');
    case 11: return t('txt_opera_browser');
    case 12: return t('txt_edge_browser');
    case 13: return t('txt_ie_browser');
    case 14: return t('txt_web');
    case 15: return t('txt_android');
    case 16: return 'Windows UWP';
    case 17: return 'Safari';
    case 18: return 'Vivaldi';
    case 19: return 'Vivaldi Extension';
    case 20: return 'Safari Extension';
    case 21: return 'SDK';
    case 22: return 'Server';
    case 23: return 'Windows CLI';
    case 24: return 'macOS CLI';
    case 25: return 'Linux CLI';
    case 26: return 'DuckDuckGo';
    default: return t('txt_type_type', { type });
  }
}
