import { ExtensionSettings } from '../types/api';

export const DEFAULT_SETTINGS: ExtensionSettings = {
  apiUrl: 'http://localhost:8000/api/v1',
  notificationsEnabled: true,
  autoScanEnabled: false,
  cacheDurationMinutes: 5,
};

export class ExtensionStorage {
  private hasChromeStorage(): boolean {
    return typeof chrome !== 'undefined' && !!chrome.storage && !!chrome.storage.local;
  }

  async getSettings(): Promise<ExtensionSettings> {
    if (this.hasChromeStorage()) {
      return new Promise((resolve) => {
        chrome.storage.local.get(['settings'], (result) => {
          if (result && result.settings) {
            resolve({ ...DEFAULT_SETTINGS, ...result.settings });
          } else {
            resolve(DEFAULT_SETTINGS);
          }
        });
      });
    }

    // Fallback for tests or local environment
    try {
      const stored = localStorage.getItem('phishguard_ext_settings');
      return stored ? { ...DEFAULT_SETTINGS, ...JSON.parse(stored) } : DEFAULT_SETTINGS;
    } catch {
      return DEFAULT_SETTINGS;
    }
  }

  async saveSettings(settings: Partial<ExtensionSettings>): Promise<ExtensionSettings> {
    const current = await this.getSettings();
    const updated = { ...current, ...settings };

    if (this.hasChromeStorage()) {
      return new Promise((resolve) => {
        chrome.storage.local.set({ settings: updated }, () => {
          resolve(updated);
        });
      });
    }

    try {
      localStorage.setItem('phishguard_ext_settings', JSON.stringify(updated));
    } catch {
      // Ignore
    }
    return updated;
  }

  async clearStorage(): Promise<void> {
    if (this.hasChromeStorage()) {
      return new Promise((resolve) => {
        chrome.storage.local.clear(() => resolve());
      });
    }
    try {
      localStorage.removeItem('phishguard_ext_settings');
    } catch {
      // Ignore
    }
  }
}

export const storage = new ExtensionStorage();
