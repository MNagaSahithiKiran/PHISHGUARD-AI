import { ScanState, ScanResultData } from '../types/api';
import { validateTargetUrl } from '../utils/url-validator';
import { scanCache } from '../utils/cache';
import { extensionApi } from './api';
import { storage } from './storage';

export class ScanService {
  async getActiveTab(): Promise<{ id?: number; url?: string; title?: string }> {
    if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs && tabs[0]) {
        return {
          id: tabs[0].id,
          url: tabs[0].url,
          title: tabs[0].title,
        };
      }
    }
    // Fallback for tests or local previews
    return {
      url: typeof window !== 'undefined' && window.location.href !== 'about:blank' ? window.location.href : 'https://example.com',
      title: 'Current Active Page',
    };
  }

  async analyzeUrlWithProgress(
    url: string,
    onStateChange?: (state: ScanState) => void
  ): Promise<{ result: ScanResultData; fromCache: boolean }> {
    const validation = validateTargetUrl(url);
    if (!validation.isValid) {
      if (onStateChange) onStateChange('unsupported');
      throw new Error(validation.reason || 'This page cannot be analyzed.');
    }

    const settings = await storage.getSettings();
    const cacheTtlMs = settings.cacheDurationMinutes * 60 * 1000;

    // 1. Check cache first
    const cached = scanCache.get(validation.sanitizedUrl, cacheTtlMs);
    if (cached) {
      if (onStateChange) onStateChange('completed');
      return { result: cached, fromCache: true };
    }

    // 2. Real Backend Multi-Modal Pipeline Progression
    if (onStateChange) onStateChange('preparing');

    // Simulate authentic pipeline stages while backend executes
    const stageTimers: NodeJS.Timeout[] = [];
    if (onStateChange) {
      stageTimers.push(setTimeout(() => onStateChange('url_analysis'), 400));
      stageTimers.push(setTimeout(() => onStateChange('website_analysis'), 1200));
      stageTimers.push(setTimeout(() => onStateChange('visual_analysis'), 2400));
      stageTimers.push(setTimeout(() => onStateChange('ai_fusion'), 3600));
    }

    try {
      const result = await extensionApi.analyzeUrl(validation.sanitizedUrl, true);

      stageTimers.forEach(clearTimeout);

      if (onStateChange) onStateChange('completed');

      // Save to short-lived cache
      scanCache.set(validation.sanitizedUrl, result);

      // Trigger optional browser notification
      if (settings.notificationsEnabled && typeof chrome !== 'undefined' && chrome.notifications) {
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon48.png',
          title: `PhishGuard AI: ${result.classification}`,
          message: `Target ${result.domain} assessed with Risk Score ${result.risk_score}/100.`,
          priority: 1,
        });
      }

      return { result, fromCache: false };
    } catch (err: any) {
      stageTimers.forEach(clearTimeout);
      if (onStateChange) onStateChange('failed');
      throw err;
    }
  }
}

export const scanService = new ScanService();
