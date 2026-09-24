import { scanService } from '../services/scan-service';
import { scanCache } from '../utils/cache';
import { BackgroundMessage, BackgroundResponse } from '../types/api';

console.log('PhishGuard AI Sentinel Service Worker initialized.');

chrome.runtime.onInstalled.addListener(() => {
  console.log('PhishGuard AI Sentinel extension installed.');
  // Set default badge
  chrome.action.setBadgeBackgroundColor({ color: '#06b6d4' });
});

// Update badge based on assessment verdict
export function updateBadgeForVerdict(tabId: number | undefined, verdict: string) {
  if (!tabId || typeof chrome === 'undefined' || !chrome.action) return;

  if (verdict === 'PHISHING') {
    chrome.action.setBadgeText({ tabId, text: '!' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#e11d48' });
  } else if (verdict === 'SUSPICIOUS') {
    chrome.action.setBadgeText({ tabId, text: '?' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#d97706' });
  } else if (verdict === 'LEGITIMATE') {
    chrome.action.setBadgeText({ tabId, text: '✓' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#10b981' });
  } else {
    chrome.action.setBadgeText({ tabId, text: '' });
  }
}

// Handle messages from Popup or Content Scripts
chrome.runtime.onMessage.addListener(
  (message: BackgroundMessage, sender, sendResponse: (res: BackgroundResponse) => void) => {
    if (message.action === 'ANALYZE_URL' && message.url) {
      scanService
        .analyzeUrlWithProgress(message.url)
        .then(({ result, fromCache }) => {
          const tabId = sender.tab?.id;
          updateBadgeForVerdict(tabId, result.classification);
          sendResponse({ success: true, data: result, fromCache });
        })
        .catch((err) => {
          sendResponse({ success: false, error: err.message });
        });
      return true; // Keep message channel open for async response
    }

    if (message.action === 'CLEAR_CACHE') {
      scanCache.clear();
      sendResponse({ success: true });
      return false;
    }

    if (message.action === 'OPEN_OPTIONS') {
      if (chrome.runtime.openOptionsPage) {
        chrome.runtime.openOptionsPage();
      }
      sendResponse({ success: true });
      return false;
    }

    return false;
  }
);
