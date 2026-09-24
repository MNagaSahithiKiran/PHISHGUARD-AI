import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ResultCache } from '../src/utils/cache';
import { ScanResultData } from '../src/types/api';

const mockScanResult: ScanResultData = {
  scan_id: 'test-scan-001',
  url: 'https://example.com/login',
  domain: 'example.com',
  risk_score: 85,
  classification: 'PHISHING',
  risk_level: 'HIGH',
  phishing_probability: 0.92,
  evidence: [
    { category: 'FORM', title: 'Deceptive Action', description: 'Form posts to external domain', severity: 'high' },
  ],
  models: {
    url: { modality: 'url', model_name: 'URL Lexical Model', status: 'completed', probability: 0.88 },
    website: { modality: 'website', model_name: 'DOM Intelligence', status: 'completed', probability: 0.94 },
    visual: { modality: 'visual', model_name: 'Visual Similarity', status: 'completed', probability: 0.75 },
    fusion: { modality: 'fusion', model_name: 'Multi-Modal Fusion', status: 'completed', probability: 0.92 },
  },
  timestamp: Date.now(),
};

describe('Scan Cache TTL & Key Management', () => {
  let cache: ResultCache;

  beforeEach(() => {
    cache = new ResultCache();
  });

  it('stores and retrieves cached scan results', () => {
    cache.set('https://example.com/login', mockScanResult);
    const cached = cache.get('https://example.com/login');
    expect(cached).not.toBeNull();
    expect(cached?.scan_id).toBe('test-scan-001');
    expect(cached?.risk_score).toBe(85);
  });

  it('normalizes URL keys (trailing slash and case-insensitivity)', () => {
    cache.set('https://EXAMPLE.com/login/', mockScanResult);

    const match1 = cache.get('https://example.com/login');
    const match2 = cache.get('https://EXAMPLE.COM/login/');
    expect(match1).not.toBeNull();
    expect(match2).not.toBeNull();
  });

  it('returns null when cached item expires based on TTL', () => {
    vi.useFakeTimers();
    cache.set('https://example.com/login', mockScanResult);

    // Immediately available with default 5m TTL
    expect(cache.get('https://example.com/login', 5000)).not.toBeNull();

    // Advance time by 6 seconds (exceeding 5000ms custom TTL)
    vi.advanceTimersByTime(6000);

    expect(cache.get('https://example.com/login', 5000)).toBeNull();
    vi.useRealTimers();
  });

  it('clears all entries correctly', () => {
    cache.set('https://site-a.com', mockScanResult);
    cache.set('https://site-b.com', mockScanResult);
    expect(cache.size()).toBe(2);

    cache.clear();
    expect(cache.size()).toBe(0);
    expect(cache.get('https://site-a.com')).toBeNull();
  });
});
