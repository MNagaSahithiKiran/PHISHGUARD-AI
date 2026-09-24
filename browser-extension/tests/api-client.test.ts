import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ExtensionApiClient } from '../src/services/api';

describe('ExtensionApiClient & Multi-Modal Response Normalization', () => {
  let client: ExtensionApiClient;

  beforeEach(() => {
    client = new ExtensionApiClient();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('normalizes backend multi-modal response into ScanResultData', async () => {
    const mockApiResponse = {
      scan_id: 'scan-777',
      url: 'https://paypal-security-update.xyz/login',
      domain: 'paypal-security-update.xyz',
      classification: 'phishing',
      risk_score: 94,
      risk_level: 'high',
      phishing_probability: 0.965,
      evidence: [
        {
          category: 'BRAND_IMPERSONATION',
          severity: 'critical',
          title: 'Brand Impersonation',
          description: 'Impersonates PayPal brand without legitimate ownership',
        },
      ],
      models: {
        url: {
          model_name: 'Lexical Random Forest',
          status: 'completed',
          prediction: 'phishing',
          probability: 0.94,
          model_version: 'v2.1',
        },
        fusion: {
          model_name: 'Calibrated Soft Voting',
          status: 'completed',
          prediction: 'phishing',
          probability: 0.965,
          model_version: 'v5.0',
        },
      },
      explanation: {
        summary: 'Critical phishing threat detected with high confidence across URL and DOM modalities.',
      },
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockApiResponse,
    });

    const result = await client.analyzeUrl('https://paypal-security-update.xyz/login');

    expect(result.scan_id).toBe('scan-777');
    expect(result.classification).toBe('PHISHING');
    expect(result.risk_level).toBe('HIGH');
    expect(result.risk_score).toBe(94);
    expect(result.phishing_probability).toBe(0.965);
    expect(result.evidence).toHaveLength(1);
    expect(result.evidence[0].title).toBe('Brand Impersonation');
    expect(result.models.url?.model_name).toBe('Lexical Random Forest');
    expect(result.models.fusion?.probability).toBe(0.965);
    expect(result.explanation).toContain('Critical phishing threat');
  });

  it('throws descriptive error on backend HTTP failure', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 422,
      json: async () => ({ detail: 'Unresolvable private IP address' }),
    });

    await expect(client.analyzeUrl('http://192.168.1.1')).rejects.toThrow(
      'Unresolvable private IP address'
    );
  });
});
