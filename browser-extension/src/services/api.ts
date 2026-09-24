import { ScanResultData, ModelSignal } from '../types/api';
import { storage } from './storage';

export class ExtensionApiClient {
  async getApiBaseUrl(): Promise<string> {
    const settings = await storage.getSettings();
    return settings.apiUrl.replace(/\/+$/, '');
  }

  async checkHealth(): Promise<{ status: string; database_connected: boolean }> {
    const baseUrl = await this.getApiBaseUrl();
    const response = await fetch(`${baseUrl}/health`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!response.ok) {
      throw new Error(`Health check returned status ${response.status}`);
    }
    return response.json();
  }

  async analyzeUrl(url: string, includeVisual = true): Promise<ScanResultData> {
    const baseUrl = await this.getApiBaseUrl();
    const endpoint = `${baseUrl}/intelligence/analyze`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 25000); // 25s timeout for deep multi-modal analysis

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, include_visual: includeVisual }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        let errorDetail = `Backend returned HTTP ${response.status}`;
        try {
          const errJson = await response.json();
          if (errJson.detail) errorDetail = errJson.detail;
        } catch {
          // Response body was not JSON
        }
        throw new Error(errorDetail);
      }

      const raw = await response.json();

      // Transform raw backend response into clean ScanResultData
      const modelsMap: Record<string, ModelSignal> = {};
      if (raw.models) {
        for (const [k, v] of Object.entries(raw.models) as [string, any][]) {
          modelsMap[k] = {
            modality: k,
            model_name: v.model_name || k,
            status: v.status || 'available',
            prediction: v.prediction,
            probability: v.probability ?? v.calibrated_probability,
            version: v.model_version,
          };
        }
      }

      return {
        scan_id: raw.scan_id,
        url: raw.url,
        domain: raw.domain || new URL(url).hostname,
        classification: raw.classification.toUpperCase() as any,
        risk_score: raw.risk_score,
        risk_level: raw.risk_level.toUpperCase() as any,
        phishing_probability: raw.phishing_probability,
        evidence: (raw.evidence || []).map((e: any) => ({
          category: e.category,
          severity: e.severity,
          title: e.title,
          description: e.description,
        })),
        models: modelsMap,
        explanation: raw.explanation?.summary,
        timestamp: Date.now(),
      };
    } catch (err: any) {
      clearTimeout(timeoutId);
      if (err.name === 'AbortError') {
        throw new Error('Analysis timed out. The backend server took too long to respond.');
      }
      throw err;
    }
  }
}

export const extensionApi = new ExtensionApiClient();
