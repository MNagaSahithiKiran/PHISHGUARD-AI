export type ScanState =
  | 'idle'
  | 'preparing'
  | 'url_analysis'
  | 'website_analysis'
  | 'visual_analysis'
  | 'ai_fusion'
  | 'completed'
  | 'failed'
  | 'unsupported';

export type Verdict = 'LEGITIMATE' | 'SUSPICIOUS' | 'PHISHING' | 'UNRATED';

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH';

export interface EvidenceItem {
  category: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
}

export interface ModelSignal {
  modality: string;
  model_name: string;
  status: 'available' | 'completed' | 'not_available' | 'skipped';
  prediction?: string;
  probability?: number;
  version?: string;
}

export interface ScanResultData {
  scan_id: string;
  url: string;
  domain: string;
  classification: Verdict;
  risk_score: number;
  risk_level: RiskLevel;
  phishing_probability: number;
  evidence: EvidenceItem[];
  models: {
    url?: ModelSignal;
    website?: ModelSignal;
    visual?: ModelSignal;
    fusion?: ModelSignal;
  };
  explanation?: string;
  timestamp: number;
}

export interface ExtensionSettings {
  apiUrl: string;
  notificationsEnabled: boolean;
  autoScanEnabled: boolean;
  cacheDurationMinutes: number;
}

export interface CacheEntry {
  result: ScanResultData;
  cachedAt: number;
}

export interface BackgroundMessage {
  action: 'ANALYZE_URL' | 'GET_CURRENT_SCAN' | 'CLEAR_CACHE' | 'OPEN_OPTIONS';
  url?: string;
  settings?: Partial<ExtensionSettings>;
}

export interface BackgroundResponse {
  success: boolean;
  state?: ScanState;
  data?: ScanResultData;
  error?: string;
  fromCache?: boolean;
}
