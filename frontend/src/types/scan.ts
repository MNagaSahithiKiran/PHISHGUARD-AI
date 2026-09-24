export interface ScanCreationResponse {
  scan_id: string;
  url: string;
  status: string;
  message: string;
}

export interface URLFeatures {
  url_length: number;
  hostname_length: number;
  path_length: number;
  query_length: number;
  count_dots: number;
  count_hyphens: number;
  count_at: number;
  count_question_marks: number;
  count_equal_signs: number;
  count_subdomains: number;
  has_ip_address: boolean;
  has_punycode: boolean;
  has_shortener: boolean;
  has_port_in_url: boolean;
  entropy_score: number | null;
}

export interface DomainInformation {
  registrar: string | null;
  creation_date: string | null;
  expiration_date: string | null;
  domain_age_days: number | null;
  dnssec: boolean | null;
  has_valid_ssl: boolean | null;
  ssl_issuer: string | null;
  nameservers: string | null;
}

export interface HTMLFeatures {
  has_login_form: boolean | null;
  external_form_action: boolean | null;
  iframe_count: number | null;
  hidden_element_count: number | null;
  script_count: number | null;
  suspicious_keywords: string | null;
}

export interface VisualAnalysis {
  screenshot_path: string | null;
  dominant_colors: string | null;
  brand_similarity_score: number | null;
  detected_logos: string | null;
}

export interface ThreatIndicator {
  id: string;
  indicator_type: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  rule_id: string;
  description: string;
  details: string | null;
  created_at: string;
}

export interface ScanResult {
  id: string;
  verdict: 'legitimate' | 'suspicious' | 'phishing' | 'unrated';
  risk_score: number | null;
  confidence_score: number | null;
  summary: string | null;
  rule_match_count: number;
  completed_at: string | null;
  model_version?: string | null;
  feature_version?: string | null;
  preprocessing_version?: string | null;
  decision_policy_version?: string | null;
  url_feature_hash?: string | null;
  dom_snapshot_hash?: string | null;
  screenshot_hash?: string | null;
  model_input_hash?: string | null;
  prediction_hash?: string | null;
  live_content_changed?: boolean;
  content_change_notice?: string | null;
  reproducibility_data?: string | null;
}

export interface ScanDetail {
  id: string;
  url: string;
  normalized_url: string;
  domain: string;
  status: 'queued' | 'processing' | 'completed' | 'failed';
  created_at: string;
  updated_at: string;
  scan_result: ScanResult | null;
  url_features: URLFeatures | null;
  domain_info: DomainInformation | null;
  html_features: HTMLFeatures | null;
  visual_analysis: VisualAnalysis | null;
  threat_indicators: ThreatIndicator[];
}

export interface ScanSummaryItem {
  id: string;
  url: string;
  domain: string;
  status: string;
  verdict: string;
  risk_score: number | null;
  created_at: string;
}

export interface ScanListResponse {
  total: number;
  page: number;
  limit: number;
  items: ScanSummaryItem[];
}

export interface SystemStats {
  total_scans: number;
  queued_scans: number;
  completed_scans: number;
  phishing_detected: number;
  suspicious_sites: number;
  legitimate_sites: number;
  unrated_sites: number;
  pipeline_state: string;
}

export interface SHAPContribution {
  feature: string;
  value: number;
  contribution: number;
  direction: string;
}

export interface MLPrediction {
  prediction: 'legitimate' | 'phishing';
  label: number;
  probability: number;
  confidence: number;
  model_version: string;
  feature_version: string;
  inference_time_ms: number;
  top_explanations?: SHAPContribution[];
}

export interface ModelBenchmark {
  model: string;
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  roc_auc: number | null;
  false_positive_rate: number;
  false_negative_rate: number;
  training_time_seconds: number;
  inference_time_ms: number;
}

export interface MLModelStatus {
  is_trained: boolean;
  selected_model: string;
  model_file: string;
  feature_version: string;
  selection_rationale: string;
  benchmarks: ModelBenchmark[];
}

export interface WebsiteEvidenceItem {
  category: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  detail: string;
  recommendation?: string;
}

export interface WebsiteAnalysis {
  scan_id: string;
  status: string;
  url: string;
  final_url: string;
  http: {
    initial_url: string;
    final_url: string;
    status_code: number | null;
    content_length: number;
    response_time_ms: number;
    error: string | null;
    truncated: boolean;
    ip_address: string | null;
    content_type: string;
  };
  redirects: {
    total_hops: number;
    hops: Array<{
      hop_number: number;
      source_url: string;
      target_url: string;
      status_code: number;
    }>;
    protocol_downgrades: number;
    cross_domain_redirects: number;
  };
  html: {
    title: string;
    language: string;
    charset: string;
    body_byte_length: number;
  };
  dom: {
    total_tags: number;
    dom_depth: number;
    text_ratio: number;
    hidden_elements_count: number;
  };
  forms: {
    total_forms: number;
    login_forms_count: number;
    has_password_field: boolean;
    external_action_count: number;
  };
  links: {
    total_links: number;
    internal_links: number;
    external_links: number;
    null_link_ratio: number;
    external_link_ratio: number;
    distinct_external_domains: string[];
  };
  scripts: {
    total_scripts: number;
    inline_scripts: number;
    external_scripts: number;
    external_script_domains: string[];
    inline_script_bytes: number;
  };
  iframes: {
    total_iframes: number;
    hidden_iframes: number;
    cross_origin_iframes: number;
  };
  resources: {
    total_resources: number;
    external_resources: number;
    external_resource_ratio: number;
    mixed_content_count: number;
  };
  headers: {
    hsts_present: boolean;
    csp_present: boolean;
    x_frame_options: string | null;
    x_content_type_options: string | null;
    security_header_score: number;
  };
  evidence: WebsiteEvidenceItem[];
  screenshot_url?: string | null;
  url_model?: any;
  website_model: {
    status: string;
    message: string;
  };
  visual_model?: {
    status: string;
    message: string;
  };
}

export interface VisualEvidenceItem {
  evidence_type: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  source: string;
}

export interface VisualFeaturesData {
  image_width: number;
  image_height: number;
  aspect_ratio: number;
  mean_luminance: number;
  visual_contrast: number;
  whitespace_ratio: number;
  edge_density: number;
  colorfulness: number;
  dominant_colors: string[];
  has_centered_card: boolean;
}

export interface VisualAnalysisResult {
  status: string;
  scan_id?: string;
  prediction?: 'phishing' | 'legitimate';
  label?: number;
  phishing_probability?: number;
  confidence_score?: number;
  model_name?: string;
  model_version?: string;
  preprocessing_version?: string;
  inference_latency_ms?: number;
  screenshot_url?: string | null;
  heatmap_url?: string | null;
  visual_features?: VisualFeaturesData;
  evidence: VisualEvidenceItem[];
  message?: string;
}

export interface IntelligenceEvidence {
  category: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  source: string;
}

export interface IntelligenceExplanation {
  summary: string;
  classification: string;
  calibrated_phishing_probability: number;
  key_model_signals: string[];
  observed_factual_evidence: string[];
  modality_status: {
    modalities_used: string[];
    missing_modalities: string[];
    fusion_routing?: string;
  };
  feature_attributions: Array<{
    feature: string;
    coefficient: number;
    magnitude: number;
    effect: string;
  }>;
}

export interface IntelligenceResponse {
  scan_id: string;
  url: string;
  normalized_url?: string;
  domain?: string;
  status: string;
  classification: 'phishing' | 'suspicious' | 'legitimate';
  phishing_probability: number;
  risk_score: number;
  risk_level: 'low' | 'medium' | 'high';
  modalities_used: string[];
  missing_modalities: string[];
  models: {
    url?: any;
    website?: any;
    visual?: any;
    fusion?: any;
  };
  evidence: IntelligenceEvidence[];
  explanation: IntelligenceExplanation;
  performance: {
    total_analysis_ms: number;
  };
  screenshot_url?: string | null;
  heatmap_url?: string | null;
  reproducibility?: Record<string, any>;
  url_feature_hash?: string;
  dom_snapshot_hash?: string;
  screenshot_hash?: string;
  model_input_hash?: string;
  prediction_hash?: string;
  live_content_changed?: boolean;
  content_change_notice?: string;
  reputation?: ExternalReputationSummary;
  reason_codes?: string[];
  reason_details?: ReasonDetail[];
  decision_policy_version?: string;
}

export interface ReputationEvidenceItem {
  provider: string;
  evidence_type: string;
  status: string;
  value?: string | null;
  confidence?: number | null;
  source_url?: string | null;
  observed_at: string;
  evidence_hash: string;
  raw_reference?: string | null;
}

export interface ReputationProviderResult {
  provider_name: string;
  status: 'CONFIRMED_RESULT' | 'NO_RESULT' | 'SAFE' | 'THREAT_MATCH' | 'NOT_CONFIGURED' | 'UNAVAILABLE' | 'ERROR' | 'RATE_LIMITED';
  summary: string;
  is_threat?: boolean | null;
  confidence?: number | null;
  details: Record<string, any>;
  query: string;
  latency_ms: number;
}

export interface ExternalReputationSummary {
  overall_status: 'CLEAN' | 'THREAT_DETECTED' | 'NO_REPUTATION_DATA' | 'PARTIAL';
  threat_matches: number;
  providers_queried: number;
  providers_configured: number;
  evidence_ledger: ReputationEvidenceItem[];
  provider_results: Record<string, ReputationProviderResult>;
}

export interface ReasonDetail {
  code: string;
  description: string;
}

export interface User {
  id: string;
  email: string;
  full_name: string | null;
  role: 'user' | 'analyst' | 'admin';
  is_active: boolean;
  created_at: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  user: User;
}

export interface AppNotification {
  id: string;
  title: string;
  message: string;
  severity: 'info' | 'warning' | 'critical' | 'success';
  link?: string | null;
  is_read: boolean;
  created_at: string;
}

export interface RiskBucket {
  range: string;
  count: number;
  label: string;
}

export interface AnalyticsOverview {
  total_scans: number;
  phishing_scans: number;
  suspicious_scans: number;
  legitimate_scans: number;
  unrated_scans: number;
  detection_rate_pct: number;
  average_risk_score: number;
  total_threat_indicators: number;
  scans_today: number;
  scans_last_7_days: number;
  risk_distribution: RiskBucket[];
}

export interface DailyTrendItem {
  date: string;
  total: number;
  phishing: number;
  suspicious: number;
  legitimate: number;
}

export interface TopIndicator {
  rule_id: string;
  indicator_type: string;
  severity: string;
  count: number;
  description: string;
}

export interface ThreatIntelResponse {
  total_indicators_detected: number;
  top_indicators: TopIndicator[];
  severity_breakdown: Record<string, number>;
  type_breakdown: Record<string, number>;
}

export interface ObservedDomain {
  domain: string;
  scan_count: number;
  phishing_count: number;
  average_risk_score: number;
  last_scanned_at: string;
}

export interface RecentThreatItem {
  scan_id: string;
  url: string;
  domain: string;
  verdict: string;
  risk_score: number;
  detected_at: string;
  rule_match_count: number;
}

export interface ModelCard {
  model_id: string;
  name: string;
  modality: string;
  architecture: string;
  input_features_count: number;
  training_data_provenance: string;
  domain_split_methodology: string;
  metrics: Record<string, any>;
  explainability_methods: string[];
  limitations: string[];
  intended_use: string;
}

export interface ModelTransparencyResponse {
  version: string;
  framework: string;
  registered_models: ModelCard[];
}

export interface AdminUserItem {
  id: string;
  email: string;
  full_name: string | null;
  role: string;
  is_active: boolean;
  scan_count: number;
  created_at: string;
}

export interface AuditLogItem {
  id: string;
  user_id?: string | null;
  user_email?: string | null;
  event_type: string;
  action: string;
  status: string;
  client_ip?: string | null;
  details?: string | null;
  created_at: string;
}

export interface SystemHealthDeepResponse {
  status: string;
  db_latency_ms: number;
  db_connected: boolean;
  active_users_count: number;
  total_scans_recorded: number;
  storage_writable: boolean;
  models_status: Array<{
    model_name: string;
    file_path: string;
    exists: boolean;
    size_bytes: number;
  }>;
  python_version: string;
}


