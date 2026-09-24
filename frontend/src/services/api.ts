import {
  ScanCreationResponse,
  ScanDetail,
  ScanListResponse,
  SystemStats,
  MLPrediction,
  MLModelStatus,
  User,
  AuthResponse,
  AppNotification,
  AnalyticsOverview,
  DailyTrendItem,
  ThreatIntelResponse,
  ObservedDomain,
  RecentThreatItem,
  ModelTransparencyResponse,
  AdminUserItem,
  AuditLogItem,
  SystemHealthDeepResponse,
} from '../types/scan';
import { API_BASE_URL, IS_API_CONFIGURED, getApiBaseUrl } from '../config/env';

export { API_BASE_URL, IS_API_CONFIGURED, getApiBaseUrl };

class ApiService {
  private authToken: string | null = localStorage.getItem('phishguard_token');

  public isConfigured(): boolean {
    return Boolean(API_BASE_URL);
  }

  public setToken(token: string | null) {
    this.authToken = token;
    if (token) {
      localStorage.setItem('phishguard_token', token);
    } else {
      localStorage.removeItem('phishguard_token');
    }
  }

  public getToken(): string | null {
    return this.authToken;
  }

  public getBaseUrl(): string {
    return API_BASE_URL;
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    if (!API_BASE_URL) {
      throw new Error('API CONFIGURATION REQUIRED: VITE_API_BASE_URL is not configured in this environment.');
    }
    const url = `${API_BASE_URL}${endpoint}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    };

    if (this.authToken) {
      headers['Authorization'] = `Bearer ${this.authToken}`;
    }

    try {
      const response = await fetch(url, { ...options, headers });
      if (!response.ok) {
        let errorMsg = `HTTP Error ${response.status}`;
        try {
          const errorData = await response.json();
          if (errorData.detail) {
            errorMsg = errorData.detail;
          }
        } catch {
          // Response body was not JSON
        }
        throw new Error(errorMsg);
      }
      return await response.json();
    } catch (err: any) {
      console.error(`API Request Failed [${endpoint}]:`, err);
      if (err.name === 'TypeError' && (err.message?.includes('fetch') || err.message?.includes('NetworkError'))) {
        throw new Error(`Unable to connect to the PhishGuard AI API at ${API_BASE_URL}. Check that the backend server is running and try again.`);
      }
      throw err;
    }
  }

  async checkHealth(): Promise<{ status: string; database_connected: boolean }> {
    return this.request('/health');
  }

  // --- Authentication Endpoints ---
  async register(data: { email: string; password: string; full_name?: string; role?: string }): Promise<AuthResponse> {
    const res = await this.request<AuthResponse>('/auth/register', {
      method: 'POST',
      body: JSON.stringify(data),
    });
    this.setToken(res.access_token);
    return res;
  }

  async login(data: { email: string; password: string }): Promise<AuthResponse> {
    const res = await this.request<AuthResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify(data),
    });
    this.setToken(res.access_token);
    return res;
  }

  async getMe(): Promise<User> {
    return this.request('/auth/me');
  }

  async updateProfile(data: { full_name?: string; current_password?: string; new_password?: string }): Promise<User> {
    return this.request('/auth/profile', {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  async logout(): Promise<void> {
    try {
      if (this.authToken) {
        await this.request('/auth/logout', { method: 'POST' });
      }
    } finally {
      this.setToken(null);
    }
  }

  // --- Notifications Endpoints ---
  async getNotifications(limit = 30): Promise<AppNotification[]> {
    return this.request(`/notifications?limit=${limit}`);
  }

  async markNotificationRead(id: string): Promise<any> {
    return this.request(`/notifications/${id}/read`, { method: 'PATCH' });
  }

  async markAllNotificationsRead(): Promise<any> {
    return this.request('/notifications/mark-all-read', { method: 'POST' });
  }

  // --- Analytics & Threats Endpoints ---
  async getAnalyticsOverview(): Promise<AnalyticsOverview> {
    return this.request('/analytics/overview');
  }

  async getAnalyticsTrends(days = 7): Promise<DailyTrendItem[]> {
    return this.request(`/analytics/trends?days=${days}`);
  }

  async getThreatIndicators(limit = 15): Promise<ThreatIntelResponse> {
    return this.request(`/threat-intel/indicators?limit=${limit}`);
  }

  async getObservedDomains(limit = 20): Promise<ObservedDomain[]> {
    return this.request(`/threat-intel/domains?limit=${limit}`);
  }

  async getRecentThreats(limit = 10): Promise<RecentThreatItem[]> {
    return this.request(`/threat-intel/recent-threats?limit=${limit}`);
  }

  // --- AI Model Transparency ---
  async getModelTransparency(): Promise<ModelTransparencyResponse> {
    return this.request('/models/transparency');
  }

  // --- Admin Endpoints ---
  async getAdminUsers(): Promise<AdminUserItem[]> {
    return this.request('/admin/users');
  }

  async updateUserStatus(userId: string, isActive: boolean): Promise<any> {
    return this.request(`/admin/users/${userId}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ is_active: isActive }),
    });
  }

  async updateUserRole(userId: string, role: string): Promise<any> {
    return this.request(`/admin/users/${userId}/role`, {
      method: 'PATCH',
      body: JSON.stringify({ role }),
    });
  }

  async getAdminAuditLogs(params: { limit?: number; event_type?: string; user_email?: string } = {}): Promise<AuditLogItem[]> {
    const q = new URLSearchParams();
    if (params.limit) q.append('limit', params.limit.toString());
    if (params.event_type) q.append('event_type', params.event_type);
    if (params.user_email) q.append('user_email', params.user_email);
    return this.request(`/admin/audit-logs?${q.toString()}`);
  }

  async getAdminSystemHealth(): Promise<SystemHealthDeepResponse> {
    return this.request('/admin/system/health');
  }

  // --- Scans & Reports Endpoints ---
  async createScan(url: string): Promise<ScanCreationResponse> {
    return this.request('/scans', {
      method: 'POST',
      body: JSON.stringify({ url }),
    });
  }

  async getScan(scanId: string): Promise<ScanDetail> {
    return this.request(`/scans/${scanId}`);
  }

  async listScans(page = 1, limit = 20, status?: string, verdict?: string, search?: string): Promise<ScanListResponse> {
    const params = new URLSearchParams({
      page: page.toString(),
      limit: limit.toString(),
    });
    if (status) params.append('status', status);
    if (verdict) params.append('verdict', verdict);
    if (search) params.append('search', search);
    return this.request(`/scans?${params.toString()}`);
  }

  async getStats(): Promise<SystemStats> {
    return this.request('/scans/stats');
  }

  getScanPdfUrl(scanId: string): string {
    return `${API_BASE_URL}/scans/${scanId}/report.pdf`;
  }

  getExportCsvUrl(status?: string, verdict?: string): string {
    const q = new URLSearchParams();
    if (status) q.append('status', status);
    if (verdict) q.append('verdict', verdict);
    return `${API_BASE_URL}/scans/export/csv?${q.toString()}`;
  }

  // --- Multi-Modal & Specialized Analysis ---
  async predictUrl(url: string): Promise<MLPrediction> {
    return this.request('/ml/predict', {
      method: 'POST',
      body: JSON.stringify({ url }),
    });
  }

  async getMLModelStatus(): Promise<MLModelStatus> {
    return this.request('/ml/models');
  }

  async analyzeWebsite(url: string): Promise<any> {
    return this.request('/analyze', {
      method: 'POST',
      body: JSON.stringify({ url }),
    });
  }

  async getWebsiteAnalysis(scanId: string): Promise<any> {
    return this.request(`/analyze/${scanId}`);
  }

  async analyzeVisual(url?: string, scanId?: string): Promise<any> {
    return this.request('/visual-analysis', {
      method: 'POST',
      body: JSON.stringify({ url, scan_id: scanId }),
    });
  }

  async getVisualAnalysis(scanId: string): Promise<any> {
    return this.request(`/visual-analysis/${scanId}`);
  }

  async analyzeIntelligence(url: string, includeVisual = true, scanId?: string): Promise<any> {
    return this.request('/intelligence/analyze', {
      method: 'POST',
      body: JSON.stringify({ url, include_visual: includeVisual, scan_id: scanId }),
    });
  }

  async getIntelligence(scanId: string): Promise<any> {
    return this.request(`/intelligence/${scanId}`);
  }

  async compareScans(scanId1: string, scanId2: string): Promise<any> {
    return this.request(`/scans/compare?scan_id_1=${encodeURIComponent(scanId1)}&scan_id_2=${encodeURIComponent(scanId2)}`);
  }
}

export const api = new ApiService();
