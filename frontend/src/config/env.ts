/**
 * Centralized Environment Configuration for PhishGuard AI Frontend.
 *
 * All frontend configuration variables and API endpoints are derived here.
 * Public VITE_* variables only. Secrets must NEVER be stored or exposed here.
 */

export const getApiBaseUrl = (): string => {
  // 1. Explicit Vite environment variable: VITE_API_BASE_URL (standard) or VITE_API_URL (legacy)
  const envUrl = (import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL || '').trim();

  if (envUrl) {
    const cleanUrl = envUrl.replace(/\/+$/, '');
    return cleanUrl.endsWith('/api/v1') ? cleanUrl : `${cleanUrl}/api/v1`;
  }

  // 2. In production mode (e.g. deployed on Vercel), NEVER silently fall back to localhost
  if (import.meta.env.PROD) {
    return '';
  }

  // 3. In local development, check window location
  if (typeof window !== 'undefined' && window.location.origin) {
    const port = window.location.port;
    if (port === '5173' || port === '3000') {
      return 'http://localhost:8000/api/v1';
    }
    return `${window.location.origin}/api/v1`;
  }

  return 'http://localhost:8000/api/v1';
};

export const API_BASE_URL = getApiBaseUrl();
export const IS_API_CONFIGURED = Boolean(API_BASE_URL);
export const IS_PRODUCTION = Boolean(import.meta.env.PROD);
export const APP_VERSION = '1.0.0';
