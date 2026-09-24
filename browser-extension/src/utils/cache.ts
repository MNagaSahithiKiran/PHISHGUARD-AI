import { CacheEntry, ScanResultData } from '../types/api';

const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

export class ResultCache {
  private inMemoryCache: Map<string, CacheEntry> = new Map();

  private normalizeKey(url: string): string {
    try {
      const u = new URL(url);
      const path = u.pathname.replace(/\/+$/, '') || '/';
      return `${u.hostname}${path}`.toLowerCase();
    } catch {
      return url.replace(/\/+$/, '').toLowerCase();
    }
  }

  get(url: string, ttlMs: number = DEFAULT_CACHE_TTL_MS): ScanResultData | null {
    const key = this.normalizeKey(url);
    const entry = this.inMemoryCache.get(key);
    if (!entry) return null;

    const age = Date.now() - entry.cachedAt;
    if (age > ttlMs) {
      this.inMemoryCache.delete(key);
      return null;
    }
    return entry.result;
  }

  set(url: string, result: ScanResultData): void {
    const key = this.normalizeKey(url);
    this.inMemoryCache.set(key, {
      result,
      cachedAt: Date.now(),
    });
  }

  clear(): void {
    this.inMemoryCache.clear();
  }

  size(): number {
    return this.inMemoryCache.size;
  }
}

export const scanCache = new ResultCache();
