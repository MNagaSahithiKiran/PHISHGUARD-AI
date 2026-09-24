import React, { useEffect, useState } from 'react';
import {
  Shield,
  Server,
  Bell,
  Trash2,
  CheckCircle2,
  RotateCcw,
  Save,
  Lock,
} from 'lucide-react';
import { storage, DEFAULT_SETTINGS } from '../services/storage';
import { scanCache } from '../utils/cache';
import { ExtensionSettings } from '../types/api';

export const Options: React.FC = () => {
  const [settings, setSettings] = useState<ExtensionSettings>(DEFAULT_SETTINGS);
  const [savedFeedback, setSavedFeedback] = useState<boolean>(false);
  const [cacheEntriesCount, setCacheEntriesCount] = useState<number>(0);
  const [testApiStatus, setTestApiStatus] = useState<'idle' | 'testing' | 'success' | 'failed'>('idle');

  useEffect(() => {
    storage.getSettings().then((s) => setSettings(s));
    setCacheEntriesCount(scanCache.size());
  }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    await storage.saveSettings(settings);
    setSavedFeedback(true);
    setTimeout(() => setSavedFeedback(false), 2500);
  };

  const handleReset = async () => {
    await storage.saveSettings(DEFAULT_SETTINGS);
    setSettings(DEFAULT_SETTINGS);
    setSavedFeedback(true);
    setTimeout(() => setSavedFeedback(false), 2500);
  };

  const handleClearCache = () => {
    scanCache.clear();
    setCacheEntriesCount(0);
  };

  const handleTestConnection = async () => {
    setTestApiStatus('testing');
    try {
      const base = settings.apiUrl.replace(/\/api\/v1\/?$/, '');
      const res = await fetch(`${base}/api/v1/health`, { method: 'GET' });
      if (res.ok) {
        setTestApiStatus('success');
      } else {
        setTestApiStatus('failed');
      }
    } catch {
      setTestApiStatus('failed');
    }
    setTimeout(() => setTestApiStatus('idle'), 3000);
  };

  return (
    <div className="min-h-screen bg-cyber-950 text-slate-100 font-sans p-6 md:p-12">
      <div className="max-w-2xl mx-auto space-y-8">
        {/* Header */}
        <div className="flex items-center justify-between pb-6 border-b border-cyber-border">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-white shadow-lg shadow-cyan-500/20">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold font-mono tracking-wider text-white">
                  PHISHGUARD <span className="text-cyan-400">AI</span>
                </h1>
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                  SENTINEL SETTINGS
                </span>
              </div>
              <p className="text-xs text-slate-400">Extension Configuration & Security Policy</p>
            </div>
          </div>

          {savedFeedback && (
            <div className="flex items-center gap-1.5 text-xs font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800 px-3 py-1.5 rounded-lg animate-fade-in">
              <CheckCircle2 className="w-4 h-4" />
              <span>Preferences Saved</span>
            </div>
          )}
        </div>

        <form onSubmit={handleSave} className="space-y-6">
          {/* API Configuration Card */}
          <div className="p-5 rounded-2xl border border-cyber-border bg-cyber-900/60 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-cyan-400" />
                <h2 className="text-sm font-semibold text-white uppercase tracking-wider font-mono">
                  PhishGuard AI Backend
                </h2>
              </div>
              <button
                type="button"
                onClick={handleTestConnection}
                disabled={testApiStatus === 'testing'}
                className="text-xs font-mono px-3 py-1 rounded-lg border border-cyan-500/40 bg-cyan-950/50 hover:bg-cyan-900 text-cyan-300 transition-colors cursor-pointer"
              >
                {testApiStatus === 'testing'
                  ? 'Testing...'
                  : testApiStatus === 'success'
                  ? '✓ Connected'
                  : testApiStatus === 'failed'
                  ? '✕ Connection Failed'
                  : 'Test Endpoint'}
              </button>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-mono text-slate-300 block">
                API Base URL
              </label>
              <input
                type="url"
                value={settings.apiUrl}
                onChange={(e) => setSettings({ ...settings, apiUrl: e.target.value })}
                required
                className="w-full px-3.5 py-2.5 rounded-xl border border-cyber-border bg-cyber-950 font-mono text-xs text-cyan-300 placeholder-slate-600 focus:outline-none focus:border-cyan-400 transition-colors"
                placeholder="http://localhost:8000/api/v1"
              />
              <p className="text-[11px] text-slate-500">
                Directs the browser extension to the multi-modal intelligence endpoint.
              </p>
            </div>
          </div>

          {/* Defensive Preferences Card */}
          <div className="p-5 rounded-2xl border border-cyber-border bg-cyber-900/60 space-y-4">
            <div className="flex items-center gap-2">
              <Bell className="w-4 h-4 text-cyan-400" />
              <h2 className="text-sm font-semibold text-white uppercase tracking-wider font-mono">
                Defensive Notifications & Cache
              </h2>
            </div>

            <div className="space-y-4 text-xs font-mono">
              <label className="flex items-start gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={settings.notificationsEnabled}
                  onChange={(e) =>
                    setSettings({ ...settings, notificationsEnabled: e.target.checked })
                  }
                  className="mt-0.5 rounded border-cyber-border bg-cyber-950 text-cyan-500 focus:ring-0 cursor-pointer"
                />
                <div className="space-y-0.5">
                  <div className="text-slate-200 font-medium">In-Page Warning Banner</div>
                  <div className="text-slate-500 text-[11px]">
                    Display defensive red warning alert banner at the top of tabs classified as PHISHING.
                  </div>
                </div>
              </label>

              <div className="pt-3 border-t border-cyber-border/60 flex items-center justify-between">
                <div>
                  <div className="text-slate-200 font-medium">Scan Cache TTL (Minutes)</div>
                  <div className="text-slate-500 text-[11px]">
                    How long analysis reports remain cached locally (Default: 5 min).
                  </div>
                </div>
                <input
                  type="number"
                  min="1"
                  max="60"
                  value={settings.cacheDurationMinutes}
                  onChange={(e) =>
                    setSettings({
                      ...settings,
                      cacheDurationMinutes: Math.max(1, parseInt(e.target.value) || 5),
                    })
                  }
                  className="w-20 px-2 py-1 rounded-lg border border-cyber-border bg-cyber-950 text-center font-mono text-cyan-300 focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div className="pt-3 border-t border-cyber-border/60 flex items-center justify-between">
                <div>
                  <div className="text-slate-200 font-medium">Local Cache Memory</div>
                  <div className="text-slate-500 text-[11px]">
                    Currently storing {cacheEntriesCount} cached inspection report(s).
                  </div>
                </div>
                <button
                  type="button"
                  onClick={handleClearCache}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-rose-500/30 bg-rose-950/30 text-rose-300 hover:bg-rose-950/60 transition-colors cursor-pointer text-xs"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>Clear Cache</span>
                </button>
              </div>
            </div>
          </div>

          {/* Privacy & Safety Guarantee */}
          <div className="p-5 rounded-2xl border border-cyan-800/40 bg-cyan-950/20 space-y-3">
            <div className="flex items-center gap-2 text-cyan-300">
              <Lock className="w-4 h-4" />
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider">
                Privacy-Preserving Defensive Architecture
              </h3>
            </div>
            <ul className="text-xs font-mono text-slate-400 space-y-1.5 list-disc list-inside">
              <li>No credential scraping: PhishGuard AI never reads password inputs or form fields.</li>
              <li>No keystroke logging: Content scripts never listen to keyboard events.</li>
              <li>No cookie snooping: Extension never queries or transmits user session cookies.</li>
              <li>Targeted inspection: URL inspection only occurs on user demand.</li>
            </ul>
          </div>

          {/* Actions */}
          <div className="flex items-center justify-end gap-3 pt-4">
            <button
              type="button"
              onClick={handleReset}
              className="flex items-center gap-1.5 px-4 py-2 rounded-xl border border-cyber-border bg-cyber-900 hover:bg-cyber-800 text-slate-300 font-mono text-xs cursor-pointer transition-colors"
            >
              <RotateCcw className="w-4 h-4" />
              <span>Reset Defaults</span>
            </button>

            <button
              type="submit"
              className="flex items-center gap-2 px-6 py-2 rounded-xl bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-cyber-950 font-mono font-bold text-xs shadow-lg shadow-cyan-500/20 cursor-pointer transition-all"
            >
              <Save className="w-4 h-4" />
              <span>Save Settings</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
