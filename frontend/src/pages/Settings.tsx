import React, { useState } from 'react';
import { Settings as SettingsIcon, ShieldCheck, Server, Lock, Save, User as UserIcon, AlertTriangle } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { api } from '../services/api';

export const Settings: React.FC = () => {
  const { user, isAuthenticated, refreshUser } = useAuth();

  const [fullName, setFullName] = useState(user?.full_name || '');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [profileMsg, setProfileMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const [apiUrl, setApiUrl] = useState(api.getBaseUrl() || 'API CONFIGURATION REQUIRED');
  const [ssrfEnforced, setSsrfEnforced] = useState(true);
  const [sandboxedWorkers, setSandboxedWorkers] = useState(true);
  const [policySaved, setPolicySaved] = useState(false);

  const handleUpdateProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    setProfileMsg(null);
    try {
      await api.updateProfile({
        full_name: fullName || undefined,
        current_password: currentPassword || undefined,
        new_password: newPassword || undefined,
      });
      setProfileMsg({ type: 'success', text: 'Analyst profile successfully updated.' });
      setCurrentPassword('');
      setNewPassword('');
      refreshUser();
    } catch (err: any) {
      setProfileMsg({ type: 'error', text: err.message || 'Failed to update profile' });
    }
  };

  const handleSavePolicies = (e: React.FormEvent) => {
    e.preventDefault();
    setPolicySaved(true);
    setTimeout(() => setPolicySaved(false), 3000);
  };

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      <div>
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-md bg-cyan-950/80 border border-cyan-800/80 text-cyan-300 text-xs font-mono mb-2">
          <SettingsIcon className="w-3.5 h-3.5 text-cyan-400" />
          SYSTEM CONFIGURATION &amp; CREDENTIALS
        </div>
        <h1 className="text-2xl font-bold text-white tracking-tight font-mono">
          PLATFORM SETTINGS &amp; POLICIES
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Configure analyst profile credentials, API gateway routing, and SSRF defensive barriers.
        </p>
      </div>

      {/* User Profile Section (if authenticated) */}
      {isAuthenticated && (
        <form onSubmit={handleUpdateProfile} className="glass-panel p-6 rounded-2xl border border-cyber-border space-y-4 bg-cyber-900/60 shadow-xl">
          <div className="flex items-center gap-2 text-sm font-bold text-white font-mono">
            <UserIcon className="w-4 h-4 text-cyan-400" />
            <span>SOC Analyst Profile &amp; Credentials</span>
          </div>

          {profileMsg && (
            <div
              className={`p-3 rounded-xl border text-xs flex items-center gap-2 ${
                profileMsg.type === 'success'
                  ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-300'
                  : 'bg-rose-950/40 border-rose-500/30 text-rose-300'
              }`}
            >
              {profileMsg.type === 'success' ? <ShieldCheck className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
              <span>{profileMsg.text}</span>
            </div>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1">
                ANALYZER HANDLE / NAME
              </label>
              <input
                type="text"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                placeholder="Analyst Name"
                className="w-full px-3.5 py-2 rounded-xl bg-cyber-950/80 border border-cyber-border font-mono text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1">
                REGISTERED EMAIL (READ-ONLY)
              </label>
              <input
                type="text"
                disabled
                value={user?.email || ''}
                className="w-full px-3.5 py-2 rounded-xl bg-cyber-950/40 border border-cyber-border/40 font-mono text-xs text-slate-500 cursor-not-allowed"
              />
            </div>

            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1">
                CURRENT PASSWORD
              </label>
              <input
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                placeholder="Required for password change"
                className="w-full px-3.5 py-2 rounded-xl bg-cyber-950/80 border border-cyber-border font-mono text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1">
                NEW PASSWORD (MIN 8 CHARS)
              </label>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="Leave blank to keep current"
                className="w-full px-3.5 py-2 rounded-xl bg-cyber-950/80 border border-cyber-border font-mono text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
              />
            </div>
          </div>

          <div className="flex justify-end pt-2">
            <button
              type="submit"
              className="px-4 py-2 rounded-xl bg-cyan-950 border border-cyan-800 hover:bg-cyan-900 text-cyan-300 font-mono text-xs font-semibold transition-colors cursor-pointer"
            >
              Update Credentials
            </button>
          </div>
        </form>
      )}

      {/* Security Policies Form */}
      <form onSubmit={handleSavePolicies} className="space-y-6">
        {/* API Connection Card */}
        <div className="glass-panel p-6 rounded-2xl border border-cyber-border space-y-4 bg-cyber-900/60 shadow-xl">
          <div className="flex items-center gap-2 text-sm font-bold text-white font-mono">
            <Server className="w-4 h-4 text-cyan-400" />
            <span>API Gateway Connection</span>
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-300 mb-1">
              BACKEND ENDPOINT URL
            </label>
            <input
              type="text"
              value={apiUrl}
              onChange={(e) => setApiUrl(e.target.value)}
              className="w-full px-4 py-2.5 rounded-xl bg-cyber-950/80 border border-cyber-border font-mono text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
            />
            <p className="text-[11px] text-slate-500 mt-1 font-mono">
              Active FastAPI service endpoint handling intake, multi-modal pipelines, and database queries.
            </p>
          </div>
        </div>

        {/* Security Policies Card */}
        <div className="glass-panel p-6 rounded-2xl border border-cyber-border space-y-4 bg-cyber-900/60 shadow-xl">
          <div className="flex items-center gap-2 text-sm font-bold text-white font-mono">
            <Lock className="w-4 h-4 text-cyan-400" />
            <span>Defensive Ingestion Policies</span>
          </div>

          <div className="space-y-3 font-mono">
            <div className="flex items-center justify-between p-3.5 rounded-xl bg-cyber-950/60 border border-cyber-border">
              <div>
                <span className="text-xs font-bold text-slate-200 block">Enforce SSRF &amp; Private IP Blocking</span>
                <span className="text-[11px] text-slate-400">
                  Strictly rejects loopback (127.0.0.1), RFC 1918 subnets, and cloud metadata.
                </span>
              </div>
              <input
                type="checkbox"
                checked={ssrfEnforced}
                onChange={(e) => setSsrfEnforced(e.target.checked)}
                className="w-4 h-4 accent-cyan-500 rounded"
              />
            </div>

            <div className="flex items-center justify-between p-3.5 rounded-xl bg-cyber-950/60 border border-cyber-border">
              <div>
                <span className="text-xs font-bold text-slate-200 block">Isolated Browser Sandboxing</span>
                <span className="text-[11px] text-slate-400">
                  Executes webpage rendering and headless DOM capture in quarantined containers.
                </span>
              </div>
              <input
                type="checkbox"
                checked={sandboxedWorkers}
                onChange={(e) => setSandboxedWorkers(e.target.checked)}
                className="w-4 h-4 accent-cyan-500 rounded"
              />
            </div>
          </div>
        </div>

        <div className="flex items-center justify-between pt-2">
          {policySaved ? (
            <span className="text-xs font-mono text-emerald-400 flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4" />
              Configuration settings saved successfully.
            </span>
          ) : (
            <div />
          )}

          <button
            type="submit"
            className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-mono font-semibold text-xs flex items-center gap-2 shadow-md transition-all cursor-pointer"
          >
            <Save className="w-4 h-4" />
            <span>Save Policies</span>
          </button>
        </div>
      </form>
    </div>
  );
};
