import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  Users,
  FileText,
  Activity,
  CheckCircle,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Search,
  HardDrive,
  Cpu,
} from 'lucide-react';
import { api } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { AdminUserItem, AuditLogItem, SystemHealthDeepResponse } from '../types/scan';

export const AdminDashboard: React.FC = () => {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState<'users' | 'audit' | 'health'>('users');

  // Users State
  const [users, setUsers] = useState<AdminUserItem[]>([]);
  const [loadingUsers, setLoadingUsers] = useState(false);

  // Audit Logs State
  const [auditLogs, setAuditLogs] = useState<AuditLogItem[]>([]);
  const [loadingLogs, setLoadingLogs] = useState(false);
  const [auditFilter, setAuditFilter] = useState('');

  // System Health State
  const [health, setHealth] = useState<SystemHealthDeepResponse | null>(null);
  const [loadingHealth, setLoadingHealth] = useState(false);

  // Error/Success state
  const [msg, setMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const fetchUsers = async () => {
    setLoadingUsers(true);
    try {
      const data = await api.getAdminUsers();
      setUsers(data);
    } catch (err: any) {
      setMsg({ type: 'error', text: err.message || 'Failed to fetch users' });
    } finally {
      setLoadingUsers(false);
    }
  };

  const fetchAuditLogs = async () => {
    setLoadingLogs(true);
    try {
      const data = await api.getAdminAuditLogs({ limit: 50, event_type: auditFilter || undefined });
      setAuditLogs(data);
    } catch (err: any) {
      setMsg({ type: 'error', text: err.message || 'Failed to fetch audit logs' });
    } finally {
      setLoadingLogs(false);
    }
  };

  const fetchHealth = async () => {
    setLoadingHealth(true);
    try {
      const data = await api.getAdminSystemHealth();
      setHealth(data);
    } catch (err: any) {
      setMsg({ type: 'error', text: err.message || 'Failed to fetch system diagnostics' });
    } finally {
      setLoadingHealth(false);
    }
  };

  useEffect(() => {
    if (activeTab === 'users') fetchUsers();
    if (activeTab === 'audit') fetchAuditLogs();
    if (activeTab === 'health') fetchHealth();
  }, [activeTab]);

  const handleToggleStatus = async (targetUser: AdminUserItem) => {
    try {
      await api.updateUserStatus(targetUser.id, !targetUser.is_active);
      setMsg({ type: 'success', text: `Updated status for ${targetUser.email}` });
      fetchUsers();
    } catch (err: any) {
      setMsg({ type: 'error', text: err.message });
    }
  };

  const handleToggleRole = async (targetUser: AdminUserItem) => {
    const newRole = targetUser.role === 'admin' ? 'user' : 'admin';
    try {
      await api.updateUserRole(targetUser.id, newRole);
      setMsg({ type: 'success', text: `Updated role for ${targetUser.email} to ${newRole}` });
      fetchUsers();
    } catch (err: any) {
      setMsg({ type: 'error', text: err.message });
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950/80 text-rose-300 border border-rose-800/60 uppercase">
              Root Authority
            </span>
            <span className="text-xs text-slate-400 font-mono">SOC Governance &amp; Audit Engine</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white font-mono flex items-center gap-3">
            <ShieldAlert className="w-6 h-6 text-rose-400" />
            ADMINISTRATION &amp; SECURITY PORTAL
          </h1>
          <p className="text-xs text-slate-400 max-w-2xl">
            Manage authorized SOC analysts, inspect tamper-resistant audit trails, and monitor deep system diagnostics.
          </p>
        </div>
      </div>

      {msg && (
        <div
          className={`p-3.5 rounded-xl border text-xs flex items-center justify-between ${
            msg.type === 'success'
              ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-300'
              : 'bg-rose-950/40 border-rose-500/30 text-rose-300'
          }`}
        >
          <span>{msg.text}</span>
          <button onClick={() => setMsg(null)} className="text-slate-400 hover:text-white text-xs">
            Dismiss
          </button>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-cyber-border pb-3">
        <button
          onClick={() => setActiveTab('users')}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-mono font-semibold transition-all cursor-pointer ${
            activeTab === 'users'
              ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-cyber-800/50 border border-transparent'
          }`}
        >
          <Users className="w-4 h-4" />
          <span>User Accounts ({users.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('audit')}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-mono font-semibold transition-all cursor-pointer ${
            activeTab === 'audit'
              ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-cyber-800/50 border border-transparent'
          }`}
        >
          <FileText className="w-4 h-4" />
          <span>Security Audit Logs</span>
        </button>

        <button
          onClick={() => setActiveTab('health')}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-mono font-semibold transition-all cursor-pointer ${
            activeTab === 'health'
              ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-cyber-800/50 border border-transparent'
          }`}
        >
          <Activity className="w-4 h-4" />
          <span>Deep Diagnostics &amp; Health</span>
        </button>
      </div>

      {/* Tab 1: Users */}
      {activeTab === 'users' && (
        <div className="glass-panel rounded-2xl border border-cyber-border overflow-hidden bg-cyber-900/60 shadow-xl">
          <div className="p-4 border-b border-cyber-border flex items-center justify-between">
            <span className="text-xs font-mono font-bold text-slate-300 uppercase">Registered Analysts</span>
            <button
              onClick={fetchUsers}
              disabled={loadingUsers}
              className="p-1.5 rounded-lg border border-cyber-border hover:bg-cyber-800 text-slate-400 hover:text-slate-200 transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingUsers ? 'animate-spin' : ''}`} />
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-cyber-border bg-cyber-950/60 text-[11px] font-mono uppercase text-slate-400">
                  <th className="py-3 px-4">User / Email</th>
                  <th className="py-3 px-4">Role</th>
                  <th className="py-3 px-4">Account Status</th>
                  <th className="py-3 px-4">Scans Run</th>
                  <th className="py-3 px-4">Created</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border/40 text-xs">
                {users.map((u) => {
                  const isCurrent = u.id === user?.id;
                  return (
                    <tr key={u.id} className="hover:bg-cyber-800/30 transition-colors">
                      <td className="py-3 px-4">
                        <div className="font-semibold text-slate-100">{u.full_name || 'Unnamed Analyst'}</div>
                        <div className="text-[11px] text-slate-400 font-mono">{u.email}</div>
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                            u.role === 'admin'
                              ? 'bg-rose-950/80 text-rose-300 border border-rose-800/60'
                              : 'bg-cyan-950/80 text-cyan-300 border border-cyan-800/60'
                          }`}
                        >
                          {u.role}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        {u.is_active ? (
                          <span className="inline-flex items-center gap-1.5 text-emerald-400 font-mono text-[11px]">
                            <CheckCircle className="w-3.5 h-3.5" /> Active
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 text-rose-400 font-mono text-[11px]">
                            <XCircle className="w-3.5 h-3.5" /> Deactivated
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 font-mono text-cyan-400 font-bold">{u.scan_count}</td>
                      <td className="py-3 px-4 text-slate-400 text-[11px] font-mono">
                        {new Date(u.created_at).toLocaleDateString()}
                      </td>
                      <td className="py-3 px-4 text-right space-x-2">
                        {!isCurrent && (
                          <>
                            <button
                              onClick={() => handleToggleRole(u)}
                              className="px-2 py-1 rounded text-[10px] font-mono border border-cyber-border hover:bg-cyber-800 text-slate-300 transition-colors cursor-pointer"
                            >
                              {u.role === 'admin' ? 'Demote to User' : 'Promote to Admin'}
                            </button>
                            <button
                              onClick={() => handleToggleStatus(u)}
                              className={`px-2 py-1 rounded text-[10px] font-mono border transition-colors cursor-pointer ${
                                u.is_active
                                  ? 'border-rose-500/40 text-rose-400 hover:bg-rose-950/40'
                                  : 'border-emerald-500/40 text-emerald-400 hover:bg-emerald-950/40'
                              }`}
                            >
                              {u.is_active ? 'Deactivate' : 'Activate'}
                            </button>
                          </>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 2: Audit Logs */}
      {activeTab === 'audit' && (
        <div className="glass-panel rounded-2xl border border-cyber-border overflow-hidden bg-cyber-900/60 shadow-xl space-y-4 p-4">
          <div className="flex items-center justify-between gap-4">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
              <input
                type="text"
                placeholder="Filter by event type (e.g. USER_LOGIN, SCAN_INITIATED)..."
                value={auditFilter}
                onChange={(e) => setAuditFilter(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && fetchAuditLogs()}
                className="w-full pl-9 pr-4 py-2 rounded-xl border border-cyber-border bg-cyber-950/70 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
              />
            </div>
            <button
              onClick={fetchAuditLogs}
              disabled={loadingLogs}
              className="px-3 py-2 rounded-xl border border-cyber-border hover:bg-cyber-800 text-slate-300 text-xs font-mono flex items-center gap-1.5 transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingLogs ? 'animate-spin' : ''}`} />
              <span>Refresh Trail</span>
            </button>
          </div>

          <div className="overflow-x-auto border border-cyber-border rounded-xl">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-cyber-border bg-cyber-950/80 text-[10px] font-mono uppercase text-slate-400">
                  <th className="py-2.5 px-3">Timestamp</th>
                  <th className="py-2.5 px-3">Event Type</th>
                  <th className="py-2.5 px-3">User</th>
                  <th className="py-2.5 px-3">Action Details</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">IP Address</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border/40 text-xs">
                {auditLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-cyber-800/30 transition-colors">
                    <td className="py-2.5 px-3 text-[11px] font-mono text-slate-400 whitespace-nowrap">
                      {new Date(log.created_at).toLocaleString()}
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyber-950 border border-cyber-border text-cyan-300">
                        {log.event_type}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-slate-300">
                      {log.user_email || 'Anonymous / System'}
                    </td>
                    <td className="py-2.5 px-3 text-slate-300 font-mono text-[11px] max-w-xs truncate">
                      {log.action} {log.details ? `— ${log.details}` : ''}
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`text-[10px] font-mono font-bold uppercase ${
                          log.status === 'success' ? 'text-emerald-400' : 'text-rose-400'
                        }`}
                      >
                        {log.status}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-[11px] font-mono text-slate-500">{log.client_ip || 'Loopback'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 3: System Health */}
      {activeTab === 'health' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-5 rounded-2xl border border-cyber-border bg-cyber-900/60 glass-panel">
              <div className="text-[11px] font-mono uppercase text-slate-400 mb-1">Database Latency</div>
              <div className="text-2xl font-bold font-mono text-cyan-400">
                {health?.db_latency_ms !== undefined ? `${health.db_latency_ms} ms` : 'Testing...'}
              </div>
              <div className="text-xs text-slate-500 mt-1">SQLite / aiosqlite Async Connection</div>
            </div>

            <div className="p-5 rounded-2xl border border-cyber-border bg-cyber-900/60 glass-panel">
              <div className="text-[11px] font-mono uppercase text-slate-400 mb-1">Screenshot Storage</div>
              <div className="text-2xl font-bold font-mono text-emerald-400 flex items-center gap-2">
                <HardDrive className="w-5 h-5" />
                {health?.storage_writable ? 'Writable' : 'Read-Only / Error'}
              </div>
              <div className="text-xs text-slate-500 mt-1">Local Sandboxed Storage Ready</div>
            </div>

            <div className="p-5 rounded-2xl border border-cyber-border bg-cyber-900/60 glass-panel">
              <div className="text-[11px] font-mono uppercase text-slate-400 mb-1">Python Environment</div>
              <div className="text-2xl font-bold font-mono text-slate-200">{health?.python_version || '3.13'}</div>
              <div className="text-xs text-slate-500 mt-1">FastAPI + PyTorch + ReportLab Active</div>
            </div>
          </div>

          {/* Model File Verification */}
          <div className="glass-panel rounded-2xl border border-cyber-border p-6 bg-cyber-900/60 shadow-xl space-y-4">
            <h3 className="text-sm font-mono font-bold text-slate-200 uppercase flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              AI Model Artifact Verification
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {health?.models_status.map((m, idx) => (
                <div key={idx} className="p-4 rounded-xl border border-cyber-border bg-cyber-950/60 flex items-center justify-between">
                  <div>
                    <div className="text-xs font-semibold text-slate-100 font-mono">{m.model_name}</div>
                    <div className="text-[11px] text-slate-400 font-mono truncate max-w-xs">{m.file_path}</div>
                  </div>
                  <div className="text-right">
                    {m.exists ? (
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950/80 text-emerald-400 border border-emerald-800/60">
                        {(m.size_bytes / 1024).toFixed(0)} KB
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950/80 text-rose-400 border border-rose-800/60">
                        Missing
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
