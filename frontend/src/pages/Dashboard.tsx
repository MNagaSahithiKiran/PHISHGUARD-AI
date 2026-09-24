import React, { useEffect, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Globe2,
  Clock,
  ArrowRight,
  TrendingUp,
  Cpu,
  FileDown,
  Activity,
  Layers,
} from 'lucide-react';
import { api } from '../services/api';
import { AnalyticsOverview, ScanSummaryItem } from '../types/scan';
import { StatCard } from '../components/common/StatCard';
import { VerdictBadge } from '../components/common/VerdictBadge';
import { EmptyState } from '../components/common/EmptyState';
import {
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
} from 'recharts';

export const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const [analytics, setAnalytics] = useState<AnalyticsOverview | null>(null);
  const [recentScans, setRecentScans] = useState<ScanSummaryItem[]>([]);
  const [loading, setLoading] = useState(true);

  // Quick scan state
  const [quickUrl, setQuickUrl] = useState('');
  const [scanning, setScanning] = useState(false);

  useEffect(() => {
    async function loadDashboardData() {
      try {
        const [analyticsData, scansData] = await Promise.all([
          api.getAnalyticsOverview(),
          api.listScans(1, 6),
        ]);
        setAnalytics(analyticsData);
        setRecentScans(scansData.items);
      } catch (err) {
        console.error('Failed to load dashboard data:', err);
      } finally {
        setLoading(false);
      }
    }
    loadDashboardData();
  }, []);

  const handleQuickScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!quickUrl.trim()) return;
    setScanning(true);
    try {
      const res = await api.analyzeIntelligence(quickUrl.trim(), true);
      navigate(`/scans/${res.scan_id}`);
    } catch {
      // Fallback to standard scanner
      navigate(`/scanner?url=${encodeURIComponent(quickUrl.trim())}`);
    } finally {
      setScanning(false);
    }
  };

  const hasScans = analytics && analytics.total_scans > 0;

  const distributionData = [
    { name: 'Phishing', count: analytics?.phishing_scans || 0, color: '#f43f5e' },
    { name: 'Suspicious', count: analytics?.suspicious_scans || 0, color: '#f59e0b' },
    { name: 'Legitimate', count: analytics?.legitimate_scans || 0, color: '#10b981' },
    { name: 'Unrated', count: analytics?.unrated_scans || 0, color: '#64748b' },
  ].filter((item) => item.count > 0);

  const riskHistogram = analytics?.risk_distribution || [];

  return (
    <div className="space-y-8">
      {/* Top Banner & Quick Scan */}
      <div className="glass-panel rounded-2xl p-6 border-cyan-500/30 relative overflow-hidden bg-cyber-900/80 shadow-2xl">
        <div className="absolute right-0 top-0 bottom-0 w-96 bg-gradient-to-l from-cyan-500/10 to-transparent pointer-events-none" />
        <div className="relative z-10 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-md bg-cyan-950/80 border border-cyan-800/80 text-cyan-300 text-xs font-mono">
              <Cpu className="w-3.5 h-3.5" />
              MULTI-MODAL CYBERSECURITY PLATFORM
            </div>
            <h1 className="text-2xl md:text-3xl font-extrabold text-white tracking-tight font-mono">
              SOC THREAT MONITOR &amp; INTELLIGENCE
            </h1>
            <p className="text-xs text-slate-400 max-w-2xl leading-relaxed">
              Synthesizing URL lexical intelligence, DOM security telemetry, and computer vision screenshot analysis
              into empirical, calibrated cybersecurity assessments.
            </p>
          </div>

          {/* Quick Scanner Box */}
          <form onSubmit={handleQuickScan} className="flex-1 max-w-md w-full">
            <div className="p-2 rounded-xl bg-cyber-950/80 border border-cyber-border focus-within:border-cyan-500 transition-colors shadow-inner flex items-center gap-2">
              <input
                type="text"
                placeholder="Enter suspicious URL for instant triage..."
                value={quickUrl}
                onChange={(e) => setQuickUrl(e.target.value)}
                className="flex-1 bg-transparent px-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none font-mono"
              />
              <button
                type="submit"
                disabled={scanning}
                className="px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-mono text-xs font-semibold shadow-md shadow-cyan-950 transition-all shrink-0 cursor-pointer disabled:opacity-50"
              >
                {scanning ? 'Analyzing...' : 'Scan Now'}
              </button>
            </div>
          </form>
        </div>
      </div>

      {/* Primary SOC Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Total Scans Ingested"
          value={analytics ? analytics.total_scans : 0}
          icon={Globe2}
          colorScheme="cyan"
          subtext={`Today: ${analytics?.scans_today || 0} | 7d: ${analytics?.scans_last_7_days || 0}`}
        />
        <StatCard
          label="Confirmed Phishing"
          value={analytics ? analytics.phishing_scans : 0}
          icon={ShieldAlert}
          colorScheme="rose"
          subtext={`Threat rate: ${analytics?.detection_rate_pct || 0}%`}
        />
        <StatCard
          label="Suspicious Sites"
          value={analytics ? analytics.suspicious_scans : 0}
          icon={AlertTriangle}
          colorScheme="amber"
          subtext="Elevated risk markers"
        />
        <StatCard
          label="Average Risk Score"
          value={analytics ? `${analytics.average_risk_score} / 100` : '0.0'}
          icon={Activity}
          colorScheme="emerald"
          subtext="Calibrated risk index"
        />
      </div>

      {/* Main Grid: Recent Scans & Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Scans Table */}
        <div className="lg:col-span-2 glass-panel rounded-xl p-5 border-cyber-border bg-cyber-900/60 shadow-xl space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-bold text-white font-mono">Recent Cyber Threat Ingestion</h2>
              <p className="text-xs text-slate-400">Live feed of targets analyzed by PhishGuard</p>
            </div>
            {hasScans && (
              <div className="flex items-center gap-3">
                <a
                  href={api.getExportCsvUrl()}
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs text-slate-400 hover:text-cyan-400 font-mono flex items-center gap-1 transition-colors"
                >
                  <FileDown className="w-3.5 h-3.5" /> Export CSV
                </a>
                <button
                  onClick={() => navigate('/history')}
                  className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono"
                >
                  View all <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>

          {!hasScans ? (
            <EmptyState
              title="No Scans Recorded Yet"
              description="Submit a website URL to begin automated multi-modal analysis, SSRF checks, and threat evaluation."
              actionLabel="Scan Target Website"
              onAction={() => navigate('/scanner')}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-cyber-border text-slate-400 font-mono text-[11px]">
                    <th className="pb-3 font-semibold">TARGET DOMAIN</th>
                    <th className="pb-3 font-semibold">STATUS</th>
                    <th className="pb-3 font-semibold">VERDICT</th>
                    <th className="pb-3 font-semibold">RISK</th>
                    <th className="pb-3 font-semibold text-right">ACTIONS</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cyber-border/40 font-mono">
                  {recentScans.map((scan) => (
                    <tr key={scan.id} className="hover:bg-cyber-800/40 transition-colors">
                      <td className="py-3 font-medium text-slate-200 max-w-[200px] truncate">
                        {scan.domain}
                      </td>
                      <td className="py-3">
                        <span className="text-cyan-300 uppercase text-[11px]">{scan.status}</span>
                      </td>
                      <td className="py-3">
                        <VerdictBadge verdict={scan.verdict} size="sm" />
                      </td>
                      <td className="py-3 font-bold">
                        {scan.risk_score !== null ? (
                          <span
                            className={
                              scan.risk_score > 66
                                ? 'text-rose-400'
                                : scan.risk_score > 25
                                ? 'text-amber-400'
                                : 'text-emerald-400'
                            }
                          >
                            {scan.risk_score.toFixed(1)}
                          </span>
                        ) : (
                          <span className="text-slate-500">—</span>
                        )}
                      </td>
                      <td className="py-3 text-right space-x-2">
                        <a
                          href={api.getScanPdfUrl(scan.id)}
                          target="_blank"
                          rel="noreferrer"
                          title="Download Official PDF Report"
                          className="p-1.5 rounded inline-block bg-cyber-800 hover:bg-cyber-700 text-slate-300 hover:text-cyan-300 text-xs transition-colors"
                        >
                          <FileDown className="w-3.5 h-3.5" />
                        </a>
                        <button
                          onClick={() => navigate(`/scans/${scan.id}`)}
                          className="px-2.5 py-1 rounded bg-cyan-950 border border-cyan-800 hover:bg-cyan-900 text-cyan-300 text-xs transition-colors cursor-pointer"
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Threat Distribution & Risk Buckets */}
        <div className="space-y-6">
          {/* Pie Chart Card */}
          <div className="glass-panel rounded-xl p-5 border-cyber-border bg-cyber-900/60 shadow-xl space-y-4">
            <div>
              <h2 className="text-sm font-bold text-white font-mono">Threat Verdict Distribution</h2>
              <p className="text-[11px] text-slate-400">Classification proportions in database</p>
            </div>

            {!hasScans || distributionData.length === 0 ? (
              <div className="py-8 text-center text-xs text-slate-500 font-mono">
                Charts populate automatically upon scan creation.
              </div>
            ) : (
              <div className="h-44 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={distributionData}
                      cx="50%"
                      cy="50%"
                      innerRadius={45}
                      outerRadius={68}
                      paddingAngle={4}
                      dataKey="count"
                    >
                      {distributionData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0c1222',
                        borderColor: '#1f2e4d',
                        borderRadius: '8px',
                        color: '#fff',
                        fontSize: '11px',
                        fontFamily: 'monospace',
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
                <div className="flex flex-wrap justify-center gap-3 mt-1 text-[11px] font-mono text-slate-400">
                  {distributionData.map((item) => (
                    <div key={item.name} className="flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
                      <span>{item.name}: {item.count}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Risk Score Histogram Card */}
          <div className="glass-panel rounded-xl p-5 border-cyber-border bg-cyber-900/60 shadow-xl space-y-3">
            <div>
              <h2 className="text-sm font-bold text-white font-mono">Calibrated Risk Score Bins</h2>
              <p className="text-[11px] text-slate-400">Risk index histogram across all evaluations</p>
            </div>

            <div className="h-28 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={riskHistogram} margin={{ top: 5, right: 5, left: -25, bottom: 0 }}>
                  <XAxis dataKey="range" stroke="#64748b" fontSize={9} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={9} tickLine={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0c1222',
                      borderColor: '#1f2e4d',
                      borderRadius: '8px',
                      color: '#fff',
                      fontSize: '11px',
                      fontFamily: 'monospace',
                    }}
                  />
                  <Bar dataKey="count" fill="#06b6d4" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
