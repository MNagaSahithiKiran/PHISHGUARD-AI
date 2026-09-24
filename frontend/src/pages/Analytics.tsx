import React, { useEffect, useState } from 'react';
import { BarChart3, PieChart as PieChartIcon, Cpu, Table, CheckCircle2, TrendingUp } from 'lucide-react';
import { api } from '../services/api';
import { SystemStats, MLModelStatus, DailyTrendItem } from '../types/scan';
import { EmptyState } from '../components/common/EmptyState';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
  AreaChart,
  Area,
} from 'recharts';

export const Analytics: React.FC = () => {
  const [stats, setStats] = useState<SystemStats | null>(null);
  const [modelStatus, setModelStatus] = useState<MLModelStatus | null>(null);
  const [trends, setTrends] = useState<DailyTrendItem[]>([]);

  useEffect(() => {
    api.getStats()
      .then((data) => setStats(data))
      .catch((err) => console.error('Failed to load stats for analytics:', err));

    api.getMLModelStatus()
      .then((status) => setModelStatus(status))
      .catch((err) => console.log('ML model status fetch:', err.message));

    api.getAnalyticsTrends(7)
      .then((t) => setTrends(t))
      .catch((err) => console.log('Trends fetch:', err.message));
  }, []);

  const hasData = stats && stats.total_scans > 0;

  const barData = [
    { category: 'Phishing', count: stats?.phishing_detected || 0, fill: '#f43f5e' },
    { category: 'Suspicious', count: stats?.suspicious_sites || 0, fill: '#f59e0b' },
    { category: 'Legitimate', count: stats?.legitimate_sites || 0, fill: '#10b981' },
    { category: 'Queued', count: stats?.queued_scans || 0, fill: '#06b6d4' },
  ];

  const pieData = [
    { name: 'Phishing', value: stats?.phishing_detected || 0, color: '#f43f5e' },
    { name: 'Suspicious', value: stats?.suspicious_sites || 0, color: '#f59e0b' },
    { name: 'Legitimate', value: stats?.legitimate_sites || 0, color: '#10b981' },
    { name: 'Queued', value: stats?.queued_scans || 0, color: '#06b6d4' },
  ].filter((d) => d.value > 0);

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-md bg-cyan-950/80 border border-cyan-800/80 text-cyan-300 text-xs font-mono mb-2">
          <BarChart3 className="w-3.5 h-3.5 text-cyan-400" />
          SYSTEM TELEMETRY &amp; ML BENCHMARKS
        </div>
        <h1 className="text-2xl font-bold text-white tracking-tight font-mono">
          CYBERSECURITY ANALYTICS &amp; TEST BENCHMARKS
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Empirical distribution of inspected target websites and verifiable ML test set performance
        </p>
      </div>

      {/* Model Benchmark Comparison Table (Real Empirical Results) */}
      {modelStatus && modelStatus.benchmarks && modelStatus.benchmarks.length > 0 && (
        <div className="glass-panel p-6 rounded-2xl border-cyan-500/30 space-y-4 bg-cyber-900/60 shadow-xl">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-cyber-border pb-3">
            <div className="flex items-center gap-2">
              <Table className="w-5 h-5 text-cyan-400" />
              <h2 className="text-base font-bold text-white font-mono">
                Empirical Test Set Evaluation Benchmarks (1,500 Holdout Samples)
              </h2>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-slate-400">Deployment Model:</span>
              <span className="text-xs font-mono font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3" />
                {modelStatus.selected_model}
              </span>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-cyber-border text-slate-400 text-[11px] uppercase">
                  <th className="py-2.5 px-3">Model</th>
                  <th className="py-2.5 px-3">Accuracy</th>
                  <th className="py-2.5 px-3">Precision</th>
                  <th className="py-2.5 px-3">Recall</th>
                  <th className="py-2.5 px-3">F1-Score</th>
                  <th className="py-2.5 px-3">ROC-AUC</th>
                  <th className="py-2.5 px-3">FPR</th>
                  <th className="py-2.5 px-3">FNR</th>
                  <th className="py-2.5 px-3">Latency</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border/40">
                {modelStatus.benchmarks.map((b) => (
                  <tr
                    key={b.model}
                    className={`hover:bg-cyber-800/40 transition-colors ${
                      b.model === modelStatus.selected_model ? 'bg-cyan-500/5 text-cyan-300 font-semibold' : 'text-slate-200'
                    }`}
                  >
                    <td className="py-2.5 px-3 flex items-center gap-1.5">
                      {b.model === modelStatus.selected_model && <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />}
                      <span>{b.model}</span>
                    </td>
                    <td className="py-2.5 px-3">{b.accuracy}</td>
                    <td className="py-2.5 px-3">{b.precision}</td>
                    <td className="py-2.5 px-3">{b.recall}</td>
                    <td className="py-2.5 px-3 font-bold">{b.f1}</td>
                    <td className="py-2.5 px-3">{b.roc_auc ?? 'N/A'}</td>
                    <td className="py-2.5 px-3 text-slate-400">{b.false_positive_rate}</td>
                    <td className="py-2.5 px-3 text-slate-400">{b.false_negative_rate}</td>
                    <td className="py-2.5 px-3 text-slate-400">{b.inference_time_ms} ms</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="p-3 bg-cyber-950/70 rounded-lg border border-cyber-border text-xs text-slate-300 font-mono">
            <span className="text-cyan-400 font-bold">Selection Rationale: </span>
            {modelStatus.selection_rationale}
          </div>
        </div>
      )}

      {/* Temporal Trends Area Chart */}
      {trends.length > 0 && (
        <div className="glass-panel p-6 rounded-2xl border-cyber-border bg-cyber-900/60 shadow-xl space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-cyan-400" />
              <span>7-Day Scan Ingestion Trend</span>
            </h2>
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trends}>
                <XAxis dataKey="date" stroke="#64748b" fontSize={10} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={10} tickLine={false} allowDecimals={false} />
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
                <Area type="monotone" dataKey="total" stroke="#06b6d4" fill="#06b6d4" fillOpacity={0.2} name="Total Scans" />
                <Area type="monotone" dataKey="phishing" stroke="#f43f5e" fill="#f43f5e" fillOpacity={0.4} name="Phishing Threat" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {!hasData ? (
        <EmptyState
          icon={BarChart3}
          title="No Ingestion Telemetry Data Available"
          description="Analytics charts will populate dynamically once websites have been submitted for evaluation."
        />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Verdict Distribution Bar Chart */}
          <div className="glass-panel p-6 rounded-2xl border-cyber-border space-y-4 bg-cyber-900/60 shadow-xl">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-cyan-400" />
                <span>Detection Classification Breakdown</span>
              </h2>
            </div>
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={barData}>
                  <XAxis dataKey="category" stroke="#64748b" fontSize={11} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={11} tickLine={false} allowDecimals={false} />
                  <Tooltip
                    cursor={{ fill: 'rgba(255, 255, 255, 0.05)' }}
                    contentStyle={{
                      backgroundColor: '#0c1222',
                      borderColor: '#1f2e4d',
                      borderRadius: '8px',
                      color: '#fff',
                      fontSize: '12px',
                    }}
                  />
                  <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                    {barData.map((entry, index) => (
                      <Cell key={`bar-${index}`} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Proportions Pie Chart */}
          <div className="glass-panel p-6 rounded-2xl border-cyber-border space-y-4 bg-cyber-900/60 shadow-xl">
            <h2 className="text-sm font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
              <PieChartIcon className="w-4 h-4 text-cyan-400" />
              <span>Verdict Proportions</span>
            </h2>
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    dataKey="value"
                    label={({ name, percent }) => `${name} ${(((percent ?? 0) * 100)).toFixed(0)}%`}
                    labelLine={false}
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`pie-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0c1222',
                      borderColor: '#1f2e4d',
                      borderRadius: '8px',
                      color: '#fff',
                      fontSize: '12px',
                    }}
                  />
                  <Legend wrapperStyle={{ fontSize: '11px', color: '#94a3b8' }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {/* Model Benchmark / Production Notice */}
      <div className="glass-panel p-5 rounded-xl border-cyber-border space-y-2 bg-cyber-900/60">
        <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs font-semibold">
          <Cpu className="w-4 h-4" />
          <span>PRODUCTION VALIDATION &amp; BENCHMARKING METHODOLOGY</span>
        </div>
        <p className="text-xs text-slate-400 leading-relaxed">
          Model metrics (Precision, Recall, ROC-AUC, F1-Score) above reflect empirical measurements evaluated on an
          isolated 1,500-sample test split from verified threat feeds and Tranco top domain corpora.
          All reported metrics are measured with root-domain holdout isolation to prevent data leakage.
        </p>
      </div>
    </div>
  );
};
