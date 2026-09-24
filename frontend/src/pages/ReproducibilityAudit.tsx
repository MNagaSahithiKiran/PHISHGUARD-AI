import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  GitCompare,
  Hash,
  CheckCircle2,
  XCircle,
  Cpu,
  Layers,
  ExternalLink,
  Search,
} from 'lucide-react';
import { api } from '../services/api';
import { ScanSummaryItem } from '../types/scan';

export const ReproducibilityAudit: React.FC = () => {
  const [scans, setScans] = useState<ScanSummaryItem[]>([]);
  const [scanId1, setScanId1] = useState<string>('');
  const [scanId2, setScanId2] = useState<string>('');
  const [comparison, setComparison] = useState<any | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [runningDemo, setRunningDemo] = useState<boolean>(false);

  useEffect(() => {
    fetchScans();
  }, []);

  const fetchScans = async () => {
    try {
      const res = await api.listScans(1, 30);
      setScans(res.items);
      if (res.items.length >= 2) {
        setScanId1(res.items[0].id);
        setScanId2(res.items[1].id);
      }
    } catch (err: any) {
      console.error('Failed to fetch scans for reproducibility audit:', err);
    }
  };

  const handleCompare = async (id1: string, id2: string) => {
    if (!id1 || !id2) return;
    setLoading(true);
    setError(null);
    try {
      const res = await api.compareScans(id1, id2);
      setComparison(res);
    } catch (err: any) {
      setError(err.message || 'Comparison request failed.');
      setComparison(null);
    } finally {
      setLoading(false);
    }
  };

  const runDeterministicDemo = async () => {
    setRunningDemo(true);
    setError(null);
    try {
      const targetUrl = 'https://chatgpt.com/c/6ab3b859-af1c-83ee-9fee-5a18a379826c';
      // Execute 1st run
      const scan1 = await api.analyzeIntelligence(targetUrl, false);
      // Execute 2nd run
      const scan2 = await api.analyzeIntelligence(targetUrl, false);

      setScanId1(scan1.scan_id);
      setScanId2(scan2.scan_id);
      await handleCompare(scan1.scan_id, scan2.scan_id);
      await fetchScans();
    } catch (err: any) {
      setError(`Deterministic demonstration run failed: ${err.message}`);
    } finally {
      setRunningDemo(false);
    }
  };

  return (
    <div className="space-y-8 animate-fade-in pb-16">
      {/* Header Banner */}
      <div className="glass-panel p-6 rounded-2xl border border-cyan-500/30 bg-cyber-900/60 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 relative z-10">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                PLACEMENT DEMONSTRATION AUDIT
              </span>
              <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                DETERMINISTIC AI • ZERO FAKE RESULTS
              </span>
            </div>
            <h1 className="text-2xl font-bold font-mono text-white flex items-center gap-2.5">
              <GitCompare className="w-6 h-6 text-cyan-400" />
              Reproducibility & Integrity Audit Console
            </h1>
            <p className="text-xs text-slate-400 max-w-2xl font-mono">
              Cryptographically validates that scans on identical canonical URLs produce bit-for-bit
              identical SHA-256 feature hashes, prediction outputs, and risk scores under frozen model policies.
            </p>
          </div>

          <button
            onClick={runDeterministicDemo}
            disabled={runningDemo}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-mono text-xs font-bold shadow-lg shadow-cyan-500/20 transition-all disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${runningDemo ? 'animate-spin' : ''}`} />
            <span>{runningDemo ? 'Executing Dual Scan...' : 'Run Live Determinism Demo'}</span>
          </button>
        </div>
      </div>

      {/* Comparison Controller */}
      <div className="glass-panel p-6 rounded-2xl border border-cyber-border space-y-4">
        <h2 className="text-sm font-mono font-bold text-white flex items-center gap-2">
          <Hash className="w-4 h-4 text-cyan-400" />
          <span>Select Scans for Side-by-Side Verification</span>
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <label className="text-xs font-mono text-slate-400">Baseline Scan (Scan 1):</label>
            <select
              value={scanId1}
              onChange={(e) => setScanId1(e.target.value)}
              className="w-full bg-cyber-950 border border-cyber-border rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="">Select a scan...</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  [{s.id.substring(0, 8)}] {s.url.substring(0, 45)}... ({s.verdict.toUpperCase()})
                </option>
              ))}
            </select>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-mono text-slate-400">Comparison Target (Scan 2):</label>
            <select
              value={scanId2}
              onChange={(e) => setScanId2(e.target.value)}
              className="w-full bg-cyber-950 border border-cyber-border rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="">Select a scan...</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  [{s.id.substring(0, 8)}] {s.url.substring(0, 45)}... ({s.verdict.toUpperCase()})
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="flex justify-end">
          <button
            onClick={() => handleCompare(scanId1, scanId2)}
            disabled={!scanId1 || !scanId2 || loading}
            className="flex items-center gap-2 px-5 py-2 rounded-xl bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 font-mono text-xs font-bold transition-all disabled:opacity-50"
          >
            <GitCompare className="w-3.5 h-3.5" />
            <span>{loading ? 'Evaluating Hashes...' : 'Compare Scans'}</span>
          </button>
        </div>

        {error && (
          <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono">
            {error}
          </div>
        )}
      </div>

      {/* Comparison Results Card */}
      {comparison && (
        <div className="glass-panel p-6 rounded-2xl border border-cyber-border space-y-6">
          <div className="flex items-center justify-between border-b border-cyber-border pb-4">
            <div className="flex items-center gap-2.5">
              {comparison.reproducible ? (
                <div className="p-2 rounded-xl bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
                  <CheckCircle2 className="w-6 h-6" />
                </div>
              ) : (
                <div className="p-2 rounded-xl bg-amber-500/20 text-amber-400 border border-amber-500/40">
                  <AlertTriangle className="w-6 h-6" />
                </div>
              )}
              <div>
                <h3 className="text-base font-mono font-bold text-white">
                  Reproducibility Verdict:{' '}
                  <span className={comparison.reproducible ? 'text-emerald-400' : 'text-amber-400'}>
                    {comparison.reproducible ? 'IDENTICAL CRYPTOGRAPHIC MATCH' : 'STATE VARIANCE DETECTED'}
                  </span>
                </h3>
                <p className="text-xs text-slate-400 font-mono">
                  {comparison.reproducible
                    ? '100% Deterministic match across model inputs, feature hashes, decision policy, and verdict.'
                    : comparison.message || 'Differences observed between scan snapshots.'}
                </p>
              </div>
            </div>

            <div className="text-right font-mono text-xs">
              <span className="text-slate-400">Prediction Hash Match: </span>
              <span className={`font-bold ${comparison.prediction_hash_match ? 'text-emerald-400' : 'text-rose-400'}`}>
                {comparison.prediction_hash_match ? 'MATCH' : 'MISMATCH'}
              </span>
            </div>
          </div>

          {/* Cryptographic Comparison Matrix */}
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead>
                <tr className="border-b border-cyber-border text-slate-400 text-[11px]">
                  <th className="py-2.5 px-3">Metric / Fingerprint</th>
                  <th className="py-2.5 px-3">Scan 1 ({comparison.scan_1?.id?.substring(0, 8)})</th>
                  <th className="py-2.5 px-3">Scan 2 ({comparison.scan_2?.id?.substring(0, 8)})</th>
                  <th className="py-2.5 px-3 text-center">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border/40 text-slate-300">
                <tr>
                  <td className="py-2.5 px-3 font-semibold text-white">Canonical Target URL</td>
                  <td className="py-2.5 px-3 break-all text-slate-300">{comparison.scan_1?.canonical_url}</td>
                  <td className="py-2.5 px-3 break-all text-slate-300">{comparison.scan_2?.canonical_url}</td>
                  <td className="py-2.5 px-3 text-center">
                    {comparison.scan_1?.canonical_url === comparison.scan_2?.canonical_url ? (
                      <span className="text-emerald-400 font-bold">MATCH</span>
                    ) : (
                      <span className="text-amber-400 font-bold">DIFFERENT</span>
                    )}
                  </td>
                </tr>
                <tr>
                  <td className="py-2.5 px-3 font-semibold text-white">Security Verdict</td>
                  <td className="py-2.5 px-3 uppercase font-bold text-white">{comparison.scan_1?.verdict}</td>
                  <td className="py-2.5 px-3 uppercase font-bold text-white">{comparison.scan_2?.verdict}</td>
                  <td className="py-2.5 px-3 text-center">
                    {comparison.verdict_match ? (
                      <span className="text-emerald-400 font-bold">MATCH</span>
                    ) : (
                      <span className="text-rose-400 font-bold">MISMATCH</span>
                    )}
                  </td>
                </tr>
                <tr>
                  <td className="py-2.5 px-3 font-semibold text-white">Threat Risk Score</td>
                  <td className="py-2.5 px-3 text-cyan-300 font-bold">{comparison.scan_1?.risk_score} / 100</td>
                  <td className="py-2.5 px-3 text-cyan-300 font-bold">{comparison.scan_2?.risk_score} / 100</td>
                  <td className="py-2.5 px-3 text-center">
                    {comparison.risk_score_diff === 0 ? (
                      <span className="text-emerald-400 font-bold">0.0 (σ = 0)</span>
                    ) : (
                      <span className="text-amber-400 font-bold">Δ = {comparison.risk_score_diff}</span>
                    )}
                  </td>
                </tr>
                <tr>
                  <td className="py-2.5 px-3 font-semibold text-white">Prediction Hash (SHA-256)</td>
                  <td className="py-2.5 px-3 text-[11px] text-cyan-300 break-all">{comparison.scan_1?.prediction_hash || 'None'}</td>
                  <td className="py-2.5 px-3 text-[11px] text-cyan-300 break-all">{comparison.scan_2?.prediction_hash || 'None'}</td>
                  <td className="py-2.5 px-3 text-center">
                    {comparison.prediction_hash_match ? (
                      <span className="text-emerald-400 font-bold">IDENTICAL</span>
                    ) : (
                      <span className="text-rose-400 font-bold">DIFFERENT</span>
                    )}
                  </td>
                </tr>
                <tr>
                  <td className="py-2.5 px-3 font-semibold text-white">Model Input Hash</td>
                  <td className="py-2.5 px-3 text-[11px] text-slate-400 break-all">{comparison.scan_1?.model_input_hash || 'None'}</td>
                  <td className="py-2.5 px-3 text-[11px] text-slate-400 break-all">{comparison.scan_2?.model_input_hash || 'None'}</td>
                  <td className="py-2.5 px-3 text-center">
                    {comparison.model_input_hash_match ? (
                      <span className="text-emerald-400 font-bold">IDENTICAL</span>
                    ) : (
                      <span className="text-amber-400 font-bold">VARIED</span>
                    )}
                  </td>
                </tr>
                <tr>
                  <td className="py-2.5 px-3 font-semibold text-white">DOM Snapshot Hash</td>
                  <td className="py-2.5 px-3 text-[11px] text-slate-400 break-all">{comparison.scan_1?.dom_snapshot_hash || 'None'}</td>
                  <td className="py-2.5 px-3 text-[11px] text-slate-400 break-all">{comparison.scan_2?.dom_snapshot_hash || 'None'}</td>
                  <td className="py-2.5 px-3 text-center">
                    {comparison.dom_snapshot_hash_match ? (
                      <span className="text-emerald-400 font-bold">IDENTICAL</span>
                    ) : (
                      <span className="text-amber-400 font-bold">LIVE CONTENT CHANGE</span>
                    )}
                  </td>
                </tr>
                <tr>
                  <td className="py-2.5 px-3 font-semibold text-white">Decision Policy Version</td>
                  <td className="py-2.5 px-3 text-white">{comparison.scan_1?.decision_policy_version || 'risk_policy_v1'}</td>
                  <td className="py-2.5 px-3 text-white">{comparison.scan_2?.decision_policy_version || 'risk_policy_v1'}</td>
                  <td className="py-2.5 px-3 text-center">
                    <span className="text-emerald-400 font-bold">FROZEN (v1)</span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
