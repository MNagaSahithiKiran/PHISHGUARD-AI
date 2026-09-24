import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Search,
  Shield,
  AlertOctagon,
  CheckCircle2,
  Lock,
  ArrowRight,
  Sparkles,
  Zap,
  Cpu,
  BarChart2,
  Globe,
  FileCode,
  Layers,
  ExternalLink,
  ShieldCheck,
  AlertTriangle,
  Info,
  ShieldAlert,
} from 'lucide-react';

import { api } from '../services/api';
import { MLPrediction, WebsiteAnalysis } from '../types/scan';

export const Scanner: React.FC = () => {
  const navigate = useNavigate();
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [loadingStep, setLoadingStep] = useState<string>('');
  const [error, setError] = useState<string | null>(null);
  const [prediction, setPrediction] = useState<MLPrediction | null>(null);
  const [analysis, setAnalysis] = useState<WebsiteAnalysis | null>(null);
  const [lastScanId, setLastScanId] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setError(null);
    setPrediction(null);
    setAnalysis(null);
    setLastScanId(null);

    const targetUrl = url.trim();

    try {
      setLoadingStep('Validating URL & Enforcing SSRF Safeguards...');
      
      // 1. Submit to Phase 3 Website Intelligence Analysis
      setLoadingStep('Executing Controlled Stream-Capped Fetch & Multi-Vector Analyzers...');
      const analysisRes = await api.analyzeWebsite(targetUrl);
      setAnalysis(analysisRes);
      setLastScanId(analysisRes.scan_id);

      if (analysisRes.status === 'blocked') {
        setError('Analysis blocked for security reasons (Restricted destination or private IP).');
      }

      // 2. Submit to Phase 2 ML prediction endpoint
      setLoadingStep('Running Phase 2 Random Forest Inference & SHAP Attribution...');
      try {
        const predRes = await api.predictUrl(targetUrl);
        setPrediction(predRes);
      } catch (mlErr: any) {
        console.warn('ML URL model notice:', mlErr.message);
      }

      // 3. Trigger Phase 5 Multi-Modal Fusion Engine (attached to this scan)
      if (analysisRes.status !== 'blocked') {
        setLoadingStep('Synthesizing Multi-Modal Model Predictions...');
        try {
          await api.analyzeIntelligence(targetUrl, false, analysisRes.scan_id);
        } catch (intelErr: any) {
          console.warn('Intelligence fusion background notice:', intelErr.message);
        }
      }
    } catch (err: any) {
      setError(err.message || 'An unexpected error occurred during URL intake.');
    } finally {
      setLoading(false);
      setLoadingStep('');
    }
  };

  const handlePreset = (sampleUrl: string) => {
    setUrl(sampleUrl);
    setError(null);
    setPrediction(null);
    setAnalysis(null);
    setLastScanId(null);
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'bg-red-500/20 text-red-400 border-red-500/40';
      case 'high':
        return 'bg-rose-500/20 text-rose-400 border-rose-500/40';
      case 'medium':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
      case 'low':
        return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40';
      default:
        return 'bg-blue-500/20 text-blue-400 border-blue-500/40';
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-8 py-4">
      {/* Header */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono">
          <Zap className="w-3.5 h-3.5 text-cyan-400" />
          ACTIVE DEFENSE ENGINE — PRODUCTION CORE
        </div>
        <h1 className="text-3xl font-extrabold text-white tracking-tight sm:text-4xl">
          Website Intelligence & Threat Scanner
        </h1>
        <p className="text-slate-400 max-w-2xl mx-auto text-sm">
          Multi-vector cybersecurity scanning: SSRF-safe HTTP intake, redirect tracking, DOM/form/iframe/script telemetry, 48-feature extraction, and machine learning risk classification.
        </p>
      </div>

      {/* Main Scanner Card */}
      <div className="glass-panel rounded-2xl p-6 md:p-8 border-cyber-border shadow-2xl relative">
        <form onSubmit={handleSubmit} className="space-y-4">
          <label className="block text-xs font-mono text-slate-300 uppercase tracking-wider font-semibold">
            Target Website URL
          </label>

          <div className="relative flex items-center">
            <div className="absolute left-4 text-slate-400">
              <Search className="w-5 h-5 text-cyan-400" />
            </div>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="e.g. https://secure-login.portal-verification.com/auth"
              disabled={loading}
              className="w-full pl-12 pr-36 py-4 rounded-xl bg-cyber-950/80 border border-cyber-border focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 text-slate-100 placeholder-slate-400 font-mono text-sm transition-all shadow-inner"
            />
            <button
              type="submit"
              disabled={loading || !url.trim()}
              className="absolute right-2 px-5 py-2.5 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 text-white font-semibold text-xs tracking-wide shadow-md transition-all flex items-center gap-1.5"
            >
              {loading ? (
                <>
                  <span className="w-3.5 h-3.5 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <span>Deep Analyze</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          </div>
        </form>

        {/* Live Loading Progress */}
        {loading && (
          <div className="mt-5 p-4 rounded-xl bg-cyan-950/30 border border-cyan-500/30 text-cyan-300 text-xs font-mono flex items-center gap-3 animate-pulse">
            <span className="w-4 h-4 border-2 border-cyan-400/20 border-t-cyan-400 rounded-full animate-spin shrink-0" />
            <span>{loadingStep || 'Executing controlled passive analysis...'}</span>
          </div>
        )}

        {/* Error notification (SSRF / Model Unavailable) */}
        {error && (
          <div className="mt-5 p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono flex items-start gap-3">
            <AlertOctagon className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            <div>
              <div className="font-bold text-rose-200 mb-0.5">Security / Policy Notice</div>
              <div>{error}</div>
            </div>
          </div>
        )}

        {/* Research Transparency Notice */}
        <div className="mt-5 pt-4 border-t border-cyber-border/60 flex items-center justify-between text-[11px] font-mono text-slate-400">
          <div className="flex items-center gap-1.5">
            <Shield className="w-3.5 h-3.5 text-cyan-400" />
            <span>Enterprise Defense Mode: Multi-vector inspection and zero domain leakage validation.</span>
          </div>
          <span className="text-slate-400 hidden sm:inline">Stream Cap: 5MB | Max Hops: 5</span>
        </div>
      </div>

      {/* Website Intelligence Telemetry Results (Phase 3) */}
      {analysis && (
        <div className="space-y-6">
          {/* Top Classification & Status Banner */}
          <div className="glass-panel p-6 rounded-2xl border-cyber-border space-y-4 shadow-xl">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-cyber-border pb-4">
              <div>
                <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-widest block font-semibold">
                  WEBSITE INTELLIGENCE RESULT
                </span>
                <h2 className="text-xl font-bold text-white mt-1 break-all">
                  {analysis.final_url || analysis.url}
                </h2>
              </div>
              <div className="flex items-center gap-2">
                <span
                  className={`px-4 py-1.5 rounded-full text-xs font-mono font-bold uppercase tracking-wider border ${
                    analysis.status === 'blocked'
                      ? 'bg-rose-500/20 text-rose-400 border-rose-500/40'
                      : prediction && prediction.prediction === 'phishing'
                      ? 'bg-red-500/20 text-red-400 border-red-500/40'
                      : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                  }`}
                >
                  STATUS: {analysis.status.toUpperCase()}
                </span>
              </div>
            </div>

            {/* HTTP & DOM Metrics Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
              <div className="p-3 rounded-lg bg-cyber-950/70 border border-cyber-border">
                <span className="text-slate-400 block text-[10px]">HTTP STATUS</span>
                <span className="text-white font-bold text-sm">
                  {analysis.http.status_code || 'N/A'}
                </span>
              </div>
              <div className="p-3 rounded-lg bg-cyber-950/70 border border-cyber-border">
                <span className="text-slate-400 block text-[10px]">RESPONSE LATENCY</span>
                <span className="text-cyan-300 font-bold text-sm">
                  {analysis.http.response_time_ms} ms
                </span>
              </div>
              <div className="p-3 rounded-lg bg-cyber-950/70 border border-cyber-border">
                <span className="text-slate-400 block text-[10px]">REDIRECT HOPS</span>
                <span className={`text-sm font-bold ${analysis.redirects.total_hops > 2 ? 'text-amber-400' : 'text-slate-200'}`}>
                  {analysis.redirects.total_hops} hops
                </span>
              </div>
              <div className="p-3 rounded-lg bg-cyber-950/70 border border-cyber-border">
                <span className="text-slate-400 block text-[10px]">SECURITY HEADER SCORE</span>
                <span className="text-emerald-400 font-bold text-sm">
                  {Math.round(analysis.headers.security_header_score * 100)}%
                </span>
              </div>
            </div>

            {/* DOM & Form Indicators */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
              <div className="p-3 rounded-lg bg-cyber-950/70 border border-cyber-border">
                <span className="text-slate-400 block text-[10px]">DOM DEPTH</span>
                <span className="text-white font-bold text-sm">{analysis.dom.dom_depth} levels</span>
              </div>
              <div className="p-3 rounded-lg bg-cyber-950/70 border border-cyber-border">
                <span className="text-slate-400 block text-[10px]">TOTAL FORMS</span>
                <span className="text-white font-bold text-sm">{analysis.forms.total_forms}</span>
              </div>
              <div className="p-3 rounded-lg bg-cyber-950/70 border border-cyber-border">
                <span className="text-slate-400 block text-[10px]">PASSWORD FIELDS</span>
                <span className={`text-sm font-bold ${analysis.forms.has_password_field ? 'text-rose-400' : 'text-slate-200'}`}>
                  {analysis.forms.has_password_field ? 'PRESENT' : 'None'}
                </span>
              </div>
              <div className="p-3 rounded-lg bg-cyber-950/70 border border-cyber-border">
                <span className="text-slate-400 block text-[10px]">EXTERNAL FORM ACTIONS</span>
                <span className={`text-sm font-bold ${analysis.forms.external_action_count > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {analysis.forms.external_action_count}
                </span>
              </div>
            </div>
          </div>

          {/* Structured Security Evidence Cards */}
          {analysis.evidence && analysis.evidence.length > 0 && (
            <div className="glass-panel p-6 rounded-2xl border-cyber-border space-y-4">
              <div className="flex items-center gap-2 border-b border-cyber-border pb-3">
                <ShieldAlert className="w-5 h-5 text-cyan-400" />
                <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-white">
                  Traceable Evidence Findings ({analysis.evidence.length})
                </h3>
              </div>
              <div className="grid grid-cols-1 gap-3">
                {analysis.evidence.map((ev, idx) => (
                  <div
                    key={idx}
                    className="p-4 rounded-xl bg-cyber-950/80 border border-cyber-border/80 space-y-2 text-xs font-mono"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-bold text-slate-200 text-sm">{ev.title}</span>
                      <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold uppercase border ${getSeverityBadge(ev.severity)}`}>
                        {ev.severity}
                      </span>
                    </div>
                    <p className="text-slate-400 leading-relaxed">{ev.detail}</p>
                    {ev.recommendation && (
                      <div className="pt-1 text-[11px] text-cyan-400/90 flex items-start gap-1.5">
                        <span className="font-bold">Recommendation:</span>
                        <span>{ev.recommendation}</span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Dual AI Models Status Layer */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Phase 2 URL Model Card */}
            <div className="glass-panel p-5 rounded-xl border-cyan-500/40 bg-cyber-900/90 space-y-3">
              <div className="flex items-center justify-between border-b border-cyber-border pb-2">
                <div className="flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-cyan-400" />
                  <span className="text-xs font-mono font-bold text-slate-200 uppercase">
                    URL Intelligence Model
                  </span>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                  ACTIVE
                </span>
              </div>
              {prediction ? (
                <div className="space-y-2 text-xs font-mono">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Prediction:</span>
                    <span className={`font-bold ${prediction.prediction === 'phishing' ? 'text-rose-400' : 'text-emerald-400'}`}>
                      {prediction.prediction.toUpperCase()}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Probability:</span>
                    <span className="text-white font-bold">{prediction.probability}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Model:</span>
                    <span className="text-cyan-300 font-bold">{prediction.model_version}</span>
                  </div>
                </div>
              ) : (
                <p className="text-xs text-slate-400 font-mono">Evaluating URL features...</p>
              )}
            </div>

            {/* Multi-Modal Fusion Engine Card */}
            <div className="glass-panel p-5 rounded-xl border-cyber-border bg-cyber-950/80 space-y-3">
              <div className="flex items-center justify-between border-b border-cyber-border pb-2">
                <div className="flex items-center gap-2">
                  <Layers className="w-4 h-4 text-slate-400" />
                  <span className="text-xs font-mono font-bold text-slate-300 uppercase">
                    Multi-Modal Fusion Engine
                  </span>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-400 border border-slate-700">
                  {analysis.website_model.status.toUpperCase()}
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono leading-relaxed">
                {analysis.website_model.message}
              </p>
              <div className="text-[11px] font-mono text-cyan-400/80">
                48 structural DOM and telemetry features evaluated and persisted.
              </div>
            </div>
          </div>

          {/* Deep Audit Link */}
          {lastScanId && (
            <div className="flex justify-end pt-2">
              <button
                type="button"
                onClick={() => navigate(`/scans/${lastScanId}`)}
                className="px-5 py-2.5 rounded-lg bg-cyber-800 hover:bg-cyber-700 border border-cyber-border text-cyan-300 text-xs font-mono font-bold flex items-center gap-2 transition-all shadow-md"
              >
                <span>View Full Audit Record & Database Log</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>
      )}

      {/* Preset Test Targets */}
      <div className="glass-panel rounded-2xl p-6 border-cyber-border space-y-4">
        <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-slate-300 font-semibold">
          <Sparkles className="w-4 h-4 text-cyan-400" />
          <span>Evaluation Targets</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
          <button
            type="button"
            onClick={() => handlePreset('https://wikipedia.org')}
            className="p-3.5 rounded-xl bg-cyber-950/60 border border-cyber-border hover:border-emerald-500/40 text-left transition-all group"
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-slate-300 font-bold group-hover:text-emerald-300">Wikipedia Foundation</span>
              <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                Legitimate Portal
              </span>
            </div>
            <div className="text-slate-400 text-[11px] truncate">https://wikipedia.org</div>
          </button>

          <button
            type="button"
            onClick={() => handlePreset('http://127.0.0.1:8000/internal-admin')}
            className="p-3.5 rounded-xl bg-cyber-950/60 border border-cyber-border hover:border-rose-500/40 text-left transition-all group"
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-slate-300 font-bold group-hover:text-rose-300">SSRF Attack Simulation</span>
              <span className="text-[10px] px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/30">
                Restricted Target
              </span>
            </div>
            <div className="text-slate-400 text-[11px] truncate">http://127.0.0.1:8000/internal-admin</div>
          </button>
        </div>
      </div>
    </div>
  );
};
