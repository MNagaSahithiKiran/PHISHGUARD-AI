import React, { useEffect, useState } from 'react';
import {
  Radio,
  Database,
  ExternalLink,
  Layers,
  ShieldAlert,
  AlertTriangle,
  Globe2,
  RefreshCw,
  Terminal,
} from 'lucide-react';
import { api } from '../services/api';
import { ThreatIntelResponse, ObservedDomain, RecentThreatItem } from '../types/scan';

const HEURISTIC_RULES = [
  {
    id: 'LEX_IP_HOSTNAME',
    name: 'Raw IP Address Hostname',
    severity: 'HIGH',
    type: 'Lexical',
    description: 'Target hostname uses direct IPv4/IPv6 notation instead of a registered domain, bypassing reputation checks.',
    example: 'http://198.51.100.4/login.php',
  },
  {
    id: 'LEX_PUNYCODE_HOMOGRAPH',
    name: 'Punycode IDN Homograph Spoof',
    severity: 'HIGH',
    type: 'Lexical',
    description: 'Contains internationalized domain characters (xn--) designed to visually mimic legitimate brands (e.g., Cyrillic "a").',
    example: 'https://xn--pple-43d.com',
  },
  {
    id: 'LEX_AT_SYMBOL_OBFUSCATION',
    name: '@ Symbol Host Obfuscation',
    severity: 'CRITICAL',
    type: 'Lexical',
    description: 'Uses the "@" character to trick users into believing they are visiting a trusted domain before the token.',
    example: 'https://google.com@malicious-phish.net/login',
  },
  {
    id: 'DOM_EXTERNAL_FORM_ACTION',
    name: 'Cross-Domain Form Action',
    severity: 'CRITICAL',
    type: 'DOM / HTML',
    description: 'Form submission endpoint posts credentials to an external third-party domain.',
    example: '<form action="https://evil-stealer.ru/post.php">',
  },
  {
    id: 'DOM_PASSWORD_ON_HTTP',
    name: 'Insecure Password Over HTTP',
    severity: 'HIGH',
    type: 'DOM / Network',
    description: 'Password input field rendered over cleartext HTTP connection.',
    example: '<input type="password"> on http://insecure-host.com',
  },
];

export const ThreatIntelligence: React.FC = () => {
  const [indicatorsIntel, setIndicatorsIntel] = useState<ThreatIntelResponse | null>(null);
  const [observedDomains, setObservedDomains] = useState<ObservedDomain[]>([]);
  const [recentThreats, setRecentThreats] = useState<RecentThreatItem[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchThreatData = async () => {
    setLoading(true);
    try {
      const [ind, doms, threats] = await Promise.all([
        api.getThreatIndicators(),
        api.getObservedDomains(),
        api.getRecentThreats(),
      ]);
      setIndicatorsIntel(ind);
      setObservedDomains(doms);
      setRecentThreats(threats);
    } catch (err) {
      console.error('Failed to load threat intelligence data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreatData();
  }, []);

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-md bg-cyan-950/80 border border-cyan-800/80 text-cyan-300 text-xs font-mono mb-2">
            <Radio className="w-3.5 h-3.5 text-cyan-400" />
            CYBER THREAT REPOSITORY &amp; IOC FEED
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight font-mono">
            THREAT INTELLIGENCE &amp; INDICATORS OF COMPROMISE
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Live database aggregations of triggered heuristic rules, targeted domains, and empirical threat signatures.
          </p>
        </div>

        <button
          onClick={fetchThreatData}
          disabled={loading}
          className="inline-flex items-center gap-2 px-3 py-2 rounded-xl bg-cyber-800 hover:bg-cyber-700 text-slate-300 text-xs font-mono transition-colors self-start sm:self-auto cursor-pointer"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Intelligence</span>
        </button>
      </div>

      {/* Grid: Indicators Prevalence & Observed Domains */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Triggered Indicator Rules Table */}
        <div className="glass-panel p-5 rounded-2xl border border-cyber-border bg-cyber-900/60 shadow-xl space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold text-white font-mono uppercase">Top Triggered Security Indicators</h2>
              <p className="text-[11px] text-slate-400">Prevalence ranking across all recorded scans</p>
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950 text-cyan-400 border border-cyan-800">
              {indicatorsIntel?.total_indicators_detected || 0} Total IOCs
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-cyber-border bg-cyber-950/60 text-slate-400 font-mono text-[10px] uppercase">
                  <th className="py-2.5 px-3">Rule ID</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Occurrences</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border/40 font-mono">
                {indicatorsIntel?.top_indicators && indicatorsIntel.top_indicators.length > 0 ? (
                  indicatorsIntel.top_indicators.map((ind) => (
                    <tr key={ind.rule_id} className="hover:bg-cyber-800/30 transition-colors">
                      <td className="py-2.5 px-3">
                        <div className="font-semibold text-slate-200">{ind.rule_id}</div>
                        <div className="text-[10px] text-slate-400 truncate max-w-xs">{ind.description}</div>
                      </td>
                      <td className="py-2.5 px-3">
                        <span
                          className={`text-[9px] font-bold px-1.5 py-0.5 rounded uppercase ${
                            ind.severity === 'critical'
                              ? 'bg-rose-950 text-rose-300 border border-rose-800'
                              : ind.severity === 'high'
                              ? 'bg-orange-950 text-orange-300 border border-orange-800'
                              : 'bg-amber-950 text-amber-300 border border-amber-800'
                          }`}
                        >
                          {ind.severity}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-cyan-400 font-bold">{ind.count}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={3} className="py-6 text-center text-slate-500 font-mono text-xs">
                      No security indicators recorded yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Observed Target Domains */}
        <div className="glass-panel p-5 rounded-2xl border border-cyber-border bg-cyber-900/60 shadow-xl space-y-4">
          <div>
            <h2 className="text-sm font-bold text-white font-mono uppercase">Observed Target Domains</h2>
            <p className="text-[11px] text-slate-400">Attack surface and threat concentration by root domain</p>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-cyber-border bg-cyber-950/60 text-slate-400 font-mono text-[10px] uppercase">
                  <th className="py-2.5 px-3">Domain</th>
                  <th className="py-2.5 px-3">Scans</th>
                  <th className="py-2.5 px-3">Phishing</th>
                  <th className="py-2.5 px-3">Avg Risk</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border/40 font-mono">
                {observedDomains.length > 0 ? (
                  observedDomains.map((d) => (
                    <tr key={d.domain} className="hover:bg-cyber-800/30 transition-colors">
                      <td className="py-2.5 px-3 font-semibold text-slate-200">{d.domain}</td>
                      <td className="py-2.5 px-3 text-slate-300">{d.scan_count}</td>
                      <td className="py-2.5 px-3 text-rose-400 font-bold">{d.phishing_count}</td>
                      <td className="py-2.5 px-3 font-bold text-cyan-400">{d.average_risk_score}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={4} className="py-6 text-center text-slate-500 font-mono text-xs">
                      No target domains recorded yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Heuristics Rules Catalog */}
      <div className="space-y-4">
        <h2 className="text-sm font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
          <Layers className="w-4 h-4 text-cyan-400" />
          <span>Active Lexical &amp; Structural Detection Rules</span>
        </h2>

        <div className="space-y-3">
          {HEURISTIC_RULES.map((rule) => (
            <div
              key={rule.id}
              className="glass-panel p-5 rounded-xl border border-cyber-border hover:border-cyan-500/40 transition-all space-y-2 bg-cyber-900/60"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="font-mono font-bold text-cyan-400 text-sm">{rule.id}</span>
                  <span className="text-slate-400 text-xs">—</span>
                  <span className="text-white font-semibold text-sm">{rule.name}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyber-800 text-slate-300">
                    {rule.type}
                  </span>
                  <span
                    className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                      rule.severity === 'CRITICAL'
                        ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                        : 'bg-orange-500/20 text-orange-300 border border-orange-500/30'
                    }`}
                  >
                    {rule.severity}
                  </span>
                </div>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">{rule.description}</p>
              <div className="text-[11px] font-mono text-slate-400 bg-cyber-950/70 p-2 rounded border border-cyber-border/60">
                Pattern: <span className="text-rose-400">{rule.example}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
