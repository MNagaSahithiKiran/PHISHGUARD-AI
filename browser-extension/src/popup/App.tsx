import React, { useEffect, useState } from 'react';
import {
  Shield,
  Search,
  Settings,
  Lock,
  Unlock,
  AlertCircle,
  FileDown,
  ArrowRight,
  Database,
} from 'lucide-react';
import { scanService } from '../services/scan-service';
import { validateTargetUrl } from '../utils/url-validator';
import { ScanState, ScanResultData } from '../types/api';
import { RiskBadge } from './components/RiskBadge';
import { RiskGauge } from './components/RiskGauge';
import { EvidenceList } from './components/EvidenceList';
import { ScanStatus } from './components/ScanStatus';
import { ModelBreakdown } from './components/ModelBreakdown';

export const App: React.FC = () => {
  const [currentUrl, setCurrentUrl] = useState<string>('');
  const [hostname, setHostname] = useState<string>('');
  const [isSecureScheme, setIsSecureScheme] = useState<boolean>(true);
  const [isSupported, setIsSupported] = useState<boolean>(true);
  const [unsupportedReason, setUnsupportedReason] = useState<string>('');

  const [scanState, setScanState] = useState<ScanState>('idle');
  const [result, setResult] = useState<ScanResultData | null>(null);
  const [errorMessage, setErrorMessage] = useState<string>('');
  const [isFromCache, setIsFromCache] = useState<boolean>(false);

  useEffect(() => {
    // Detect active tab on mount
    scanService.getActiveTab().then((tab) => {
      if (tab.url) {
        setCurrentUrl(tab.url);
        const val = validateTargetUrl(tab.url);
        if (!val.isValid) {
          setIsSupported(false);
          setUnsupportedReason(val.reason || 'This internal page cannot be analyzed.');
          setScanState('unsupported');
        } else {
          setIsSupported(true);
          setHostname(val.hostname);
          setIsSecureScheme(val.scheme === 'https:');
        }
      }
    });
  }, []);

  const handleStartScan = async () => {
    if (!currentUrl || !isSupported) return;

    setErrorMessage('');
    setResult(null);

    try {
      const { result: scanData, fromCache } = await scanService.analyzeUrlWithProgress(
        currentUrl,
        (st) => setScanState(st)
      );
      setResult(scanData);
      setIsFromCache(fromCache);

      // If phishing detected, broadcast threat warning to tab content script
      if (scanData.classification === 'PHISHING' && typeof chrome !== 'undefined' && chrome.tabs) {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          if (tabs[0]?.id) {
            chrome.tabs.sendMessage(tabs[0].id, {
              action: 'SHOW_THREAT_WARNING',
              riskScore: scanData.risk_score,
              domain: scanData.domain,
            }).catch(() => {
              // Content script might not be injected on this page
            });
          }
        });
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Analysis failed. Could not communicate with PhishGuard API.');
    }
  };

  const handleOpenDashboard = () => {
    const targetUrl = result
      ? `http://localhost:5173/scans/${result.scan_id}`
      : 'http://localhost:5173/';

    if (typeof chrome !== 'undefined' && chrome.tabs) {
      chrome.tabs.create({ url: targetUrl });
    } else {
      window.open(targetUrl, '_blank');
    }
  };

  const handleOpenPdf = () => {
    if (!result) return;
    const pdfUrl = `http://localhost:8000/api/v1/scans/${result.scan_id}/report.pdf`;
    if (typeof chrome !== 'undefined' && chrome.tabs) {
      chrome.tabs.create({ url: pdfUrl });
    } else {
      window.open(pdfUrl, '_blank');
    }
  };

  const handleOpenOptions = () => {
    if (typeof chrome !== 'undefined' && chrome.runtime?.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    } else {
      window.open('/options.html', '_blank');
    }
  };

  return (
    <div className="w-[380px] min-h-[480px] bg-cyber-950 text-slate-100 flex flex-col justify-between p-4 space-y-4 select-none">
      {/* Header */}
      <div className="space-y-3">
        <div className="flex items-center justify-between pb-3 border-b border-cyber-border">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-white shadow-md shadow-cyan-500/20">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="font-extrabold text-sm font-mono tracking-wider text-white">
                  PHISHGUARD <span className="text-cyan-400">AI</span>
                </span>
                <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                  SENTINEL
                </span>
              </div>
            </div>
          </div>

          <button
            onClick={handleOpenOptions}
            className="p-1.5 rounded-lg border border-cyber-border hover:bg-cyber-800 text-slate-400 hover:text-cyan-300 transition-colors cursor-pointer"
            title="Options & Preferences"
          >
            <Settings className="w-4 h-4" />
          </button>
        </div>

        {/* Target Website Box */}
        <div className="p-3 rounded-xl border border-cyber-border bg-cyber-900/60 space-y-1">
          <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
            <span>ACTIVE WEB TARGET</span>
            {isSupported && (
              <span className="flex items-center gap-1">
                {isSecureScheme ? (
                  <span className="text-emerald-400 flex items-center gap-0.5">
                    <Lock className="w-3 h-3" /> HTTPS
                  </span>
                ) : (
                  <span className="text-amber-400 flex items-center gap-0.5">
                    <Unlock className="w-3 h-3" /> HTTP (Insecure)
                  </span>
                )}
              </span>
            )}
          </div>
          <div className="font-mono text-xs font-semibold text-white truncate">
            {isSupported ? hostname : 'Internal Browser Page'}
          </div>
          <div className="font-mono text-[10px] text-slate-500 truncate">{currentUrl}</div>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 space-y-3.5 my-1">
        {/* Unsupported Page Alert */}
        {!isSupported ? (
          <div className="p-4 rounded-xl border border-amber-500/30 bg-amber-950/20 text-amber-300 text-xs font-mono space-y-1.5 text-center">
            <AlertCircle className="w-5 h-5 mx-auto text-amber-400" />
            <div className="font-bold">Analysis Not Permitted</div>
            <p className="text-[11px] text-slate-400 leading-tight">
              {unsupportedReason || 'Internal browser pages and non-HTTP protocols are protected.'}
            </p>
          </div>
        ) : (
          <>
            {/* Action Button if idle */}
            {scanState === 'idle' && !result && (
              <div className="py-6 text-center space-y-4">
                <p className="text-xs text-slate-400 leading-relaxed max-w-[280px] mx-auto">
                  Analyze active DOM structure, lexical patterns, and visual components using PhishGuard AI.
                </p>
                <button
                  onClick={handleStartScan}
                  className="w-full py-3 px-4 rounded-xl font-mono font-bold text-xs text-cyber-950 bg-gradient-to-r from-cyan-400 to-blue-400 hover:from-cyan-300 hover:to-blue-300 focus:outline-none shadow-lg shadow-cyan-500/20 transition-all flex items-center justify-center gap-2 cursor-pointer"
                >
                  <Search className="w-4 h-4" />
                  <span>ANALYZE CURRENT WEBSITE</span>
                </button>
              </div>
            )}

            {/* Stepper Progression */}
            <ScanStatus state={scanState} error={errorMessage} />

            {/* Scan Result */}
            {result && (
              <div className="space-y-3">
                {/* Verdict Badge & Cache Indicator */}
                <div className="flex items-center justify-between">
                  <RiskBadge verdict={result.classification} />
                  {isFromCache && (
                    <span className="flex items-center gap-1 text-[9px] font-mono text-cyan-400/80 bg-cyan-950/60 px-1.5 py-0.5 rounded border border-cyan-900">
                      <Database className="w-2.5 h-2.5" /> Cached
                    </span>
                  )}
                </div>

                {/* Risk Gauge */}
                <RiskGauge score={result.risk_score} probability={result.phishing_probability} />

                {/* Evidence List */}
                <EvidenceList evidence={result.evidence} />

                {/* Model Breakdown */}
                <ModelBreakdown models={result.models} />
              </div>
            )}
          </>
        )}
      </div>

      {/* Footer Actions */}
      <div className="pt-3 border-t border-cyber-border space-y-2">
        {result ? (
          <div className="grid grid-cols-2 gap-2">
            <button
              onClick={handleOpenPdf}
              className="py-2 px-3 rounded-lg border border-cyan-500/40 bg-cyan-950/40 hover:bg-cyan-900/60 text-cyan-300 text-xs font-mono flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
            >
              <FileDown className="w-3.5 h-3.5" />
              <span>PDF Report</span>
            </button>

            <button
              onClick={handleOpenDashboard}
              className="py-2 px-3 rounded-lg bg-cyber-800 hover:bg-cyber-700 text-slate-100 text-xs font-mono flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
            >
              <span>Full Report</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        ) : (
          <div className="flex items-center justify-between text-[10px] font-mono text-slate-500">
            <span>DEFENSIVE SENTINEL V1.0</span>
            <span className="flex items-center gap-1 text-cyan-500">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
              SSRF Hardened
            </span>
          </div>
        )}
      </div>
    </div>
  );
};
