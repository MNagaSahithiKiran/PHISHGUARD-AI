import React from 'react';
import { ScanState } from '../../types/api';
import { RefreshCw, XCircle, AlertCircle } from 'lucide-react';

interface ScanStatusProps {
  state: ScanState;
  error?: string;
}

const STAGES: { key: ScanState; label: string }[] = [
  { key: 'preparing', label: 'Preparing Target' },
  { key: 'url_analysis', label: 'URL Intelligence' },
  { key: 'website_analysis', label: 'DOM & Network' },
  { key: 'visual_analysis', label: 'Computer Vision' },
  { key: 'ai_fusion', label: 'Multi-Modal Fusion' },
];

export const ScanStatus: React.FC<ScanStatusProps> = ({ state, error }) => {
  if (state === 'failed') {
    return (
      <div className="p-3.5 rounded-xl border border-rose-500/40 bg-rose-950/40 text-rose-300 text-xs font-mono space-y-1">
        <div className="flex items-center gap-2 font-bold">
          <XCircle className="w-4 h-4 text-rose-400" />
          <span>Analysis Interrupted</span>
        </div>
        <p className="text-[11px] opacity-90 leading-tight">
          {error || 'PhishGuard AI could not analyze this page right now. Please verify network access.'}
        </p>
      </div>
    );
  }

  if (state === 'unsupported') {
    return (
      <div className="p-3.5 rounded-xl border border-amber-500/40 bg-amber-950/40 text-amber-300 text-xs font-mono space-y-1">
        <div className="flex items-center gap-2 font-bold">
          <AlertCircle className="w-4 h-4 text-amber-400" />
          <span>Page Cannot Be Analyzed</span>
        </div>
        <p className="text-[11px] opacity-90 leading-tight">
          {error || 'Browser internal pages (chrome://, about:, file://) are protected and not analyzable.'}
        </p>
      </div>
    );
  }

  const currentIndex = STAGES.findIndex((s) => s.key === state);
  const isRunning = currentIndex !== -1;

  if (!isRunning && state !== 'completed') return null;

  return (
    <div className="p-3.5 rounded-xl border border-cyber-border bg-cyber-950/80 space-y-3 font-mono">
      <div className="flex items-center justify-between text-xs">
        <span className="text-slate-400 font-semibold uppercase">Inspection Pipeline</span>
        <span className="text-cyan-400 flex items-center gap-1.5 text-[11px]">
          {state !== 'completed' && <RefreshCw className="w-3 h-3 animate-spin" />}
          <span>{state === 'completed' ? 'Analysis Complete' : 'Synthesizing Signals...'}</span>
        </span>
      </div>

      <div className="grid grid-cols-5 gap-1.5 pt-1">
        {STAGES.map((stage, idx) => {
          const isDone = state === 'completed' || currentIndex > idx;
          const isCurrent = currentIndex === idx;

          return (
            <div key={stage.key} className="space-y-1 text-center">
              <div
                className={`h-1.5 rounded-full transition-all duration-300 ${
                  isDone
                    ? 'bg-cyan-500 shadow-sm shadow-cyan-500/50'
                    : isCurrent
                    ? 'bg-cyan-400 animate-pulse'
                    : 'bg-cyber-900 border border-cyber-border'
                }`}
              />
              <div
                className={`text-[9px] truncate ${
                  isDone ? 'text-slate-300' : isCurrent ? 'text-cyan-400 font-bold' : 'text-slate-600'
                }`}
              >
                {stage.label.split(' ')[0]}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
