import React, { useState } from 'react';
import { ModelSignal } from '../../types/api';
import { ChevronDown, ChevronUp, Cpu, Globe, Layout, Camera, Layers } from 'lucide-react';

interface ModelBreakdownProps {
  models?: {
    url?: ModelSignal;
    website?: ModelSignal;
    visual?: ModelSignal;
    fusion?: ModelSignal;
  };
}

export const ModelBreakdown: React.FC<ModelBreakdownProps> = ({ models }) => {
  const [expanded, setExpanded] = useState(false);

  if (!models) return null;

  const items = [
    { key: 'url', label: 'URL Lexical Model', icon: Globe, signal: models.url },
    { key: 'website', label: 'DOM / HTML Telemetry', icon: Layout, signal: models.website },
    { key: 'visual', label: 'MobileNetV2 Vision', icon: Camera, signal: models.visual },
    { key: 'fusion', label: 'Stacking Calibrator', icon: Layers, signal: models.fusion },
  ];

  return (
    <div className="border border-cyber-border rounded-xl bg-cyber-950/60 overflow-hidden font-mono text-xs">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full p-2.5 flex items-center justify-between text-slate-300 hover:text-white transition-colors cursor-pointer"
      >
        <span className="flex items-center gap-1.5 font-semibold text-[11px] text-cyan-400">
          <Cpu className="w-3.5 h-3.5" />
          <span>Multi-Modal AI Breakdown</span>
        </span>
        {expanded ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
      </button>

      {expanded && (
        <div className="p-3 border-t border-cyber-border/60 space-y-2 bg-cyber-900/40">
          {items.map((item) => {
            const Icon = item.icon;
            const sig = item.signal;
            const hasProb = sig?.probability !== undefined && sig.probability !== null;
            const probPct = hasProb ? `${(sig!.probability! * 100).toFixed(1)}%` : 'N/A';

            return (
              <div key={item.key} className="flex items-center justify-between text-[11px] py-1 border-b border-cyber-border/30 last:border-none">
                <div className="flex items-center gap-2">
                  <Icon className="w-3.5 h-3.5 text-slate-400" />
                  <span className="text-slate-300">{item.label}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span
                    className={`text-[10px] px-1.5 py-0.2 rounded ${
                      sig?.status === 'available' || sig?.status === 'completed'
                        ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                        : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {sig?.status || 'available'}
                  </span>
                  <span className="font-bold text-slate-100">{probPct}</span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
