import React from 'react';
import { EvidenceItem } from '../../types/api';
import { AlertTriangle, ShieldAlert } from 'lucide-react';

interface EvidenceListProps {
  evidence: EvidenceItem[];
}

export const EvidenceList: React.FC<EvidenceListProps> = ({ evidence }) => {
  if (!evidence || evidence.length === 0) {
    return (
      <div className="p-3 rounded-lg border border-cyber-border bg-cyber-950/40 text-[11px] font-mono text-slate-400 text-center">
        No anomalous heuristic threat indicators identified.
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <div className="text-[11px] font-mono uppercase text-slate-400 font-semibold tracking-wider">
        Identified Security Evidence ({evidence.length})
      </div>

      <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
        {evidence.slice(0, 6).map((item, idx) => {
          const isCritical = item.severity === 'critical' || item.severity === 'high';
          return (
            <div
              key={idx}
              className={`p-2 rounded-lg border text-xs font-mono flex items-start gap-2 ${
                isCritical
                  ? 'border-rose-500/30 bg-rose-950/30 text-rose-300'
                  : 'border-amber-500/30 bg-amber-950/30 text-amber-300'
              }`}
            >
              {isCritical ? (
                <ShieldAlert className="w-3.5 h-3.5 shrink-0 mt-0.5 text-rose-400" />
              ) : (
                <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5 text-amber-400" />
              )}
              <div className="space-y-0.5">
                <div className="font-semibold text-[11px]">{item.title}</div>
                <div className="text-[10px] opacity-80 leading-tight">{item.description}</div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
