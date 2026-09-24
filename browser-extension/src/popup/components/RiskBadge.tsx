import React from 'react';
import { Verdict } from '../../types/api';
import { ShieldCheck, AlertTriangle, ShieldAlert, HelpCircle } from 'lucide-react';

interface RiskBadgeProps {
  verdict: Verdict;
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({ verdict }) => {
  if (verdict === 'PHISHING') {
    return (
      <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold bg-rose-950/90 text-rose-300 border border-rose-600/80 shadow-sm shadow-rose-950">
        <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
        <span>PHISHING DETECTED</span>
      </div>
    );
  }

  if (verdict === 'SUSPICIOUS') {
    return (
      <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold bg-amber-950/90 text-amber-300 border border-amber-600/80 shadow-sm shadow-amber-950">
        <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
        <span>SUSPICIOUS TARGET</span>
      </div>
    );
  }

  if (verdict === 'LEGITIMATE') {
    return (
      <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold bg-emerald-950/90 text-emerald-300 border border-emerald-600/80 shadow-sm shadow-emerald-950">
        <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
        <span>LEGITIMATE WEBSITE</span>
      </div>
    );
  }

  return (
    <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold bg-slate-900 text-slate-300 border border-slate-700">
      <HelpCircle className="w-3.5 h-3.5 text-slate-400" />
      <span>UNRATED</span>
    </div>
  );
};
