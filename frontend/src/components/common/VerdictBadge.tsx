import React from 'react';

interface VerdictBadgeProps {
  verdict?: string;
  size?: 'sm' | 'md' | 'lg';
}

export const VerdictBadge: React.FC<VerdictBadgeProps> = ({ verdict = 'unrated', size = 'md' }) => {
  const v = verdict.toLowerCase();

  const sizeClasses = {
    sm: 'px-2 py-0.5 text-xs',
    md: 'px-2.5 py-1 text-xs font-semibold',
    lg: 'px-3 py-1.5 text-sm font-bold',
  }[size];

  switch (v) {
    case 'phishing':
      return (
        <span className={`inline-flex items-center gap-1.5 rounded-full bg-rose-500/10 border border-rose-500/30 text-rose-400 ${sizeClasses}`}>
          <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse" />
          PHISHING
        </span>
      );
    case 'suspicious':
      return (
        <span className={`inline-flex items-center gap-1.5 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-400 ${sizeClasses}`}>
          <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
          SUSPICIOUS
        </span>
      );
    case 'legitimate':
      return (
        <span className={`inline-flex items-center gap-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 ${sizeClasses}`}>
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
          LEGITIMATE
        </span>
      );
    case 'queued':
      return (
        <span className={`inline-flex items-center gap-1.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 ${sizeClasses}`}>
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
          QUEUED
        </span>
      );
    default:
      return (
        <span className={`inline-flex items-center gap-1.5 rounded-full bg-slate-800 border border-slate-700 text-slate-400 ${sizeClasses}`}>
          <span className="w-1.5 h-1.5 rounded-full bg-slate-500" />
          UNRATED
        </span>
      );
  }
};
