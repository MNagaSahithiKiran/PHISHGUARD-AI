import React from 'react';

interface RiskGaugeProps {
  score: number; // 0 to 100
  probability: number; // 0 to 1
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({ score, probability }) => {
  const clampedScore = Math.max(0, Math.min(100, Math.round(score)));
  const pct = (probability * 100).toFixed(1);

  // Determine color based on calibrated policy
  let color = '#10b981'; // green
  let glow = 'rgba(16, 185, 129, 0.3)';
  if (clampedScore > 66) {
    color = '#f43f5e'; // rose
    glow = 'rgba(244, 63, 94, 0.4)';
  } else if (clampedScore > 21) {
    color = '#f59e0b'; // amber
    glow = 'rgba(245, 158, 11, 0.4)';
  }

  return (
    <div className="p-3.5 rounded-xl border border-cyber-border bg-cyber-950/70 space-y-2.5">
      <div className="flex items-center justify-between text-xs font-mono">
        <span className="text-slate-400">Calibrated Risk Index</span>
        <span className="font-bold text-sm" style={{ color }}>
          {clampedScore} <span className="text-xs text-slate-500 font-normal">/ 100</span>
        </span>
      </div>

      {/* Progress Bar with glow */}
      <div className="w-full bg-cyber-900 rounded-full h-2.5 overflow-hidden p-0.5 border border-cyber-border/80">
        <div
          className="h-full rounded-full transition-all duration-700 ease-out"
          style={{
            width: `${clampedScore}%`,
            backgroundColor: color,
            boxShadow: `0 0 10px ${glow}`,
          }}
        />
      </div>

      <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 pt-0.5">
        <span>Estimated Phishing Probability</span>
        <span className="text-slate-200 font-semibold">{pct}%</span>
      </div>
    </div>
  );
};
