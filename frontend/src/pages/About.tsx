import React from 'react';
import { BookOpen, Shield, Cpu, Layers } from 'lucide-react';

export const About: React.FC = () => {
  return (
    <div className="space-y-8 max-w-5xl mx-auto">
      {/* Header Banner */}
      <div className="glass-panel p-6 md:p-8 rounded-2xl border-cyan-500/30 space-y-4">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <span className="text-xs font-mono uppercase tracking-wider text-cyan-400 font-bold">
              Enterprise Cyber Defense Platform
            </span>
            <h1 className="text-2xl md:text-3xl font-extrabold text-white">
              PHISHGUARD AI: Intelligent Phishing Detection
            </h1>
          </div>
        </div>
        <p className="text-slate-300 text-sm leading-relaxed max-w-3xl">
          An enterprise-grade, multi-modal cybersecurity platform engineered to detect sophisticated phishing,
          homograph spoofing, and credential harvesting campaigns by harmonizing URL lexical analysis,
          domain telemetry, sandboxed DOM inspection, and Explainable Machine Learning (XAI).
        </p>
      </div>

      {/* Overview & Objectives Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="glass-panel p-6 rounded-xl border-cyber-border space-y-3">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <BookOpen className="w-5 h-5 text-cyan-400" />
            <span>Platform Overview</span>
          </h2>
          <p className="text-xs text-slate-300 leading-relaxed">
            Legacy phishing defenses rely predominantly on static blacklists, leaving internet users vulnerable
            during zero-hour windows. PhishGuard AI addresses this vulnerability by formulating phishing detection
            as a multi-feature classification problem over four orthogonal feature spaces: lexical syntax, domain
            registration topology, DOM element distribution, and visual brand identity.
          </p>
        </div>

        <div className="glass-panel p-6 rounded-xl border-cyber-border space-y-3">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <Layers className="w-5 h-5 text-cyan-400" />
            <span>Platform Capabilities</span>
          </h2>
          <ul className="text-xs text-slate-300 space-y-2 list-disc list-inside">
            <li>Eliminate Server-Side Request Forgery (SSRF) vulnerabilities via SSRFGuard DNS pre-resolution.</li>
            <li>Execute deterministic, 34+ feature lexical and Shannon entropy extraction.</li>
            <li>Maintain auditable transactional scanning records using PostgreSQL/SQLite and SQLAlchemy 2.0.</li>
            <li>Deliver transparent explainability via TreeSHAP feature attributions and Grad-CAM visual heatmaps.</li>
          </ul>
        </div>
      </div>

      {/* Technical Methodology */}
      <div className="glass-panel p-6 rounded-xl border-cyber-border space-y-4">
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <Cpu className="w-5 h-5 text-cyan-400" />
          <span>System Pipeline & Classification Methodology</span>
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
          <div className="p-4 rounded-xl bg-cyber-950/80 border border-cyber-border space-y-1">
            <span className="text-cyan-400 font-bold">STAGE 1</span>
            <div className="text-white font-semibold">SSRF Guard & Parse</div>
            <p className="text-slate-400 text-[11px] font-sans">
              DNS pre-resolution to block loopback, RFC 1918 subnets, and cloud metadata.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-cyber-950/80 border border-cyber-border space-y-1">
            <span className="text-cyan-400 font-bold">STAGE 2</span>
            <div className="text-white font-semibold">Lexical Feature Vector</div>
            <p className="text-slate-400 text-[11px] font-sans">
              Shannon entropy, dot/hyphen distributions, Punycode detection, and shortener tracking.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-cyber-950/80 border border-cyber-border space-y-1">
            <span className="text-cyan-400 font-bold">STAGE 3</span>
            <div className="text-white font-semibold">Isolated Crawling</div>
            <p className="text-slate-400 text-[11px] font-sans">
              Sandboxed Playwright headless worker rendering DOM and screenshots safely.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-cyber-950/80 border border-cyber-border space-y-1">
            <span className="text-cyan-400 font-bold">STAGE 4</span>
            <div className="text-white font-semibold">ML & SHAP Explainability</div>
            <p className="text-slate-400 text-[11px] font-sans">
              XGBoost ensemble inference with feature contribution waterfalls for security analysts.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
