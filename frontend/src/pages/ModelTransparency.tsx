import React, { useEffect, useState } from 'react';
import {
  Cpu,
  Layers,
  CheckCircle,
  AlertTriangle,
  HelpCircle,
  FileCheck,
  ShieldCheck,
  BarChart2,
  Eye,
  Terminal,
} from 'lucide-react';
import { api } from '../services/api';
import { ModelCard } from '../types/scan';

export const ModelTransparency: React.FC = () => {
  const [modelCards, setModelCards] = useState<ModelCard[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<string>('multimodal_fusion_stacking_v1');

  const fetchModelCards = () => {
    setLoading(true);
    setError(null);
    api.getModelTransparency()
      .then((data) => {
        setModelCards(data.registered_models);
        if (data.registered_models.length > 0) {
          setActiveTab(data.registered_models[3]?.model_id || data.registered_models[0].model_id);
        }
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchModelCards();
  }, []);

  const activeModel = modelCards.find((m) => m.model_id === activeTab) || modelCards[0];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950/80 text-cyan-300 border border-cyan-800/60 uppercase">
              Production AI Architecture
            </span>
            <span className="text-xs text-slate-400 font-mono">Isolated Domain Holdout Validation</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white font-mono flex items-center gap-3">
            <Cpu className="w-6 h-6 text-cyan-400" />
            AI MODEL TRANSPARENCY & MODEL CARDS
          </h1>
          <p className="text-xs text-slate-400 max-w-3xl">
            Detailed operational documentation of model architectures, dataset splits, cross-modality ablation
            benchmarks, and explainability mechanisms (TreeSHAP &amp; Grad-CAM) deployed in the PhishGuard AI engine.
          </p>
        </div>
      </div>

      {loading ? (
        <div className="glass-panel p-12 text-center text-slate-400 font-mono text-sm animate-pulse rounded-2xl border border-cyber-border">
          Loading AI Model Cards and Architecture Metadata...
        </div>
      ) : error ? (
        <div className="p-6 rounded-xl border border-rose-500/30 bg-rose-950/40 text-rose-300 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
          <button
            onClick={fetchModelCards}
            className="px-4 py-2 bg-rose-500/20 hover:bg-rose-500/30 text-rose-200 border border-rose-500/40 rounded-lg font-mono text-xs cursor-pointer transition-colors"
          >
            Retry Connection
          </button>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Model Selector Tabs */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            {modelCards.map((card) => {
              const isSelected = card.model_id === activeTab;
              return (
                <button
                  key={card.model_id}
                  onClick={() => setActiveTab(card.model_id)}
                  className={`p-4 rounded-xl border text-left transition-all cursor-pointer ${
                    isSelected
                      ? 'border-cyan-500 bg-cyan-950/40 shadow-lg shadow-cyan-950/50 ring-1 ring-cyan-500/30'
                      : 'border-cyber-border bg-cyber-900/60 hover:bg-cyber-800/50 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyber-950 text-slate-300 border border-cyber-border">
                      {card.modality}
                    </span>
                    {isSelected && <CheckCircle className="w-3.5 h-3.5 text-cyan-400" />}
                  </div>
                  <div className="text-sm font-semibold text-slate-100 font-mono truncate">{card.name}</div>
                  <div className="text-[11px] text-slate-400 mt-1 line-clamp-1">{card.architecture}</div>
                </button>
              );
            })}
          </div>

          {/* Active Model Card Details */}
          {activeModel && (
            <div className="glass-panel rounded-2xl border border-cyber-border p-6 sm:p-8 space-y-6 bg-cyber-900/70">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-6 border-b border-cyber-border">
                <div>
                  <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-1">
                    <Layers className="w-3.5 h-3.5" />
                    <span>ID: {activeModel.model_id}</span>
                  </div>
                  <h2 className="text-xl font-bold text-white font-mono">{activeModel.name}</h2>
                  <p className="text-xs text-slate-400 mt-1">{activeModel.intended_use}</p>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <span className="px-3 py-1 rounded-lg text-xs font-mono font-semibold bg-emerald-950/60 text-emerald-400 border border-emerald-800/60 flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                    Production Ready
                  </span>
                </div>
              </div>

              {/* Grid Specifications */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Column 1: Architecture & Data Provenance */}
                <div className="space-y-4">
                  <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-2">
                    <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                    Architecture & Data Split
                  </h3>

                  <div className="p-4 rounded-xl border border-cyber-border bg-cyber-950/60 space-y-3">
                    <div>
                      <div className="text-[11px] text-slate-400 font-mono">Neural / ML Architecture</div>
                      <div className="text-sm text-slate-200 font-medium mt-0.5">{activeModel.architecture}</div>
                    </div>
                    <div>
                      <div className="text-[11px] text-slate-400 font-mono">Input Dimension</div>
                      <div className="text-sm text-cyan-400 font-mono mt-0.5">
                        {activeModel.input_features_count.toLocaleString()} features
                      </div>
                    </div>
                    <div>
                      <div className="text-[11px] text-slate-400 font-mono">Dataset Provenance</div>
                      <div className="text-xs text-slate-300 mt-0.5 leading-relaxed">{activeModel.training_data_provenance}</div>
                    </div>
                    <div>
                      <div className="text-[11px] text-slate-400 font-mono">Holdout Partition Strategy</div>
                      <div className="text-xs text-slate-300 mt-0.5 leading-relaxed">{activeModel.domain_split_methodology}</div>
                    </div>
                  </div>
                </div>

                {/* Column 2: Performance Metrics */}
                <div className="space-y-4">
                  <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-2">
                    <BarChart2 className="w-3.5 h-3.5 text-cyan-400" />
                    Empirical Evaluation Metrics
                  </h3>

                  <div className="p-4 rounded-xl border border-cyber-border bg-cyber-950/60 space-y-2.5">
                    {Object.entries(activeModel.metrics).map(([key, value]) => {
                      const displayKey = key.replace(/_/g, ' ').toUpperCase();
                      const isObj = typeof value === 'object' && value !== null;
                      return (
                        <div key={key} className="flex items-center justify-between py-1 border-b border-cyber-border/50 last:border-none">
                          <span className="text-xs font-mono text-slate-400">{displayKey}</span>
                          <span className="text-xs font-mono font-bold text-slate-100">
                            {isObj ? JSON.stringify(value) : typeof value === 'number' ? (value < 1 ? value.toFixed(4) : value) : String(value)}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>

              {/* Explainability & Limitations */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-4 border-t border-cyber-border">
                {/* Explainability */}
                <div className="space-y-3">
                  <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-2">
                    <Eye className="w-3.5 h-3.5 text-cyan-400" />
                    Explainability & Interpretation Methods
                  </h3>
                  <div className="space-y-2">
                    {activeModel.explainability_methods.map((method, idx) => (
                      <div key={idx} className="p-3 rounded-lg border border-cyan-500/20 bg-cyan-950/20 text-xs text-cyan-300 font-mono flex items-center gap-2">
                        <FileCheck className="w-3.5 h-3.5 shrink-0" />
                        <span>{method}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Limitations */}
                <div className="space-y-3">
                  <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-2">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                    Known Limitations & Operational Boundaries
                  </h3>
                  <div className="space-y-2">
                    {activeModel.limitations.map((lim, idx) => (
                      <div key={idx} className="p-3 rounded-lg border border-amber-500/20 bg-amber-950/20 text-xs text-amber-300 font-mono flex items-center gap-2">
                        <AlertTriangle className="w-3.5 h-3.5 shrink-0 text-amber-400" />
                        <span>{lim}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
