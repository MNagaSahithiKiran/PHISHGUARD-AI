import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { History, Search, ArrowRight, RefreshCw, Filter, FileDown, ChevronLeft, ChevronRight } from 'lucide-react';
import { api } from '../services/api';
import { ScanSummaryItem } from '../types/scan';
import { VerdictBadge } from '../components/common/VerdictBadge';
import { EmptyState } from '../components/common/EmptyState';

export const ScanHistory: React.FC = () => {
  const navigate = useNavigate();
  const [scans, setScans] = useState<ScanSummaryItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [limit] = useState(15);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [verdictFilter, setVerdictFilter] = useState<string>('');

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const res = await api.listScans(
        page,
        limit,
        statusFilter || undefined,
        verdictFilter || undefined,
        search || undefined
      );
      setScans(res.items);
      setTotal(res.total);
    } catch (err) {
      console.error('Failed to load history:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [page, statusFilter, verdictFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchHistory();
  };

  const totalPages = Math.ceil(total / limit) || 1;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2 font-mono">
            <History className="w-6 h-6 text-cyan-400" />
            <span>SCAN AUDIT REPOSITORY</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Complete cryptographic audit trail of all inspected website targets, verdicts, and exportable intelligence.
          </p>
        </div>

        <div className="flex items-center gap-2 self-start sm:self-auto">
          <a
            href={api.getExportCsvUrl(statusFilter, verdictFilter)}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl border border-cyan-500/40 bg-cyan-950/40 hover:bg-cyan-900/50 text-cyan-300 text-xs font-mono transition-colors"
          >
            <FileDown className="w-4 h-4" />
            <span>Export CSV</span>
          </a>

          <button
            onClick={fetchHistory}
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-cyber-800 hover:bg-cyber-700 text-slate-300 text-xs font-mono transition-colors cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <form onSubmit={handleSearchSubmit} className="glass-panel p-4 rounded-2xl border border-cyber-border flex flex-col sm:flex-row gap-3 bg-cyber-900/60 shadow-lg">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-3" />
          <input
            type="text"
            placeholder="Search by domain or target URL..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-10 pr-4 py-2 rounded-xl bg-cyber-950/80 border border-cyber-border focus:border-cyan-500 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Verdict Filter */}
          <div className="flex items-center gap-1.5">
            <select
              value={verdictFilter}
              onChange={(e) => {
                setVerdictFilter(e.target.value);
                setPage(1);
              }}
              className="px-3 py-2 rounded-xl bg-cyber-950/80 border border-cyber-border text-xs font-mono text-slate-300 focus:border-cyan-500 focus:outline-none"
            >
              <option value="">All Verdicts</option>
              <option value="phishing">Phishing</option>
              <option value="suspicious">Suspicious</option>
              <option value="legitimate">Legitimate</option>
            </select>
          </div>

          {/* Status Filter */}
          <div className="flex items-center gap-1.5">
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setPage(1);
              }}
              className="px-3 py-2 rounded-xl bg-cyber-950/80 border border-cyber-border text-xs font-mono text-slate-300 focus:border-cyan-500 focus:outline-none"
            >
              <option value="">All Statuses</option>
              <option value="completed">Completed</option>
              <option value="queued">Queued</option>
              <option value="failed">Failed</option>
            </select>
          </div>

          <button
            type="submit"
            className="px-3.5 py-2 rounded-xl bg-cyber-800 hover:bg-cyber-700 text-cyan-300 text-xs font-mono transition-colors cursor-pointer"
          >
            Apply Filter
          </button>
        </div>
      </form>

      {/* Main Table */}
      {scans.length === 0 && !loading ? (
        <EmptyState
          title="No Historical Records Found"
          description="No website scans match the selected search criteria or filter configuration."
          actionLabel="Execute New Scan"
          onAction={() => navigate('/scanner')}
        />
      ) : (
        <div className="glass-panel rounded-2xl border border-cyber-border overflow-hidden bg-cyber-900/60 shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-cyber-border bg-cyber-950/80 text-slate-400 font-mono text-[11px] uppercase">
                  <th className="py-3 px-4 font-semibold">Target Domain &amp; URL</th>
                  <th className="py-3 px-4 font-semibold">Status</th>
                  <th className="py-3 px-4 font-semibold">Verdict</th>
                  <th className="py-3 px-4 font-semibold">Risk Score</th>
                  <th className="py-3 px-4 font-semibold">Timestamp</th>
                  <th className="py-3 px-4 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border/40 font-mono">
                {scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-cyber-800/40 transition-colors">
                    <td className="py-3.5 px-4 font-medium text-slate-200">
                      <div className="font-semibold text-white">{scan.domain}</div>
                      <div className="text-[10px] text-slate-400 truncate max-w-xs">{scan.url}</div>
                    </td>
                    <td className="py-3.5 px-4 text-cyan-400 uppercase text-[11px]">
                      {scan.status}
                    </td>
                    <td className="py-3.5 px-4">
                      <VerdictBadge verdict={scan.verdict} size="sm" />
                    </td>
                    <td className="py-3.5 px-4 font-bold">
                      {scan.risk_score !== null ? (
                        <span
                          className={
                            scan.risk_score > 66
                              ? 'text-rose-400'
                              : scan.risk_score > 25
                              ? 'text-amber-400'
                              : 'text-emerald-400'
                          }
                        >
                          {scan.risk_score.toFixed(1)}
                        </span>
                      ) : (
                        <span className="text-slate-500">—</span>
                      )}
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 text-[11px]">
                      {new Date(scan.created_at).toLocaleString()}
                    </td>
                    <td className="py-3.5 px-4 text-right space-x-2">
                      <a
                        href={api.getScanPdfUrl(scan.id)}
                        target="_blank"
                        rel="noreferrer"
                        title="Download Vector PDF Report"
                        className="p-1.5 rounded inline-block bg-cyber-800 hover:bg-cyber-700 text-slate-300 hover:text-cyan-300 text-xs transition-colors"
                      >
                        <FileDown className="w-3.5 h-3.5" />
                      </a>
                      <button
                        onClick={() => navigate(`/scans/${scan.id}`)}
                        className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-cyan-950 border border-cyan-800 hover:bg-cyan-900 text-cyan-300 text-xs transition-colors cursor-pointer"
                      >
                        <span>Details</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination Controls */}
          <div className="p-4 border-t border-cyber-border bg-cyber-950/60 text-xs font-mono text-slate-400 flex flex-col sm:flex-row items-center justify-between gap-3">
            <div>
              <span>Showing {scans.length} of {total} records</span>
              <span className="mx-2">|</span>
              <span>Page {page} of {totalPages}</span>
            </div>

            <div className="flex items-center gap-1.5">
              <button
                onClick={() => setPage((p) => Math.max(p - 1, 1))}
                disabled={page <= 1}
                className="p-1.5 rounded-lg border border-cyber-border hover:bg-cyber-800 disabled:opacity-30 disabled:cursor-not-allowed text-slate-300"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <button
                onClick={() => setPage((p) => Math.min(p + 1, totalPages))}
                disabled={page >= totalPages}
                className="p-1.5 rounded-lg border border-cyber-border hover:bg-cyber-800 disabled:opacity-30 disabled:cursor-not-allowed text-slate-300"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
