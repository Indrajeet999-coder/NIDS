import React, { useState, useEffect } from 'react';
import {
  Database,
  Trash2,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  FileSpreadsheet,
  Cpu,
  Layers,
  AlertTriangle,
  Clock,
} from 'lucide-react';
import { getHistory, deleteHistory } from '../api';

export default function DetectionHistoryView({ onNotify }) {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [deleting, setDeleting] = useState(false);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const data = await getHistory(100);
      setLogs(data.logs || []);
    } catch (err) {
      if (onNotify) {
        onNotify('error', 'History Load Failed', err.message);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  const handleClearHistory = async () => {
    if (!window.confirm('Clear all detection history? This cannot be undone.')) return;
    setDeleting(true);
    try {
      await deleteHistory();
      setLogs([]);
      if (onNotify) {
        onNotify('success', 'History Cleared', 'All detection logs have been removed.');
      }
    } catch (err) {
      if (onNotify) {
        onNotify('error', 'Clear Failed', err.message);
      }
    } finally {
      setDeleting(false);
    }
  };

  // Computed metrics
  const totalAuditEvents = logs.length;
  const totalInspectedFlows = logs.reduce((acc, l) => acc + (l.total_flows || 0), 0);
  const interceptedIntrusions = logs.reduce((acc, l) => acc + (l.intrusion_count || 0), 0);
  const normalFlows = logs.reduce((acc, l) => acc + (l.normal_count || 0), 0);

  // Filtered logs
  const filteredLogs = logs.filter((log) => {
    const q = searchQuery.toLowerCase();
    const source = (log.source_type || '').toLowerCase();
    const summary = (log.summary_json || '').toLowerCase();
    const idStr = String(log.id);
    return source.includes(q) || summary.includes(q) || idStr.includes(q);
  });

  const cardStyle = 'bg-[#0d182e] border border-[#1e3a5f] rounded-xl p-5 shadow-lg';

  const parseSummary = (jsonStr) => {
    if (!jsonStr) return null;
    try {
      return JSON.parse(jsonStr);
    } catch {
      return null;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#1e3a5f] pb-5">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-white font-mono">
              Detection History
            </h1>
            <span className="rounded-full bg-cyan-500/10 px-2.5 py-0.5 text-xs font-semibold text-cyan-400 border border-cyan-500/30">
              SQLite Audit Log
            </span>
          </div>
          <p className="mt-1 text-xs text-gray-400">
            Forensic Audit Stream — Persistent SQLite Record of Every Evaluated Network Flow & Batch File
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={fetchLogs}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#0d182e] border border-[#1e3a5f] text-xs text-cyan-300 hover:bg-cyan-500/10 transition-colors"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>
          <button
            onClick={handleClearHistory}
            disabled={deleting || logs.length === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs text-rose-400 hover:bg-rose-500/20 disabled:opacity-40 transition-colors"
          >
            <Trash2 size={13} />
            <span>Clear History</span>
          </button>
        </div>
      </div>

      {/* Row 1: 4 KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Audit Events */}
        <div className={cardStyle}>
          <div className="flex items-center justify-between text-gray-400 text-xs">
            <span>Total Audit Events</span>
            <Database size={16} className="text-cyan-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-white">
            {totalAuditEvents.toLocaleString()}
          </div>
          <p className="mt-1 text-[11px] text-gray-500">Recorded sessions in SQLite</p>
        </div>

        {/* Inspected Flows */}
        <div className={cardStyle}>
          <div className="flex items-center justify-between text-gray-400 text-xs">
            <span>Inspected Flows</span>
            <Layers size={16} className="text-sky-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-sky-400">
            {totalInspectedFlows.toLocaleString()}
          </div>
          <p className="mt-1 text-[11px] text-gray-500">Cumulative packet flow records</p>
        </div>

        {/* Intercepted Intrusions */}
        <div className={`${cardStyle} border-rose-900/40`}>
          <div className="flex items-center justify-between text-gray-400 text-xs">
            <span>Intercepted Intrusions</span>
            <ShieldAlert size={16} className="text-rose-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-rose-400">
            {interceptedIntrusions.toLocaleString()}
          </div>
          <p className="mt-1 text-[11px] text-rose-500/70">Flagged malicious attack flows</p>
        </div>

        {/* Normal Flows */}
        <div className={`${cardStyle} border-emerald-900/40`}>
          <div className="flex items-center justify-between text-gray-400 text-xs">
            <span>Normal Traffic</span>
            <ShieldCheck size={16} className="text-emerald-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-emerald-400">
            {normalFlows.toLocaleString()}
          </div>
          <p className="mt-1 text-[11px] text-emerald-500/70">Verified benign flows</p>
        </div>
      </div>

      {/* Forensic Audit Log Table Card */}
      <div className={cardStyle}>
        {/* Controls row */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pb-4 border-b border-[#1e3a5f]">
          <div className="relative w-full sm:w-72">
            <Search size={14} className="absolute left-3 top-2.5 text-gray-400" />
            <input
              type="text"
              placeholder="Search by ID, source, or metadata..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-[#060d1f] border border-[#1e3a5f] rounded-lg pl-9 pr-3 py-1.5 text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <div className="text-xs text-gray-400 font-mono self-end sm:self-center">
            Showing <span className="text-cyan-300 font-semibold">{filteredLogs.length}</span> of {logs.length} records
          </div>
        </div>

        {/* Table / Empty State */}
        {filteredLogs.length === 0 ? (
          <div className="py-16 text-center">
            <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 mb-3">
              <Database size={24} />
            </div>
            <h3 className="text-sm font-semibold text-gray-200">No Detection Logs Found</h3>
            <p className="text-xs text-gray-500 mt-1 max-w-sm mx-auto">
              {searchQuery
                ? 'No audit records match your search criteria. Try a different query.'
                : 'Run an inference in the Live Simulator or CSV Analyzer to populate persistent forensic logs.'}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto mt-4">
            <table className="w-full text-xs text-left">
              <thead>
                <tr className="bg-[#060d1f] text-cyan-400/70 uppercase text-[10px] tracking-wider font-mono">
                  <th className="py-2.5 px-3">ID</th>
                  <th className="py-2.5 px-3">Timestamp (UTC)</th>
                  <th className="py-2.5 px-3">Source</th>
                  <th className="py-2.5 px-3 text-right">Flows</th>
                  <th className="py-2.5 px-3 text-right">Intrusions</th>
                  <th className="py-2.5 px-3 text-right">Normal</th>
                  <th className="py-2.5 px-3 text-right">Confidence</th>
                  <th className="py-2.5 px-3">Context / Metadata</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e3a5f]/40 font-mono">
                {filteredLogs.map((log) => {
                  const summary = parseSummary(log.summary_json);
                  const isCsv = log.source_type === 'csv_upload' || log.source_type === 'sample_file';
                  const hasIntrusions = (log.intrusion_count || 0) > 0;

                  return (
                    <tr
                      key={log.id}
                      className="hover:bg-[#060d1f]/60 transition-colors text-gray-300"
                    >
                      <td className="py-2.5 px-3 text-cyan-400 font-bold">#{log.id}</td>
                      <td className="py-2.5 px-3 text-gray-400 whitespace-nowrap text-[11px]">
                        {log.timestamp ? log.timestamp.replace('T', ' ').slice(0, 19) : '—'}
                      </td>
                      <td className="py-2.5 px-3">
                        {isCsv ? (
                          <span className="inline-flex items-center gap-1 rounded bg-blue-500/10 px-2 py-0.5 text-[10px] font-semibold text-blue-400 border border-blue-500/30">
                            <FileSpreadsheet size={10} />
                            {log.source_type === 'sample_file' ? 'Sample CSV' : 'CSV Upload'}
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 rounded bg-purple-500/10 px-2 py-0.5 text-[10px] font-semibold text-purple-400 border border-purple-500/30">
                            <Cpu size={10} />
                            Single Flow
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-3 text-right text-gray-200">
                        {log.total_flows?.toLocaleString()}
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        {hasIntrusions ? (
                          <span className="text-rose-400 font-bold">
                            {log.intrusion_count?.toLocaleString()}
                          </span>
                        ) : (
                          <span className="text-gray-500">0</span>
                        )}
                      </td>
                      <td className="py-2.5 px-3 text-right text-emerald-400 font-medium">
                        {log.normal_count?.toLocaleString()}
                      </td>
                      <td className="py-2.5 px-3 text-right text-cyan-300">
                        {log.max_confidence ? `${(log.max_confidence * 100).toFixed(1)}%` : '—'}
                      </td>
                      <td className="py-2.5 px-3 text-[11px] text-gray-400 max-w-xs truncate">
                        {summary ? (
                          isCsv ? (
                            <span>
                              File: <span className="text-gray-200">{summary.filename || summary.source || 'batch.csv'}</span>
                              {summary.inference_time_ms ? ` (${summary.inference_time_ms} ms)` : ''}
                            </span>
                          ) : (
                            <span>
                              Verdict: <span className={summary.prediction === 'Intrusion' ? 'text-rose-400 font-semibold' : 'text-emerald-400 font-semibold'}>{summary.prediction}</span>
                              {summary.destination_port ? ` (Port ${summary.destination_port})` : ''}
                              {summary.risk_level ? ` • ${summary.risk_level} Risk` : ''}
                            </span>
                          )
                        ) : (
                          <span className="text-gray-600">N/A</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

