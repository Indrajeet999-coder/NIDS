import React from 'react';
import { RefreshCw } from 'lucide-react';

export default function TopHeader({ health, healthLoading, onRefreshHealth, activeDataset }) {
  const isHealthy = health && health.status === 'healthy';
  const datasetName = activeDataset || health?.active_dataset || '5_mixed_enterprise_soc.csv';

  return (
    <header className="h-14 bg-[#060d1f] border-b border-[#1e3a5f] flex items-center justify-between px-6 relative overflow-hidden">
      {/* Top cyber wave glow */}
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-500/50 to-transparent" />
      <div className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-blue-900/60 to-transparent" />

      {/* Left: Title + Active Source Badge */}
      <div className="flex items-center gap-4">
        <div>
          <h1 className="text-sm font-bold text-white tracking-wide">Network Intrusion Detection System</h1>
          <p className="text-[10px] text-cyan-500/60 font-mono tracking-widest">Monitor • Analyze • Protect</p>
        </div>

        {/* Subtle active dataset source badge */}
        {datasetName && (
          <div className="hidden md:flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[10px] font-mono border bg-cyan-950/40 border-cyan-500/30 text-cyan-300 shadow-[0_0_10px_rgba(6,182,212,0.1)]">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
            <span className="text-gray-400 uppercase tracking-wider text-[9px]">Source:</span>
            <span className="font-semibold text-cyan-300 truncate max-w-[220px]" title={datasetName}>
              {datasetName}
            </span>
          </div>
        )}
      </div>

      {/* Right: Status + Avatar */}
      <div className="flex items-center gap-3">
        {/* System Online pill */}
        <div className={`flex items-center gap-1.5 rounded-full px-3 py-1 text-[10px] font-mono font-semibold border ${
          isHealthy
            ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
            : 'bg-rose-500/10 border-rose-500/30 text-rose-400'
        }`}>
          <span className="relative flex h-1.5 w-1.5">
            {isHealthy ? (
              <>
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-500" />
              </>
            ) : (
              <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-rose-500" />
            )}
          </span>
          {isHealthy ? 'System Online' : 'Offline'}
        </div>

        {/* Refresh */}
        <button
          onClick={onRefreshHealth}
          disabled={healthLoading}
          className="text-gray-500 hover:text-cyan-400 transition-colors"
          title="Refresh API health"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${healthLoading ? 'animate-spin text-cyan-400' : ''}`} />
        </button>

        {/* Avatar */}
        <div className="h-7 w-7 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-[10px] font-bold text-white border border-cyan-500/40 shadow-[0_0_8px_rgba(6,182,212,0.4)]">
          IS
        </div>
      </div>
    </header>
  );
}
