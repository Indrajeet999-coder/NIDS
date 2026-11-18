import React from 'react';
import {
  Activity,
  Cpu,
  Database,
  FileSpreadsheet,
  LayoutDashboard,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  Wifi,
  WifiOff,
} from 'lucide-react';

/**
 * Navbar — SOC Top Navigation & Telemetry Health Status Bar
 */
export default function Navbar({
  activeTab,
  setActiveTab,
  health,
  healthLoading,
  onRefreshHealth,
}) {
  const tabs = [
    {
      id: 'overview',
      label: 'Overview & Benchmarks',
      icon: LayoutDashboard,
      description: 'System KPIs, Model Comparisons & Confusion Matrix',
    },
    {
      id: 'csv',
      label: 'CSV Traffic Analyzer',
      icon: FileSpreadsheet,
      description: 'Batch file upload & multi-flow detection',
    },
    {
      id: 'simulator',
      label: 'Live Flow Simulator',
      icon: Sliders,
      description: 'Single packet parameter tuner & attack presets',
    },
    {
      id: 'audit',
      label: 'Audit Logs',
      icon: Database,
      description: 'Persistent SQLite detection stream',
    },
  ];

  const isHealthy = health && health.status === 'healthy';

  return (
    <header className="sticky top-0 z-40 border-b border-gray-800/80 bg-[#0b1120]/95 backdrop-blur-md">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="flex h-20 items-center justify-between gap-4">

          {/* Left: Brand Identity */}
          <div className="flex items-center gap-3">
            <div className="relative flex h-11 w-11 items-center justify-center rounded-xl bg-gradient-to-br from-sky-500/20 to-blue-600/10 border border-sky-500/30 text-sky-400 shadow-[0_0_15px_rgba(56,189,248,0.2)]">
              <ShieldCheck className="h-6 w-6 text-sky-400" />
              <div className="absolute -top-1 -right-1 h-2.5 w-2.5 rounded-full bg-emerald-500 animate-ping opacity-75" />
              <div className="absolute -top-1 -right-1 h-2.5 w-2.5 rounded-full bg-emerald-500" />
            </div>

            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-base font-extrabold tracking-wider text-gray-100">
                  NIDS <span className="text-sky-400">SEC-OPS</span>
                </span>
                <span className="rounded bg-sky-950/80 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-sky-400 border border-sky-800/50">
                  v1.0
                </span>
              </div>
              <p className="text-[11px] text-gray-400 font-mono tracking-tight">
                ML-Powered CICIDS2017 Classifier
              </p>
            </div>
          </div>

          {/* Center: Live API Engine Health Badge */}
          <div className="hidden lg:flex items-center gap-2">
            <div
              className={`flex items-center gap-3 rounded-full px-4 py-1.5 text-xs font-mono border transition-all ${isHealthy
                  ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-300 shadow-[0_0_12px_rgba(16,185,129,0.15)]'
                  : 'bg-rose-950/40 border-rose-500/30 text-rose-300 shadow-[0_0_12px_rgba(244,63,94,0.15)]'
                }`}
            >
              <div className="flex items-center gap-2">
                <span className="relative flex h-2.5 w-2.5">
                  {isHealthy ? (
                    <>
                      <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
                      <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-emerald-500" />
                    </>
                  ) : (
                    <>
                      <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-rose-400 opacity-75" />
                      <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-rose-500" />
                    </>
                  )}
                </span>
                <span className="font-semibold">
                  {isHealthy ? 'Connected' : 'Disconnected'}
                </span>
              </div>

              <span className="text-gray-600">|</span>

              <div className="flex items-center gap-1.5 text-gray-300">
                <Cpu className="h-3.5 w-3.5 text-sky-400" />
                <span>{health?.model_name || 'XGBoost'}</span>
              </div>

              <span className="text-gray-600">|</span>

              <div className="flex items-center gap-1.5 text-gray-300">
                <Activity className="h-3.5 w-3.5 text-emerald-400" />
                <span>{health?.expected_feature_count ? `${health.expected_feature_count} Features` : '25 Features'}</span>
              </div>

              <button
                onClick={onRefreshHealth}
                title="Ping Backend API"
                className="ml-1 text-gray-400 hover:text-sky-400 transition-colors p-1"
                disabled={healthLoading}
              >
                <RefreshCw className={`h-3.5 w-3.5 ${healthLoading ? 'animate-spin text-sky-400' : ''}`} />
              </button>
            </div>
          </div>

          {/* Right: Navigation Tabs */}
          <nav className="flex items-center gap-1 rounded-xl bg-[#111827] p-1 border border-gray-800">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-medium transition-all ${isActive
                      ? 'bg-sky-500 text-slate-950 font-bold shadow-[0_0_15px_rgba(56,189,248,0.4)]'
                      : 'text-gray-400 hover:bg-gray-800/60 hover:text-gray-200'
                    }`}
                  title={tab.description}
                >
                  <Icon className={`h-4 w-4 ${isActive ? 'text-slate-950' : 'text-gray-400'}`} />
                  <span className="hidden md:inline">{tab.label}</span>
                </button>
              );
            })}
          </nav>

        </div>

        {/* Mobile Health Bar (Only visible on small screens) */}
        <div className="lg:hidden pb-3 pt-1 flex items-center justify-between text-xs font-mono text-gray-400 border-t border-gray-800/40">
          <div className="flex items-center gap-2">
            <span className={`inline-block h-2 w-2 rounded-full ${isHealthy ? 'bg-emerald-500' : 'bg-rose-500'}`} />
            <span>{isHealthy ? 'API Online' : 'API Offline'}</span>
            <span>•</span>
            <span>{health?.model_name || 'XGBoost'}</span>
            <span>•</span>
            <span>{health?.expected_feature_count || 25} Features</span>
          </div>
          <button
            onClick={onRefreshHealth}
            className="text-sky-400 text-[11px] underline flex items-center gap-1"
          >
            <RefreshCw className={`h-3 w-3 ${healthLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

      </div>
    </header>
  );
}

