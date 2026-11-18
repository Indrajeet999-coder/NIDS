import React from 'react';
import { Shield, Activity, BarChart2, Cpu, FileSpreadsheet, History, BarChart3 } from 'lucide-react';

const NAV_TABS = [
  { id: 'overview', label: 'Overview', icon: BarChart2 },
  { id: 'traffic', label: 'Traffic Analysis', icon: Activity },
  { id: 'simulator', label: 'Intrusion Detection', icon: Cpu },
  { id: 'csv', label: 'CSV Analyzer', icon: FileSpreadsheet },
  { id: 'model', label: 'Model Analytics', icon: BarChart3 },
  { id: 'history', label: 'Detection History', icon: History },
];

// Cyan Cyber Network Globe SVG
function CyberGlobe() {
  return (
    <div className="relative w-full flex justify-center items-end pb-2 pt-4">
      <svg width="140" height="140" viewBox="0 0 140 140" fill="none" xmlns="http://www.w3.org/2000/svg">
        {/* Outer glow circle */}
        <circle cx="70" cy="70" r="60" stroke="rgba(6,182,212,0.15)" strokeWidth="1" fill="none" />
        <circle cx="70" cy="70" r="55" stroke="rgba(6,182,212,0.08)" strokeWidth="0.5" fill="rgba(6,182,212,0.02)" />
        
        {/* Globe meridians */}
        <ellipse cx="70" cy="70" rx="40" ry="40" stroke="rgba(6,182,212,0.3)" strokeWidth="0.8" fill="none" />
        <ellipse cx="70" cy="70" rx="20" ry="40" stroke="rgba(6,182,212,0.2)" strokeWidth="0.6" fill="none" />
        <ellipse cx="70" cy="70" rx="40" ry="15" stroke="rgba(6,182,212,0.2)" strokeWidth="0.6" fill="none" />
        <ellipse cx="70" cy="70" rx="40" ry="30" stroke="rgba(6,182,212,0.15)" strokeWidth="0.5" fill="none" />
        
        {/* Rotating orbit ring */}
        <g className="globe-orbit">
          <ellipse cx="70" cy="70" rx="55" ry="18" stroke="rgba(6,182,212,0.4)" strokeWidth="1" strokeDasharray="4 3" fill="none" />
          <circle cx="125" cy="70" r="3" fill="#06b6d4" />
        </g>
        
        {/* Reverse orbit */}
        <g className="globe-orbit-reverse">
          <ellipse cx="70" cy="70" rx="18" ry="55" stroke="rgba(99,102,241,0.3)" strokeWidth="0.8" strokeDasharray="3 4" fill="none" />
          <circle cx="70" cy="15" r="2" fill="#818cf8" />
        </g>
        
        {/* Network nodes */}
        <circle cx="70" cy="30" r="2.5" fill="#06b6d4" opacity="0.9" />
        <circle cx="40" cy="55" r="2" fill="#06b6d4" opacity="0.7" />
        <circle cx="100" cy="55" r="2" fill="#06b6d4" opacity="0.7" />
        <circle cx="55" cy="85" r="1.5" fill="#22d3ee" opacity="0.8" />
        <circle cx="85" cy="85" r="1.5" fill="#22d3ee" opacity="0.8" />
        <circle cx="70" cy="100" r="2" fill="#06b6d4" opacity="0.6" />
        <circle cx="70" cy="70" r="6" fill="rgba(6,182,212,0.3)" stroke="#06b6d4" strokeWidth="1.5" />
        
        {/* Network connections */}
        <line x1="70" y1="30" x2="40" y2="55" stroke="rgba(6,182,212,0.3)" strokeWidth="0.5" />
        <line x1="70" y1="30" x2="100" y2="55" stroke="rgba(6,182,212,0.3)" strokeWidth="0.5" />
        <line x1="40" y1="55" x2="70" y2="70" stroke="rgba(6,182,212,0.25)" strokeWidth="0.5" />
        <line x1="100" y1="55" x2="70" y2="70" stroke="rgba(6,182,212,0.25)" strokeWidth="0.5" />
        <line x1="70" y1="70" x2="55" y2="85" stroke="rgba(6,182,212,0.25)" strokeWidth="0.5" />
        <line x1="70" y1="70" x2="85" y2="85" stroke="rgba(6,182,212,0.25)" strokeWidth="0.5" />
        <line x1="55" y1="85" x2="70" y2="100" stroke="rgba(6,182,212,0.2)" strokeWidth="0.5" />
        <line x1="85" y1="85" x2="70" y2="100" stroke="rgba(6,182,212,0.2)" strokeWidth="0.5" />
        
        {/* Bottom label */}
        <text x="70" y="130" textAnchor="middle" fill="rgba(6,182,212,0.5)" fontSize="8" fontFamily="monospace">GLOBAL MONITOR</text>
      </svg>
    </div>
  );
}

export default function Sidebar({ activeTab, setActiveTab, isHealthy }) {
  return (
    <aside className="flex flex-col h-screen w-56 bg-[#060d1f] border-r border-[#1e3a5f] fixed left-0 top-0 z-30">
      {/* Brand Logo */}
      <div className="px-4 py-5 border-b border-[#1e3a5f]">
        <div className="flex items-center gap-2.5">
          <div className="relative flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-700/20 border border-cyan-500/40 shadow-[0_0_15px_rgba(6,182,212,0.3)]">
            <Shield className="h-5 w-5 text-cyan-400" />
            <span className="absolute -top-0.5 -right-0.5 h-2 w-2 rounded-full bg-emerald-500 animate-ping opacity-75" />
            <span className="absolute -top-0.5 -right-0.5 h-2 w-2 rounded-full bg-emerald-500" />
          </div>
          <div>
            <div className="text-base font-extrabold tracking-widest text-white font-mono" style={{textShadow:'0 0 15px rgba(6,182,212,0.5)'}}>NIDS</div>
            <div className="text-[9px] text-cyan-400/70 font-mono tracking-widest uppercase">Network Security Platform</div>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-2 py-4 space-y-1 overflow-y-auto">
        {NAV_TABS.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-medium transition-all duration-200 text-left ${
                isActive
                  ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-[0_0_10px_rgba(6,182,212,0.15)]'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-white/5 border border-transparent'
              }`}
            >
              <Icon className={`h-4 w-4 flex-shrink-0 ${isActive ? 'text-cyan-400' : 'text-gray-500'}`} />
              <span className={isActive ? 'font-semibold' : ''}>{tab.label}</span>
              {isActive && <span className="ml-auto h-1.5 w-1.5 rounded-full bg-cyan-400" />}
            </button>
          );
        })}
      </nav>

      {/* Bottom: System Status + Globe */}
      <div className="border-t border-[#1e3a5f]">
        {/* Status Box */}
        <div className="mx-2 my-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 px-3 py-2">
          <div className="flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
            </span>
            <span className="text-[10px] font-semibold text-emerald-400 font-mono">System Online</span>
          </div>
          <p className="mt-0.5 text-[9px] text-emerald-500/70 font-mono">All Systems Operational</p>
        </div>

        {/* Cyber Globe */}
        <CyberGlobe />
      </div>
    </aside>
  );
}
