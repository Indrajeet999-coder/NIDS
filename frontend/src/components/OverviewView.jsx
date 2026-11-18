import React, { useState, useEffect } from 'react';
import { ShieldCheck, AlertTriangle, Target, Activity } from 'lucide-react';
import { getDashboardTelemetry, formatDuration } from '../api';

// ---------------------------------------------------------------------------
// Fallback data (used when API is unavailable)
// ---------------------------------------------------------------------------
const FALLBACK = {
  kpi: {
    total_packets_analyzed: 120000,
    normal_traffic_count: 99550,
    normal_percent: 82.96,
    intrusions_detected: 20450,
    intrusion_percent: 17.04,
    detection_rate: 99.38,
    avg_packet_size_bytes: 342.1,
    avg_duration_sec: 0.482,
    total_connections: 285430,
  },
  traffic_series: Array.from({ length: 12 }, (_, i) => ({
    time: `${String(i * 2).padStart(2, '0')}:00`,
    normal: 7000 + Math.floor(i * 300),
    intrusion: 500 + Math.floor(i * 150),
  })),
  live_sample_flows: Array.from({ length: 10 }, (_, i) => ({
    packet_size_bytes: 100 + i * 80,
    protocol: ['TCP', 'UDP', 'ICMP'][i % 3],
    duration_sec: parseFloat((0.1 + i * 0.3).toFixed(3)),
    connections: 1 + i * 4,
    source_ip: `192.168.1.${10 + i}`,
    destination_ip: `172.217.10.${10 + i}`,
    prediction: i % 4 === 0 ? 'Intrusion' : 'Normal',
    confidence: 0.95,
    attack_type: i % 4 === 0 ? 'DDoS Attack Pattern' : 'Normal Traffic',
  })),
  recent_alerts: [
    { attack_type: 'DDoS Attack Pattern',       prediction: 'Intrusion', source_ip: '192.168.1.44', timestamp: '2 min ago'  },
    { attack_type: 'Port Scan Activity',         prediction: 'Intrusion', source_ip: '192.168.1.78', timestamp: '5 min ago'  },
    { attack_type: 'Normal Traffic',             prediction: 'Normal',    source_ip: '192.168.1.21', timestamp: '7 min ago'  },
    { attack_type: 'Brute Force Attempt',        prediction: 'Intrusion', source_ip: '192.168.1.99', timestamp: '11 min ago' },
    { attack_type: 'Normal Traffic',             prediction: 'Normal',    source_ip: '192.168.1.14', timestamp: '15 min ago' },
    { attack_type: 'Anomalous Flow Intrusion',   prediction: 'Intrusion', source_ip: '192.168.1.55', timestamp: '18 min ago' },
  ],
};

// ---------------------------------------------------------------------------
// AreaChart – SVG area chart for traffic series
// ---------------------------------------------------------------------------
function AreaChart({ data }) {
  const W = 600, H = 200, PAD = 30;
  const maxV = Math.max(1, ...data.map(d => d.normal + d.intrusion));

  const pts = (key) =>
    data.map((d, i) => [
      PAD + (i * (W - 2 * PAD)) / (data.length - 1),
      H - PAD - (d[key] / maxV) * (H - 2 * PAD),
    ]);

  const pathStr = (points) =>
    points.map((p, i) => `${i === 0 ? 'M' : 'L'}${p[0]},${p[1]}`).join(' ');

  const areaStr = (points, bottom) =>
    `${pathStr(points)} L${points[points.length - 1][0]},${bottom} L${points[0][0]},${bottom} Z`;

  const nPts = pts('normal');
  const iPts = pts('intrusion');

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ height: 220 }}>
      <defs>
        <linearGradient id="gnorm" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%"   stopColor="#10b981" stopOpacity="0.3" />
          <stop offset="100%" stopColor="#10b981" stopOpacity="0.02" />
        </linearGradient>
        <linearGradient id="gintr" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%"   stopColor="#f43f5e" stopOpacity="0.3" />
          <stop offset="100%" stopColor="#f43f5e" stopOpacity="0.02" />
        </linearGradient>
      </defs>
      {/* Normal area + line */}
      <path d={areaStr(nPts, H - PAD)} fill="url(#gnorm)" />
      <path d={pathStr(nPts)} stroke="#10b981" strokeWidth="2" fill="none" />
      {/* Intrusion area + line */}
      <path d={areaStr(iPts, H - PAD)} fill="url(#gintr)" />
      <path d={pathStr(iPts)} stroke="#f43f5e" strokeWidth="1.5" fill="none" />
      {/* X-axis labels */}
      {data.map((d, i) => (
        <text
          key={i}
          x={PAD + (i * (W - 2 * PAD)) / (data.length - 1)}
          y={H - 8}
          textAnchor="middle"
          fill="#6b7280"
          fontSize="10"
        >
          {d.time}
        </text>
      ))}
    </svg>
  );
}

// ---------------------------------------------------------------------------
// DonutChart – two-segment donut (Normal vs Intrusion)
// ---------------------------------------------------------------------------
function DonutChart({ normalPct, intrusionPct }) {
  const C = 2 * Math.PI * 65; // circumference
  const nDash = (normalPct / 100) * C;
  const iDash = (intrusionPct / 100) * C;

  return (
    <svg viewBox="0 0 180 180" className="w-full max-w-[180px] mx-auto">
      {/* Background track */}
      <circle cx="90" cy="90" r="65" fill="none" stroke="#1e3a5f" strokeWidth="22" />
      {/* Normal segment */}
      <circle
        cx="90" cy="90" r="65" fill="none"
        stroke="#10b981" strokeWidth="22"
        strokeDasharray={`${nDash} ${C - nDash}`}
        strokeDashoffset={C / 4}
        strokeLinecap="round"
        transform="rotate(-90 90 90)"
      />
      {/* Intrusion segment */}
      <circle
        cx="90" cy="90" r="65" fill="none"
        stroke="#f43f5e" strokeWidth="22"
        strokeDasharray={`${iDash} ${C - iDash}`}
        strokeDashoffset={C / 4 - nDash}
        strokeLinecap="round"
        transform="rotate(-90 90 90)"
      />
      {/* Center label */}
      <text x="90" y="85"  textAnchor="middle" fill="white"   fontSize="22" fontWeight="bold">{normalPct.toFixed(1)}%</text>
      <text x="90" y="105" textAnchor="middle" fill="#6b7280" fontSize="10">Normal</text>
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Sparkline – tiny 5-point rising polyline for KPI card
// ---------------------------------------------------------------------------
function Sparkline({ color = '#06b6d4' }) {
  const pts = [[0, 16], [15, 12], [30, 10], [45, 6], [60, 2]];
  const d = pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${p[0]},${p[1]}`).join(' ');
  return (
    <svg viewBox="0 0 60 20" className="w-full mt-2" style={{ height: 20 }}>
      <polyline points={pts.map(p => p.join(',')).join(' ')} fill="none" stroke={color} strokeWidth="1.5" />
    </svg>
  );
}

// ---------------------------------------------------------------------------
// OverviewView – main component
// ---------------------------------------------------------------------------
export default function OverviewView({ onNotify, setActiveTab, telemetryData }) {
  const [data, setData] = useState(telemetryData || null);
  const [loading, setLoading] = useState(!telemetryData);

  useEffect(() => {
    if (telemetryData) {
      setData(telemetryData);
      setLoading(false);
    } else {
      getDashboardTelemetry()
        .then(res => setData(res))
        .catch(() => setData(FALLBACK))
        .finally(() => setLoading(false));
    }
  }, [telemetryData]);

  // Show a subtle loading state; never block render entirely
  const d = data || FALLBACK;

  // Shared card class
  const card = 'bg-[#0d182e] border border-[#1e3a5f] rounded-xl p-4';

  return (
    <div className="flex flex-col gap-6">

      {/* ------------------------------------------------------------------ */}
      {/* Row 1 – KPI cards                                                   */}
      {/* ------------------------------------------------------------------ */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">

        {/* Card 1 – Total Packets Analyzed */}
        <div className={`${card} shadow-[0_0_10px_rgba(6,182,212,0.1)] relative`}>
          <div className="flex items-start justify-between">
            <p className="text-xs text-gray-400 uppercase tracking-wider">Total Packets Analyzed</p>
            <ShieldCheck className="text-cyan-400 w-5 h-5 flex-shrink-0" />
          </div>
          <p className="text-2xl font-bold text-white mt-1">
            {d.kpi.total_packets_analyzed.toLocaleString()}
          </p>
          <Sparkline color="#06b6d4" />
        </div>

        {/* Card 2 – Normal Traffic */}
        <div className={`${card} border-emerald-900/40`}>
          <div className="flex items-start justify-between">
            <p className="text-xs text-gray-400 uppercase tracking-wider">Normal Traffic</p>
            <span className="px-2 py-0.5 rounded-full bg-emerald-900/40 text-emerald-400 text-xs font-medium">
              {d.kpi.normal_percent}%
            </span>
          </div>
          <p className="text-2xl font-bold text-white mt-1">
            {d.kpi.normal_traffic_count.toLocaleString()}
          </p>
          <Sparkline color="#10b981" />
        </div>

        {/* Card 3 – Intrusions Detected */}
        <div className={`${card} border-rose-900/40`}>
          <div className="flex items-start justify-between">
            <p className="text-xs text-gray-400 uppercase tracking-wider">Intrusions Detected</p>
            <div className="flex items-center gap-1.5">
              <span className="px-2 py-0.5 rounded-full bg-rose-900/40 text-rose-400 text-xs font-medium">
                {d.kpi.intrusion_percent}%
              </span>
              <AlertTriangle className="text-rose-400 w-4 h-4 flex-shrink-0" />
            </div>
          </div>
          <p className="text-2xl font-bold text-white mt-1">
            {d.kpi.intrusions_detected.toLocaleString()}
          </p>
          <Sparkline color="#f43f5e" />
        </div>

        {/* Card 4 – Detection Rate */}
        <div className={`${card} shadow-[0_0_10px_rgba(6,182,212,0.08)]`}>
          <div className="flex items-start justify-between">
            <p className="text-xs text-gray-400 uppercase tracking-wider">Detection Rate</p>
            <Target className="text-cyan-400 w-5 h-5 flex-shrink-0" />
          </div>
          <p className="text-2xl font-bold text-cyan-400 mt-1">99.38%</p>
          <Sparkline color="#06b6d4" />
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* Row 2 – Area chart + Donut                                          */}
      {/* ------------------------------------------------------------------ */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Traffic Overview – Area Chart */}
        <div className={`${card} lg:col-span-2`}>
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-white">Network Traffic Overview</h3>
            <div className="flex gap-1">
              {['1h', '6h', '24h', '7d'].map(t => (
                <button
                  key={t}
                  className="px-2 py-0.5 rounded text-[10px] text-gray-400 border border-[#1e3a5f] hover:border-cyan-500 hover:text-cyan-400 transition-colors"
                >
                  {t}
                </button>
              ))}
            </div>
          </div>
          {/* Legend */}
          <div className="flex gap-4 mb-2">
            <span className="flex items-center gap-1 text-xs text-gray-400">
              <span className="w-2 h-2 rounded-full bg-emerald-500 inline-block" /> Normal
            </span>
            <span className="flex items-center gap-1 text-xs text-gray-400">
              <span className="w-2 h-2 rounded-full bg-rose-500 inline-block" /> Intrusion
            </span>
          </div>
          <AreaChart data={d.traffic_series} />
        </div>

        {/* Traffic Distribution – Donut */}
        <div className={`${card} lg:col-span-1 flex flex-col items-center`}>
          <h3 className="text-sm font-semibold text-white mb-3 self-start">Traffic Distribution</h3>
          <DonutChart
            normalPct={d.kpi.normal_percent}
            intrusionPct={d.kpi.intrusion_percent}
          />
          {/* Legend */}
          <div className="mt-4 w-full space-y-2">
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-2 text-xs text-gray-300">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block" />
                Normal
              </span>
              <span className="text-xs font-medium text-emerald-400">{d.kpi.normal_percent}%</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-2 text-xs text-gray-300">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block" />
                Intrusion
              </span>
              <span className="text-xs font-medium text-rose-400">{d.kpi.intrusion_percent}%</span>
            </div>
          </div>
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* Row 3 – Live Flows Table + Recent Alerts                            */}
      {/* ------------------------------------------------------------------ */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Live Sample Flows Table */}
        <div className={`${card} lg:col-span-2`}>
          <h3 className="text-sm font-semibold text-white mb-3">Network Features (Live Sample)</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-[#060d1f]">
                  {['Packet Size (Bytes)', 'Protocol', 'Duration', 'Connections', 'Source IP', 'Destination IP', 'Label'].map(col => (
                    <th
                      key={col}
                      className="px-2 py-1.5 text-left text-cyan-400/60 text-[10px] uppercase tracking-wider font-medium whitespace-nowrap"
                    >
                      {col}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {d.live_sample_flows.slice(0, 10).map((flow, i) => (
                  <tr key={i} className="border-t border-[#1e3a5f]/50 hover:bg-[#0d182e]/60 transition-colors">
                    <td className="px-2 py-1.5 text-gray-300">{flow.packet_size_bytes}</td>
                    <td className="px-2 py-1.5 text-gray-300">{flow.protocol}</td>
                    <td className="px-2 py-1.5 text-gray-300 font-mono">{formatDuration(flow.duration_sec, flow.duration_ms)}</td>
                    <td className="px-2 py-1.5 text-gray-300">{flow.connections}</td>
                    <td className="px-2 py-1.5 text-gray-400 font-mono text-[10px]">{flow.source_ip}</td>
                    <td className="px-2 py-1.5 text-gray-400 font-mono text-[10px]">{flow.destination_ip}</td>
                    <td className="px-2 py-1.5">
                      {flow.prediction === 'Intrusion' ? (
                        <span className="px-1.5 py-0.5 rounded-full bg-rose-900/50 text-rose-400 text-[10px] font-medium">
                          Intrusion
                        </span>
                      ) : (
                        <span className="px-1.5 py-0.5 rounded-full bg-emerald-900/50 text-emerald-400 text-[10px] font-medium">
                          Normal
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Recent Alerts */}
        <div className={`${card} lg:col-span-1 flex flex-col`}>
          <h3 className="text-sm font-semibold text-white mb-3">Recent Alerts</h3>
          <div className="flex-1 space-y-2">
            {d.recent_alerts.map((item, i) => (
              <div
                key={i}
                className="flex items-center justify-between py-1.5 border-b border-[#1e3a5f]/40 last:border-0"
              >
                <div className="flex items-start gap-2 min-w-0">
                  {/* Status dot */}
                  <span
                    className={`mt-0.5 w-2 h-2 rounded-full flex-shrink-0 ${
                      item.prediction === 'Intrusion' ? 'bg-rose-500' : 'bg-emerald-500'
                    }`}
                  />
                  <div className="min-w-0">
                    <p className="text-xs text-white truncate">{item.attack_type}</p>
                    <p className="text-[10px] text-gray-500 font-mono">{item.source_ip}</p>
                  </div>
                </div>
                <span className="text-[10px] text-gray-500 ml-2 flex-shrink-0">{item.timestamp}</span>
              </div>
            ))}
          </div>
          {/* Footer link */}
          <button
            onClick={() => setActiveTab && setActiveTab('history')}
            className="mt-3 text-cyan-400 text-xs hover:underline self-start"
          >
            View All →
          </button>
        </div>
      </div>
    </div>
  );
}
