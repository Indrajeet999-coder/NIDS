import React, { useState, useEffect } from 'react';
import { Package, Clock, Wifi, Activity } from 'lucide-react';
import { getDashboardTelemetry, formatDuration } from '../api';

// ---------------------------------------------------------------------------
// Fallback data
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
    avg_duration_ms: 482.0,
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
    duration_ms: parseFloat(((0.1 + i * 0.3) * 1000).toFixed(1)),
    connections: 1 + i * 4,
    source_ip: `192.168.1.${10 + i}`,
    destination_ip: `172.217.10.${10 + i}`,
    prediction: i % 4 === 0 ? 'Intrusion' : 'Normal',
    confidence: 0.95,
    attack_type: i % 4 === 0 ? 'DDoS Attack Pattern' : 'Normal Traffic',
    time: null,
  })),
  protocol_distribution: [
    { protocol: 'TCP',  count: 68000 },
    { protocol: 'UDP',  count: 36000 },
    { protocol: 'ICMP', count: 16000 },
  ],
  feature_averages: {
    'Packet Size': 0.45,
    'Duration': 0.28,
    'Connections': 0.35,
    'Src Bytes': 0.58,
    'Dst Bytes': 0.42,
  },
  top_source_ips: undefined,
};

const FALLBACK_IPS = [
  { ip: '192.168.1.44', packets: 12450, share: 10.4  },
  { ip: '192.168.1.78', packets:  9870, share:  8.2  },
  { ip: '192.168.1.21', packets:  8340, share:  6.95 },
  { ip: '192.168.1.99', packets:  7120, share:  5.93 },
  { ip: '192.168.1.55', packets:  5680, share:  4.73 },
];

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
        <linearGradient id="ta-gnorm" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%"   stopColor="#10b981" stopOpacity="0.3" />
          <stop offset="100%" stopColor="#10b981" stopOpacity="0.02" />
        </linearGradient>
        <linearGradient id="ta-gintr" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%"   stopColor="#f43f5e" stopOpacity="0.3" />
          <stop offset="100%" stopColor="#f43f5e" stopOpacity="0.02" />
        </linearGradient>
      </defs>
      <path d={areaStr(nPts, H - PAD)} fill="url(#ta-gnorm)" />
      <path d={pathStr(nPts)} stroke="#10b981" strokeWidth="2" fill="none" />
      <path d={areaStr(iPts, H - PAD)} fill="url(#ta-gintr)" />
      <path d={pathStr(iPts)} stroke="#f43f5e" strokeWidth="1.5" fill="none" />
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
// ProtocolDonut – 3-segment donut for protocol distribution
// ---------------------------------------------------------------------------
function ProtocolDonut({ data }) {
  const C = 2 * Math.PI * 55;
  const colors = { TCP: '#3b82f6', UDP: '#8b5cf6', ICMP: '#10b981' };
  const total = data.reduce((s, d) => s + d.count, 0);

  let offset = C / 4;
  const segments = data.map(d => {
    const pct = d.count / total;
    const dash = pct * C;
    const seg = {
      protocol: d.protocol,
      color: colors[d.protocol] || '#6b7280',
      dash,
      offset,
      pct: Math.round(pct * 100),
    };
    offset -= dash;
    return seg;
  });

  return (
    <svg viewBox="0 0 160 160" className="w-full max-w-[160px] mx-auto">
      {/* Background track */}
      <circle cx="80" cy="80" r="55" fill="none" stroke="#1e3a5f" strokeWidth="20" />
      {segments.map((s, i) => (
        <circle
          key={i}
          cx="80" cy="80" r="55"
          fill="none"
          stroke={s.color}
          strokeWidth="20"
          strokeDasharray={`${s.dash} ${C - s.dash}`}
          strokeDashoffset={s.offset}
          transform="rotate(-90 80 80)"
          strokeLinecap="butt"
        />
      ))}
      <text x="80" y="78" textAnchor="middle" fill="white"   fontSize="13" fontWeight="bold">Proto</text>
      <text x="80" y="93" textAnchor="middle" fill="#6b7280" fontSize="9">Distribution</text>
    </svg>
  );
}

// ---------------------------------------------------------------------------
// FeatureBarChart – 5-bar vertical chart with explicit h-48 container
// ---------------------------------------------------------------------------
function FeatureBarChart({ data }) {
  const features = [
    { key: 'Packet Size', label: 'Packet Size', short: 'Pkt Size' },
    { key: 'Duration',    label: 'Duration',    short: 'Duration' },
    { key: 'Connections', label: 'Connections', short: 'Conns' },
    { key: 'Src Bytes',   label: 'Src Bytes',   short: 'Src Bytes' },
    { key: 'Dst Bytes',   label: 'Dst Bytes',   short: 'Dst Bytes' },
  ];
  const fallbackVals = {
    'Packet Size': 0.45,
    'Duration': 0.28,
    'Connections': 0.35,
    'Src Bytes': 0.58,
    'Dst Bytes': 0.42,
  };

  return (
    <div className="h-48 w-full flex items-end justify-between gap-3 px-2 pt-6 pb-2">
      {features.map((feat) => {
        const raw = data?.[feat.key] !== undefined ? data[feat.key] : fallbackVals[feat.key];
        const pct = Math.min(100, Math.max(6, Math.round(Number(raw) * 100)));
        return (
          <div key={feat.key} className="flex-1 flex flex-col items-center h-full justify-end group">
            {/* Value Label */}
            <span className="text-[10px] font-mono font-bold text-cyan-400 mb-1.5 group-hover:text-cyan-300 transition-colors">
              {pct}%
            </span>
            {/* Bar Track & Fill */}
            <div className="w-full max-w-[34px] bg-[#060d1f] rounded-t-md border border-[#1e3a5f]/80 flex items-end p-0.5 h-[110px] relative overflow-hidden">
              <div
                className="w-full rounded-t bg-gradient-to-t from-cyan-600 via-cyan-500 to-blue-400 border-t border-cyan-300 shadow-[0_0_10px_rgba(6,182,212,0.35)] transition-all duration-700"
                style={{ height: `${pct}%` }}
              />
            </div>
            {/* Feature Label */}
            <span
              className="text-[10px] font-mono text-gray-400 mt-2 text-center truncate w-full"
              title={feat.label}
            >
              {feat.short}
            </span>
          </div>
        );
      })}
    </div>
  );
}

function Sparkline({ color = '#06b6d4' }) {
  const pts = [[0, 16], [15, 12], [30, 10], [45, 6], [60, 2]];
  return (
    <svg viewBox="0 0 60 20" className="w-full mt-2" style={{ height: 20 }}>
      <polyline points={pts.map(p => p.join(',')).join(' ')} fill="none" stroke={color} strokeWidth="1.5" />
    </svg>
  );
}

// ---------------------------------------------------------------------------
// TrafficAnalysisView – main component
// ---------------------------------------------------------------------------
export default function TrafficAnalysisView({ onNotify, telemetryData }) {
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

  const d = data || FALLBACK;

  // Shared card class
  const card = 'bg-[#0d182e] border border-[#1e3a5f] rounded-xl p-4';

  // Protocol distribution: prefer API data, fall back to static
  const protocolData = d.protocol_distribution?.length
    ? d.protocol_distribution
    : FALLBACK.protocol_distribution;

  // Top source IPs: prefer API data, fall back to static
  const topIPs = d.top_source_ips?.length ? d.top_source_ips : FALLBACK_IPS;

  // Derive protocol legend segments for text display
  const protoTotal = protocolData.reduce((s, p) => s + p.count, 0);
  const protoColors = { TCP: '#3b82f6', UDP: '#8b5cf6', ICMP: '#10b981' };

  return (
    <div className="flex flex-col gap-6">

      {/* ------------------------------------------------------------------ */}
      {/* Row 1 – 4 KPI cards                                                 */}
      {/* ------------------------------------------------------------------ */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">

        {/* Total Packets */}
        <div className={`${card} shadow-[0_0_10px_rgba(6,182,212,0.1)]`}>
          <div className="flex items-start justify-between">
            <p className="text-xs text-gray-400 uppercase tracking-wider">Total Packets</p>
            <Package className="text-cyan-400 w-5 h-5 flex-shrink-0" />
          </div>
          <p className="text-2xl font-bold text-white mt-1">
            {d.kpi.total_packets_analyzed.toLocaleString()}
          </p>
          <Sparkline color="#06b6d4" />
        </div>

        {/* Avg Packet Size */}
        <div className={card}>
          <div className="flex items-start justify-between">
            <p className="text-xs text-gray-400 uppercase tracking-wider">Avg Packet Size</p>
            <Activity className="text-emerald-400 w-5 h-5 flex-shrink-0" />
          </div>
          <p className="text-2xl font-bold text-white mt-1">
            {d.kpi.avg_packet_size_bytes} <span className="text-xs text-gray-400 font-normal">B</span>
          </p>
          <Sparkline color="#10b981" />
        </div>

        {/* Avg Duration */}
        <div className={card}>
          <div className="flex items-start justify-between">
            <p className="text-xs text-gray-400 uppercase tracking-wider">Avg Duration</p>
            <Clock className="text-purple-400 w-5 h-5 flex-shrink-0" />
          </div>
          <p className="text-2xl font-bold text-white mt-1">
            {formatDuration(d.kpi.avg_duration_sec, d.kpi.avg_duration_ms)}
          </p>
          <Sparkline color="#8b5cf6" />
        </div>

        {/* Total Connections */}
        <div className={card}>
          <div className="flex items-start justify-between">
            <p className="text-xs text-gray-400 uppercase tracking-wider">Total Connections</p>
            <Wifi className="text-blue-400 w-5 h-5 flex-shrink-0" />
          </div>
          <p className="text-2xl font-bold text-white mt-1">
            {d.kpi.total_connections.toLocaleString()}
          </p>
          <Sparkline color="#3b82f6" />
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* Row 2 – Traffic Trends + Protocol Donut                             */}
      {/* ------------------------------------------------------------------ */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Area Chart */}
        <div className={`${card} lg:col-span-2`}>
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-white">Traffic Trends</h3>
            <div className="flex gap-3">
              <span className="flex items-center gap-1 text-xs text-gray-400">
                <span className="w-2 h-2 rounded-full bg-emerald-500 inline-block" /> Normal
              </span>
              <span className="flex items-center gap-1 text-xs text-gray-400">
                <span className="w-2 h-2 rounded-full bg-rose-500 inline-block" /> Intrusion
              </span>
            </div>
          </div>
          <AreaChart data={d.traffic_series} />
        </div>

        {/* Protocol Donut */}
        <div className={`${card} lg:col-span-1 flex flex-col items-center`}>
          <h3 className="text-sm font-semibold text-white mb-3 self-start">Protocol Distribution</h3>
          <ProtocolDonut data={protocolData} />
          {/* Legend */}
          <div className="mt-4 w-full space-y-2">
            {protocolData.map(p => (
              <div key={p.protocol} className="flex items-center justify-between">
                <span className="flex items-center gap-2 text-xs text-gray-300">
                  <span
                    className="w-2.5 h-2.5 rounded-full inline-block"
                    style={{ backgroundColor: protoColors[p.protocol] || '#6b7280' }}
                  />
                  {p.protocol}
                </span>
                <span className="text-xs font-medium" style={{ color: protoColors[p.protocol] || '#6b7280' }}>
                  {Math.round((p.count / protoTotal) * 100)}%
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* Row 3 – Top Source IPs | Traffic by Feature | Recent Activity       */}
      {/* ------------------------------------------------------------------ */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Card 1 – Top Source IPs */}
        <div className={card}>
          <h3 className="text-sm font-semibold text-white mb-3">Top Source IPs</h3>
          <div className="space-y-2.5">
            {topIPs.map((item, i) => (
              <div key={i}>
                <div className="flex items-center justify-between mb-0.5">
                  <span className="text-[11px] font-mono text-gray-300">{item.ip}</span>
                  <div className="flex gap-2 text-[10px] text-gray-500">
                    <span>{item.packets.toLocaleString()}</span>
                    <span className="text-blue-400">{item.share}%</span>
                  </div>
                </div>
                <div className="w-full h-1.5 bg-[#1e3a5f]/60 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-blue-500/60 rounded-full"
                    style={{ width: `${item.share}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Card 2 – Traffic by Feature */}
        <div className={card}>
          <h3 className="text-sm font-semibold text-white mb-3">Traffic by Feature</h3>
          <FeatureBarChart data={d.feature_averages} />
          <p className="text-[10px] text-gray-500 mt-1 text-center">Normalized feature averages</p>
        </div>

        {/* Card 3 – Recent Traffic Activity */}
        <div className={card}>
          <h3 className="text-sm font-semibold text-white mb-3">Recent Traffic Activity</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-[#060d1f]">
                  {['Time', 'Source IP', 'Dest IP', 'Status'].map(col => (
                    <th
                      key={col}
                      className="px-1.5 py-1.5 text-left text-cyan-400/60 text-[10px] uppercase tracking-wider font-medium whitespace-nowrap"
                    >
                      {col}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {d.live_sample_flows.slice(0, 8).map((flow, i) => (
                  <tr
                    key={i}
                    className="border-t border-[#1e3a5f]/40 hover:bg-[#0d182e]/60 transition-colors"
                  >
                    <td className="px-1.5 py-1.5 text-gray-500 font-mono text-[10px]">
                      {flow.time || 'HH:MM:SS'}
                    </td>
                    <td className="px-1.5 py-1.5 text-gray-400 font-mono text-[10px]">{flow.source_ip}</td>
                    <td className="px-1.5 py-1.5 text-gray-400 font-mono text-[10px]">{flow.destination_ip}</td>
                    <td className="px-1.5 py-1.5">
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
      </div>
    </div>
  );
}
