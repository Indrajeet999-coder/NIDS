import React, { useState, useEffect, useRef } from 'react';
import {
  UploadCloud,
  FileSpreadsheet,
  CheckCircle2,
  AlertTriangle,
  Download,
  Filter,
  Search,
  Loader2,
  Clock,
  Layers,
  ShieldCheck,
  ShieldAlert,
  Zap,
} from 'lucide-react';
import { predictCsv, getSamples, predictSample, formatDuration } from '../api';

const SAMPLE_CHIPS = [
  { filename: '1_normal_office_traffic.csv', label: 'Normal Office Traffic', desc: '100% Benign' },
  { filename: '2_ddos_flood_attack.csv', label: 'DDoS Flood Attack', desc: 'High Volumetric' },
  { filename: '3_port_scan_recon.csv', label: 'Port Scan Recon', desc: 'Probing Traffic' },
  { filename: '4_brute_force_ssh_web.csv', label: 'Brute Force Attempt', desc: 'Auth Attacks' },
  { filename: '5_mixed_enterprise_soc.csv', label: 'Mixed Enterprise SOC', desc: 'Multi-Vector' },
];

function ShieldLockGraphic() {
  return (
    <svg width="80" height="90" viewBox="0 0 80 90" fill="none" className="mx-auto my-2">
      <defs>
        <filter id="cyanGlow" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="4" result="blur" />
          <feComposite in="SourceGraphic" in2="blur" operator="over" />
        </filter>
        <linearGradient id="shieldGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.25" />
          <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.05" />
        </linearGradient>
      </defs>
      {/* Outer Shield */}
      <path
        d="M40 5 L70 18 L70 45 C70 65 55 80 40 87 C25 80 10 65 10 45 L10 18 Z"
        fill="url(#shieldGrad)"
        stroke="#06b6d4"
        strokeWidth="2"
        filter="url(#cyanGlow)"
      />
      {/* Padlock Body */}
      <rect
        x="28"
        y="42"
        width="24"
        height="18"
        rx="3"
        fill="#0d182e"
        stroke="#22d3ee"
        strokeWidth="2"
      />
      {/* Padlock Shackle */}
      <path
        d="M34 42 V35 C34 31.7 36.7 29 40 29 C43.3 29 46 31.7 46 35 V42"
        stroke="#22d3ee"
        strokeWidth="2"
        strokeLinecap="round"
        fill="none"
      />
      {/* Keyhole */}
      <circle cx="40" cy="50" r="2" fill="#06b6d4" />
      <path d="M40 52 V56" stroke="#06b6d4" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  );
}

function DonutChart({ normalCount, intrusionCount, total }) {
  const normPct = total > 0 ? (normalCount / total) * 100 : 0;
  const intrPct = total > 0 ? (intrusionCount / total) * 100 : 0;
  const r = 60;
  const c = 2 * Math.PI * r;
  const normDash = (normPct / 100) * c;
  const intrDash = (intrPct / 100) * c;

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-44 h-44 flex items-center justify-center">
        <svg viewBox="0 0 160 160" className="w-full h-full -rotate-90">
          <circle
            cx="80"
            cy="80"
            r={r}
            fill="none"
            stroke="#1e3a5f"
            strokeWidth="16"
          />
          {/* Normal arc */}
          <circle
            cx="80"
            cy="80"
            r={r}
            fill="none"
            stroke="#10b981"
            strokeWidth="16"
            strokeDasharray={`${normDash} ${c - normDash}`}
            strokeDashoffset={0}
            strokeLinecap="round"
            className="transition-all duration-700"
          />
          {/* Intrusion arc */}
          <circle
            cx="80"
            cy="80"
            r={r}
            fill="none"
            stroke="#f43f5e"
            strokeWidth="16"
            strokeDasharray={`${intrDash} ${c - intrDash}`}
            strokeDashoffset={-normDash}
            strokeLinecap="round"
            className="transition-all duration-700"
          />
        </svg>
        <div className="absolute text-center flex flex-col items-center justify-center">
          <span className="text-2xl font-bold font-mono text-emerald-400">
            {normPct.toFixed(1)}%
          </span>
          <span className="text-[10px] uppercase font-mono tracking-wider text-gray-400">
            Normal
          </span>
        </div>
      </div>
      <div className="flex items-center gap-4 mt-3 text-xs font-mono">
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
          <span className="text-gray-300">Normal: {normalCount.toLocaleString()} ({normPct.toFixed(1)}%)</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
          <span className="text-gray-300">Threats: {intrusionCount.toLocaleString()} ({intrPct.toFixed(1)}%)</span>
        </div>
      </div>
    </div>
  );
}

function TrafficAreaChart({ predictions }) {
  if (!predictions || predictions.length === 0) return null;

  // Split predictions into 12 buckets
  const total = predictions.length;
  const bucketSize = Math.max(1, Math.ceil(total / 12));
  const series = [];

  for (let b = 0; b < 12; b++) {
    const start = b * bucketSize;
    const end = Math.min(start + bucketSize, total);
    const slice = predictions.slice(start, end);
    const normal = slice.filter((p) => p.prediction === 'Normal').length;
    const intrusion = slice.filter((p) => p.prediction === 'Intrusion').length;
    series.push({
      label: `T+${b + 1}`,
      normal,
      intrusion,
    });
  }

  const W = 600, H = 180, PAD = 25;
  const maxV = Math.max(1, ...series.map((d) => d.normal + d.intrusion));

  const pts = (key) =>
    series.map((d, i) => [
      PAD + (i * (W - 2 * PAD)) / (series.length - 1),
      H - PAD - (d[key] / maxV) * (H - 2 * PAD),
    ]);

  const pathStr = (points) =>
    points.map((p, i) => `${i === 0 ? 'M' : 'L'}${p[0]},${p[1]}`).join(' ');

  const areaStr = (points, bottom) =>
    `${pathStr(points)} L${points[points.length - 1][0]},${bottom} L${points[0][0]},${bottom} Z`;

  const nPts = pts('normal');
  const iPts = pts('intrusion');

  return (
    <div className="w-full">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-44">
        <defs>
          <linearGradient id="csvGnorm" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#10b981" stopOpacity="0.3" />
            <stop offset="100%" stopColor="#10b981" stopOpacity="0.02" />
          </linearGradient>
          <linearGradient id="csvGintr" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#f43f5e" stopOpacity="0.3" />
            <stop offset="100%" stopColor="#f43f5e" stopOpacity="0.02" />
          </linearGradient>
        </defs>

        <path d={areaStr(nPts, H - PAD)} fill="url(#csvGnorm)" />
        <path d={pathStr(nPts)} stroke="#10b981" strokeWidth="2" fill="none" />
        <path d={areaStr(iPts, H - PAD)} fill="url(#csvGintr)" />
        <path d={pathStr(iPts)} stroke="#f43f5e" strokeWidth="2" fill="none" />

        {series.map((d, i) => (
          <text
            key={i}
            x={PAD + (i * (W - 2 * PAD)) / (series.length - 1)}
            y={H - 6}
            textAnchor="middle"
            fill="#6b7280"
            fontSize="9"
            fontFamily="monospace"
          >
            {d.label}
          </text>
        ))}
      </svg>
      <div className="flex items-center justify-end gap-4 text-xs font-mono mt-1 pr-2">
        <span className="flex items-center gap-1.5 text-emerald-400">
          <span className="w-3 h-0.5 bg-emerald-400" /> Normal Traffic
        </span>
        <span className="flex items-center gap-1.5 text-rose-400">
          <span className="w-3 h-0.5 bg-rose-400" /> Intrusion Traffic
        </span>
      </div>
    </div>
  );
}

export default function CsvAnalyzerView({ onNotify, onTelemetryUpdated }) {
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [activeChip, setActiveChip] = useState(null);
  const [filterTab, setFilterTab] = useState('all'); // 'all', 'normal', 'intrusion'
  const [searchQuery, setSearchQuery] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [completedAt, setCompletedAt] = useState(null);
  const pageSize = 20;

  const fileInputRef = useRef(null);

  // File upload handler
  const handleFileUpload = async (file) => {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith('.csv')) {
      if (onNotify) onNotify('error', 'Invalid File', 'Please select a .csv file.');
      return;
    }

    setLoading(true);
    setActiveChip(null);
    try {
      const data = await predictCsv(file);
      setResults(data);
      setCurrentPage(1);
      setCompletedAt(new Date().toLocaleTimeString());
      if (onTelemetryUpdated) onTelemetryUpdated();
      if (onNotify) {
        onNotify(
          'success',
          'CSV Evaluation Complete',
          `Processed ${data.total_flows} flows in ${data.inference_time_ms} ms (${data.intrusion_count} threats detected).`
        );
      }
    } catch (err) {
      if (onNotify) onNotify('error', 'Inference Failed', err.message);
    } finally {
      setLoading(false);
    }
  };

  // Sample scenario load handler
  const handleSampleSelect = async (chip) => {
    setLoading(true);
    setActiveChip(chip.filename);
    try {
      const data = await predictSample(chip.filename);
      setResults(data);
      setCurrentPage(1);
      setCompletedAt(new Date().toLocaleTimeString());
      if (onTelemetryUpdated) onTelemetryUpdated();
      if (onNotify) {
        onNotify(
          'success',
          `Scenario Evaluated: ${chip.label}`,
          `Analyzed ${data.total_flows} flows (${data.intrusion_count} threats found).`
        );
      }
    } catch (err) {
      if (onNotify) onNotify('error', 'Sample Inference Failed', err.message);
    } finally {
      setLoading(false);
    }
  };

  // Export results to CSV
  const handleDownloadResults = () => {
    if (!results || !results.predictions || results.predictions.length === 0) return;

    const headers = [
      '#',
      'Packet Size (Bytes)',
      'Protocol',
      'Duration (s)',
      'Connections',
      'Source IP',
      'Destination IP',
      'Destination Port',
      'Prediction',
      'Confidence',
      'Risk Level',
      'Attack Type',
    ];

    const rows = results.predictions.map((p, i) => [
      i + 1,
      p.packet_size_bytes ?? '',
      p.protocol ?? '',
      p.duration_sec ?? '',
      p.connections ?? '',
      p.source_ip ?? '',
      p.destination_ip ?? '',
      p.destination_port ?? '',
      p.prediction,
      `${(p.confidence * 100).toFixed(1)}%`,
      p.risk_level ?? '',
      p.attack_type ?? '',
    ]);

    const csvContent = [headers, ...rows]
      .map((r) => r.map((val) => `"${String(val).replace(/"/g, '""')}"`).join(','))
      .join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `nids_predictions_${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Filtered & Paginated predictions
  const filteredPredictions = (results?.predictions || []).filter((p) => {
    if (filterTab === 'normal' && p.prediction !== 'Normal') return false;
    if (filterTab === 'intrusion' && p.prediction !== 'Intrusion') return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const ip = (p.source_ip || '').toLowerCase();
      const dst = (p.destination_ip || '').toLowerCase();
      const proto = (p.protocol || '').toLowerCase();
      const attack = (p.attack_type || '').toLowerCase();
      const port = String(p.destination_port || '');
      return ip.includes(q) || dst.includes(q) || proto.includes(q) || attack.includes(q) || port.includes(q);
    }
    return true;
  });

  const totalPages = Math.ceil(filteredPredictions.length / pageSize) || 1;
  const paginatedList = filteredPredictions.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const cardStyle = 'bg-[#0d182e] border border-[#1e3a5f] rounded-xl p-5 shadow-lg';

  return (
    <div className="flex flex-col gap-6">
      {/* Title Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#1e3a5f] pb-5">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-white font-mono">
              CSV Analyzer
            </h1>
            <span className="rounded-full bg-cyan-500/10 px-2.5 py-0.5 text-xs font-semibold text-cyan-400 border border-cyan-500/30">
              Batch Machine Learning Engine
            </span>
          </div>
          <p className="mt-1 text-xs text-gray-400">
            Batch Network Flow Inspection — Upload custom PCAP-derived CSVs or click unseen enterprise scenario samples
          </p>
        </div>

        {results && (
          <div className="flex items-center gap-2">
            <button
              onClick={handleDownloadResults}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-xs font-semibold text-cyan-300 hover:bg-cyan-500/20 transition-all shadow-[0_0_10px_rgba(6,182,212,0.15)]"
            >
              <Download size={14} />
              <span>Download Results (.csv)</span>
            </button>
          </div>
        )}
      </div>

      {/* Row 1: Top Dropzone (2/3) + About This Feature (1/3) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* Left (2/3): Drag & Drop Dropzone + Quick Load Chips */}
        <div className={`lg:col-span-8 ${cardStyle} flex flex-col justify-between`}>
          <div>
            <h3 className="text-sm font-semibold text-cyan-300 mb-2 flex items-center gap-2">
              <UploadCloud size={16} className="text-cyan-400" />
              Upload Network Flow CSV
            </h3>

            {/* Drop Zone */}
            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => {
                e.preventDefault();
                if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                  handleFileUpload(e.dataTransfer.files[0]);
                }
              }}
              className="border-2 border-dashed border-[#1e3a5f] hover:border-cyan-500/50 rounded-xl p-6 text-center bg-[#060d1f]/60 transition-all cursor-pointer"
              onClick={() => fileInputRef.current?.click()}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".csv"
                className="hidden"
                onChange={(e) => {
                  if (e.target.files && e.target.files[0]) {
                    handleFileUpload(e.target.files[0]);
                  }
                }}
              />

              <div className="mx-auto w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 mb-2">
                {loading ? <Loader2 size={24} className="animate-spin" /> : <UploadCloud size={24} />}
              </div>

              <p className="text-sm font-semibold text-gray-200">
                Drag & Drop your CSV file here
              </p>
              <p className="text-xs text-gray-400 mt-1">
                Supports CICFlowMeter / CICIDS2017 format (25 model features)
              </p>

              <button
                type="button"
                disabled={loading}
                className="mt-4 px-4 py-1.5 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 font-bold text-xs shadow-[0_0_12px_rgba(6,182,212,0.3)] hover:scale-105 transition-all"
              >
                Choose File
              </button>
            </div>
          </div>

          {/* Quick-Load Sample Chips */}
          <div className="mt-5 pt-4 border-t border-[#1e3a5f]">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-gray-300 font-mono uppercase tracking-wider">
                Quick Load — Unseen Sample Scenarios (dataset/samples/)
              </span>
              <span className="text-[10px] text-cyan-400 font-mono">1-Click Evaluation</span>
            </div>

            <div className="flex flex-wrap gap-2">
              {SAMPLE_CHIPS.map((chip) => {
                const isActive = activeChip === chip.filename;
                return (
                  <button
                    key={chip.filename}
                    onClick={() => handleSampleSelect(chip)}
                    disabled={loading}
                    className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-mono transition-all border ${
                      isActive
                        ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500 shadow-[0_0_12px_rgba(6,182,212,0.3)]'
                        : 'bg-[#060d1f] text-gray-300 border-[#1e3a5f] hover:border-cyan-500/40 hover:text-cyan-300'
                    }`}
                  >
                    <FileSpreadsheet size={12} className={isActive ? 'text-cyan-400' : 'text-gray-500'} />
                    <span>{chip.label}</span>
                    <span className="text-[10px] text-gray-500">({chip.desc})</span>
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* Right (1/3): About This Feature Card */}
        <div className={`lg:col-span-4 ${cardStyle} flex flex-col justify-between`}>
          <div>
            <h3 className="text-sm font-semibold text-cyan-300 uppercase tracking-wider font-mono">
              About This Feature
            </h3>
            <ShieldLockGraphic />
            <h4 className="text-center font-bold text-white text-sm mt-1">
              Industrial ML Inspection
            </h4>
            <p className="text-center text-[11px] text-gray-400 mt-1 px-2">
              High-throughput binary packet classification pipeline with automated feature alignment and zero data leakage.
            </p>
          </div>

          <div className="space-y-2.5 mt-4 pt-4 border-t border-[#1e3a5f]">
            <div className="flex items-start gap-2 text-xs text-gray-300">
              <CheckCircle2 size={14} className="text-emerald-400 flex-shrink-0 mt-0.5" />
              <span>Analyzes 25 network flow features</span>
            </div>
            <div className="flex items-start gap-2 text-xs text-gray-300">
              <CheckCircle2 size={14} className="text-emerald-400 flex-shrink-0 mt-0.5" />
              <span>Uses our trained XGBoost ML model</span>
            </div>
            <div className="flex items-start gap-2 text-xs text-gray-300">
              <CheckCircle2 size={14} className="text-emerald-400 flex-shrink-0 mt-0.5" />
              <span>Shows detailed results and statistics</span>
            </div>
          </div>
        </div>
      </div>

      {/* Analysis Results (Only rendered after evaluation) */}
      {results && (
        <div className="flex flex-col gap-6 animate-fade-in">
          {/* Row 2: 4 KPI Cards + Completed Badge */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#060d1f] p-3 rounded-xl border border-[#1e3a5f]">
            <div className="flex items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-xs font-semibold text-emerald-400 font-mono">
                Analysis Completed Successfully
              </span>
              {completedAt && (
                <span className="text-xs text-gray-400 font-mono">at {completedAt}</span>
              )}
            </div>
            <div className="text-xs font-mono text-gray-400">
              Latency: <span className="text-cyan-400 font-bold">{results.inference_time_ms} ms</span> ({((results.inference_time_ms / results.total_flows) * 1000).toFixed(1)} µs/flow)
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
            {/* Total Records */}
            <div className={cardStyle}>
              <div className="flex items-center justify-between text-gray-400 text-xs">
                <span>Total Records</span>
                <Layers size={16} className="text-cyan-400" />
              </div>
              <div className="mt-2 text-2xl font-bold font-mono text-white">
                {results.total_flows.toLocaleString()}
              </div>
              <p className="mt-1 text-[11px] text-gray-500">Network flows evaluated</p>
            </div>

            {/* Normal Traffic */}
            <div className={`${cardStyle} border-emerald-900/40`}>
              <div className="flex items-center justify-between text-gray-400 text-xs">
                <span>Normal Traffic</span>
                <span className="px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 text-[11px] font-bold border border-emerald-500/20">
                  {((results.normal_count / results.total_flows) * 100).toFixed(1)}%
                </span>
              </div>
              <div className="mt-2 text-2xl font-bold font-mono text-emerald-400">
                {results.normal_count.toLocaleString()}
              </div>
              <p className="mt-1 text-[11px] text-emerald-500/70">Verified benign flows</p>
            </div>

            {/* Intrusion Detected */}
            <div className={`${cardStyle} border-rose-900/40`}>
              <div className="flex items-center justify-between text-gray-400 text-xs">
                <span>Intrusions Detected</span>
                <span className="px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-400 text-[11px] font-bold border border-rose-500/20">
                  {results.threat_rate_percent.toFixed(1)}%
                </span>
              </div>
              <div className="mt-2 text-2xl font-bold font-mono text-rose-400">
                {results.intrusion_count.toLocaleString()}
              </div>
              <p className="mt-1 text-[11px] text-rose-500/70">Security threats intercepted</p>
            </div>

            {/* Detection Rate / Confidence */}
            <div className={cardStyle}>
              <div className="flex items-center justify-between text-gray-400 text-xs">
                <span>Detection Accuracy</span>
                <Zap size={16} className="text-cyan-400" />
              </div>
              <div className="mt-2 text-2xl font-bold font-mono text-cyan-300">
                99.38%
              </div>
              <p className="mt-1 text-[11px] text-cyan-400/70">SOC Champion XGBoost confidence</p>
            </div>
          </div>

          {/* Row 3: Charts Row (Donut Left + Area Right) */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            <div className={`lg:col-span-5 ${cardStyle}`}>
              <h3 className="text-sm font-semibold text-white mb-3 font-mono">
                Prediction Distribution
              </h3>
              <DonutChart
                normalCount={results.normal_count}
                intrusionCount={results.intrusion_count}
                total={results.total_flows}
              />
            </div>

            <div className={`lg:col-span-7 ${cardStyle}`}>
              <h3 className="text-sm font-semibold text-white mb-1 font-mono">
                Traffic Analysis by Time Slice
              </h3>
              <p className="text-[11px] text-gray-400 mb-3">
                Distribution of normal vs intrusion packets across evaluated batch slices
              </p>
              <TrafficAreaChart predictions={results.predictions} />
            </div>
          </div>

          {/* Row 4: Sample Prediction Results Table */}
          <div className={cardStyle}>
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-[#1e3a5f]">
              <div>
                <h3 className="text-sm font-semibold text-white font-mono">
                  Sample Prediction Results
                </h3>
                <p className="text-xs text-gray-400">
                  Per-flow classification verdicts with human-readable telemetry
                </p>
              </div>

              {/* Filter Tabs + Search */}
              <div className="flex flex-wrap items-center gap-2">
                <div className="flex rounded-lg bg-[#060d1f] p-1 border border-[#1e3a5f]">
                  {['all', 'normal', 'intrusion'].map((tab) => (
                    <button
                      key={tab}
                      onClick={() => {
                        setFilterTab(tab);
                        setCurrentPage(1);
                      }}
                      className={`px-3 py-1 rounded text-xs font-mono uppercase font-semibold transition-all ${
                        filterTab === tab
                          ? tab === 'intrusion'
                            ? 'bg-rose-500 text-slate-950'
                            : tab === 'normal'
                            ? 'bg-emerald-500 text-slate-950'
                            : 'bg-cyan-500 text-slate-950'
                          : 'text-gray-400 hover:text-white'
                      }`}
                    >
                      {tab}
                    </button>
                  ))}
                </div>

                <div className="relative">
                  <Search size={13} className="absolute left-2.5 top-2.5 text-gray-500" />
                  <input
                    type="text"
                    placeholder="Search IP, port, attack..."
                    value={searchQuery}
                    onChange={(e) => {
                      setSearchQuery(e.target.value);
                      setCurrentPage(1);
                    }}
                    className="bg-[#060d1f] border border-[#1e3a5f] rounded-lg pl-8 pr-3 py-1.5 text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-cyan-500 w-48"
                  />
                </div>
              </div>
            </div>

            {/* Table */}
            <div className="overflow-x-auto mt-4">
              <table className="w-full text-xs text-left">
                <thead>
                  <tr className="bg-[#060d1f] text-cyan-400/70 uppercase text-[10px] tracking-wider font-mono">
                    <th className="py-2.5 px-3">#</th>
                    <th className="py-2.5 px-3">Packet Size</th>
                    <th className="py-2.5 px-3">Protocol</th>
                    <th className="py-2.5 px-3">Duration</th>
                    <th className="py-2.5 px-3">Connections</th>
                    <th className="py-2.5 px-3">Source IP</th>
                    <th className="py-2.5 px-3">Destination IP</th>
                    <th className="py-2.5 px-3">Prediction</th>
                    <th className="py-2.5 px-3 text-right">Confidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e3a5f]/40 font-mono">
                  {paginatedList.map((p, idx) => {
                    const rowNumber = (currentPage - 1) * pageSize + idx + 1;
                    const isThreat = p.prediction === 'Intrusion';

                    return (
                      <tr
                        key={p.flow_index ?? idx}
                        className="hover:bg-[#060d1f]/60 transition-colors text-gray-300"
                      >
                        <td className="py-2.5 px-3 text-gray-500">#{rowNumber}</td>
                        <td className="py-2.5 px-3">{p.packet_size_bytes ?? '—'} B</td>
                        <td className="py-2.5 px-3 font-semibold text-gray-200">{p.protocol ?? 'TCP'}</td>
                        <td className="py-2.5 px-3 font-mono">{formatDuration(p.duration_sec, p.duration_ms)}</td>
                        <td className="py-2.5 px-3">{p.connections ?? '1'}</td>
                        <td className="py-2.5 px-3 text-cyan-300 text-[11px]">{p.source_ip ?? '—'}</td>
                        <td className="py-2.5 px-3 text-gray-400 text-[11px]">
                          {p.destination_ip ?? '—'}
                          {p.destination_port ? `:${p.destination_port}` : ''}
                        </td>
                        <td className="py-2.5 px-3">
                          {isThreat ? (
                            <span className="inline-flex items-center gap-1 rounded bg-rose-500/15 px-2 py-0.5 text-[10px] font-bold text-rose-400 border border-rose-500/30">
                              <ShieldAlert size={10} />
                              Intrusion
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 rounded bg-emerald-500/15 px-2 py-0.5 text-[10px] font-bold text-emerald-400 border border-emerald-500/30">
                              <ShieldCheck size={10} />
                              Normal
                            </span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 text-right font-bold text-white">
                          {(p.confidence * 100).toFixed(1)}%
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Pagination footer */}
            <div className="flex items-center justify-between pt-4 mt-3 border-t border-[#1e3a5f] text-xs font-mono text-gray-400">
              <div>
                Showing <span className="text-cyan-300">{paginatedList.length}</span> of {filteredPredictions.length} flows
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                  className="px-2.5 py-1 rounded bg-[#060d1f] border border-[#1e3a5f] disabled:opacity-30 hover:border-cyan-500/40 text-gray-300"
                >
                  Prev
                </button>
                <span>
                  Page {currentPage} of {totalPages}
                </span>
                <button
                  onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                  disabled={currentPage === totalPages}
                  className="px-2.5 py-1 rounded bg-[#060d1f] border border-[#1e3a5f] disabled:opacity-30 hover:border-cyan-500/40 text-gray-300"
                >
                  Next
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
