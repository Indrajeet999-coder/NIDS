import React, { useState, useEffect } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Cpu,
  Gauge,
  HelpCircle,
  Loader2,
  Play,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  Sparkles,
  Zap,
} from 'lucide-react';
import { getFeatures, predictSingle } from '../api';

/**
 * Fallback preset samples if backend features API is not yet loaded
 */
const DEFAULT_NORMAL_FLOW = {
  'Destination Port': 443,
  'Bwd Packet Length Std': 12.5,
  'Average Packet Size': 86.4,
  'Bwd Header Length': 64,
  'Max Packet Length': 512,
  'PSH Flag Count': 1,
  'ACK Flag Count': 4,
  'Total Fwd Packets': 5,
  'Total Backward Packets': 4,
  'Total Length of Fwd Packets': 320,
  'Total Length of Bwd Packets': 1280,
  'min_seg_size_forward': 32,
  'Fwd Packet Length Max': 180,
  'Avg Fwd Segment Size': 64,
  'Avg Bwd Segment Size': 320,
  'Subflow Fwd Packets': 5,
  'Subflow Fwd Bytes': 320,
  'Subflow Bwd Bytes': 1280,
  'Bwd Packet Length Mean': 320,
  'Bwd Packet Length Max': 640,
  'Packet Length Mean': 86.4,
  'Packet Length Std': 45.2,
  'Packet Length Variance': 2043.0,
  'Fwd Header Length.1': 100,
  'Bwd Packets/s': 120.5,
};

const DEFAULT_ATTACK_FLOW = {
  'Destination Port': 80,
  'Bwd Packet Length Std': 1420.8,
  'Average Packet Size': 1240.5,
  'Bwd Header Length': 20,
  'Max Packet Length': 1460,
  'PSH Flag Count': 0,
  'ACK Flag Count': 0,
  'Total Fwd Packets': 120,
  'Total Backward Packets': 1,
  'Total Length of Fwd Packets': 54000,
  'Total Length of Bwd Packets': 0,
  'min_seg_size_forward': 20,
  'Fwd Packet Length Max': 1460,
  'Avg Fwd Segment Size': 450,
  'Avg Bwd Segment Size': 0,
  'Subflow Fwd Packets': 120,
  'Subflow Fwd Bytes': 54000,
  'Subflow Bwd Bytes': 0,
  'Bwd Packet Length Mean': 0,
  'Bwd Packet Length Max': 0,
  'Packet Length Mean': 446.2,
  'Packet Length Std': 672.4,
  'Packet Length Variance': 452125.0,
  'Fwd Header Length.1': 2400,
  'Bwd Packets/s': 0.2,
};

/**
 * Top key features for slider controls with ranges & descriptions
 */
const KEY_FEATURE_METADATA = [
  { key: 'Destination Port', min: 0, max: 65535, step: 1, desc: 'Target service port (80=HTTP, 443=HTTPS)' },
  { key: 'Bwd Packet Length Std', min: 0, max: 3000, step: 5, desc: 'Standard deviation of backward packet lengths' },
  { key: 'Average Packet Size', min: 0, max: 2000, step: 5, desc: 'Mean size of all exchanged packets' },
  { key: 'Max Packet Length', min: 0, max: 5000, step: 10, desc: 'Maximum observed packet byte size' },
  { key: 'Bwd Header Length', min: 0, max: 1000, step: 4, desc: 'Total bytes of backward TCP/IP headers' },
  { key: 'Total Fwd Packets', min: 1, max: 500, step: 1, desc: 'Count of forward transmission packets' },
  { key: 'Total Length of Fwd Packets', min: 0, max: 65535, step: 50, desc: 'Aggregate payload bytes sent forward' },
  { key: 'PSH Flag Count', min: 0, max: 20, step: 1, desc: 'Push flag indicators in flow' },
  { key: 'ACK Flag Count', min: 0, max: 20, step: 1, desc: 'Acknowledgment flag indicators' },
];

/**
 * FlowSimulatorView — Intrusion Detection / Live 25-Feature Flow Simulator
 */
export default function FlowSimulatorView({ onNotify, onTelemetryUpdated }) {
  const [featuresList, setFeaturesList] = useState([]);
  const [sampleNormal, setSampleNormal] = useState(DEFAULT_NORMAL_FLOW);
  const [sampleAttack, setSampleAttack] = useState(DEFAULT_ATTACK_FLOW);
  const [formValues, setFormValues] = useState(DEFAULT_NORMAL_FLOW);
  const [activePreset, setActivePreset] = useState('normal'); // 'normal', 'attack', 'portscan', 'ssh', 'custom'

  const [loading, setLoading] = useState(false);
  const [predictionResult, setPredictionResult] = useState(null);
  const [showAllFeatures, setShowAllFeatures] = useState(false);

  // Load backend features & presets on mount
  useEffect(() => {
    async function loadPresets() {
      try {
        const data = await getFeatures();
        if (data.feature_names && data.feature_names.length > 0) {
          setFeaturesList(data.feature_names);
        }
        if (data.sample_normal && Object.keys(data.sample_normal).length > 0) {
          setSampleNormal(data.sample_normal);
          setFormValues(data.sample_normal);
        }
        if (data.sample_attack && Object.keys(data.sample_attack).length > 0) {
          setSampleAttack(data.sample_attack);
        }
      } catch (err) {
        // Fallback to embedded default features if API not yet reachable
        console.warn('Could not fetch preset features from backend:', err);
      }
    }
    loadPresets();
  }, []);

  // Preset Handlers
  const handleLoadNormalPreset = () => {
    setFormValues({ ...sampleNormal });
    setActivePreset('normal');
    setPredictionResult(null);
    onNotify('info', 'Loaded Preset Flow', 'Populated parameters with standard Normal/Benign HTTPS flow.');
  };

  const handleLoadAttackPreset = () => {
    setFormValues({ ...sampleAttack });
    setActivePreset('attack');
    setPredictionResult(null);
    onNotify('warning', 'Loaded Attack Preset', 'Populated parameters with high-rate malicious DDoS attack flow.');
  };

  const handleLoadPortScanPreset = () => {
    setFormValues({
      ...DEFAULT_NORMAL_FLOW,
      'Destination Port': 22,
      'Total Fwd Packets': 200,
      'Average Packet Size': 40,
      'Total Length of Fwd Packets': 8000,
    });
    setActivePreset('portscan');
    setPredictionResult(null);
    onNotify('warning', 'Loaded Port Scan Preset', 'Simulating a port scan reconnaissance pattern on SSH port 22.');
  };

  const handleLoadSshPreset = () => {
    setFormValues({
      ...DEFAULT_ATTACK_FLOW,
      'Destination Port': 22,
      'Total Fwd Packets': 500,
      'ACK Flag Count': 15,
    });
    setActivePreset('ssh');
    setPredictionResult(null);
    onNotify('error', 'Loaded SSH Brute Force Preset', 'Simulating a brute force credential attack over SSH port 22.');
  };

  const handleResetForm = () => {
    setFormValues({ ...DEFAULT_NORMAL_FLOW });
    setActivePreset('custom');
    setPredictionResult(null);
  };

  const handleInputChange = (featureName, value) => {
    setActivePreset('custom');
    const numVal = parseFloat(value);
    setFormValues((prev) => ({
      ...prev,
      [featureName]: isNaN(numVal) ? 0 : numVal,
    }));
  };

  // Submit to POST /predict/single
  const handlePredictSingle = async (e) => {
    if (e) e.preventDefault();
    setLoading(true);

    try {
      // Ensure all 25 features exist in form payload with numbers
      const payloadFeatures = { ...formValues };
      featuresList.forEach((feat) => {
        if (payloadFeatures[feat] === undefined) {
          payloadFeatures[feat] = 0.0;
        }
      });

      const res = await predictSingle(payloadFeatures);
      setPredictionResult(res);
      if (onTelemetryUpdated) onTelemetryUpdated();

      if (res.label_binary === 1) {
        onNotify('error', 'Threat Detected!', `Flow classified as Intrusion with ${(res.confidence * 100).toFixed(1)}% confidence.`);
      } else {
        onNotify('success', 'Safe Flow Confirmed', `Flow classified as Normal with ${(res.confidence * 100).toFixed(1)}% confidence.`);
      }
    } catch (err) {
      onNotify('error', 'Inference Failed', err.message);
    } finally {
      setLoading(false);
    }
  };

  // Filter keys for top controls vs secondary controls
  const keyKeys = KEY_FEATURE_METADATA.map((m) => m.key);
  const remainingKeys = Object.keys(formValues).filter((k) => !keyKeys.includes(k));

  return (
    <div className="space-y-8 animate-fade-in">

      {/* Title & Description Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#1e3a5f] pb-5">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-gray-50">
              Intrusion Detection
            </h1>
            <span className="rounded-full bg-emerald-500/10 px-2.5 py-0.5 text-xs font-semibold text-emerald-400 border border-emerald-500/30">
              Zero Latency Inference
            </span>
          </div>
          <p className="mt-1 text-xs text-gray-400">
            Live 25-Feature Flow Simulator — load attack presets or tune flow features to test the XGBoost engine in real-time.
          </p>
        </div>

        {/* Preset Action Buttons */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Normal HTTPS */}
          <button
            type="button"
            onClick={handleLoadNormalPreset}
            className={`flex items-center gap-1.5 rounded-lg px-3.5 py-2 text-xs font-semibold transition-all ${activePreset === 'normal'
                ? 'bg-emerald-500 text-slate-950 shadow-[0_0_15px_rgba(16,185,129,0.4)]'
                : 'bg-emerald-950/40 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-900/60'
              }`}
          >
            <ShieldCheck className="h-4 w-4" />
            <span>Normal HTTPS</span>
          </button>

          {/* DDoS Flood */}
          <button
            type="button"
            onClick={handleLoadAttackPreset}
            className={`flex items-center gap-1.5 rounded-lg px-3.5 py-2 text-xs font-semibold transition-all ${activePreset === 'attack'
                ? 'bg-rose-500 text-slate-950 shadow-[0_0_15px_rgba(244,63,94,0.4)]'
                : 'bg-rose-950/40 text-rose-300 border border-rose-500/30 hover:bg-rose-900/60'
              }`}
          >
            <ShieldAlert className="h-4 w-4" />
            <span>DDoS Flood</span>
          </button>

          {/* Port Scan */}
          <button
            type="button"
            onClick={handleLoadPortScanPreset}
            className={`flex items-center gap-1.5 rounded-lg px-3.5 py-2 text-xs font-semibold transition-all ${activePreset === 'portscan'
                ? 'bg-amber-500 text-slate-950 shadow-[0_0_15px_rgba(245,158,11,0.4)]'
                : 'bg-amber-950/40 text-amber-300 border border-amber-500/30 hover:bg-amber-900/60'
              }`}
          >
            <Zap className="h-4 w-4" />
            <span>Port Scan</span>
          </button>

          {/* SSH Brute Force */}
          <button
            type="button"
            onClick={handleLoadSshPreset}
            className={`flex items-center gap-1.5 rounded-lg px-3.5 py-2 text-xs font-semibold transition-all ${activePreset === 'ssh'
                ? 'bg-purple-500 text-slate-950 shadow-[0_0_15px_rgba(168,85,247,0.4)]'
                : 'bg-purple-950/40 text-purple-300 border border-purple-500/30 hover:bg-purple-900/60'
              }`}
          >
            <AlertOctagon className="h-4 w-4" />
            <span>SSH Brute Force</span>
          </button>

          {/* Reset */}
          <button
            type="button"
            onClick={handleResetForm}
            title="Reset parameters"
            className="rounded-lg bg-[#0d182e] p-2 text-gray-400 border border-[#1e3a5f] hover:text-gray-100 hover:bg-[#1e3a5f]"
          >
            <RotateCcw className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Main Grid: Parameters Tuner (Left 7 cols) & Live Verdict Card (Right 5 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">

        {/* Left Column: Feature Controls */}
        <form onSubmit={handlePredictSingle} className="lg:col-span-7 space-y-6">

          <div className="rounded-xl bg-[#0d182e] p-6 border border-[#1e3a5f] shadow-xl space-y-5">
            <div className="flex items-center justify-between border-b border-[#1e3a5f] pb-3">
              <div className="flex items-center gap-2">
                <Sliders className="h-5 w-5 text-cyan-400" />
                <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-200">
                  Primary Flow Telemetry Controls
                </h3>
              </div>
              <span className="text-[11px] font-mono text-gray-400">
                Preset: <strong className="text-cyan-300 uppercase">{activePreset}</strong>
              </span>
            </div>

            {/* Top Key Features Sliders + Inputs */}
            <div className="space-y-4">
              {KEY_FEATURE_METADATA.map((meta) => {
                const val = formValues[meta.key] ?? 0;
                return (
                  <div key={meta.key} className="space-y-1.5 rounded-lg bg-[#060d1f]/60 p-3 border border-[#1e3a5f]/80">
                    <div className="flex items-center justify-between">
                      <div>
                        <label className="text-xs font-semibold text-gray-200 font-mono">
                          {meta.key}
                        </label>
                        <p className="text-[10px] text-gray-400">{meta.desc}</p>
                      </div>

                      <div className="flex items-center gap-2">
                        <input
                          type="number"
                          step={meta.step}
                          value={val}
                          onChange={(e) => handleInputChange(meta.key, e.target.value)}
                          className="w-24 rounded bg-[#060d1f] px-2 py-1 text-right text-xs font-mono font-bold text-cyan-300 border border-[#1e3a5f] focus:border-cyan-500 focus:outline-none"
                        />
                      </div>
                    </div>

                    <div className="pt-1">
                      <input
                        type="range"
                        min={meta.min}
                        max={meta.max}
                        step={meta.step}
                        value={val}
                        onChange={(e) => handleInputChange(meta.key, e.target.value)}
                        className="w-full accent-cyan-400 cursor-pointer h-1.5 bg-[#1e3a5f] rounded-lg"
                      />
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Expandable Section for Remaining Features */}
            <div className="border-t border-[#1e3a5f] pt-3">
              <button
                type="button"
                onClick={() => setShowAllFeatures(!showAllFeatures)}
                className="flex items-center justify-between w-full rounded-lg bg-[#060d1f] p-3 text-xs font-medium text-gray-300 border border-[#1e3a5f] hover:bg-[#1e3a5f]/40 transition-colors"
              >
                <div className="flex items-center gap-2">
                  <Cpu className="h-4 w-4 text-cyan-400" />
                  <span>
                    View / Edit All 25 Network Features ({remainingKeys.length} advanced parameters)
                  </span>
                </div>
                {showAllFeatures ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </button>

              {showAllFeatures && (
                <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-3 p-3 bg-[#060d1f]/60 rounded-lg border border-[#1e3a5f]">
                  {remainingKeys.map((featKey) => (
                    <div key={featKey} className="space-y-1">
                      <label className="block text-[11px] font-mono text-gray-400 truncate" title={featKey}>
                        {featKey}
                      </label>
                      <input
                        type="number"
                        step="any"
                        value={formValues[featKey] ?? 0}
                        onChange={(e) => handleInputChange(featKey, e.target.value)}
                        className="w-full rounded bg-[#0d182e] px-2.5 py-1 text-xs font-mono text-gray-200 border border-[#1e3a5f] focus:border-cyan-500 focus:outline-none"
                      />
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Submit Action Button */}
            <div className="pt-3">
              <button
                type="submit"
                disabled={loading}
                className="w-full flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 px-6 py-3.5 text-sm font-bold text-slate-950 shadow-[0_0_20px_rgba(6,182,212,0.35)] transition-all hover:scale-[1.02] hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50"
              >
                {loading ? (
                  <>
                    <Loader2 className="h-5 w-5 animate-spin" />
                    <span>Evaluating Flow with XGBoost...</span>
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4 fill-current" />
                    <span>Analyze Traffic Flow (POST /predict/single)</span>
                  </>
                )}
              </button>
            </div>

          </div>

        </form>

        {/* Right Column: Live Verdict Card */}
        <div className="lg:col-span-5 space-y-6">
          <div className="sticky top-28">

            {predictionResult ? (
              // Active Prediction Result Card
              <div
                className={`overflow-hidden rounded-2xl border p-6 shadow-2xl transition-all duration-500 ${predictionResult.label_binary === 1
                    ? 'border-rose-500/60 bg-gradient-to-b from-rose-950/50 via-[#0d182e] to-[#0d182e] shadow-[0_0_35px_rgba(244,63,94,0.25)]'
                    : 'border-emerald-500/60 bg-gradient-to-b from-emerald-950/50 via-[#0d182e] to-[#0d182e] shadow-[0_0_35px_rgba(16,185,129,0.25)]'
                  }`}
              >

                {/* Threat Banner Header */}
                <div className="flex items-center gap-3 border-b border-[#1e3a5f]/80 pb-4">
                  <div
                    className={`rounded-xl p-3 border ${predictionResult.label_binary === 1
                        ? 'bg-rose-500/20 text-rose-400 border-rose-500/40'
                        : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                      }`}
                  >
                    {predictionResult.label_binary === 1 ? (
                      <AlertOctagon className="h-8 w-8 animate-pulse" />
                    ) : (
                      <ShieldCheck className="h-8 w-8" />
                    )}
                  </div>

                  <div>
                    <span
                      className={`inline-block rounded-full px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider border ${predictionResult.label_binary === 1
                          ? 'bg-rose-950 text-rose-300 border-rose-500/50'
                          : 'bg-emerald-950 text-emerald-300 border-emerald-500/50'
                        }`}
                    >
                      {predictionResult.label_binary === 1 ? 'MALICIOUS THREAT' : 'AUTHORIZED TRAFFIC'}
                    </span>
                    <h2
                      className={`text-xl font-extrabold tracking-tight mt-1 ${predictionResult.label_binary === 1 ? 'text-rose-400' : 'text-emerald-400'
                        }`}
                    >
                      {predictionResult.label_binary === 1 ? 'INTRUSION DETECTED' : 'NORMAL / BENIGN FLOW'}
                    </h2>
                  </div>
                </div>

                {/* Confidence & Risk Level Breakdown */}
                <div className="mt-6 space-y-4">

                  {/* Confidence Gauge */}
                  <div>
                    <div className="flex justify-between items-baseline text-xs font-mono">
                      <span className="text-gray-400 uppercase font-semibold">Model Confidence</span>
                      <span className="text-2xl font-extrabold text-gray-100">
                        {(predictionResult.confidence * 100).toFixed(2)}%
                      </span>
                    </div>

                    <div className="mt-2 h-3 w-full rounded-full bg-[#060d1f] border border-[#1e3a5f] overflow-hidden p-0.5">
                      <div
                        className={`h-full rounded-full transition-all duration-700 ${predictionResult.label_binary === 1
                            ? 'bg-gradient-to-r from-orange-500 to-rose-500 shadow-[0_0_12px_rgba(244,63,94,0.6)]'
                            : 'bg-gradient-to-r from-emerald-400 to-teal-500 shadow-[0_0_12px_rgba(16,185,129,0.6)]'
                          }`}
                        style={{ width: `${predictionResult.confidence * 100}%` }}
                      />
                    </div>
                  </div>

                  {/* Telemetry Metrics Grid */}
                  <div className="grid grid-cols-2 gap-3 pt-2">
                    <div className="rounded-lg bg-[#060d1f]/80 p-3 border border-[#1e3a5f] text-xs font-mono">
                      <span className="text-gray-400 block text-[10px] uppercase font-semibold">
                        Assessed Risk
                      </span>
                      <span
                        className={`mt-1 font-bold text-sm block ${predictionResult.risk_level === 'Critical'
                            ? 'text-rose-400'
                            : predictionResult.risk_level === 'High'
                              ? 'text-orange-400'
                              : predictionResult.risk_level === 'Medium'
                                ? 'text-amber-400'
                                : 'text-emerald-400'
                          }`}
                      >
                        {predictionResult.risk_level}
                      </span>
                    </div>

                    <div className="rounded-lg bg-[#060d1f]/80 p-3 border border-[#1e3a5f] text-xs font-mono">
                      <span className="text-gray-400 block text-[10px] uppercase font-semibold">
                        Binary Label
                      </span>
                      <span className="mt-1 font-bold text-sm text-gray-200 block">
                        Class {predictionResult.label_binary}
                      </span>
                    </div>

                    <div className="rounded-lg bg-[#060d1f]/80 p-3 border border-[#1e3a5f] text-xs font-mono">
                      <span className="text-gray-400 block text-[10px] uppercase font-semibold">
                        Destination Port
                      </span>
                      <span className="mt-1 font-bold text-sm text-cyan-300 block">
                        {predictionResult.destination_port !== null
                          ? `Port ${predictionResult.destination_port}`
                          : 'N/A'}
                      </span>
                    </div>

                    <div className="rounded-lg bg-[#060d1f]/80 p-3 border border-[#1e3a5f] text-xs font-mono">
                      <span className="text-gray-400 block text-[10px] uppercase font-semibold">
                        Inference Latency
                      </span>
                      <span className="mt-1 font-bold text-sm text-emerald-400 block flex items-center gap-1">
                        <Zap className="h-3 w-3 fill-current" />
                        &lt; 5 ms
                      </span>
                    </div>
                  </div>

                  {/* Attack Classification */}
                  <div className="rounded-lg bg-[#060d1f]/80 p-3 border border-[#1e3a5f] text-xs font-mono">
                    <span className="text-gray-400 block text-[10px] uppercase font-semibold">Attack Classification</span>
                    <span className="mt-1 font-bold text-sm text-cyan-300 block">{predictionResult.attack_type || 'N/A'}</span>
                  </div>

                  {/* Audit DB Logging Notice */}
                  <div className="rounded-lg bg-[#060d1f]/60 p-3 border border-[#1e3a5f] text-[11px] text-gray-400">
                    <span className="font-semibold text-cyan-400">SOC Audit Logged:</span> This flow evaluation has been persistently recorded into SQLite <code className="text-gray-300">backend/detections.db</code>.
                  </div>

                </div>

              </div>
            ) : (
              // Idle Prompt Card
              <div className="rounded-2xl bg-[#0d182e] p-8 border border-[#1e3a5f] shadow-xl text-center space-y-4">
                <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  <Gauge className="h-7 w-7" />
                </div>

                <div>
                  <h3 className="text-base font-semibold text-gray-200">
                    Awaiting Flow Telemetry
                  </h3>
                  <p className="mt-1 text-xs text-gray-400 max-w-sm mx-auto">
                    Click one of the sample presets above or adjust feature sliders, then hit <strong className="text-cyan-300">"Analyze Traffic Flow"</strong> to see live AI detection.
                  </p>
                </div>

                <div className="pt-2 flex justify-center gap-2 flex-wrap">
                  <button
                    type="button"
                    onClick={handleLoadNormalPreset}
                    className="rounded-lg bg-[#060d1f] px-3 py-1.5 text-xs text-emerald-400 border border-[#1e3a5f] hover:border-emerald-500/40"
                  >
                    Test Normal HTTPS
                  </button>
                  <button
                    type="button"
                    onClick={handleLoadAttackPreset}
                    className="rounded-lg bg-[#060d1f] px-3 py-1.5 text-xs text-rose-400 border border-[#1e3a5f] hover:border-rose-500/40"
                  >
                    Test DDoS Attack
                  </button>
                  <button
                    type="button"
                    onClick={handleLoadPortScanPreset}
                    className="rounded-lg bg-[#060d1f] px-3 py-1.5 text-xs text-amber-400 border border-[#1e3a5f] hover:border-amber-500/40"
                  >
                    Test Port Scan
                  </button>
                  <button
                    type="button"
                    onClick={handleLoadSshPreset}
                    className="rounded-lg bg-[#060d1f] px-3 py-1.5 text-xs text-purple-400 border border-[#1e3a5f] hover:border-purple-500/40"
                  >
                    Test SSH Brute Force
                  </button>
                </div>
              </div>
            )}

          </div>
        </div>

      </div>

    </div>
  );
}
