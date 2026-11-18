import React, { useState } from 'react';
import {
  TrendingUp,
  Cpu,
  BarChart2,
  CheckCircle,
  Zap,
  Target,
  Award,
} from 'lucide-react';

// ---------------------------------------------------------------------------
// Default metrics (matches historical benchmark data)
// ---------------------------------------------------------------------------
const DEFAULT_METRICS = {
  champion_model: 'XGBoost',
  models: {
    'Logistic Regression': {
      train_time_s: 4.68, latency_ms_1k: 1.23, accuracy: 0.8948,
      precision: 0.6271, recall: 0.944, f1_score: 0.7536, roc_auc: 0.9616,
    },
    'Decision Tree': {
      train_time_s: 13.95, latency_ms_1k: 0.73, accuracy: 0.9936,
      precision: 0.9697, recall: 0.9934, f1_score: 0.9814, roc_auc: 0.9991,
    },
    'Random Forest': {
      train_time_s: 28.26, latency_ms_1k: 44.18, accuracy: 0.9938,
      precision: 0.9703, recall: 0.9939, f1_score: 0.982, roc_auc: 0.9998,
    },
    XGBoost: {
      train_time_s: 5.67, latency_ms_1k: 6.91, accuracy: 0.9938,
      precision: 0.9709, recall: 0.9936, f1_score: 0.9821, roc_auc: 0.9998,
    },
  },
  best_model_confusion_matrix: {
    labels: ['Normal (0)', 'Attack (1)'],
    matrix: [[98942, 608], [131, 20319]],
  },
  top_15_feature_importances: [
    { feature: 'Bwd Packet Length Std', importance: 0.381652 },
    { feature: 'Average Packet Size', importance: 0.331955 },
    { feature: 'Bwd Header Length', importance: 0.096879 },
    { feature: 'Max Packet Length', importance: 0.086055 },
    { feature: 'Destination Port', importance: 0.018848 },
    { feature: 'PSH Flag Count', importance: 0.014424 },
    { feature: 'min_seg_size_forward', importance: 0.013462 },
    { feature: 'Fwd Packet Length Max', importance: 0.009742 },
    { feature: 'Avg Fwd Segment Size', importance: 0.006761 },
    { feature: 'Subflow Fwd Packets', importance: 0.006694 },
    { feature: 'Bwd Packet Length Mean', importance: 0.006361 },
    { feature: 'Fwd Header Length.1', importance: 0.00628 },
    { feature: 'Packet Length Variance', importance: 0.004054 },
    { feature: 'ACK Flag Count', importance: 0.003394 },
    { feature: 'Bwd Packet Length Max', importance: 0.002826 },
  ],
};

// ---------------------------------------------------------------------------
// ROC Curve SVG component
// ---------------------------------------------------------------------------
function RocCurve() {
  return (
    <svg viewBox="0 0 200 200" className="w-full max-w-[200px] mx-auto">
      <rect width="200" height="200" fill="transparent" stroke="#1e3a5f" strokeWidth="1" />
      {/* Random-guess diagonal (dashed) */}
      <line x1="0" y1="200" x2="200" y2="0" stroke="#374151" strokeWidth="1" strokeDasharray="4 4" />
      {/* ROC curve (AUC ≈ 0.9998) */}
      <path
        d="M0,200 C0,100 10,10 30,8 C60,5 100,3 200,0"
        stroke="#06b6d4"
        strokeWidth="2.5"
        fill="rgba(6,182,212,0.1)"
      />
      <text x="100" y="120" textAnchor="middle" fill="#06b6d4" fontSize="12" fontWeight="bold">
        AUC = 0.9998
      </text>
      <text x="100" y="140" textAnchor="middle" fill="#6b7280" fontSize="9">
        vs dashed random guess
      </text>
    </svg>
  );
}

// ---------------------------------------------------------------------------
// KPI card
// ---------------------------------------------------------------------------
function KpiCard({ label, value, icon: Icon, color = 'cyan' }) {
  const colorMap = {
    cyan: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30',
    emerald: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
    violet: 'text-violet-400 bg-violet-500/10 border-violet-500/30',
    amber: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
  };
  const cls = colorMap[color] || colorMap.cyan;
  return (
    <div className={`rounded-xl border p-4 ${cls}`} style={{ background: '#0d182e' }}>
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-gray-400 uppercase tracking-wider">{label}</span>
        {Icon && <Icon size={16} className={cls.split(' ')[0]} />}
      </div>
      <div className={`text-2xl font-bold font-mono ${cls.split(' ')[0]}`}>{value}</div>
      {/* Sparkline — 5 upward ticks */}
      <svg viewBox="0 0 60 20" className="w-full mt-2 h-4 opacity-60">
        <polyline
          points="0,18 15,14 30,10 45,6 60,2"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          className={cls.split(' ')[0]}
        />
      </svg>
      <div className="flex items-center gap-1 mt-1">
        <TrendingUp size={10} className="text-emerald-400" />
        <span className="text-[10px] text-emerald-400">Trending up</span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// ModelAnalyticsView
// ---------------------------------------------------------------------------
export default function ModelAnalyticsView({ metricsData, onNotify }) {
  const data = metricsData || DEFAULT_METRICS;
  const modelNames = Object.keys(data.models);

  const [selectedModel, setSelectedModel] = useState('XGBoost');

  const m = data.models[selectedModel] || data.models['XGBoost'];
  const topFeatures = data.top_15_feature_importances || [];

  const cm = data.best_model_confusion_matrix?.matrix || [[98942, 608], [131, 20319]];
  const TN = cm[0][0];
  const FP = cm[0][1];
  const FN = cm[1][0];
  const TP = cm[1][1];
  const totalNormal = TN + FP;
  const totalAttack = FN + TP;
  const tnPct = totalNormal ? ((TN / totalNormal) * 100).toFixed(2) : '0.00';
  const fpPct = totalNormal ? ((FP / totalNormal) * 100).toFixed(2) : '0.00';
  const fnPct = totalAttack ? ((FN / totalAttack) * 100).toFixed(2) : '0.00';
  const tpPct = totalAttack ? ((TP / totalAttack) * 100).toFixed(2) : '0.00';

  // Classification report rows (static for XGBoost champion)
  const classReport = [
    { cls: 'Normal',    prec: '99.87%', rec: '99.39%', f1: '99.63%', sup: '99,550' },
    { cls: 'Intrusion', prec: '97.09%', rec: '99.36%', f1: '98.21%', sup: '20,450' },
    { cls: 'Overall',   prec: '98.06%', rec: '99.38%', f1: '98.70%', sup: '120,000' },
  ];

  const insights = [
    'XGBoost achieves 99.38% accuracy on holdout data',
    '99.36% attack recall — misses only 0.64% of intrusions',
    '5x faster training than Random Forest (5.67s vs 28.26s)',
    '6.4x lower latency per 1,000 flows (6.91ms vs 44.18ms)',
  ];

  return (
    <div className="flex flex-col gap-6">
      {/* Header + model selector */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <BarChart2 size={20} className="text-cyan-400" />
            Model Analytics
          </h2>
          <p className="text-gray-400 text-sm mt-0.5">Benchmark comparison &amp; champion model deep-dive</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-400">Model:</span>
          <select
            value={selectedModel}
            onChange={e => setSelectedModel(e.target.value)}
            className="bg-[#0d182e] border border-[#1e3a5f] text-cyan-300 rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:border-cyan-500"
          >
            <option value="XGBoost">XGBoost (Champion)</option>
            <option value="Random Forest">Random Forest</option>
            <option value="Decision Tree">Decision Tree</option>
            <option value="Logistic Regression">Logistic Regression</option>
          </select>
        </div>
      </div>

      {/* Row 1 — 4 KPI cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        <KpiCard label="Accuracy"  value={`${(m.accuracy  * 100).toFixed(2)}%`} icon={Target}  color="cyan"    />
        <KpiCard label="Precision" value={`${(m.precision * 100).toFixed(2)}%`} icon={Award}   color="emerald" />
        <KpiCard label="Recall"    value={`${(m.recall    * 100).toFixed(2)}%`} icon={Zap}     color="violet"  />
        <KpiCard label="F1-Score"  value={m.f1_score.toFixed(4)}                icon={Cpu}     color="amber"   />
      </div>

      {/* Row 2 — Confusion Matrix + Feature Importance */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Confusion Matrix */}
        <div
          className="rounded-xl border border-[#1e3a5f] p-5"
          style={{ background: '#0d182e' }}
        >
          <h3 className="text-sm font-semibold text-cyan-300 mb-4 flex items-center gap-2">
            <Target size={14} />
            Confusion Matrix
            <span className="text-[10px] text-gray-500 font-normal ml-1">(XGBoost champion)</span>
          </h3>

          {/* Column headers */}
          <div className="grid grid-cols-2 gap-2 mb-1 ml-0 pl-0">
            <div className="text-[10px] text-gray-500 text-center">Pred: Normal</div>
            <div className="text-[10px] text-gray-500 text-center">Pred: Attack</div>
          </div>

          <div className="grid grid-cols-2 gap-2">
            {/* TN */}
            <div className="rounded-lg border bg-emerald-950/40 border-emerald-500/30 p-3 text-center relative">
              <div className="text-[10px] text-gray-400 mb-1">Actual: Normal</div>
              <div className="text-xl font-bold font-mono text-emerald-400">
                {TN.toLocaleString()}
              </div>
              <div className="text-[10px] text-emerald-300 mt-1">True Negative ✓</div>
              <div className="text-[10px] text-emerald-500/70">({tnPct}% Correct)</div>
            </div>
            {/* FP */}
            <div className="rounded-lg border bg-amber-950/30 border-amber-500/30 p-3 text-center">
              <div className="text-[10px] text-gray-400 mb-1">Actual: Normal</div>
              <div className="text-xl font-bold font-mono text-amber-400">
                {FP.toLocaleString()}
              </div>
              <div className="text-[10px] text-amber-300 mt-1">False Positive ✗</div>
              <div className="text-[10px] text-amber-500/70">({fpPct}% Error)</div>
            </div>
            {/* FN */}
            <div className="rounded-lg border bg-rose-950/40 border-rose-500/40 p-3 text-center">
              <div className="text-[10px] text-gray-400 mb-1">Actual: Attack</div>
              <div className="text-xl font-bold font-mono text-rose-400">
                {FN.toLocaleString()}
              </div>
              <div className="text-[10px] text-rose-300 mt-1">False Negative ✗</div>
              <div className="text-[10px] text-rose-500/70">({fnPct}% Missed)</div>
            </div>
            {/* TP */}
            <div className="rounded-lg border bg-emerald-950/40 border-emerald-500/30 p-3 text-center">
              <div className="text-[10px] text-gray-400 mb-1">Actual: Attack</div>
              <div className="text-xl font-bold font-mono text-emerald-400">
                {TP.toLocaleString()}
              </div>
              <div className="text-[10px] text-emerald-300 mt-1">True Positive ✓</div>
              <div className="text-[10px] text-emerald-500/70">({tpPct}% Correct)</div>
            </div>
          </div>
        </div>

        {/* Feature Importance */}
        <div
          className="rounded-xl border border-[#1e3a5f] p-5"
          style={{ background: '#0d182e' }}
        >
          <h3 className="text-sm font-semibold text-cyan-300 mb-4 flex items-center gap-2">
            <BarChart2 size={14} />
            Top Feature Importances
          </h3>
          <div className="space-y-2.5">
            {topFeatures.slice(0, 10).map((item, i) => {
              const pct = (item.importance / topFeatures[0].importance) * 100;
              return (
                <div key={i} className="space-y-1">
                  <div className="flex justify-between text-xs">
                    <span className="text-gray-300 font-mono text-[11px] truncate max-w-[180px]">
                      #{i + 1} {item.feature}
                    </span>
                    <span className="text-cyan-400 font-mono">
                      {(item.importance * 100).toFixed(2)}%
                    </span>
                  </div>
                  <div className="h-2 bg-[#060d1f] rounded-full">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-blue-600"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Row 3 — ROC Curve | Classification Report | Key Insights */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* ROC Curve */}
        <div
          className="rounded-xl border border-[#1e3a5f] p-5 flex flex-col"
          style={{ background: '#0d182e' }}
        >
          <h3 className="text-sm font-semibold text-cyan-300 mb-3">ROC Curve</h3>
          <RocCurve />
        </div>

        {/* Classification Report */}
        <div
          className="rounded-xl border border-[#1e3a5f] p-5"
          style={{ background: '#0d182e' }}
        >
          <h3 className="text-sm font-semibold text-cyan-300 mb-3">Classification Report</h3>
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="text-cyan-400/60 uppercase text-[10px]">
                <th className="text-left pb-2">Class</th>
                <th className="text-right pb-2">Prec</th>
                <th className="text-right pb-2">Rec</th>
                <th className="text-right pb-2">F1</th>
                <th className="text-right pb-2">Sup</th>
              </tr>
            </thead>
            <tbody>
              {classReport.map((row, i) => (
                <tr
                  key={row.cls}
                  className={i % 2 === 0 ? 'bg-white/[0.02]' : ''}
                >
                  <td className={`py-1.5 ${row.cls === 'Overall' ? 'text-cyan-300 font-semibold' : 'text-gray-300'}`}>
                    {row.cls}
                  </td>
                  <td className="text-right text-emerald-400">{row.prec}</td>
                  <td className="text-right text-violet-400">{row.rec}</td>
                  <td className="text-right text-amber-400">{row.f1}</td>
                  <td className="text-right text-gray-400">{row.sup}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Key Insights */}
        <div
          className="rounded-xl border border-[#1e3a5f] p-5"
          style={{ background: '#0d182e' }}
        >
          <h3 className="text-sm font-semibold text-cyan-300 mb-3 flex items-center gap-2">
            <CheckCircle size={14} className="text-emerald-400" />
            Key Insights
          </h3>
          <ul className="space-y-2.5">
            {insights.map((insight, i) => (
              <li key={i} className="flex items-start gap-2 text-xs text-gray-300 leading-relaxed">
                <CheckCircle size={13} className="text-emerald-400 flex-shrink-0 mt-0.5" />
                {insight}
              </li>
            ))}
          </ul>

          {/* Deployment banner */}
          <div className="mt-4 rounded-lg bg-amber-500/10 border border-amber-500/30 px-4 py-3 text-center">
            <span className="text-amber-400 font-semibold text-sm">
              🏆 Your model is ready for deployment!
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
