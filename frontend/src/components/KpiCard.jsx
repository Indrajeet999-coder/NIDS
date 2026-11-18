import React from 'react';

/**
 * KpiCard — High-contrast SOC Telemetry Metric Card
 */
export default function KpiCard({
  title,
  value,
  subtext,
  icon: Icon,
  variant = 'cyan', // 'cyan', 'emerald', 'rose', 'amber', 'purple'
  badge = null,
}) {
  const variantStyles = {
    cyan: {
      border: 'border-sky-500/20 hover:border-sky-500/40',
      iconBg: 'bg-sky-500/10 text-sky-400',
      glow: 'group-hover:shadow-[0_0_20px_rgba(56,189,248,0.15)]',
      valueColor: 'text-sky-300',
    },
    emerald: {
      border: 'border-emerald-500/20 hover:border-emerald-500/40',
      iconBg: 'bg-emerald-500/10 text-emerald-400',
      glow: 'group-hover:shadow-[0_0_20px_rgba(16,185,129,0.15)]',
      valueColor: 'text-emerald-300',
    },
    rose: {
      border: 'border-rose-500/20 hover:border-rose-500/40',
      iconBg: 'bg-rose-500/10 text-rose-400',
      glow: 'group-hover:shadow-[0_0_20px_rgba(244,63,94,0.15)]',
      valueColor: 'text-rose-300',
    },
    amber: {
      border: 'border-amber-500/20 hover:border-amber-500/40',
      iconBg: 'bg-amber-500/10 text-amber-400',
      glow: 'group-hover:shadow-[0_0_20px_rgba(245,158,11,0.15)]',
      valueColor: 'text-amber-300',
    },
    purple: {
      border: 'border-purple-500/20 hover:border-purple-500/40',
      iconBg: 'bg-purple-500/10 text-purple-400',
      glow: 'group-hover:shadow-[0_0_20px_rgba(168,85,247,0.15)]',
      valueColor: 'text-purple-300',
    },
  };

  const style = variantStyles[variant] || variantStyles.cyan;

  return (
    <div
      className={`group relative overflow-hidden rounded-xl bg-[#111827] p-5 border ${style.border} transition-all duration-300 ${style.glow}`}
    >
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-gray-400">{title}</p>
          <div className="mt-2 flex items-baseline gap-2">
            <span className={`text-3xl font-extrabold tracking-tight font-mono ${style.valueColor}`}>
              {value}
            </span>
            {badge && (
              <span className="inline-flex items-center rounded-full bg-gray-800/80 px-2 py-0.5 text-xs font-medium text-gray-300 border border-gray-700">
                {badge}
              </span>
            )}
          </div>
          {subtext && <p className="mt-1.5 text-xs text-gray-400">{subtext}</p>}
        </div>

        {Icon && (
          <div className={`rounded-lg p-3 ${style.iconBg} border border-white/5`}>
            <Icon className="h-6 w-6" />
          </div>
        )}
      </div>

      {/* Decorative gradient corner accent */}
      <div className="pointer-events-none absolute -bottom-6 -right-6 h-20 w-20 rounded-full bg-white/5 blur-2xl transition-opacity group-hover:opacity-100 opacity-40" />
    </div>
  );
}

