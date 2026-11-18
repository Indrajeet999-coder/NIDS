import React from 'react';
import { AlertTriangle, CheckCircle, Info, X, XCircle } from 'lucide-react';

/**
 * AlertToast — Floating notifications system for SOC dashboard
 */
export default function AlertToast({ toasts, onDismiss }) {
  if (!toasts || toasts.length === 0) return null;

  return (
    <div className="fixed bottom-5 right-5 z-50 flex flex-col gap-2 max-w-md w-full pointer-events-none">
      {toasts.map((toast) => {
        const { id, type = 'info', message, details } = toast;

        const config = {
          success: {
            border: 'border-emerald-500/50',
            bg: 'bg-emerald-950/90',
            icon: CheckCircle,
            iconColor: 'text-emerald-400',
            glow: 'shadow-[0_0_20px_rgba(16,185,129,0.3)]',
          },
          error: {
            border: 'border-rose-500/50',
            bg: 'bg-rose-950/90',
            icon: XCircle,
            iconColor: 'text-rose-400',
            glow: 'shadow-[0_0_20px_rgba(244,63,94,0.3)]',
          },
          warning: {
            border: 'border-amber-500/50',
            bg: 'bg-amber-950/90',
            icon: AlertTriangle,
            iconColor: 'text-amber-400',
            glow: 'shadow-[0_0_20px_rgba(245,158,11,0.3)]',
          },
          info: {
            border: 'border-sky-500/50',
            bg: 'bg-slate-900/90',
            icon: Info,
            iconColor: 'text-sky-400',
            glow: 'shadow-[0_0_20px_rgba(56,189,248,0.3)]',
          },
        }[type] || config.info;

        const IconComponent = config.icon;

        return (
          <div
            key={id}
            className={`pointer-events-auto flex items-start gap-3 rounded-lg border p-4 backdrop-blur-md transition-all duration-300 animate-slide-in ${config.bg} ${config.border} ${config.glow}`}
          >
            <IconComponent className={`h-5 w-5 shrink-0 mt-0.5 ${config.iconColor}`} />
            <div className="flex-1 text-xs">
              <p className="font-semibold text-gray-100">{message}</p>
              {details && <p className="mt-1 text-gray-300 font-mono text-[11px] break-all">{details}</p>}
            </div>
            <button
              onClick={() => onDismiss(id)}
              className="text-gray-400 hover:text-gray-100 transition-colors p-1"
              aria-label="Close notification"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        );
      })}
    </div>
  );
}

