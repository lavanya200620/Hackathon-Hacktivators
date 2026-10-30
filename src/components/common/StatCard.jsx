import React from 'react';
import { TrendingUp, TrendingDown } from 'lucide-react';

export default function StatCard({ title, value, icon: Icon, description, trend, trendType = 'up', color = 'cyan' }) {
  const colorMap = {
    cyan: {
      border: 'hover:border-cyan-400/50',
      iconBg: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
      glow: 'hover:shadow-glow-cyan',
      value: 'text-cyan-400',
    },
    green: {
      border: 'hover:border-emerald-400/50',
      iconBg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
      glow: 'hover:shadow-glow-green',
      value: 'text-emerald-400',
    },
    red: {
      border: 'hover:border-rose-400/50',
      iconBg: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
      glow: 'hover:shadow-glow-red',
      value: 'text-rose-400',
    },
    amber: {
      border: 'hover:border-amber-400/50',
      iconBg: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
      glow: 'hover:shadow-glow-amber',
      value: 'text-amber-400',
    },
    blue: {
      border: 'hover:border-blue-400/50',
      iconBg: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
      glow: 'hover:shadow-glow-blue',
      value: 'text-blue-400',
    },
  };

  const scheme = colorMap[color] || colorMap.cyan;

  return (
    <div className={`glass-panel p-5 rounded-xl border border-background-border transition-all duration-300 ${scheme.border} ${scheme.glow} relative overflow-hidden group`}>
      {/* Subtle background glow highlight */}
      <div className="absolute -right-8 -top-8 w-28 h-28 rounded-full bg-cyan-500/5 blur-2xl group-hover:bg-cyan-500/10 transition-all pointer-events-none" />

      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <p className="text-xs font-medium tracking-wide uppercase text-slate-400">{title}</p>
          <div className="flex items-baseline gap-2">
            <h3 className={`text-2xl lg:text-3xl font-bold tracking-tight ${scheme.value}`}>
              {value}
            </h3>
            {trend && (
              <span className={`inline-flex items-center text-xs font-medium ${trendType === 'up' ? 'text-emerald-400' : 'text-slate-400'}`}>
                {trendType === 'up' ? <TrendingUp className="w-3 h-3 mr-0.5" /> : <TrendingDown className="w-3 h-3 mr-0.5" />}
                {trend}
              </span>
            )}
          </div>
        </div>

        <div className={`p-2.5 rounded-lg border ${scheme.iconBg}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>

      <p className="mt-3 text-xs text-slate-400 leading-relaxed border-t border-slate-800/80 pt-2.5">
        {description}
      </p>
    </div>
  );
}

