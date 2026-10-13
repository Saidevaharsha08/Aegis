'use client';

import React from 'react';
import { ShieldAlert, CheckCircle2 } from 'lucide-react';

interface ThreatGaugeProps {
  score: number; // 0.0 to 1.0
  attackType: string;
  threatDetected: boolean;
  latencyMs: number;
  topFeatures?: { feature: string; shap_value: number }[];
}

export default function ThreatGauge({ score, attackType, threatDetected, latencyMs, topFeatures }: ThreatGaugeProps) {
  const percentage = Math.min(100, Math.max(0, Math.round(score * 100)));
  const radius = 60;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (percentage / 100) * circumference;

  const gradientId = threatDetected ? 'threatGradient' : 'benignGradient';

  return (
    <div className="flex flex-col md:flex-row items-center justify-center p-4 bg-[#0f1424]/80 rounded-3xl border border-white/10 glass-panel relative overflow-hidden gap-6">
      <div className="gauge-container">
        {/* SVG Arc Gauge */}
        <svg className="gauge-svg transform -rotate-90" viewBox="0 0 140 140" preserveAspectRatio="xMidYMid meet">
          <defs>
            <linearGradient id="threatGradient" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#f59e0b" />
              <stop offset="100%" stopColor="#f43f5e" />
            </linearGradient>
            <linearGradient id="benignGradient" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#06b6d4" />
              <stop offset="100%" stopColor="#10b981" />
            </linearGradient>
          </defs>
          <circle
            cx="70"
            cy="70"
            r={radius}
            stroke="rgba(255,255,255,0.08)"
            strokeWidth="12"
            fill="transparent"
          />
          <circle
            cx="70"
            cy="70"
            r={radius}
            stroke={`url(#${gradientId})`}
            strokeWidth="12"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Center Percentage Display */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className="text-3xl font-black font-mono text-white tracking-tight">
            {percentage}%
          </span>
          <span className="text-[10px] uppercase font-bold text-[#e4e6f1]/60 tracking-wider">
            Threat Score
          </span>
        </div>
      </div>

      {/* Results panel (inline) */}
      <div className="flex-1 min-w-[160px]">
        <div className={`inline-flex items-center space-x-2 px-3 py-1 rounded-full text-xs font-extrabold uppercase tracking-wide border ${threatDetected ? 'pill-rose glow-rose' : 'pill-success glow-emerald'
          }`}>
          {threatDetected ? <ShieldAlert className="w-4 h-4" /> : <CheckCircle2 className="w-4 h-4" />}
          <span>{threatDetected ? `THREAT: ${attackType}` : 'NORMAL TRAFFIC'}</span>
        </div>

        <div className="mt-3">
          <div className="text-3xl font-black font-mono text-white">{percentage}%</div>
          <div className="text-xs text-[#e4e6f1]/70 font-mono mt-1">Inference Latency: <strong className="text-[#06b6d4]">{latencyMs} ms</strong></div>
        </div>

        {topFeatures && (topFeatures.length ?? 0) > 0 ? (
          <div className="mt-4 text-sm">
            <div className="text-xs text-[#e4e6f1]/70 uppercase tracking-wider font-bold mb-2">Top Features</div>
            <ul className="space-y-2 text-xs">
              {topFeatures.slice(0, 3).map((f, i) => (
                <li key={i} className="flex items-center justify-between bg-[#070a13] px-3 py-2 rounded-lg border border-white/6">
                  <span className="font-medium">{f.feature}</span>
                  <span className={`font-mono ${f.shap_value > 0 ? 'text-rose-400' : 'text-[#06b6d4]'}`}>{f.shap_value.toFixed(4)}</span>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </div>
    </div>
  );
}
