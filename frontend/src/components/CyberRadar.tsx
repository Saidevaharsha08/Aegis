'use client';

import React, { useEffect, useState } from 'react';
import { Shield, ShieldAlert, Radio } from 'lucide-react';

interface RadarBlip {
  label: string;
  type: string;
  intensity: number;
  x: number;
  y: number;
}

interface CyberRadarProps {
  blips?: RadarBlip[];
  scanningFeatures?: number;
}

const DEFAULT_BLIPS: RadarBlip[] = [
  { id: '1', x: 35, y: 40, type: 'DoS', intensity: 0.9, label: '192.168.1.105:80' } as any,
  { id: '2', x: 70, y: 65, type: 'BruteForce', intensity: 0.7, label: '10.0.0.42:22' } as any,
  { id: '3', x: 50, y: 25, type: 'BENIGN', intensity: 0.2, label: '172.16.0.12:443' } as any,
  { id: '4', x: 25, y: 75, type: 'PortScan', intensity: 0.8, label: '192.168.1.201:8080' } as any,
];

export default function CyberRadar({ blips: externalBlips, scanningFeatures = 78 }: CyberRadarProps) {
  // If no blips passed, fall back to a small demo set with gentle jitter
  // so the radar canvas is never empty in the static views (homepage etc.).
  const [fallbackBlips, setFallbackBlips] = useState<RadarBlip[]>(DEFAULT_BLIPS);

  useEffect(() => {
    if (externalBlips !== undefined) return; // caller controls it
    const t = setInterval(() => {
      setFallbackBlips((prev) =>
        prev.map((b, i) => ({
          ...b,
          x: Math.max(15, Math.min(85, b.x + (Math.random() * 6 - 3))),
          y: Math.max(15, Math.min(85, b.y + (Math.random() * 6 - 3))),
        })),
      );
    }, 2000);
    return () => clearInterval(t);
  }, [externalBlips]);

  const blips = externalBlips ?? fallbackBlips;

  return (
    <div className="relative rounded-3xl bg-[#080d1a] border border-cyan-500/30 p-6 shadow-2xl overflow-hidden glass-panel glow-cyan">
      {/* Background Radar Grid */}
      <div className="flex flex-col md:flex-row items-center justify-between gap-6">
        <div className="relative w-64 h-64 sm:w-72 sm:h-72 flex-shrink-0 flex items-center justify-center">
          {/* Concentric Circles */}
          <div className="absolute inset-0 rounded-full border border-cyan-500/20"></div>
          <div className="absolute inset-6 rounded-full border border-cyan-500/20"></div>
          <div className="absolute inset-16 rounded-full border border-cyan-500/20"></div>
          <div className="absolute inset-28 rounded-full border border-cyan-500/30 bg-cyan-500/5"></div>

          {/* Crosshairs */}
          <div className="absolute w-full h-[1px] bg-cyan-500/20"></div>
          <div className="absolute h-full w-[1px] bg-cyan-500/20"></div>
          <div className="absolute w-full h-full border border-dashed border-cyan-500/10 rounded-full"></div>

          {/* Rotating Radar Sweep */}
          <div className="absolute inset-0 rounded-full overflow-hidden pointer-events-none">
            <div className="w-full h-full origin-center animate-[spin_4s_linear_infinite] bg-[conic-gradient(from_0deg,transparent_0_300deg,rgba(6,182,212,0.35)_360deg)]"></div>
          </div>

          {/* Center Hub */}
          <div className="relative z-10 w-6 h-6 rounded-full bg-cyan-500/30 border border-cyan-400 flex items-center justify-center shadow-lg shadow-cyan-500/50">
            <div className="w-2 h-2 rounded-full bg-cyan-300 animate-ping"></div>
          </div>

          {/* Radar Blips */}
          {blips.map((blip, idx) => {
            const isAttack = blip.type !== 'BENIGN';
            return (
              <div
                key={`${blip.label}-${idx}`}
                style={{ left: `${blip.x}%`, top: `${blip.y}%` }}
                className="absolute transform -translate-x-1/2 -translate-y-1/2 group cursor-pointer"
              >
                <div className={`relative w-4 h-4 rounded-full flex items-center justify-center ${
                  isAttack ? 'bg-rose-500/40 border border-rose-400' : 'bg-emerald-500/40 border border-emerald-400'
                }`}>
                  <div className={`w-2 h-2 rounded-full ${isAttack ? 'bg-rose-400 animate-ping' : 'bg-emerald-400'}`}></div>
                </div>

                {/* Tooltip */}
                <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 hidden group-hover:block z-30 whitespace-nowrap bg-slate-950 px-2.5 py-1 rounded-lg border border-slate-800 text-[10px] font-mono text-cyan-300 shadow-xl">
                  {blip.label} ({blip.type})
                </div>
              </div>
            );
          })}
        </div>

        {/* Live Radar Feed Info */}
        <div className="flex-1 space-y-4 w-full">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center space-x-2">
              <Radio className="w-4 h-4 text-cyan-400 animate-pulse" />
              <span className="text-sm font-bold text-white uppercase tracking-wider">Live Packet Radar Feed</span>
            </div>
            <span className="text-xs font-mono text-cyan-400 bg-cyan-500/10 px-2.5 py-1 rounded-full border border-cyan-500/30">
              Scanning {scanningFeatures} Features
            </span>
          </div>

          <div className="space-y-2">
            {blips.map((blip, idx) => {
              const isAttack = blip.type !== 'BENIGN';
              return (
                <div key={`${blip.label}-${idx}`} className="flex items-center justify-between bg-[#0b101d] px-3.5 py-2 rounded-xl border border-slate-800/80 text-xs">
                  <div className="flex items-center space-x-2.5">
                    <div className={`w-2 h-2 rounded-full ${isAttack ? 'bg-rose-500 animate-pulse' : 'bg-emerald-500'}`}></div>
                    <span className="font-mono text-slate-200 font-medium">{blip.label}</span>
                  </div>
                  <div className="flex items-center space-x-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      isAttack ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                    }`}>
                      {blip.type}
                    </span>
                    <span className="font-mono text-[11px] text-slate-400">{(blip.intensity * 100).toFixed(0)}% risk</span>
                  </div>
                </div>
              );
            })}
          </div>

          <div className="pt-2 text-[11px] text-slate-400 flex items-center justify-between">
            <span>Spatial Attributions: SHAP Kernel Explainer</span>
            <span className="text-emerald-400 font-mono">Status: MONITORING</span>
          </div>
        </div>
      </div>
    </div>
  );
}