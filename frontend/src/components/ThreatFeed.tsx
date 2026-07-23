import React from 'react';
import { DetectionResult } from '@/lib/api';
import { ShieldAlert } from 'lucide-react';

interface Props {
  detection: DetectionResult;
}

export const ThreatFeed: React.FC<Props> = ({ detection }) => {
  return (
    <div className="rounded-xl bg-[#121824] border border-slate-800 p-6 space-y-4">
      <div className="flex items-center justify-between">
        <span className="text-xs uppercase tracking-wider text-slate-400 font-semibold">Threat Detection Panel</span>
        <span className={`px-2.5 py-1 rounded text-xs font-bold ${detection.threat_detected ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'}`}>
          {detection.threat_detected ? 'THREAT CONFIRMED' : 'BENIGN TRAFFIC'}
        </span>
      </div>

      <div className="space-y-2">
        <div className="flex justify-between text-sm text-slate-300">
          <span>Threat Score:</span>
          <span className="font-bold text-white">{(detection.threat_score * 100).toFixed(2)}%</span>
        </div>
        <div className="w-full h-2.5 rounded-full bg-slate-800 overflow-hidden">
          <div className={`h-full ${detection.threat_detected ? 'bg-rose-500' : 'bg-emerald-500'}`} style={{ width: `${detection.threat_score * 100}%` }}></div>
        </div>
      </div>
    </div>
  );
};
