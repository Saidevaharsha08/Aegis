'use client';

import React from 'react';
import { Database, Link2, ShieldCheck, ArrowRight } from 'lucide-react';

interface LedgerChainGraphProps {
  entries: any[];
  valid: boolean;
}

export default function LedgerChainGraph({ entries, valid }: LedgerChainGraphProps) {
  const displayBlocks = (entries ?? []).slice(0, 4);

  return (
    <div className="bg-[#080d1a] rounded-3xl p-6 border border-slate-800 glass-panel space-y-4">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center space-x-2">
          <Database className="w-4 h-4 text-emerald-400" />
          <span className="text-sm font-bold text-white uppercase tracking-wider">Cryptographic Topology Flow</span>
        </div>
        <span className="text-xs font-mono text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded-full border border-emerald-500/30">
          SHA256 Hash Chained
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 relative pt-2">
        {displayBlocks.map((item, idx) => (
          <div key={idx} className="relative group">
            <div className="bg-[#0c1222] rounded-2xl p-4 border border-slate-800/80 hover:border-emerald-500/50 transition-all space-y-2.5 shadow-lg">
              <div className="flex items-center justify-between text-xs">
                <span className="font-mono font-bold text-cyan-400">Block #{idx + 1}</span>
                <span className="text-[10px] text-slate-500 font-mono">{item?.timestamp ? new Date(item.timestamp * 1000).toLocaleTimeString() : '-'}</span>
              </div>

              <div className="space-y-1">
                <span className="text-[10px] text-slate-400 uppercase font-bold tracking-wider block">Event</span>
                <span className="text-xs font-bold text-white block truncate">{item?.event_type ?? '-'}</span>
              </div>

              <div className="space-y-1 pt-1 border-t border-slate-800/60">
                <span className="text-[10px] text-slate-400 uppercase font-bold tracking-wider block">SHA256 Hash</span>
                <span className="text-[10px] font-mono text-indigo-300 block truncate bg-slate-950 px-2 py-1 rounded border border-slate-900">
                  {item?.row_hash ? `${item.row_hash.slice(0, 16)}...` : '-'}
                </span>
              </div>
            </div>

            {/* Connecting Arrow */}
            {idx < displayBlocks.length - 1 && (
              <div className="hidden md:flex absolute top-1/2 -right-3 transform -translate-y-1/2 z-20 text-emerald-400">
                <Link2 className="w-5 h-5 bg-[#080d1a] rounded-full p-0.5 border border-emerald-500/40" />
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
