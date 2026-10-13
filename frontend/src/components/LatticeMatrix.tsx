'use client';

import React, { useEffect, useState } from 'react';
import { Lock, KeyRound, Shield, RefreshCw } from 'lucide-react';

export default function LatticeMatrix() {
  const [hexGrid, setHexGrid] = useState<string[][]>([]);

  useEffect(() => {
    const generateGrid = () => {
      const rows = 4;
      const cols = 8;
      const newGrid: string[][] = [];
      for (let i = 0; i < rows; i++) {
        const row: string[] = [];
        for (let j = 0; j < cols; j++) {
          row.push(Math.floor(Math.random() * 65536).toString(16).padStart(4, '0').toUpperCase());
        }
        newGrid.push(row);
      }
      setHexGrid(newGrid);
    };

    generateGrid();
    const interval = setInterval(generateGrid, 3000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="bg-[#080d1a] rounded-3xl p-6 border border-purple-500/30 glass-panel space-y-4 glow-purple">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center space-x-2">
          <KeyRound className="w-5 h-5 text-purple-400" />
          <span className="text-sm font-bold text-white uppercase tracking-wider font-display">
            Module-LWE Lattice Polynomial Matrix Visualizer
          </span>
        </div>
        <span className="text-xs font-mono text-purple-300 bg-purple-500/10 px-2.5 py-1 rounded-full border border-purple-500/30">
          ML-KEM-768 (k=3)
        </span>
      </div>

      <p className="text-xs text-slate-400">
        Live polynomial coefficient matrix vector <code className="text-purple-300 font-mono">A ∈ R_q^(3x3)</code> used for quantum-resistant shared secret encapsulation.
      </p>

      {/* Hex Coefficients Grid */}
      <div className="grid grid-cols-4 sm:grid-cols-8 gap-2 font-mono text-xs pt-1">
        {hexGrid.flat().map((hex, idx) => (
          <div
            key={idx}
            className="bg-[#0c1222] p-2.5 rounded-xl border border-purple-500/20 text-center hover:border-purple-400 transition-all hover:scale-105 shadow-md"
          >
            <span className="text-slate-500 text-[9px] block">coeff[{idx}]</span>
            <span className="font-bold text-purple-300 tracking-wider">0x{hex}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
