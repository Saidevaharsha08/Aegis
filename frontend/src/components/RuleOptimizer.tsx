import React from 'react';
import { OptimizationResult } from '@/lib/api';
import { Activity } from 'lucide-react';

interface Props {
  result: OptimizationResult;
}

export const RuleOptimizer: React.FC<Props> = ({ result }) => {
  return (
    <div className="rounded-xl bg-[#121824] border border-slate-800 p-6 space-y-4">
      <div className="flex items-center space-x-2 text-cyan-400 font-bold text-sm">
        <Activity className="w-4 h-4" />
        <span>QAOA Optimizer Component</span>
      </div>
      <div className="text-sm text-slate-300">
        <div>Solver: <span className="font-semibold text-white">{result.solver}</span></div>
        <div>Rules Selected: <span className="font-bold text-emerald-400">{result.n_rules_selected}</span></div>
      </div>
    </div>
  );
};
