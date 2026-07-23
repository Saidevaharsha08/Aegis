'use client';

import React, { useState } from 'react';
import { optimizeRules, OptimizationResult } from '@/lib/api';
import { Activity, Sliders, CheckCircle2, Zap } from 'lucide-react';

export default function OptimizerPage() {
  const [fprBudget, setFprBudget] = useState(0.10);
  const [costBudget, setCostBudget] = useState(10.0);
  const [nRules, setNRules] = useState(15);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<OptimizationResult | null>(null);

  const handleRunOptimization = async () => {
    setLoading(true);
    try {
      const res = await optimizeRules(fprBudget, costBudget, nRules);
      setResult(res);
    } catch (e) {
      console.error('Optimization failed:', e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Quantum-Inspired Firewall Rule Optimizer</h1>
          <p className="text-slate-400 text-sm">QAOA 0-1 Multi-Dimensional Knapsack combinatorial solver</p>
        </div>
        <button
          onClick={handleRunOptimization}
          disabled={loading}
          className="px-5 py-2.5 text-sm font-semibold rounded-lg bg-cyan-500 text-slate-950 hover:bg-cyan-400 transition-all shadow-lg shadow-cyan-500/20 flex items-center space-x-2"
        >
          <Zap className="w-4 h-4" />
          <span>{loading ? 'Solving QAOA...' : 'Run QAOA Optimization'}</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Controls Card */}
        <div className="rounded-xl bg-[#121824] border border-slate-800 p-6 space-y-6">
          <div className="flex items-center space-x-2 text-cyan-400 font-bold text-sm">
            <Sliders className="w-4 h-4" />
            <span>Optimization Constraints</span>
          </div>

          <div className="space-y-2">
            <div className="flex justify-between text-xs text-slate-300">
              <span>False Positive Rate (FPR) Budget:</span>
              <span className="font-mono text-cyan-400 font-bold">{(fprBudget * 100).toFixed(1)}%</span>
            </div>
            <input
              type="range"
              min="0.01"
              max="0.20"
              step="0.01"
              value={fprBudget}
              onChange={(e) => setFprBudget(parseFloat(e.target.value))}
              className="w-full accent-cyan-500"
            />
          </div>

          <div className="space-y-2">
            <div className="flex justify-between text-xs text-slate-300">
              <span>Operational Cost Budget:</span>
              <span className="font-mono text-cyan-400 font-bold">{costBudget.toFixed(1)}</span>
            </div>
            <input
              type="range"
              min="2.0"
              max="20.0"
              step="1.0"
              value={costBudget}
              onChange={(e) => setCostBudget(parseFloat(e.target.value))}
              className="w-full accent-cyan-500"
            />
          </div>

          <div className="space-y-2">
            <div className="flex justify-between text-xs text-slate-300">
              <span>Candidate Rules Pool (N):</span>
              <span className="font-mono text-cyan-400 font-bold">{nRules} rules</span>
            </div>
            <input
              type="range"
              min="5"
              max="30"
              step="1"
              value={nRules}
              onChange={(e) => setNRules(parseInt(e.target.value))}
              className="w-full accent-cyan-500"
            />
          </div>
        </div>

        {/* Results Panel */}
        <div className="lg:col-span-2 space-y-6">
          {result ? (
            <div className="space-y-6">
              <div className="grid grid-cols-3 gap-4">
                <div className="bg-[#121824] p-4 rounded-xl border border-slate-800">
                  <span className="text-xs text-slate-400 block">Total Block Probability</span>
                  <span className="text-2xl font-bold text-emerald-400">{(result.total_block_probability * 100).toFixed(1)}%</span>
                </div>
                <div className="bg-[#121824] p-4 rounded-xl border border-slate-800">
                  <span className="text-xs text-slate-400 block">Consumed FPR</span>
                  <span className="text-2xl font-bold text-cyan-400">{(result.total_fpr * 100).toFixed(2)}%</span>
                </div>
                <div className="bg-[#121824] p-4 rounded-xl border border-slate-800">
                  <span className="text-xs text-slate-400 block">Solver Runtime</span>
                  <span className="text-2xl font-bold text-indigo-400">{result.optimization_time_ms} ms</span>
                </div>
              </div>

              <div className="rounded-xl bg-[#121824] border border-slate-800 p-6 space-y-4">
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">QAOA Selected Optimal Firewall Rules ({result.n_rules_selected} Selected)</h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs text-slate-300">
                    <thead className="border-b border-slate-800 text-slate-400">
                      <tr>
                        <th className="py-2">ID</th>
                        <th className="py-2">Rule Name</th>
                        <th className="py-2">Action</th>
                        <th className="py-2">P(Block)</th>
                        <th className="py-2">FPR</th>
                        <th className="py-2">Cost</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-mono">
                      {result.selected_rules.map((rule, idx) => (
                        <tr key={idx} className="hover:bg-slate-800/30">
                          <td className="py-2.5 font-bold text-cyan-400">{rule.rule_id}</td>
                          <td className="py-2.5 font-sans font-medium text-white">{rule.name}</td>
                          <td className="py-2.5 text-indigo-300">{rule.action}</td>
                          <td className="py-2.5 text-emerald-400">{(rule.block_probability * 100).toFixed(0)}%</td>
                          <td className="py-2.5 text-amber-400">{(rule.false_positive_rate * 100).toFixed(1)}%</td>
                          <td className="py-2.5 text-slate-400">{rule.cost}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          ) : (
            <div className="rounded-xl bg-[#121824] border border-slate-800 p-12 flex flex-col items-center justify-center text-center space-y-3">
              <Activity className="w-10 h-10 text-cyan-500/40 animate-pulse" />
              <p className="text-slate-400 text-sm">Click &quot;Run QAOA Optimization&quot; to execute QAOA classical simulation solver.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
