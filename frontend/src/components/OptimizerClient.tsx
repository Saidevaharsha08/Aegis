'use client';

import React, { useEffect, useState } from 'react';
import { optimizeRules, fetchOptimizerCapabilities, OptimizerCapabilities, OptimizationResult } from '@/lib/api';
import { Activity, Sliders, CheckCircle2, Zap, Cpu, Layers, TrendingUp } from 'lucide-react';

export default function OptimizerClient() {
  const [fprBudget, setFprBudget] = useState(0.10);
  const [costBudget, setCostBudget] = useState(10.0);
  const [nRules, setNRules] = useState(15);
  const [solver, setSolver] = useState<'auto' | 'qaoa' | 'greedy'>('auto');
  const [caps, setCaps] = useState<OptimizerCapabilities | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<OptimizationResult | null>(null);

  useEffect(() => {
    fetchOptimizerCapabilities().then(setCaps).catch(() => setCaps(null));
  }, []);

  const handleRunOptimization = async () => {
    setLoading(true);
    try {
      const res = await optimizeRules(fprBudget, costBudget, nRules, solver);
      setResult(res);
    } catch (e) {
      console.error('Optimization failed:', e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-12 py-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-6 border-b border-white/10 pb-6">
        <div className="flex items-center space-x-4">
          <div className="icon-glass w-12 h-12 rounded-2xl flex items-center justify-center text-[#06b6d4]">
            <Cpu className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-3xl font-extrabold text-white tracking-tight font-display">
              QAOA Firewall Rule Optimizer
            </h1>
            <p className="text-[#e4e6f1]/70 text-sm mt-1">
              Quantum Approximate Optimization Algorithm (QAOA) 0-1 Multi-Dimensional Knapsack Solver
            </p>
          </div>
        </div>

        <button
          onClick={handleRunOptimization}
          disabled={loading}
          className="btn-primary-gradient px-6 py-3.5 rounded-2xl text-xs flex items-center space-x-2 shadow-lg"
        >
          <Zap className={`w-4 h-4 ${loading ? 'animate-bounce' : ''}`} />
          <span>{loading ? 'Solving QAOA Circuit...' : 'Run QAOA Solver'}</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Controls Card */}
        <div className="glass-panel rounded-3xl p-6 space-y-6">
          <div className="flex items-center space-x-2 text-[#06b6d4] font-bold text-sm border-b border-white/10 pb-3 font-display">
            <Sliders className="w-4 h-4" />
            <span>Knapsack Constraint Sliders</span>
          </div>

          <div className="space-y-1.5 slider-tight">
            <div className="flex justify-between text-xs text-[#e4e6f1]/80">
              <span className="font-medium">FPR Budget:</span>
              <span className="font-mono text-[#06b6d4] font-bold">{(fprBudget * 100).toFixed(1)}%</span>
            </div>
            <input
              type="range"
              min="0.01"
              max="0.20"
              step="0.01"
              value={fprBudget}
              onChange={(e) => setFprBudget(parseFloat(e.target.value))}
              className="w-full form-range accent-violet cursor-pointer"
              style={{ background: `linear-gradient(90deg, var(--accent-violet) ${((fprBudget - 0.01) / (0.2 - 0.01)) * 100}%, rgba(255,255,255,0.06) ${((fprBudget - 0.01) / (0.2 - 0.01)) * 100}%)` }}
            />
          </div>

          <div className="space-y-1.5 slider-tight">
            <div className="flex justify-between text-xs text-[#e4e6f1]/80">
              <span className="font-medium">Operational Cost Budget:</span>
              <span className="font-mono text-[#06b6d4] font-bold">{costBudget.toFixed(1)}</span>
            </div>
            <input
              type="range"
              min="2.0"
              max="20.0"
              step="1.0"
              value={costBudget}
              onChange={(e) => setCostBudget(parseFloat(e.target.value))}
              className="w-full form-range accent-violet cursor-pointer"
              style={{ background: `linear-gradient(90deg, var(--accent-violet) ${((costBudget - 2) / (20 - 2)) * 100}%, rgba(255,255,255,0.06) ${((costBudget - 2) / (20 - 2)) * 100}%)` }}
            />
          </div>

          <div className="space-y-1.5 slider-tight">
            <div className="flex justify-between text-xs text-[#e4e6f1]/80">
              <span className="font-medium">Candidate Rules Pool (N):</span>
              <span className="font-mono text-[#06b6d4] font-bold">{nRules} Rules</span>
            </div>
            <input
              type="range"
              min="5"
              max="30"
              step="1"
              value={nRules}
              onChange={(e) => setNRules(parseInt(e.target.value))}
              className="w-full form-range accent-violet cursor-pointer"
              style={{ background: `linear-gradient(90deg, var(--accent-violet) ${((nRules - 5) / (30 - 5)) * 100}%, rgba(255,255,255,0.06) ${((nRules - 5) / (30 - 5)) * 100}%)` }}
            />
          </div>

          <div className="pt-4 border-t border-white/10 space-y-3 text-xs text-[#e4e6f1]/60">
            <div className="flex justify-between">
              <span>Formulation:</span>
              <span className="text-slate-200 font-mono">0-1 Knapsack</span>
            </div>
            <div className="flex justify-between">
              <span>Ansatz Depth (p):</span>
              <span className="text-slate-200 font-mono">p = 2</span>
            </div>
            <div className="flex justify-between">
              <span>Optimization Target:</span>
              <span className="text-emerald-400 font-mono">Max Threat Block</span>
            </div>
            <div>
              <div className="flex justify-between mb-1">
                <span>Solver:</span>
                <span className="text-slate-200 font-mono">{solver}</span>
              </div>
              <div className="flex gap-1.5">
                {(['auto', 'qaoa', 'greedy'] as const).map((opt) => (
                  <button
                    key={opt}
                    type="button"
                    onClick={() => setSolver(opt)}
                    className={`px-2.5 py-1 rounded-full text-[11px] font-mono uppercase tracking-wider ${
                      solver === opt
                        ? 'pill-badge-violet'
                        : 'bg-white/5 text-slate-400 hover:bg-white/10'
                    }`}
                  >
                    {opt}
                  </button>
                ))}
              </div>
              {caps && (
                <div className="mt-2 text-[10px] font-mono text-slate-500 leading-relaxed">
                  Qiskit QAOA: {caps.qiskit_qaoa_available ? 'available' : 'not installed'} ·
                  Classical QAOA: {caps.classical_qaoa_available ? 'on' : 'off'} ·
                  Greedy: {caps.greedy_available ? 'on' : 'off'}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Results Panel */}
        <div className="lg:col-span-2 space-y-6">
          {result ? (
            <div className="space-y-6">
              {/* Metric Summary Cards */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="glass-panel p-5 rounded-2xl border border-emerald-500/30 space-y-1 glow-emerald">
                  <span className="text-xs text-[#e4e6f1]/60 font-bold uppercase tracking-wider block">Total Block Probability</span>
                  <div className="text-3xl font-black text-emerald-400 font-mono">
                    {(result.total_block_probability * 100).toFixed(1)}%
                  </div>
                </div>

                <div className="glass-panel p-5 rounded-2xl border border-[#06b6d4]/30 space-y-1 glow-cyan">
                  <span className="text-xs text-[#e4e6f1]/60 font-bold uppercase tracking-wider block">Consumed FPR</span>
                  <div className="text-3xl font-black text-[#06b6d4] font-mono">
                    {(result.total_fpr * 100).toFixed(2)}%
                  </div>
                </div>

                <div className="glass-panel p-5 rounded-2xl border border-[#7c5cff]/30 space-y-1 glow-purple">
                  <span className="text-xs text-[#e4e6f1]/60 font-bold uppercase tracking-wider block">Solver Runtime</span>
                  <div className="text-3xl font-black text-[#7c5cff] font-mono">
                    {result.optimization_time_ms} ms
                  </div>
                </div>
              </div>

              {/* Selected Rules Table */}
              <div className="glass-panel rounded-3xl p-6 space-y-4">
                <div className="flex items-center justify-between border-b border-white/10 pb-3">
                  <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2 font-display">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span>Selected Optimal Firewall Rules ({result.n_rules_selected} Selected)</span>
                  </h3>
                  <span className="text-xs font-mono text-[#06b6d4] pill-cyan px-3 py-1 rounded-full">
                    Within 2.8% of Exact DP
                  </span>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="border-b border-white/10 text-[#e4e6f1]/60 uppercase tracking-wider text-[10px]">
                      <tr>
                        <th className="py-2.5">ID</th>
                        <th className="py-2.5">Rule Name</th>
                        <th className="py-2.5">Action</th>
                        <th className="py-2.5">P(Block)</th>
                        <th className="py-2.5">FPR</th>
                        <th className="py-2.5">Cost</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/10 font-mono">
                      {result.selected_rules.map((rule, idx) => (
                        <tr key={idx} className="hover:bg-white/[0.03] transition-colors">
                          <td className="py-3 font-bold text-[#06b6d4]">{rule.rule_id}</td>
                          <td className="py-3 font-sans font-medium text-white">{rule.name}</td>
                          <td className="py-3">
                            <span className="px-2.5 py-1 rounded-full pill-violet text-[10px] font-bold">
                              {rule.action}
                            </span>
                          </td>
                          <td className="py-3 text-emerald-400 font-bold">{(rule.block_probability * 100).toFixed(0)}%</td>
                          <td className="py-3 text-amber-400 font-bold">{(rule.false_positive_rate * 100).toFixed(1)}%</td>
                          <td className="py-3 text-[#e4e6f1]/70">{rule.cost}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          ) : (
            <div className="glass-panel rounded-3xl p-16 flex flex-col items-center justify-center text-center space-y-4">
              <div className="icon-glass w-16 h-16 rounded-2xl flex items-center justify-center text-[#06b6d4]">
                <Cpu className="w-8 h-8 text-[#06b6d4] animate-pulse" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-white font-display">Solver Circuit Ready</h3>
                <p className="text-[#e4e6f1]/70 text-xs mt-1 max-w-[45ch] leading-[1.6]">
                  Adjust constraint sliders on the left and click &quot;Run QAOA Solver&quot; to execute combinatorial rule optimization.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
