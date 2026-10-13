'use client';

import React, { useEffect, useState } from 'react';
import {
  fetchGeneratorAttackTypes,
  generateSingleAttack,
  launchAttackBarrage,
  GeneratorAttackType,
} from '@/lib/api';
import {
  ShieldAlert,
  Zap,
  Activity,
  Sliders,
  Terminal,
  KeyRound,
  Search,
  Sparkles,
  Layers,
  Cpu,
  Flame,
  CheckCircle,
  AlertTriangle,
  Play,
  RotateCw,
  Server,
  Lock,
} from 'lucide-react';
import ThreatGauge from '@/components/ThreatGauge';

export default function AttackGeneratorPage() {
  const [attackTypes, setAttackTypes] = useState<GeneratorAttackType[]>([]);
  const [selectedType, setSelectedType] = useState<string>('DoS');
  const [sourceIp, setSourceIp] = useState<string>('198.51.100.42');
  const [autoRespond, setAutoRespond] = useState<boolean>(true);
  const [optimizeRules, setOptimizeRules] = useState<boolean>(true);

  const [loading, setLoading] = useState<boolean>(false);
  const [singleResult, setSingleResult] = useState<any | null>(null);

  // Barrage states
  const [barrageCount, setBarrageCount] = useState<number>(15);
  const [barrageLoading, setBarrageLoading] = useState<boolean>(false);
  const [barrageResult, setBarrageResult] = useState<any | null>(null);

  useEffect(() => {
    fetchGeneratorAttackTypes()
      .then(setAttackTypes)
      .catch((err) => console.error('Failed to load attack types:', err));
  }, []);

  const handleInjectSingle = async (typeKey?: string) => {
    const targetKey = typeKey || selectedType;
    setSelectedType(targetKey);
    setLoading(true);
    setSingleResult(null);
    try {
      const res = await generateSingleAttack({
        attack_type: targetKey,
        source_ip: sourceIp,
        auto_respond: autoRespond,
        optimize_rules: optimizeRules,
      });
      setSingleResult(res);
    } catch (err) {
      console.error('Error generating attack:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleLaunchBarrage = async () => {
    setBarrageLoading(true);
    setBarrageResult(null);
    try {
      const res = await launchAttackBarrage(barrageCount, autoRespond);
      setBarrageResult(res);
    } catch (err) {
      console.error('Barrage launch failed:', err);
    } finally {
      setBarrageLoading(false);
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return <span className="px-2.5 py-1 text-[10px] font-mono font-bold rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/40">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2.5 py-1 text-[10px] font-mono font-bold rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/40">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2.5 py-1 text-[10px] font-mono font-bold rounded-full bg-cyan-500/20 text-cyan-400 border border-cyan-500/40">MEDIUM</span>;
      default:
        return <span className="px-2.5 py-1 text-[10px] font-mono font-bold rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">INFORMATIONAL</span>;
    }
  };

  return (
    <div className="space-y-10 py-6 max-w-7xl mx-auto px-4">
      {/* Hero Header */}
      <div className="border-b border-white/10 pb-8 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
        <div>
          <div className="flex items-center space-x-3 mb-2">
            <span className="px-3 py-1 text-xs font-mono font-semibold rounded-full bg-[#06b6d4]/10 text-[#06b6d4] border border-[#06b6d4]/30 flex items-center space-x-1.5">
              <Flame className="w-3.5 h-3.5 text-rose-400 animate-pulse" />
              <span>Multi-Vector Red Team Barrage Engine</span>
            </span>
            <span className="text-xs text-slate-400 font-mono">10 Attack Profiles · QAOA Coupled</span>
          </div>
          <h1 className="text-4xl font-extrabold text-white tracking-tight font-display">
            Attack Generator Studio
          </h1>
          <p className="text-slate-400 text-sm mt-2 max-w-3xl leading-relaxed">
            Synthesize and inject realistic attack vectors (DoS, DDoS, PortScan, BruteForce, Botnet, Web Exploits, Heartbleed, Infiltration) into Aegis. Observe full end-to-end processing across XGBoost ML classification, SHAP explanations, QAOA rule optimization, and hash-chained ledger logging.
          </p>
        </div>

        {/* Quick Stats Pill */}
        <div className="flex items-center space-x-4 bg-[#070a13] p-4 rounded-2xl border border-white/10 text-xs font-mono">
          <div>
            <div className="text-slate-500 text-[10px]">PROFILES AVAILABLE</div>
            <div className="text-lg font-bold text-white mt-0.5">10 Categories</div>
          </div>
          <div className="h-8 w-px bg-white/10" />
          <div>
            <div className="text-slate-500 text-[10px]">PIPELINE STATUS</div>
            <div className="text-emerald-400 font-bold flex items-center space-x-1 mt-0.5">
              <CheckCircle className="w-3.5 h-3.5" />
              <span>Active</span>
            </div>
          </div>
        </div>
      </div>

      {/* Main Grid: Attack Selectors vs Live Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left 2 Cols: Attack Vector Catalogue */}
        <div className="lg:col-span-2 space-y-6">
          <div className="flex items-center justify-between border-b border-white/10 pb-3">
            <h2 className="text-base font-bold text-white flex items-center space-x-2 font-display">
              <Layers className="w-5 h-5 text-[#06b6d4]" />
              <span>Select &amp; Inject Attack Profile</span>
            </h2>
            <span className="text-xs text-slate-400 font-mono">Click any card to inject directly</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {attackTypes.map((atk) => {
              const isSelected = selectedType === atk.key;
              return (
                <div
                  key={atk.key}
                  onClick={() => handleInjectSingle(atk.key)}
                  className={`p-4 rounded-2xl border transition-all cursor-pointer relative overflow-hidden group ${
                    isSelected
                      ? 'bg-[#06b6d4]/10 border-[#06b6d4] shadow-lg shadow-[#06b6d4]/10'
                      : 'bg-[#070a13] border-white/10 hover:border-white/20 hover:bg-[#0c101c]'
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="font-bold text-sm text-white font-display flex items-center space-x-2">
                        <span>{atk.name}</span>
                      </div>
                      <div className="text-[11px] text-slate-400 font-mono mt-1">
                        Key: <span className="text-slate-200">{atk.key}</span> · Port: <span className="text-[#06b6d4]">{atk.target_port}</span>
                      </div>
                    </div>
                    {getSeverityBadge(atk.severity)}
                  </div>

                  <p className="text-xs text-slate-400 mt-2.5 line-clamp-2 leading-relaxed">
                    {atk.description}
                  </p>

                  <div className="mt-4 flex items-center justify-between pt-3 border-t border-white/5 text-xs font-mono">
                    <span className="text-slate-500 group-hover:text-slate-300 transition-colors">
                      {isSelected ? '● Currently Selected' : 'Click to Inject →'}
                    </span>
                    <button
                      type="button"
                      disabled={loading}
                      onClick={(e) => {
                        e.stopPropagation();
                        handleInjectSingle(atk.key);
                      }}
                      className="px-3 py-1.5 rounded-lg bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 text-[11px] font-semibold flex items-center space-x-1.5"
                    >
                      <Sparkles className="w-3.5 h-3.5" />
                      <span>{loading && isSelected ? 'Injecting...' : 'Inject Attack'}</span>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Col: Custom Injector & Multi-Vector Barrage Launcher */}
        <div className="space-y-6">
          {/* Single Injector Controls */}
          <div className="claude-card p-6 space-y-5">
            <div className="flex items-center space-x-2 text-[#06b6d4] font-bold text-sm border-b border-white/10 pb-3 font-display">
              <Sliders className="w-4 h-4" />
              <span>Injection Parameters</span>
            </div>

            <div className="space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs text-slate-300 font-medium">Selected Attack Vector</label>
                <select
                  value={selectedType}
                  onChange={(e) => setSelectedType(e.target.value)}
                  className="w-full form-control font-mono text-xs"
                >
                  {attackTypes.map((a) => (
                    <option key={a.key} value={a.key}>
                      {a.name} ({a.key})
                    </option>
                  ))}
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs text-slate-300 font-medium">Simulated Attacker Source IP</label>
                <input
                  type="text"
                  value={sourceIp}
                  onChange={(e) => setSourceIp(e.target.value)}
                  className="w-full form-control font-mono text-xs"
                  placeholder="203.0.113.42"
                />
              </div>

              <div className="flex items-center justify-between pt-1">
                <label className="text-xs text-slate-300 font-medium cursor-pointer flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={autoRespond}
                    onChange={(e) => setAutoRespond(e.target.checked)}
                    className="rounded bg-slate-900 border-white/20 text-[#06b6d4] focus:ring-0"
                  />
                  <span>Execute Automated Response</span>
                </label>
              </div>

              <div className="flex items-center justify-between">
                <label className="text-xs text-slate-300 font-medium cursor-pointer flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={optimizeRules}
                    onChange={(e) => setOptimizeRules(e.target.checked)}
                    className="rounded bg-slate-900 border-white/20 text-[#06b6d4] focus:ring-0"
                  />
                  <span>Run QAOA Rule Optimizer</span>
                </label>
              </div>

              <button
                type="button"
                onClick={() => handleInjectSingle()}
                disabled={loading}
                className="w-full btn-hacktober-primary py-3.5 rounded-xl text-xs flex items-center justify-center space-x-2 shadow-lg"
              >
                <Zap className="w-4 h-4" />
                <span>{loading ? 'Evaluating Pipeline...' : `Inject ${selectedType} Attack`}</span>
              </button>
            </div>
          </div>

          {/* Multi-Vector Barrage Launcher */}
          <div className="claude-card p-6 border border-rose-500/30 space-y-5">
            <div className="flex items-center space-x-2 text-rose-400 font-bold text-sm border-b border-white/10 pb-3 font-display">
              <Flame className="w-4 h-4 animate-bounce text-rose-400" />
              <span>Multi-Vector Barrage Campaign</span>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              Blast Aegis with a multi-vector barrage across randomized attack vectors to stress-test real-time detection, QAOA synthesis, and ledger speed.
            </p>

            <div className="space-y-3">
              <div className="flex justify-between items-center text-xs">
                <span className="text-slate-300">Barrage Vector Count:</span>
                <span className="font-mono font-bold text-[#06b6d4] text-sm">{barrageCount} Attacks</span>
              </div>
              <input
                type="range"
                min={5}
                max={50}
                step={5}
                value={barrageCount}
                onChange={(e) => setBarrageCount(Number(e.target.value))}
                className="w-full accent-[#06b6d4]"
              />

              <button
                type="button"
                onClick={handleLaunchBarrage}
                disabled={barrageLoading}
                className="w-full py-3.5 rounded-xl bg-gradient-to-r from-rose-600 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white font-bold text-xs flex items-center justify-center space-x-2 shadow-lg transition-all"
              >
                <Play className="w-4 h-4 fill-white" />
                <span>{barrageLoading ? 'Running Attack Barrage...' : `Launch ${barrageCount}-Attack Barrage`}</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* End-to-End Pipeline Output Section */}
      {singleResult && (
        <div className="space-y-6 border-t border-white/10 pt-8">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-bold text-white flex items-center space-x-2 font-display">
              <Cpu className="w-6 h-6 text-[#06b6d4]" />
              <span>End-to-End Evaluation Output for {singleResult.attack_profile?.name}</span>
            </h2>
            <span className="text-xs font-mono text-emerald-400 bg-emerald-500/10 px-3 py-1 rounded-full border border-emerald-500/30">
              ● Pipeline Executed
            </span>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* Left: Gauge Meter */}
            <div>
              <ThreatGauge
                score={singleResult.detection?.threat_score || 0}
                attackType={singleResult.detection?.attack_type || 'BENIGN'}
                threatDetected={singleResult.detection?.threat_detected || false}
                latencyMs={singleResult.detection?.inference_latency_ms || 0}
                topFeatures={singleResult.detection?.top_features}
              />
            </div>

            {/* Right: QAOA & Response & Ledger Breakdown */}
            <div className="lg:col-span-2 space-y-6">
              {/* SHAP Attributions */}
              <div className="claude-card p-6 space-y-4">
                <div className="flex items-center justify-between border-b border-white/10 pb-3">
                  <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2 font-display">
                    <Terminal className="w-4 h-4 text-[#06b6d4]" />
                    <span>SHAP Feature Attributions</span>
                  </h3>
                  <span className="text-xs text-slate-400 font-mono">Local Explainability</span>
                </div>

                <div className="space-y-2.5">
                  {(singleResult.detection?.top_features || []).map((feat: any, idx: number) => {
                    const isPos = feat.shap_value > 0;
                    return (
                      <div key={idx} className="bg-[#070a13] rounded-xl p-3 border border-white/10 flex justify-between items-center text-xs">
                        <span className="font-mono text-slate-200">{feat.feature}</span>
                        <div className="flex items-center space-x-3">
                          <span className="text-slate-500 font-mono">val={feat.value}</span>
                          <span className={`font-mono font-bold ${isPos ? 'text-rose-400' : 'text-[#06b6d4]'}`}>
                            {isPos ? `+${feat.shap_value.toFixed(4)}` : feat.shap_value.toFixed(4)}
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* QAOA & Ledger Results */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* QAOA Optimizer Result */}
                {singleResult.qaoa_optimization && (
                  <div className="bg-[#070a13] p-5 rounded-2xl border border-[#06b6d4]/30 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-[#06b6d4] uppercase tracking-wider flex items-center space-x-1.5 font-display">
                        <Cpu className="w-4 h-4" />
                        <span>QAOA Firewall Synthesis</span>
                      </span>
                      <span className="text-[10px] font-mono text-slate-400">
                        {singleResult.qaoa_optimization.solver}
                      </span>
                    </div>

                    <div className="text-xs space-y-1.5 font-mono">
                      <div className="flex justify-between">
                        <span className="text-slate-400">Rules Selected:</span>
                        <span className="text-emerald-400 font-bold">{singleResult.qaoa_optimization.selected_rules?.length} rules</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Block Probability:</span>
                        <span className="text-white">{(singleResult.qaoa_optimization.total_block_probability * 100).toFixed(1)}%</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">False Positive Rate:</span>
                        <span className="text-amber-400">{(singleResult.qaoa_optimization.total_fpr * 100).toFixed(2)}%</span>
                      </div>
                    </div>

                    <div className="pt-2 border-t border-white/10">
                      <span className="text-[10px] text-slate-500 uppercase block font-bold">Applied Rules</span>
                      <ul className="mt-1 space-y-1 text-xs font-mono text-slate-300">
                        {(singleResult.qaoa_optimization.selected_rules || []).map((r: string, i: number) => (
                          <li key={i} className="flex items-center space-x-1.5">
                            <span className="text-[#06b6d4]">•</span>
                            <span>{r}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                )}

                {/* Audit Ledger & Response */}
                <div className="bg-[#070a13] p-5 rounded-2xl border border-purple-500/30 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-purple-400 uppercase tracking-wider flex items-center space-x-1.5 font-display">
                      <Lock className="w-4 h-4" />
                      <span>Ledger &amp; PQC Defense</span>
                    </span>
                    <span className="text-[10px] font-mono text-slate-400">ML-KEM-768</span>
                  </div>

                  <div className="space-y-2 text-xs">
                    <div>
                      <span className="text-slate-500 text-[10px] uppercase font-bold block">Ledger Current Hash</span>
                      <span className="font-mono text-[11px] text-[#06b6d4] break-all block mt-0.5">
                        {singleResult.ledger_entry?.current_hash}
                      </span>
                    </div>

                    {singleResult.response && (
                      <div className="pt-2 border-t border-white/10 space-y-1 font-mono">
                        <span className="text-slate-500 text-[10px] uppercase font-bold block">Response Actions Executed</span>
                        {(singleResult.response?.actions_taken || []).map((act: string, i: number) => (
                          <div key={i} className="text-rose-400 flex items-center space-x-1.5">
                            <span>✓</span>
                            <span>{act}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Barrage Campaign Results Table */}
      {barrageResult && (
        <div className="claude-card p-6 space-y-5 border border-amber-500/30">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/10 pb-4">
            <div>
              <h3 className="text-lg font-bold text-white flex items-center space-x-2 font-display">
                <Flame className="w-5 h-5 text-amber-400" />
                <span>Multi-Vector Barrage Campaign Analytics</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Aggregated IDS evaluation across {barrageResult.total_attacks_generated} injected attack vectors
              </p>
            </div>

            <div className="flex items-center space-x-4 font-mono text-xs">
              <div className="bg-[#070a13] px-3 py-1.5 rounded-xl border border-white/10">
                <span className="text-slate-500">Threat Detection Rate: </span>
                <span className="text-emerald-400 font-bold">{barrageResult.detection_rate_percent}%</span>
              </div>
              <div className="bg-[#070a13] px-3 py-1.5 rounded-xl border border-white/10">
                <span className="text-slate-500">Avg Latency: </span>
                <span className="text-[#06b6d4] font-bold">{barrageResult.avg_inference_latency_ms} ms</span>
              </div>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="text-slate-500 border-b border-white/10">
                  <th className="py-2.5 px-3">#</th>
                  <th className="py-2.5 px-3">ATTACK TYPE</th>
                  <th className="py-2.5 px-3">ATTACKER IP</th>
                  <th className="py-2.5 px-3">THREAT SCORE</th>
                  <th className="py-2.5 px-3">CONFIDENCE</th>
                  <th className="py-2.5 px-3">LEDGER HASH</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {barrageResult.attacks.map((item: any) => (
                  <tr key={item.step} className="hover:bg-white/5 transition-colors">
                    <td className="py-2.5 px-3 text-slate-500">{item.step}</td>
                    <td className="py-2.5 px-3 font-bold text-white">
                      <span className={item.threat_detected ? 'text-rose-400' : 'text-emerald-400'}>
                        {item.attack_type}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-300">{item.source_ip}</td>
                    <td className="py-2.5 px-3 font-bold">
                      <span className={item.threat_score >= 0.5 ? 'text-rose-400' : 'text-emerald-400'}>
                        {item.threat_score.toFixed(3)}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-400">{item.confidence}</td>
                    <td className="py-2.5 px-3 text-[#06b6d4]">{item.ledger_hash}...</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
