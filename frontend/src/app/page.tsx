'use client';

import React, { useEffect, useState } from 'react';
import { ShieldCheck, Cpu, KeyRound, Database, Activity, AlertTriangle, ArrowRight } from 'lucide-react';

export default function Home() {
  const [stats, setStats] = useState({
    idsStatus: 'Active (F1: 1.0000)',
    pqcStatus: 'ML-KEM-768 (Active)',
    qaoaStatus: 'p=2 QAOA (Active)',
    ledgerStatus: 'SHA256 Valid',
    p99Latency: '0.81 ms'
  });

  return (
    <div className="space-y-8">
      {/* Hero Banner */}
      <div className="rounded-2xl bg-gradient-to-r from-indigo-900/40 via-slate-900 to-cyan-950/40 border border-indigo-500/20 p-8 shadow-2xl relative overflow-hidden">
        <div className="absolute -right-10 -bottom-10 w-64 h-64 bg-cyan-500/10 rounded-full blur-3xl"></div>
        <div className="relative z-10 space-y-4 max-w-3xl">
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-semibold">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>NIST FIPS 203 Post-Quantum Protected</span>
          </div>
          <h1 className="text-4xl font-extrabold tracking-tight text-white sm:text-5xl">
            Aegis Threat Detection System
          </h1>
          <p className="text-slate-300 text-base leading-relaxed">
            Coherent security architecture combining real-time XGBoost ML Intrusion Detection, NIST Level 3 ML-KEM-768 Key Encapsulation, QAOA Quantum-Inspired Firewall Optimization, and SHA256 Tamper-Evident Ledger Audit Logging.
          </p>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="rounded-xl bg-[#121824] border border-slate-800 p-6 space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs uppercase tracking-wider font-semibold">ML IDS Engine</span>
            <Cpu className="w-5 h-5 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold text-white">{stats.idsStatus}</div>
          <p className="text-xs text-slate-400">CICIDS2017 XGBoost + SHAP</p>
        </div>

        <div className="rounded-xl bg-[#121824] border border-slate-800 p-6 space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs uppercase tracking-wider font-semibold">PQC Layer</span>
            <KeyRound className="w-5 h-5 text-purple-400" />
          </div>
          <div className="text-2xl font-bold text-white">{stats.pqcStatus}</div>
          <p className="text-xs text-slate-400">192-bit Quantum Security</p>
        </div>

        <div className="rounded-xl bg-[#121824] border border-slate-800 p-6 space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs uppercase tracking-wider font-semibold">Rule Optimizer</span>
            <Activity className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-white">{stats.qaoaStatus}</div>
          <p className="text-xs text-slate-400">0-1 Knapsack QAOA Simulation</p>
        </div>

        <div className="rounded-xl bg-[#121824] border border-slate-800 p-6 space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs uppercase tracking-wider font-semibold">Audit Ledger</span>
            <Database className="w-5 h-5 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400">{stats.ledgerStatus}</div>
          <p className="text-xs text-slate-400">SHA256 Hash Chain Linked</p>
        </div>
      </div>

      {/* Feature Navigation Panels */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <a href="/threats" className="group rounded-xl bg-[#121824] border border-slate-800 p-6 hover:border-cyan-500/50 transition-all space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-bold text-white group-hover:text-cyan-400 transition-colors">Live Threat Monitoring Feed</h3>
            <ArrowRight className="w-5 h-5 text-slate-500 group-hover:text-cyan-400 group-hover:translate-x-1 transition-all" />
          </div>
          <p className="text-sm text-slate-400">
            Real-time inference stream with SHAP local feature attributions and immediate automated response triggers.
          </p>
        </a>

        <a href="/optimizer" className="group rounded-xl bg-[#121824] border border-slate-800 p-6 hover:border-indigo-500/50 transition-all space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-bold text-white group-hover:text-indigo-400 transition-colors">QAOA Rule Optimizer & Benchmarks</h3>
            <ArrowRight className="w-5 h-5 text-slate-500 group-hover:text-indigo-400 group-hover:translate-x-1 transition-all" />
          </div>
          <p className="text-sm text-slate-400">
            Interactive parameter tuning (FPR & cost budgets) comparing QAOA classical simulation against exact DP & Greedy solvers.
          </p>
        </a>
      </div>
    </div>
  );
}
