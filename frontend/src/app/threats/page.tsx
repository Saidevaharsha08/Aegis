'use client';

import React, { useState } from 'react';
import { detectThreat, respondToThreat, DetectionResult } from '@/lib/api';
import { ShieldAlert, Activity, CheckCircle, Zap } from 'lucide-react';

export default function ThreatFeedPage() {
  const [loading, setLoading] = useState(false);
  const [detection, setDetection] = useState<DetectionResult | null>(null);
  const [responseLog, setResponseLog] = useState<any | null>(null);

  const simulateSampleAttack = async (type: 'BENIGN' | 'DoS' | 'BruteForce') => {
    setLoading(true);
    setResponseLog(null);
    try {
      let payload = {};
      if (type === 'DoS') {
        payload = {
          flow_duration: 95000.0,
          total_fwd_packets: 3000,
          total_bwd_packets: 1,
          flow_bytes_per_second: 95000000.0,
          syn_flag_count: 1,
          ack_flag_count: 0
        };
      } else if (type === 'BruteForce') {
        payload = {
          flow_duration: 5000.0,
          total_fwd_packets: 25,
          total_bwd_packets: 2,
          flow_bytes_per_second: 150000.0,
          psh_flag_count: 5,
          syn_flag_count: 1
        };
      } else {
        payload = {
          flow_duration: 1200.0,
          total_fwd_packets: 5,
          total_bwd_packets: 4,
          flow_bytes_per_second: 12000.0,
          syn_flag_count: 0,
          ack_flag_count: 1
        };
      }

      const res = await detectThreat(payload);
      setDetection(res);

      if (res.threat_detected) {
        const resp = await respondToThreat(res);
        setResponseLog(resp);
      }
    } catch (err) {
      console.error('Detection error:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Live Threat Feed & Detection Console</h1>
          <p className="text-slate-400 text-sm">Real-time XGBoost ML inference + SHAP local feature attributions</p>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={() => simulateSampleAttack('BENIGN')}
            disabled={loading}
            className="px-4 py-2 text-sm font-semibold rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20 transition-all"
          >
            Simulate BENIGN Traffic
          </button>
          <button
            onClick={() => simulateSampleAttack('DoS')}
            disabled={loading}
            className="px-4 py-2 text-sm font-semibold rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/30 hover:bg-rose-500/20 transition-all flex items-center space-x-1.5"
          >
            <ShieldAlert className="w-4 h-4" />
            <span>Simulate DoS Attack</span>
          </button>
        </div>
      </div>

      {detection && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Detection Card */}
          <div className="rounded-xl bg-[#121824] border border-slate-800 p-6 space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs uppercase tracking-wider text-slate-400 font-semibold">Inference Result</span>
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

            <div className="grid grid-cols-2 gap-4 text-xs pt-2">
              <div className="bg-[#0a0d14] p-3 rounded border border-slate-800">
                <span className="text-slate-400 block">Attack Classification</span>
                <span className="font-semibold text-white">{detection.attack_type}</span>
              </div>
              <div className="bg-[#0a0d14] p-3 rounded border border-slate-800">
                <span className="text-slate-400 block">Inference Latency</span>
                <span className="font-semibold text-cyan-400">{detection.inference_latency_ms} ms</span>
              </div>
            </div>

            {/* SHAP Explanations */}
            <div className="pt-2">
              <h4 className="text-xs uppercase tracking-wider font-semibold text-slate-400 mb-2">SHAP Top-5 Local Feature Attributions</h4>
              <div className="space-y-1.5">
                {detection.top_features.map((feat, idx) => (
                  <div key={idx} className="flex justify-between items-center text-xs bg-[#0a0d14] px-3 py-1.5 rounded border border-slate-800/80">
                    <span className="text-slate-300 font-mono">{feat.feature}</span>
                    <span className="text-cyan-400 font-bold">{feat.shap_value > 0 ? `+${feat.shap_value.toFixed(4)}` : feat.shap_value.toFixed(4)}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Response Execution Card */}
          {responseLog ? (
            <div className="rounded-xl bg-[#121824] border border-rose-500/30 p-6 space-y-4">
              <div className="flex items-center space-x-2 text-rose-400 font-bold text-sm">
                <Zap className="w-5 h-5" />
                <span>Automated Playbook Triggered ({responseLog.response_time_ms} ms)</span>
              </div>
              <div className="space-y-2 text-xs">
                <div className="bg-[#0a0d14] p-3 rounded border border-slate-800">
                  <span className="text-slate-400 block">Actions Executed</span>
                  <ul className="list-disc list-inside text-rose-300 space-y-1 mt-1 font-mono">
                    {responseLog.actions_taken.map((act: string, i: number) => (
                      <li key={i}>{act}</li>
                    ))}
                  </ul>
                </div>
                <div className="bg-[#0a0d14] p-3 rounded border border-slate-800">
                  <span className="text-slate-400 block">PQC Keys Rotated</span>
                  <span className="font-semibold text-emerald-400">{responseLog.keys_rotated ? 'ML-KEM-768 Keys Rotated Successfully' : 'No'}</span>
                </div>
                <div className="bg-[#0a0d14] p-3 rounded border border-slate-800">
                  <span className="text-slate-400 block">Tamper-Evident Ledger Entry ID</span>
                  <span className="font-mono text-cyan-400 text-[10px] break-all">{responseLog.ledger_entry_id}</span>
                </div>
              </div>
            </div>
          ) : (
            <div className="rounded-xl bg-[#121824] border border-slate-800 p-6 flex items-center justify-center text-slate-500 text-sm">
              No active threat response triggered.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
