'use client';

import React, { useEffect, useRef, useState } from 'react';
import { detectThreat, respondToThreat, DetectionResult, subscribeDetections, fetchExplain, submitLabel, StreamedDetection, CachedExplanation } from '@/lib/api';
import {
  ShieldAlert,
  Activity,
  CheckCircle,
  Zap,
  Sliders,
  Terminal,
  KeyRound,
  Search,
  Sparkles,
  Radio
} from 'lucide-react';
import ThreatGauge from '@/components/ThreatGauge';

export default function ThreatFeedPage() {
  const [loading, setLoading] = useState(false);
  const [detection, setDetection] = useState<DetectionResult | null>(null);
  const [responseLog, setResponseLog] = useState<any | null>(null);
  const [activePreset, setActivePreset] = useState<string | null>(null);

  // Live SSE feed (milestone 3).
  const [liveFeed, setLiveFeed] = useState<StreamedDetection[]>([]);
  const [sseStatus, setSseStatus] = useState<'connecting' | 'live' | 'error'>('connecting');
  const [explainFor, setExplainFor] = useState<{ id: string; data: CachedExplanation | null; loading: boolean; error: string | null }>({ id: '', data: null, loading: false, error: null });
  const sseRef = useRef<EventSource | null>(null);

  // Custom vector inputs
  const [customFlowDuration, setCustomFlowDuration] = useState(95000);
  const [customFwdPackets, setCustomFwdPackets] = useState(3000);
  const [customBytesPerSec, setCustomBytesPerSec] = useState(95000000);
  const [customSynFlags, setCustomSynFlags] = useState(1);
  const [customAckFlags, setCustomAckFlags] = useState(0);

  const runDetectionWithPayload = async (payload: any) => {
    setLoading(true);
    setResponseLog(null);
    try {
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

  // Subscribe to the live detection SSE stream on mount.
  useEffect(() => {
    setSseStatus('connecting');
    const es = subscribeDetections(
      (det) => {
        setSseStatus('live');
        setLiveFeed((prev) => [det, ...prev].slice(0, 50));
      },
      () => setSseStatus('error'),
    );
    sseRef.current = es;
    // Mark live after a short grace period if no event arrives.
    const t = setTimeout(() => setSseStatus((s) => (s === 'connecting' ? 'live' : s)), 1500);
    return () => {
      clearTimeout(t);
      es.close();
      sseRef.current = null;
    };
  }, []);

  const handleExplain = async (detectionId: string) => {
    setExplainFor({ id: detectionId, data: null, loading: true, error: null });
    try {
      const data = await fetchExplain(detectionId);
      setExplainFor({ id: detectionId, data, loading: false, error: null });
    } catch (e: any) {
      setExplainFor({ id: detectionId, data: null, loading: false, error: e.message || 'fetch failed' });
    }
  };

  const handleLabel = async (detectionId: string, label: 'true_positive' | 'false_positive') => {
    try {
      await submitLabel(detectionId, label);
    } catch (e) {
      console.error('label submit failed', e);
    }
  };

  const simulatePreset = (type: 'BENIGN' | 'DoS' | 'BruteForce' | 'PortScan') => {
    setActivePreset(type);
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
      setCustomFlowDuration(95000);
      setCustomFwdPackets(3000);
      setCustomBytesPerSec(95000000);
      setCustomSynFlags(1);
      setCustomAckFlags(0);
    } else if (type === 'BruteForce') {
      payload = {
        flow_duration: 5000.0,
        total_fwd_packets: 25,
        total_bwd_packets: 2,
        flow_bytes_per_second: 150000.0,
        psh_flag_count: 5,
        syn_flag_count: 1
      };
      setCustomFlowDuration(5000);
      setCustomFwdPackets(25);
      setCustomBytesPerSec(150000);
      setCustomSynFlags(1);
      setCustomAckFlags(1);
    } else if (type === 'PortScan') {
      payload = {
        flow_duration: 350.0,
        total_fwd_packets: 1,
        total_bwd_packets: 1,
        flow_bytes_per_second: 5000.0,
        syn_flag_count: 1,
        ack_flag_count: 0
      };
      setCustomFlowDuration(350);
      setCustomFwdPackets(1);
      setCustomBytesPerSec(5000);
      setCustomSynFlags(1);
      setCustomAckFlags(0);
    } else {
      payload = {
        flow_duration: 1200.0,
        total_fwd_packets: 5,
        total_bwd_packets: 4,
        flow_bytes_per_second: 12000.0,
        syn_flag_count: 0,
        ack_flag_count: 1
      };
      setCustomFlowDuration(1200);
      setCustomFwdPackets(5);
      setCustomBytesPerSec(12000);
      setCustomSynFlags(0);
      setCustomAckFlags(1);
    }

    runDetectionWithPayload(payload);
  };

  const handleCustomSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const payload = {
      flow_duration: customFlowDuration,
      total_fwd_packets: customFwdPackets,
      flow_bytes_per_second: customBytesPerSec,
      syn_flag_count: customSynFlags,
      ack_flag_count: customAckFlags
    };
    runDetectionWithPayload(payload);
  };

  return (
    <div className="space-y-12 py-4">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 border-b border-white/10 pb-6">
        <div className="flex items-center space-x-4">
          <div className="icon-box-soft w-12 h-12 rounded-2xl flex items-center justify-center text-[#06b6d4]">
            <Activity className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-3xl font-extrabold text-white tracking-tight font-display">
              Threat Detection Console
            </h1>
            <p className="text-slate-400 text-sm mt-1">
              Real-time XGBoost ML inference stream with local SHAP feature attributions
            </p>
          </div>
        </div>

        {/* Attack Presets */}
        <div className="flex flex-wrap items-center gap-2.5">
          <button
            onClick={() => simulatePreset('BENIGN')}
            disabled={loading}
            className={`preset-btn ${activePreset === 'BENIGN' ? 'active' : 'inactive'}`}
          >
            <CheckCircle className="w-4 h-4" />
            <span>Simulate Benign</span>
          </button>

          <button
            onClick={() => simulatePreset('DoS')}
            disabled={loading}
            className={`preset-btn ${activePreset === 'DoS' ? 'active' : 'inactive'}`}
          >
            <ShieldAlert className="w-4 h-4" />
            <span>Simulate DoS</span>
          </button>

          <button
            onClick={() => simulatePreset('BruteForce')}
            disabled={loading}
            className={`preset-btn ${activePreset === 'BruteForce' ? 'active' : 'inactive'}`}
          >
            <Zap className="w-4 h-4" />
            <span>Simulate BruteForce</span>
          </button>

          <button
            onClick={() => simulatePreset('PortScan')}
            disabled={loading}
            className={`preset-btn ${activePreset === 'PortScan' ? 'active' : 'inactive'}`}
          >
            <Search className="w-4 h-4" />
            <span>Simulate PortScan</span>
          </button>
        </div>
        <div className="preset-row-subtext">Choose a traffic pattern to test.</div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Controls Card */}
        <div className="claude-card p-6 space-y-6">
          <div className="flex items-center space-x-2 text-[#06b6d4] font-bold text-sm border-b border-white/10 pb-3 font-display">
            <Sliders className="w-4 h-4" />
            <span>Traffic Vector Input Parameters</span>
          </div>

          <form onSubmit={handleCustomSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label className="text-xs text-slate-300 font-medium relative">Flow Duration (ms)
                <span className="info-icon" data-tip="How long this network connection lasted, in milliseconds">ⓘ</span>
              </label>
              <input
                type="number"
                value={customFlowDuration}
                onChange={(e) => setCustomFlowDuration(Number(e.target.value))}
                className="w-full form-control"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs text-slate-300 font-medium relative">Total Fwd Packets
                <span className="info-icon" data-tip="Number of data packets sent from source to destination">ⓘ</span>
              </label>
              <input
                type="number"
                value={customFwdPackets}
                onChange={(e) => setCustomFwdPackets(Number(e.target.value))}
                className="w-full form-control"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs text-slate-300 font-medium relative">Flow Bytes / Sec
                <span className="info-icon" data-tip="How much data was transferred per second — unusually high values can signal an attack">ⓘ</span>
              </label>
              <input
                type="number"
                value={customBytesPerSec}
                onChange={(e) => setCustomBytesPerSec(Number(e.target.value))}
                className="w-full form-control"
              />
            </div>

            <div className="grid grid-cols-2 gap-3 pt-2">
              <div className="space-y-1.5">
                <label className="text-xs text-slate-300 font-medium relative">SYN Flag
                  <span className="info-icon" data-tip="Whether this packet is trying to start a new connection (1 = yes, 0 = no)">ⓘ</span>
                </label>
                <select
                  value={customSynFlags}
                  onChange={(e) => setCustomSynFlags(Number(e.target.value))}
                  className="w-full form-control"
                >
                  <option value={0}>0 (False)</option>
                  <option value={1}>1 (True)</option>
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs text-slate-300 font-medium relative">ACK Flag
                  <span className="info-icon" data-tip="Whether this packet is acknowledging a received packet (1 = yes, 0 = no)">ⓘ</span>
                </label>
                <select
                  value={customAckFlags}
                  onChange={(e) => setCustomAckFlags(Number(e.target.value))}
                  className="w-full form-control"
                >
                  <option value={0}>0 (False)</option>
                  <option value={1}>1 (True)</option>
                </select>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full btn-hacktober-primary py-3.5 rounded-xl text-xs flex items-center justify-center space-x-2 shadow-lg"
            >
              <Sparkles className="w-4 h-4" />
              <span>{loading ? 'Evaluating Model...' : 'Run Custom Detection'}</span>
            </button>
          </form>
        </div>

        {/* Right Output View */}
        <div className="lg:col-span-2 space-y-6">
          {detection ? (
            <div className="space-y-6">
              {/* Circular Threat Gauge Meter */}
              <ThreatGauge
                score={detection.threat_score}
                attackType={detection.attack_type}
                threatDetected={detection.threat_detected}
                latencyMs={detection.inference_latency_ms}
                topFeatures={detection.top_features}
              />

              {/* SHAP Attributions */}
              <div className="claude-card p-6 space-y-4">
                <div className="flex items-center justify-between border-b border-white/10 pb-3">
                  <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2 font-display">
                    <Terminal className="w-4 h-4 text-[#06b6d4]" />
                    <span>SHAP Local Feature Impact Attributions</span>
                  </h3>
                  <span className="text-xs text-slate-400 font-mono">XGBoost Explainer</span>
                </div>

                <div className="space-y-3">
                  {(detection.top_features ?? []).map((feat, idx) => {
                    const isPositive = feat.shap_value > 0;
                    return (
                      <div key={idx} className="bg-[#070a13] rounded-xl p-3.5 border border-white/10 space-y-2">
                        <div className="flex justify-between items-center text-xs">
                          <span className="font-mono text-slate-200 font-medium">{feat.feature}</span>
                          <span className={`font-mono font-bold ${isPositive ? 'text-rose-400' : 'text-[#06b6d4]'}`}>
                            {isPositive ? `+${feat.shap_value.toFixed(4)}` : feat.shap_value.toFixed(4)}
                          </span>
                        </div>
                        <div className="w-full h-1.5 rounded-full bg-slate-900 overflow-hidden">
                          <div
                            className={`h-full ${isPositive ? 'bg-rose-500' : 'bg-[#06b6d4]'}`}
                            style={{ width: `${Math.min(Math.abs(feat.shap_value) * 100, 100)}%` }}
                          ></div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Response Log */}
              {responseLog ? (
                <div className="claude-card p-6 border border-rose-500/30 space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2.5 text-rose-400 font-bold text-sm font-display">
                      <Zap className="w-5 h-5 animate-pulse" />
                      <span>Automated Defense Playbook Triggered</span>
                    </div>
                    <span className="text-xs font-mono px-3 py-1 rounded-full pill-badge-violet">
                      Response: {responseLog.response_time_ms} ms
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                    <div className="bg-[#070a13] p-4 rounded-2xl border border-white/10 space-y-2">
                      <span className="text-slate-400 font-bold uppercase tracking-wider text-[10px] block">Actions Executed</span>
                      <ul className="space-y-1 font-mono text-rose-300">
                        {(responseLog.actions_taken ?? []).map((act: string, i: number) => (
                          <li key={i} className="flex items-center space-x-2">
                            <span className="text-rose-500">•</span>
                            <span>{act}</span>
                          </li>
                        ))}
                      </ul>
                    </div>

                    <div className="bg-[#070a13] p-4 rounded-2xl border border-white/10 space-y-3">
                      <div>
                        <span className="text-slate-400 font-bold uppercase tracking-wider text-[10px] block">NIST ML-KEM-768 PQC Keys</span>
                        <span className="font-semibold text-emerald-400 flex items-center space-x-1.5 mt-1 font-mono">
                          <KeyRound className="w-4 h-4 text-[#7c5cff]" />
                          <span>{responseLog.keys_rotated ? 'Rotated ML-KEM Keypair' : 'Retained Active Channel'}</span>
                        </span>
                      </div>

                      <div className="pt-2 border-t border-white/10">
                        <span className="text-slate-400 font-bold uppercase tracking-wider text-[10px] block">Audit Ledger Hash ID</span>
                        <span className="font-mono text-[11px] text-[#06b6d4] break-all block mt-0.5">
                          {responseLog.ledger_entry_id}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              ) : null}
            </div>
          ) : (
            <div className="claude-card p-16 flex flex-col items-center justify-center text-center space-y-4">
              <div className="icon-box-soft w-16 h-16 rounded-2xl flex items-center justify-center text-[#06b6d4]">
                <Activity className="w-8 h-8 text-[#06b6d4] animate-pulse" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-white font-display">Console Idle — Ready for Inference</h3>
                <p className="text-slate-400 text-xs mt-1 max-w-[45ch] leading-[1.7]">
                  Select an attack preset at the top or adjust vector parameters to evaluate live XGBoost model predictions.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Live detection feed (milestone 3) */}
      <div className="claude-card p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-white/10 pb-3">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2 font-display">
            <Radio className={`w-4 h-4 ${sseStatus === 'live' ? 'text-emerald-400' : sseStatus === 'error' ? 'text-rose-400' : 'text-[#06b6d4]'}`} />
            <span>Live Detection Stream (SSE)</span>
          </h3>
          <span className="text-xs font-mono text-slate-400">
            {sseStatus === 'live' && <span className="text-emerald-400">● Connected</span>}
            {sseStatus === 'connecting' && <span className="text-[#06b6d4]">● Connecting…</span>}
            {sseStatus === 'error' && <span className="text-rose-400">● Disconnected</span>}
            <span className="ml-2">{liveFeed.length} event{liveFeed.length === 1 ? '' : 's'}</span>
          </span>
        </div>

        {liveFeed.length === 0 ? (
          <p className="text-xs text-slate-500">
            Waiting for the online detector to push events. Send traffic via the Ingest page or run a preset above.
          </p>
        ) : (
          <ul className="space-y-2">
            {liveFeed.map((det) => (
              <li key={det.detection_id + det.timestamp} className="bg-[#070a13] rounded-xl p-3 border border-white/10 space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                  <div className="flex items-center space-x-2 font-mono">
                    <span className={det.threat_detected ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}>
                      {det.threat_detected ? '⚠ ' : '✓ '}{det.attack_type}
                    </span>
                    <span className="text-slate-500">score={det.threat_score.toFixed(3)}</span>
                    <span className="text-slate-600">·</span>
                    <span className="text-slate-400">id={det.detection_id.slice(0, 8)}</span>
                  </div>
                  <div className="flex items-center space-x-1.5">
                    <button
                      type="button"
                      onClick={() => handleExplain(det.detection_id)}
                      className="px-2 py-1 rounded-md bg-white/5 hover:bg-white/10 text-[11px] font-mono text-slate-200"
                    >
                      Explain
                    </button>
                    <button
                      type="button"
                      onClick={() => handleLabel(det.detection_id, 'true_positive')}
                      className="px-2 py-1 rounded-md bg-emerald-500/15 hover:bg-emerald-500/25 text-[11px] font-mono text-emerald-300"
                    >
                      TP
                    </button>
                    <button
                      type="button"
                      onClick={() => handleLabel(det.detection_id, 'false_positive')}
                      className="px-2 py-1 rounded-md bg-rose-500/15 hover:bg-rose-500/25 text-[11px] font-mono text-rose-300"
                    >
                      FP
                    </button>
                  </div>
                </div>
                {explainFor.id === det.detection_id && (
                  <div className="text-[11px] font-mono text-slate-300 border-t border-white/5 pt-2">
                    {explainFor.loading && 'loading explain…'}
                    {explainFor.error && <span className="text-rose-400">{explainFor.error}</span>}
                    {explainFor.data && (
                      <ol className="space-y-0.5">
                        {explainFor.data.top_features.map((f, i) => (
                          <li key={i}>
                            <span className="text-slate-400">{f.feature}</span>
                            <span className="text-slate-600"> · </span>
                            <span className={f.shap_value >= 0 ? 'text-rose-300' : 'text-cyan-300'}>
                              {f.shap_value.toFixed(4)}
                            </span>
                          </li>
                        ))}
                      </ol>
                    )}
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
