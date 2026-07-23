'use client';

import React, { useEffect, useState } from 'react';
import { fetchCryptoStatus, triggerKeyRotation, CryptoStatus } from '@/lib/api';
import { KeyRound, RefreshCw, ShieldCheck, Cpu } from 'lucide-react';

export default function CryptoPage() {
  const [status, setStatus] = useState<CryptoStatus | null>(null);
  const [loading, setLoading] = useState(false);

  const loadStatus = async () => {
    try {
      const data = await fetchCryptoStatus();
      setStatus(data);
    } catch (e) {
      console.error('Crypto status fetch error:', e);
    }
  };

  useEffect(() => {
    loadStatus();
  }, []);

  const handleRotate = async () => {
    setLoading(true);
    try {
      await triggerKeyRotation();
      await loadStatus();
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Post-Quantum Cryptography (PQC) Status</h1>
          <p className="text-slate-400 text-sm">NIST FIPS 203 ML-KEM-768 key encapsulation for internal API telemetry</p>
        </div>
        <button
          onClick={handleRotate}
          disabled={loading}
          className="px-4 py-2 text-sm font-semibold rounded-lg bg-indigo-500 text-white hover:bg-indigo-600 transition-all flex items-center space-x-2 shadow-lg shadow-indigo-500/20"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          <span>Manual Key Rotation</span>
        </button>
      </div>

      {status && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="rounded-xl bg-[#121824] border border-slate-800 p-6 space-y-4">
            <div className="flex items-center space-x-3 text-indigo-400 font-bold">
              <KeyRound className="w-6 h-6" />
              <span className="text-lg text-white">Cryptographic Parameters</span>
            </div>
            <div className="space-y-2 text-sm text-slate-300">
              <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                <span className="text-slate-400">Algorithm</span>
                <span className="font-mono text-cyan-400 font-semibold">{status.algorithm}</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                <span className="text-slate-400">Standard Specification</span>
                <span className="font-semibold text-white">{status.standard}</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                <span className="text-slate-400">Security Category</span>
                <span className="font-semibold text-emerald-400">{status.security_level}</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                <span className="text-slate-400">Active Key Fingerprint</span>
                <span className="font-mono text-xs text-indigo-300">{status.public_key_fingerprint}</span>
              </div>
            </div>
          </div>

          <div className="rounded-xl bg-[#121824] border border-slate-800 p-6 space-y-4">
            <div className="flex items-center space-x-3 text-purple-400 font-bold">
              <ShieldCheck className="w-6 h-6" />
              <span className="text-lg text-white">Key Rotation Telemetry</span>
            </div>
            <div className="space-y-2 text-sm text-slate-300">
              <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                <span className="text-slate-400">Total Rotations Executed</span>
                <span className="font-bold text-white">{status.total_rotations}</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                <span className="text-slate-400">Last Rotation Trigger</span>
                <span className="font-mono text-xs text-purple-300">{status.last_rotation_reason}</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                <span className="text-slate-400">Active PQC Sessions</span>
                <span className="font-semibold text-emerald-400">{status.active_sessions}</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
