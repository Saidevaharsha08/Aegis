'use client';

import React, { useEffect, useState } from 'react';
import { fetchCryptoStatus, triggerKeyRotation, CryptoStatus } from '@/lib/api';
import { KeyRound, RefreshCw, ShieldCheck, Lock, Cpu, Server, CheckCircle2, Zap, AlertTriangle } from 'lucide-react';
import LatticeMatrix from '@/components/LatticeMatrix';

export default function CryptoPage() {
  const [status, setStatus] = useState<CryptoStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [rotating, setRotating] = useState(false);

  const loadStatus = async () => {
    setLoading(true);
    try {
      const data = await fetchCryptoStatus();
      setStatus(data);
    } catch (e) {
      console.error('Crypto status fetch error:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadStatus();
  }, []);

  const handleRotate = async () => {
    setRotating(true);
    try {
      await triggerKeyRotation();
      await loadStatus();
    } catch (e) {
      console.error(e);
    } finally {
      setRotating(false);
    }
  };

  return (
    <div className="space-y-12 py-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-6 border-b border-white/10 pb-6">
        <div className="flex items-center space-x-4">
          <div className="icon-glass w-12 h-12 rounded-2xl flex items-center justify-center text-[#7c5cff]">
            <KeyRound className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-3xl font-extrabold text-white tracking-tight font-display">
              Post-Quantum Cryptography (PQC) Engine
            </h1>
            <p className="text-[#e4e6f1]/70 text-sm mt-1">
              NIST FIPS 203 ML-KEM-768 Key Encapsulation protecting internal API telemetry against quantum decryption
            </p>
          </div>
        </div>

        <button
          onClick={handleRotate}
          disabled={rotating}
          className="btn-primary-gradient px-6 py-3.5 rounded-2xl text-xs flex items-center space-x-2 shadow-lg"
        >
          <RefreshCw className={`w-4 h-4 ${rotating ? 'animate-spin' : ''}`} />
          <span>{rotating ? 'Generating ML-KEM Keypair...' : 'Trigger PQC Key Rotation'}</span>
        </button>
      </div>

      {status ? (
        <div className="space-y-10">
          {/* Active Key Status Card */}
          <div className="glass-panel rounded-3xl p-8 border border-[#7c5cff]/30 space-y-6 glow-purple">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/10 pb-6">
              <div className="flex items-center space-x-4">
                <div className="icon-glass w-14 h-14 rounded-2xl flex items-center justify-center text-[#7c5cff]">
                  <Lock className="w-7 h-7" />
                </div>
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="px-3 py-1 rounded-full text-xs font-bold pill-violet font-mono uppercase tracking-wide">
                      Active Keypair
                    </span>
                    <span className="text-xs text-[#e4e6f1]/70 font-mono">Algorithm: {status.algorithm}</span>
                  </div>
                  <h2 className="text-2xl font-bold text-white mt-1 font-display">{status.standard}</h2>
                </div>
              </div>

              <div className="flex items-center space-x-3 bg-[#0c1222] px-4 py-2.5 rounded-2xl border border-white/10">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
                <div className="text-xs">
                  <span className="text-[#e4e6f1]/60 block text-[10px] uppercase font-bold">Security Level</span>
                  <span className="font-bold text-emerald-400 font-mono">{status.security_level}</span>
                </div>
              </div>
            </div>

            {/* Parameter Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-[#0c1222] p-5 rounded-2xl border border-white/10 space-y-2">
                <span className="text-[#e4e6f1]/60 text-xs uppercase tracking-wider font-bold block">Active Key Fingerprint</span>
                <p className="font-mono text-xs text-[#7c5cff] break-all bg-slate-950 p-3 rounded-xl border border-slate-900">
                  {status.public_key_fingerprint}
                </p>
              </div>

              <div className="bg-[#0c1222] p-5 rounded-2xl border border-white/10 space-y-2">
                <span className="text-[#e4e6f1]/60 text-xs uppercase tracking-wider font-bold block">Total Key Rotations</span>
                <div className="text-3xl font-black text-white font-mono">{status.total_rotations}</div>
                <span className="text-xs text-[#e4e6f1]/60">Reason: {status.last_rotation_reason}</span>
              </div>

              <div className="bg-[#0c1222] p-5 rounded-2xl border border-white/10 space-y-2">
                <span className="text-[#e4e6f1]/60 text-xs uppercase tracking-wider font-bold block">Active PQC Sessions</span>
                <div className="text-3xl font-black text-emerald-400 font-mono">{status.active_sessions}</div>
                <span className="text-xs text-[#e4e6f1]/60 font-mono">Encapsulated Overhead: &lt; 0.15 ms</span>
              </div>
            </div>
          </div>

          {/* Module-LWE Polynomial Matrix Visualizer */}
          <LatticeMatrix />

          {/* Quantum Defense Comparison */}
          <div className="glass-panel rounded-3xl p-8 space-y-6">
            <h2 className="text-xl font-bold text-white flex items-center space-x-2 font-display">
              <ShieldCheck className="w-5 h-5 text-[#7c5cff]" />
              <span>Quantum Interception Security Comparison</span>
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="bg-[#0c1222] rounded-2xl p-6 border border-rose-500/30 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="font-bold text-rose-400 text-sm font-display">Classical RSA / ECC Cryptography</h3>
                  <span className="px-2.5 py-0.5 rounded-full pill-rose text-[10px] font-bold font-mono">Vulnerable</span>
                </div>
                <p className="text-xs text-[#e4e6f1]/80 leading-[1.7]">
                  Relies on integer factorization or discrete logarithms. Easily broken by Shor&apos;s quantum algorithm on a Cryptographically Relevant Quantum Computer (CRQC).
                </p>
                <div className="text-[11px] font-mono text-rose-300 bg-rose-950/40 p-3 rounded-xl border border-rose-900/50">
                  Target for Harvest-Now-Decrypt-Later Interception
                </div>
              </div>

              <div className="bg-[#0c1222] rounded-2xl p-6 border border-[#7c5cff]/30 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="font-bold text-[#7c5cff] text-sm font-display">NIST ML-KEM-768 (Module-LWE)</h3>
                  <span className="px-2.5 py-0.5 rounded-full pill-success text-[10px] font-bold font-mono">Quantum Secure</span>
                </div>
                <p className="text-xs text-[#e4e6f1]/80 leading-[1.7]">
                  Based on Module Learning With Errors (M-LWE) lattice problems. Provably secure against quantum matrix reduction and lattice-sieving attacks.
                </p>
                <div className="text-[11px] font-mono text-emerald-300 bg-emerald-950/40 p-3 rounded-xl border border-emerald-900/50">
                  NIST FIPS 203 Standardized • Category 3 Protection
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="glass-panel rounded-3xl p-16 flex items-center justify-center text-[#e4e6f1]/60">
          <RefreshCw className="w-8 h-8 text-[#7c5cff] animate-spin" />
        </div>
      )}
    </div>
  );
}
