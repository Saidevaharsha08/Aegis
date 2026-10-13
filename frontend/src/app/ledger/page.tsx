'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { verifyLedgerChain, fetchLedgerEntries, LedgerVerification } from '@/lib/api';
import { Database, ShieldCheck, AlertCircle, RefreshCw, FileText, Link2, Lock } from 'lucide-react';
import LedgerChainGraph from '@/components/LedgerChainGraph';

export default function LedgerPage() {
  const [verification, setVerification] = useState<LedgerVerification | null>(null);
  const [entries, setEntries] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);

  const loadData = async () => {
    setLoading(true);
    try {
      const v = await verifyLedgerChain();
      setVerification(v);
      const e = await fetchLedgerEntries(20, 0);
      setEntries(e.entries || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  return (
    <div className="feature-page">
      <header className="feature-hero">
        <div className="eyebrow">SHA256 · NIS2 / SOC2</div>
        <h1>Audit Ledger</h1>
        <p>Immutable SHA256 audit chain for detections, model versions, and response actions.</p>
      </header>

      <section className="feature-content" style={{ marginBottom: 24 }}>
        <div className="feature-section">
          <span className="feature-section-eyebrow">Tamper-evidence</span>
          <h2>Tamper-evident Records</h2>
          <p>Every detection and response is appended to the ledger with a cryptographic hash linking each block to its predecessor.</p>
          <Link href="/detection" className="feature-cta">View Detections →</Link>
        </div>

        <div className="feature-section">
          <span className="feature-section-eyebrow">Integrity Proof</span>
          <h2>O(N) Chain Verification</h2>
          <p>Verify the entire chain in linear time — broken links surface the exact block where continuity fails.</p>
          <Link href="/response" className="feature-cta">Response Playbooks →</Link>
        </div>

        <div className="feature-section">
          <span className="feature-section-eyebrow">Compliance</span>
          <h2>NIS2 / SOC2 Evidence</h2>
          <p>Cryptographically signed audit evidence ready for regulator export and incident postmortems.</p>
          <Link href="/optimizer" className="feature-cta">Rule Optimizer →</Link>
        </div>
      </section>

      <div className="space-y-12 py-2">
        {/* Header strip */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-6 border-b border-white/10 pb-6">
          <div className="flex items-center space-x-4">
            <div className="icon-glass w-12 h-12 rounded-2xl flex items-center justify-center text-emerald-400">
              <Database className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-2xl font-extrabold text-white tracking-tight font-display">
                Tamper-Evident Audit Ledger
              </h2>
              <p className="text-[#e4e6f1]/70 text-sm mt-1">
                Immutable SHA256 cryptographic hash-chain ledger verifying NIS2 / SOC2 incident audit integrity
              </p>
            </div>
          </div>

          <button
            onClick={loadData}
            disabled={loading}
            className="btn-hacktober-primary px-6 py-3.5 rounded-xl text-xs flex items-center space-x-2"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            <span>Verify Hash Chain Integrity</span>
          </button>
        </div>

        {/* Verification Status Banner */}
        {verification && (
          <div className={`claude-card p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-all border ${
            verification.valid ? 'border-emerald-500/30' : 'border-rose-500/30'
          }`}>
            <div className="flex items-center space-x-4">
              <div className={`w-12 h-12 rounded-2xl flex items-center justify-center font-bold ${
                verification.valid ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
              }`}>
                {verification.valid ? <ShieldCheck className="w-7 h-7" /> : <AlertCircle className="w-7 h-7" />}
              </div>
              <div>
                <span className="text-lg font-bold text-white block font-display">
                  {verification.valid ? 'Hash Chain Cryptographically Validated' : 'Cryptographic Tampering Detected!'}
                </span>
                <span className="text-xs text-[#e4e6f1]/70">Total chained blocks verified: <strong className="text-white font-mono">{verification.chain_length}</strong></span>
              </div>
            </div>

            <div className="flex items-center space-x-2">
              <span className="text-xs font-mono pill-badge-green px-4 py-2 rounded-xl">
                {verification.valid ? 'O(N) Hash Integrity: PASSED' : `Broken Link at Block #${verification.broken_at}`}
              </span>
            </div>
          </div>
        )}

        {/* Visual Hash Chain Topology */}
        {entries.length > 0 && (
          <LedgerChainGraph entries={entries} valid={verification?.valid ?? true} />
        )}

        {/* Ledger Block Log Table */}
        <div className="claude-card p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-white/10 pb-3">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2 font-display">
              <FileText className="w-4 h-4 text-emerald-400" />
              <span>Audit Log Entries ({entries.length} Immutable Blocks)</span>
            </h3>
            <span className="text-xs text-[#e4e6f1]/60 font-mono">SHA256 Hash Chained</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-white/10 text-[#e4e6f1]/60 uppercase tracking-wider text-[10px]">
                <tr>
                  <th className="py-2.5">Timestamp</th>
                  <th className="py-2.5">Event Type</th>
                  <th className="py-2.5">Classification</th>
                  <th className="py-2.5">Response Actions</th>
                  <th className="py-2.5">SHA256 Row Hash</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/10 font-mono">
                {entries.map((item, idx) => (
                  <tr key={idx} className="hover:bg-white/[0.03] transition-colors">
                    <td className="py-3 text-[#e4e6f1]/70">{new Date(item.timestamp * 1000).toLocaleTimeString()}</td>
                    <td className="py-3">
                      <span className="px-2.5 py-1 rounded-full pill-badge-cyan text-[10px] font-bold">
                        {item.event_type}
                      </span>
                    </td>
                    <td className="py-3 font-bold text-rose-400">{item.attack_type}</td>
                    <td className="py-3 text-[#e4e6f1] font-sans">{item.actions_taken?.join(', ') || 'Logged'}</td>
                    <td className="py-3 text-[11px] text-[#7c5cff] font-mono break-all">{item.row_hash.slice(0, 24)}...</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
