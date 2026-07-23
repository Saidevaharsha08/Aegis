'use client';

import React, { useEffect, useState } from 'react';
import { verifyLedgerChain, fetchLedgerEntries, LedgerVerification } from '@/lib/api';
import { Database, ShieldCheck, AlertCircle, RefreshCw } from 'lucide-react';

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
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Tamper-Evident Audit Ledger</h1>
          <p className="text-slate-400 text-sm">Immutable SHA256 cryptographic hash chain verifying NIS2 / SOC2 incident compliance</p>
        </div>
        <button
          onClick={loadData}
          disabled={loading}
          className="px-4 py-2 text-sm font-semibold rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20 transition-all flex items-center space-x-2"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          <span>Verify Hash Chain Integrity</span>
        </button>
      </div>

      {verification && (
        <div className={`p-4 rounded-xl border flex items-center justify-between ${verification.valid ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' : 'bg-rose-500/10 border-rose-500/30 text-rose-400'}`}>
          <div className="flex items-center space-x-3">
            {verification.valid ? <ShieldCheck className="w-6 h-6" /> : <AlertCircle className="w-6 h-6" />}
            <div>
              <span className="font-bold text-base block">{verification.valid ? 'Hash Chain Cryptographically Valid' : 'Tampering Detected'}</span>
              <span className="text-xs text-slate-400">Total blocks verified: {verification.chain_length}</span>
            </div>
          </div>
          <span className="text-xs font-mono bg-[#0a0d14] px-3 py-1.5 rounded border border-slate-800 text-slate-300">
            {verification.valid ? 'O(N) Verification PASSED' : `Broken at: ${verification.broken_at}`}
          </span>
        </div>
      )}

      {/* Ledger Table */}
      <div className="rounded-xl bg-[#121824] border border-slate-800 p-6 space-y-4">
        <h3 className="text-sm font-bold text-white uppercase tracking-wider">Audit Log Entries ({entries.length} Blocks)</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="border-b border-slate-800 text-slate-400">
              <tr>
                <th className="py-2">Timestamp</th>
                <th className="py-2">Event Type</th>
                <th className="py-2">Attack Type</th>
                <th className="py-2">Actions Executed</th>
                <th className="py-2">SHA256 Row Hash</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {entries.map((item, idx) => (
                <tr key={idx} className="hover:bg-slate-800/30">
                  <td className="py-2.5 text-slate-400">{new Date(item.timestamp * 1000).toLocaleTimeString()}</td>
                  <td className="py-2.5 font-bold text-cyan-400">{item.event_type}</td>
                  <td className="py-2.5 text-rose-400">{item.attack_type}</td>
                  <td className="py-2.5 text-slate-300 font-sans">{item.actions_taken.join(', ')}</td>
                  <td className="py-2.5 text-xs text-indigo-300 break-all">{item.row_hash.slice(0, 20)}...</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
