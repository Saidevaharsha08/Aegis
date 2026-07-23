import React from 'react';
import { CryptoStatus as CryptoStatusType } from '@/lib/api';
import { KeyRound } from 'lucide-react';

interface Props {
  status: CryptoStatusType;
}

export const CryptoStatus: React.FC<Props> = ({ status }) => {
  return (
    <div className="rounded-xl bg-[#121824] border border-slate-800 p-6 space-y-4">
      <div className="flex items-center space-x-3 text-indigo-400 font-bold">
        <KeyRound className="w-5 h-5" />
        <span className="text-base text-white">PQC Encryption Component</span>
      </div>
      <div className="text-sm text-slate-300 space-y-1 font-mono">
        <div>Algorithm: <span className="text-cyan-400 font-bold">{status.algorithm}</span></div>
        <div>Security: <span className="text-emerald-400">{status.security_level}</span></div>
        <div>Active Sessions: <span className="text-white">{status.active_sessions}</span></div>
      </div>
    </div>
  );
};
