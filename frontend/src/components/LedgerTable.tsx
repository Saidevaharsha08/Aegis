import React from 'react';
import { Database } from 'lucide-react';

interface Props {
  entries: any[];
}

export const LedgerTable: React.FC<Props> = ({ entries }) => {
  return (
    <div className="rounded-xl bg-[#121824] border border-slate-800 p-6 space-y-4">
      <div className="flex items-center space-x-2 text-emerald-400 font-bold text-sm">
        <Database className="w-4 h-4" />
        <span>Tamper-Evident Ledger Table ({entries?.length ?? 0} Blocks)</span>
      </div>
    </div>
  );
};
