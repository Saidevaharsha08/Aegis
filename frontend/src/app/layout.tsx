import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Aegis — Quantum-Safe AI Threat Detection System',
  description: 'Production network security combining XGBoost IDS, NIST FIPS 203 ML-KEM-768 PQC, and QAOA Rule Optimization.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="bg-[#0a0d14] text-slate-100 antialiased min-h-screen">
        <div className="flex flex-col min-h-screen">
          <header className="border-b border-slate-800 bg-[#121824]/80 backdrop-blur sticky top-0 z-50 px-6 py-4 flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-indigo-500 to-cyan-400 flex items-center justify-center font-bold text-white shadow-lg shadow-indigo-500/20">
                AE
              </div>
              <span className="font-semibold text-lg tracking-wide text-white">
                Aegis <span className="text-xs px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">NIST FIPS 203 PQC</span>
              </span>
            </div>
            <nav className="flex items-center space-x-6 text-sm font-medium text-slate-400">
              <a href="/" className="hover:text-cyan-400 transition-colors">Overview</a>
              <a href="/threats" className="hover:text-cyan-400 transition-colors">Threat Feed</a>
              <a href="/crypto" className="hover:text-cyan-400 transition-colors">PQC Status</a>
              <a href="/optimizer" className="hover:text-cyan-400 transition-colors">QAOA Optimizer</a>
              <a href="/ledger" className="hover:text-cyan-400 transition-colors">Audit Ledger</a>
            </nav>
          </header>
          <main className="flex-1 p-6 max-w-7xl mx-auto w-full">{children}</main>
          <footer className="border-t border-slate-800/80 py-4 px-6 text-center text-xs text-slate-500">
            Aegis Quantum-Safe Defense Architecture • IEEE S&P / USENIX Security Research Target • Build Cost: $0
          </footer>
        </div>
      </body>
    </html>
  );
}
