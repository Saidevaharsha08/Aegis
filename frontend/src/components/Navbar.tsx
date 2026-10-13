'use client';

import React from 'react';
import Link from 'next/link';

export default function Navbar() {
    return (
        <div role="banner" className="site-navbar">
            <div className="page-container">
                <div className="nav-outer">
                    <div className="nav-left" style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                        <Link href="/" className="wordmark">Aegis</Link>
                        <div style={{ opacity: 0.85, fontFamily: 'JetBrains Mono, monospace', fontSize: 12, letterSpacing: '0.12em' }}>NIST FIPS 203</div>
                    </div>

                    <div className="nav-center" aria-hidden>
                        <nav className="nav-menu">
                            <a className="nav-link" href="/">Overview</a>
                            <a className="nav-link" href="/generator" style={{ color: '#06b6d4', fontWeight: 600 }}>Attack Studio</a>
                            <a className="nav-link" href="/mesh">Mesh</a>
                            <a className="nav-link" href="/ingest">Ingest</a>
                            <a className="nav-link" href="/detection">Detection</a>
                            <a className="nav-link" href="/ledger">Ledger</a>
                            <a className="nav-link" href="/optimizer">Optimizer</a>
                            <a className="nav-link" href="/response">Response</a>
                        </nav>
                    </div>

                    <div className="nav-right" style={{ display: 'flex', alignItems: 'center', gap: 8, justifyContent: 'flex-end' }}>
                        <Link href="/generator" className="sticker-btn" style={{ background: 'linear-gradient(135deg, #ef4444, #7c5cff)' }}>Attack Generator</Link>
                        <Link href="/threats" className="sticker-btn">Threat Console</Link>
                    </div>
                </div>
            </div>
        </div>
    );
}
