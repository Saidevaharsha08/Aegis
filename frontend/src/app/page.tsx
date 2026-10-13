'use client';

import React, { useEffect, useState, useRef, useCallback } from 'react';
import {
  fetchBlockedIps, clearBlockedIps, detectThreat,
  unblockIp, fetchHealth, BlockedIpEntry, DetectionResult,
} from '@/lib/api';

/* ─── Types ─────────────────────────────────────────────────────────────── */
interface FeedEvent {
  id: string; timestamp: string; source_ip: string;
  attack_type: string; threat_score: number;
  matched_database: boolean; threat_detected: boolean;
  latency_ms: number; actions: string[]; status: string;
}
interface TerminalLine { id: string; text: string; type: 'info'|'warn'|'danger'|'success'|'dim'; }

/* ─── Attack profiles ────────────────────────────────────────────────────── */
const PROFILES: Record<string, Record<string, number>> = {
  DoS:         { flow_duration:95000, total_fwd_packets:3500, total_bwd_packets:1, total_length_fwd:95000, flow_bytes_per_second:95000000, flow_packets_per_second:120000, syn_flag_count:1, rst_flag_count:1 },
  DDoS:        { flow_duration:180000, total_fwd_packets:15000, total_bwd_packets:0, total_length_fwd:450000000, flow_bytes_per_second:450000000, flow_packets_per_second:350000, syn_flag_count:1, rst_flag_count:1 },
  BruteForce:  { flow_duration:8500, total_fwd_packets:45, total_bwd_packets:12, total_length_fwd:2500, flow_bytes_per_second:250000, flow_packets_per_second:8000, psh_flag_count:8, syn_flag_count:1 },
  PortScan:    { flow_duration:150, total_fwd_packets:1, total_bwd_packets:1, total_length_fwd:60, flow_bytes_per_second:3500, syn_flag_count:1, fin_flag_count:1 },
  WebAttack:   { flow_duration:3200, total_fwd_packets:18, total_bwd_packets:14, total_length_fwd:850000, flow_bytes_per_second:850000, psh_flag_count:7 },
  Bot:         { flow_duration:45000, total_fwd_packets:80, total_bwd_packets:65, total_length_fwd:180000, flow_bytes_per_second:180000, urg_flag_count:1 },
  Infiltration:{ flow_duration:150000, total_fwd_packets:320, total_bwd_packets:280, total_length_fwd:1200000, total_length_bwd:1050000, flow_bytes_per_second:1200000, bwd_packet_length_mean:1950 },
  Heartbleed:  { flow_duration:850, total_fwd_packets:2, total_bwd_packets:1, total_length_fwd:190, total_length_bwd:65535, flow_bytes_per_second:950000, bwd_packet_length_max:65535 },
  BENIGN:      { flow_duration:1200, total_fwd_packets:5, total_bwd_packets:4, total_length_fwd:12000, total_length_bwd:8000, flow_bytes_per_second:12000, ack_flag_count:1 },
};

const META: Record<string,{label:string;color:string;bg:string;icon:string}> = {
  DoS:         { label:'DoS SYN Flood',         color:'#f97316', bg:'rgba(249,115,22,0.1)',  icon:'💥' },
  DDoS:        { label:'DDoS Volumetric',        color:'#ef4444', bg:'rgba(239,68,68,0.1)',   icon:'🌊' },
  BruteForce:  { label:'Brute Force SSH/FTP',   color:'#eab308', bg:'rgba(234,179,8,0.1)',   icon:'🔨' },
  PortScan:    { label:'Port Scan',             color:'#a855f7', bg:'rgba(168,85,247,0.1)', icon:'🔍' },
  WebAttack:   { label:'Web Attack SQLi/XSS',   color:'#ec4899', bg:'rgba(236,72,153,0.1)', icon:'🕷️' },
  Bot:         { label:'Botnet C2',             color:'#f59e0b', bg:'rgba(245,158,11,0.1)', icon:'🤖' },
  Infiltration:{ label:'Lateral Movement',      color:'#e879f9', bg:'rgba(232,121,249,0.1)',icon:'🕵️' },
  Heartbleed:  { label:'TLS Exploit Heartbleed',color:'#ff3e6c', bg:'rgba(255,62,108,0.1)', icon:'🩸' },
  BENIGN:      { label:'Normal Traffic',        color:'#22c55e', bg:'rgba(34,197,94,0.1)',  icon:'✅' },
};

/* ─── Radar ──────────────────────────────────────────────────────────────── */
function Radar({ count, alert }: { count: number; alert: boolean }) {
  const ac = alert ? '#ef4444' : '#00d4ff';
  return (
    <div style={{ position: 'relative', width: 190, height: 190 }}>
      {[1, 0.68, 0.36].map((s, i) => (
        <div key={i} style={{
          position: 'absolute', top: '50%', left: '50%', borderRadius: '50%',
          width: s * 190, height: s * 190, transform: 'translate(-50%,-50%)',
          border: `1px solid ${alert ? 'rgba(239,68,68,0.25)' : 'rgba(0,212,255,0.18)'}`,
          transition: 'border-color 0.5s',
        }} />
      ))}
      <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', pointerEvents: 'none' }}>
        <div style={{ position: 'absolute', width: '100%', height: 1, background: 'rgba(0,212,255,0.05)' }} />
        <div style={{ position: 'absolute', height: '100%', width: 1, background: 'rgba(0,212,255,0.05)' }} />
      </div>
      <div style={{ position: 'absolute', inset: 0, borderRadius: '50%', overflow: 'hidden', animation: 'radar-sweep 3s linear infinite' }}>
        <div style={{
          position: 'absolute', top: '50%', left: '50%', width: '50%', height: 1,
          transformOrigin: 'left center', transform: 'translateY(-50%)',
          background: `linear-gradient(90deg,${ac}cc,transparent)`,
          boxShadow: `0 0 8px 2px ${ac}44`,
        }} />
      </div>
      {alert && (
        <div style={{ position: 'absolute', inset: -6, borderRadius: '50%', border: `2px solid ${ac}88`, animation: 'pulse-ring 1s ease-out infinite' }} />
      )}
      <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', fontFamily: "'JetBrains Mono',monospace" }}>
        <div style={{ fontSize: 42, fontWeight: 900, lineHeight: 1, color: ac, transition: 'color 0.4s' }}>{count}</div>
        <div style={{ fontSize: 9, letterSpacing: 3.5, color: '#0f2030', marginTop: 5, fontWeight: 700 }}>THREATS</div>
      </div>
    </div>
  );
}

/* ─── Terminal ────────────────────────────────────────────────────────────── */
function Term({ lines }: { lines: TerminalLine[] }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight; }, [lines]);
  const C: Record<string, string> = { info: '#38bdf8', warn: '#fbbf24', danger: '#f87171', success: '#4ade80', dim: '#1e3a4a' };
  return (
    <div ref={ref} style={{ height: 230, overflowY: 'auto', fontFamily: "'JetBrains Mono',monospace", fontSize: 11, lineHeight: 1.8, padding: '12px 14px', background: '#020408', borderRadius: 10, border: '1px solid rgba(0,212,255,0.07)' }}>
      {lines.length === 0
        ? <span style={{ color: '#0a1a26' }}>aegis@ids:~$ <span style={{ animation: 'blink 1s step-end infinite', color: '#00d4ff' }}>█</span></span>
        : lines.map(l => <div key={l.id} style={{ color: C[l.type] }}>{l.text}</div>)
      }
      {lines.length > 0 && <span style={{ animation: 'blink 1s step-end infinite', color: '#00d4ff' }}>█</span>}
    </div>
  );
}

/* ─── ScoreBar ───────────────────────────────────────────────────────────── */
function Bar({ v, color }: { v: number; color: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ width: 70, height: 5, background: 'rgba(255,255,255,0.05)', borderRadius: 999, overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${v * 100}%`, background: `linear-gradient(90deg,${color}77,${color})`, borderRadius: 999, boxShadow: `0 0 6px ${color}55`, transition: 'width 0.4s' }} />
      </div>
      <span style={{ fontSize: 11, fontFamily: "'JetBrains Mono',monospace", color, minWidth: 32 }}>{(v * 100).toFixed(0)}%</span>
    </div>
  );
}

/* ─── PingDot ────────────────────────────────────────────────────────────── */
function Dot({ on, color = '#4ade80' }: { on: boolean; color?: string }) {
  return (
    <span style={{ position: 'relative', display: 'inline-flex', width: 10, height: 10, alignItems: 'center', justifyContent: 'center' }}>
      {on && <span style={{ position: 'absolute', inset: 0, borderRadius: '50%', background: color, opacity: 0.4, animation: 'ping 1.2s cubic-bezier(0,0,0.2,1) infinite' }} />}
      <span style={{ position: 'relative', width: 8, height: 8, borderRadius: '50%', background: on ? color : '#1f2937' }} />
    </span>
  );
}

/* ─── CARD helper ────────────────────────────────────────────────────────── */
const card = (children: React.ReactNode, extra?: React.CSSProperties) => (
  <div style={{ background: 'rgba(8,14,26,0.92)', border: '1px solid rgba(255,255,255,0.055)', borderRadius: 18, backdropFilter: 'blur(8px)', ...extra }}>
    {children}
  </div>
);

/* ─── Home ────────────────────────────────────────────────────────────────── */
export default function Home() {
  const [blockedIps, setBlockedIps] = useState<BlockedIpEntry[]>([]);
  const [dbCount, setDbCount]       = useState(0);
  const [feed, setFeed]             = useState<FeedEvent[]>([]);
  const [lines, setLines]           = useState<TerminalLine[]>([]);
  const [online, setOnline]         = useState(false);
  const [simIp, setSimIp]           = useState('203.0.113.42');
  const [simType, setSimType]       = useState('DoS');
  const [loading, setLoading]       = useState(false);
  const [last, setLast]             = useState<DetectionResult | null>(null);
  const [threats, setThreats]       = useState(0);
  const [fastBlocks, setFastBlocks] = useState(0);
  const [alertOn, setAlertOn]       = useState(false);
  const alertRef = useRef<ReturnType<typeof setTimeout>>();

  const log = useCallback((text: string, type: TerminalLine['type'] = 'info') => {
    const ts = new Date().toLocaleTimeString('en-GB', { hour12: false });
    setLines(p => [...p.slice(-60), { id: `${Date.now()}-${Math.random()}`, text: `[${ts}] ${text}`, type }]);
  }, []);

  const loadDB = useCallback(async () => {
    try { const r = await fetchBlockedIps(); setBlockedIps(r.blocked_ips ?? []); setDbCount(r.count ?? 0); } catch { /* offline */ }
  }, []);

  useEffect(() => {
    const check = async () => {
      try { const h = await fetchHealth(); if (h.status === 'healthy') setOnline(true); }
      catch { setOnline(false); }
    };
    check(); const iv = setInterval(check, 8000); return () => clearInterval(iv);
  }, []);

  useEffect(() => { if (online) log('Aegis IDS online — monitoring active.', 'success'); }, [online]);
  useEffect(() => { loadDB(); const iv = setInterval(loadDB, 3000); return () => clearInterval(iv); }, [loadDB]);

  const flash = () => {
    if (alertRef.current) clearTimeout(alertRef.current);
    setAlertOn(true);
    alertRef.current = setTimeout(() => setAlertOn(false), 3500);
  };

  const fire = async () => {
    if (!online) { log('ERROR: Backend offline.', 'danger'); return; }
    setLoading(true);
    log(`> Firing ${simType} from ${simIp}...`, 'warn');
    try {
      const res = await detectThreat(PROFILES[simType] ?? PROFILES.DoS, simIp);
      setLast(res);
      const ev: FeedEvent = {
        id: Math.random().toString(36).slice(2, 9), timestamp: new Date().toLocaleTimeString(),
        source_ip: simIp, attack_type: res.attack_type || simType,
        threat_score: res.threat_score ?? 0, matched_database: res.matched_database,
        threat_detected: res.threat_detected, latency_ms: res.inference_latency_ms ?? 0.1,
        actions: res.actions_taken ?? [], status: res.status,
      };
      setFeed(p => [ev, ...p].slice(0, 25));
      if (ev.threat_detected) { setThreats(n => n + 1); flash(); }
      if (ev.matched_database) setFastBlocks(n => n + 1);
      if (ev.matched_database)
        log(`⚡ INSTANT BLOCK — ${ev.source_ip} (${ev.attack_type}) — 0.12ms edge block`, 'danger');
      else if (ev.threat_detected)
        (log(`🚨 THREAT — ${ev.attack_type} from ${ev.source_ip} | score=${ev.threat_score.toFixed(3)} | ${ev.latency_ms.toFixed(1)}ms`, 'danger'),
        log(`   → IP stored in Known Attacker Database`, 'warn'));
      else
        log(`✓ BENIGN — ${ev.source_ip} allowed through`, 'success');
      await loadDB();
    } catch (e: unknown) { log(`ERROR: ${e instanceof Error ? e.message : 'failed'}`, 'danger'); }
    finally { setLoading(false); }
  };

  const clearDB = async () => { await clearBlockedIps(); setBlockedIps([]); setDbCount(0); log('Database cleared.', 'dim'); };
  const doUnblock = async (ip: string) => { await unblockIp(ip); log(`Unblocked ${ip}.`, 'dim'); await loadDB(); };

  const meta = META[simType] ?? META.DoS;

  /* ── Shared styles ── */
  const S = {
    label: { fontSize: 9, color: '#0f2030', letterSpacing: 1.5, textTransform: 'uppercase' as const, marginBottom: 5 },
    mono: { fontFamily: "'JetBrains Mono',monospace" },
    section: { fontSize: 11, fontWeight: 700, color: '#94a3b8', letterSpacing: 1.5, textTransform: 'uppercase' as const },
  };

  return (
    <div style={{ minHeight: '100vh', background: '#030609', color: '#7899b4', fontFamily: "'Inter',system-ui,sans-serif" }}>
      {/* BG grid */}
      <div style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 0, backgroundImage: 'linear-gradient(rgba(0,212,255,0.02) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,0.02) 1px,transparent 1px)', backgroundSize: '50px 50px' }} />
      <div style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 0, background: 'radial-gradient(ellipse 60% 35% at 50% 0%,rgba(0,100,255,0.05),transparent 60%)' }} />

      {/* ── HEADER ── */}
      <header style={{ position: 'sticky', top: 0, zIndex: 100, borderBottom: '1px solid rgba(0,212,255,0.07)', background: 'rgba(3,6,9,0.96)', backdropFilter: 'blur(24px)' }}>
        <div style={{ maxWidth: 1400, margin: '0 auto', padding: '0 28px', height: 58, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <svg width="28" height="28" viewBox="0 0 32 32" fill="none">
              <path d="M16 2L4 7v9c0 7.18 5.16 13.89 12 15.93C23.84 29.89 28 23.18 28 16V7L16 2z" fill="rgba(0,212,255,0.08)" stroke="#00d4ff" strokeWidth="1.5"/>
              <path d="M12 16l3 3 5-6" stroke="#4ade80" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
            <span style={{ fontSize: 16, fontWeight: 800, color: '#e2e8f0', letterSpacing: 2.5 }}>AEGIS</span>
            <span style={{ fontSize: 10, color: '#1e3a4a', ...S.mono, letterSpacing: 1 }}>INTRUSION DETECTION v1.0</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 18 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
              <Dot on={online} color={online ? '#4ade80' : '#ef4444'} />
              <span style={{ fontSize: 10, ...S.mono, letterSpacing: 1.5, color: online ? '#4ade80' : '#ef4444' }}>{online ? 'ONLINE' : 'OFFLINE'}</span>
            </div>
            <div style={{ fontSize: 10, ...S.mono, padding: '4px 14px', borderRadius: 999, background: 'rgba(0,212,255,0.06)', border: '1px solid rgba(0,212,255,0.14)', color: '#00d4ff' }}>
              {dbCount} IPs blocked
            </div>
            {alertOn && (
              <div style={{ fontSize: 10, ...S.mono, fontWeight: 800, padding: '4px 14px', borderRadius: 999, letterSpacing: 1.5, background: 'rgba(239,68,68,0.12)', border: '1px solid rgba(239,68,68,0.45)', color: '#f87171', animation: 'glow-pulse 0.7s ease-in-out infinite' }}>
                ⚠ THREAT ACTIVE
              </div>
            )}
          </div>
        </div>
      </header>

      <div style={{ position: 'relative', zIndex: 1, maxWidth: 1400, margin: '0 auto', padding: '24px 28px 60px' }}>

        {/* ── STAT CARDS ── */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 14, marginBottom: 22 }}>
          {[
            { label: 'Threats Detected',  val: threats,    color: '#ef4444', icon: '🚨', sh: 'rgba(239,68,68,0.12)' },
            { label: 'Instant DB Blocks', val: fastBlocks, color: '#00d4ff', icon: '⚡', sh: 'rgba(0,212,255,0.12)' },
            { label: 'Known Attackers',   val: dbCount,    color: '#a855f7', icon: '🗃️', sh: 'rgba(168,85,247,0.12)' },
          ].map(({ label, val, color, icon, sh }) => (
            <div key={label} style={{ background: 'linear-gradient(135deg,rgba(10,18,32,0.95),rgba(5,9,17,0.95))', border: `1px solid ${color}1a`, borderRadius: 16, padding: '18px 22px', display: 'flex', alignItems: 'center', gap: 16, boxShadow: `0 0 32px ${sh},inset 0 1px 0 rgba(255,255,255,0.03)` }}>
              <span style={{ fontSize: 26 }}>{icon}</span>
              <div>
                <div style={{ fontSize: 34, fontWeight: 900, color, ...S.mono, lineHeight: 1 }}>{val}</div>
                <div style={{ fontSize: 10, marginTop: 4, color: '#334155', letterSpacing: 1.5, textTransform: 'uppercase' }}>{label}</div>
              </div>
            </div>
          ))}
        </div>

        {/* ── 3-COL GRID ── */}
        <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr 320px', gap: 18, marginBottom: 18 }}>

          {/* COL 1: Radar + Launcher */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {card(
              <div style={{ padding: '22px 16px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 14 }}>
                <div style={{ fontSize: 9, letterSpacing: 3.5, color: '#0f2030', fontWeight: 700, textTransform: 'uppercase' }}>Threat Radar</div>
                <Radar count={threats} alert={alertOn} />
                <div style={{ fontSize: 9, letterSpacing: 2.5, ...S.mono, fontWeight: 700, color: alertOn ? '#ef4444' : '#0f2030', transition: 'color 0.4s' }}>
                  {alertOn ? '● ACTIVE THREAT' : '● MONITORING'}
                </div>
              </div>,
              { border: '1px solid rgba(0,212,255,0.09)', boxShadow: '0 0 40px rgba(0,212,255,0.04)' }
            )}

            {card(
              <div style={{ padding: 18, display: 'flex', flexDirection: 'column', gap: 13 }}>
                <div style={S.section}>Launch Attack</div>

                <div>
                  <div style={S.label}>Source IP</div>
                  <input value={simIp} onChange={e => setSimIp(e.target.value)} placeholder="203.0.113.42"
                    style={{ width: '100%', boxSizing: 'border-box', background: 'rgba(0,0,0,0.5)', border: '1px solid rgba(0,212,255,0.18)', borderRadius: 9, padding: '9px 11px', fontSize: 12, color: '#22d3ee', ...S.mono, outline: 'none', transition: 'border-color 0.2s' }}
                    onFocus={e => (e.target.style.borderColor = 'rgba(0,212,255,0.5)')}
                    onBlur={e => (e.target.style.borderColor = 'rgba(0,212,255,0.18)')}
                  />
                </div>

                <div>
                  <div style={S.label}>Attack Type</div>
                  <select value={simType} onChange={e => setSimType(e.target.value)}
                    style={{ width: '100%', boxSizing: 'border-box', background: 'rgba(0,0,0,0.55)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 9, padding: '9px 11px', fontSize: 11, color: '#94a3b8', ...S.mono, cursor: 'pointer', outline: 'none' }}>
                    {Object.keys(META).map(k => <option key={k} value={k} style={{ background: '#030609' }}>{META[k].icon}  {META[k].label}</option>)}
                  </select>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '7px 11px', borderRadius: 8, background: meta.bg, border: `1px solid ${meta.color}2a` }}>
                  <span style={{ fontSize: 15 }}>{meta.icon}</span>
                  <span style={{ fontSize: 10, fontWeight: 800, color: meta.color, ...S.mono, letterSpacing: 1 }}>{simType}</span>
                </div>

                <button onClick={fire} disabled={loading} style={{ width: '100%', padding: '12px', borderRadius: 11, border: 'none', background: loading ? 'rgba(220,38,38,0.15)' : 'linear-gradient(135deg,#dc2626,#991b1b)', color: '#fff', fontSize: 13, fontWeight: 700, cursor: loading ? 'wait' : 'pointer', boxShadow: loading ? 'none' : '0 4px 20px rgba(220,38,38,0.35)', transition: 'all 0.2s', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
                  {loading
                    ? <><span style={{ width: 13, height: 13, borderRadius: '50%', border: '2px solid rgba(255,255,255,0.25)', borderTopColor: '#fff', display: 'inline-block', animation: 'radar-sweep 0.7s linear infinite' }} /> Analyzing...</>
                    : <>⚡ Fire {simType} Attack</>}
                </button>

                <div style={{ borderRadius: 9, padding: '9px 11px', background: 'rgba(0,0,0,0.55)', border: '1px solid rgba(255,255,255,0.04)' }}>
                  <div style={{ ...S.label, color: '#0a1a26', marginBottom: 3 }}>TERMINAL COMMAND</div>
                  <div style={{ fontSize: 10, color: '#164e63', ...S.mono, wordBreak: 'break-all', lineHeight: 1.6 }}>
                    $ python scripts/send_attack.py --ip {simIp} --type {simType}
                  </div>
                </div>

                <button onClick={clearDB} disabled={dbCount === 0} style={{ width: '100%', padding: '8px', borderRadius: 9, fontSize: 10, ...S.mono, background: 'rgba(239,68,68,0.04)', border: '1px solid rgba(239,68,68,0.12)', color: dbCount === 0 ? '#0a1a26' : '#f87171', cursor: dbCount === 0 ? 'not-allowed' : 'pointer', transition: 'all 0.2s' }}>
                  🗑 Clear Attacker Database
                </button>
              </div>
            )}
          </div>

          {/* COL 2: Terminal + Result + Steps */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {card(
              <div style={{ padding: '14px 16px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 12 }}>
                  <div style={{ display: 'flex', gap: 5 }}>
                    {['#ff5f57', '#febc2e', '#28c840'].map(c => <div key={c} style={{ width: 10, height: 10, borderRadius: '50%', background: c }} />)}
                  </div>
                  <span style={{ fontSize: 10, color: '#0f2030', ...S.mono }}>aegis@ids — detection.log</span>
                  <span style={{ marginLeft: 'auto', fontSize: 10, color: '#0f2030', ...S.mono }}>{lines.length} lines</span>
                </div>
                <Term lines={lines} />
              </div>,
              { border: '1px solid rgba(0,212,255,0.07)', background: 'rgba(2,4,8,0.98)' }
            )}

            {last ? (
              <div style={{ borderRadius: 18, padding: 18, animation: 'slide-in 0.3s ease-out', background: last.matched_database ? 'linear-gradient(135deg,rgba(0,212,255,0.05),rgba(5,10,20,0.95))' : last.threat_detected ? 'linear-gradient(135deg,rgba(239,68,68,0.06),rgba(5,10,20,0.95))' : 'linear-gradient(135deg,rgba(34,197,94,0.05),rgba(5,10,20,0.95))', border: `1px solid ${last.matched_database ? 'rgba(0,212,255,0.22)' : last.threat_detected ? 'rgba(239,68,68,0.22)' : 'rgba(34,197,94,0.22)'}` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
                  <span style={{ fontSize: 9, letterSpacing: 2.5, color: '#1e3a4a', fontWeight: 700, textTransform: 'uppercase' }}>Detection Result</span>
                  <span style={{ fontSize: 10, fontWeight: 800, padding: '4px 12px', borderRadius: 999, letterSpacing: 1, background: last.matched_database ? 'rgba(0,212,255,0.12)' : last.threat_detected ? 'rgba(239,68,68,0.12)' : 'rgba(34,197,94,0.12)', color: last.matched_database ? '#00d4ff' : last.threat_detected ? '#f87171' : '#4ade80', border: `1px solid ${last.matched_database ? 'rgba(0,212,255,0.28)' : last.threat_detected ? 'rgba(239,68,68,0.28)' : 'rgba(34,197,94,0.28)'}` }}>
                    {last.matched_database ? '⚡ INSTANT BLOCK' : last.threat_detected ? '🚨 THREAT BLOCKED' : '✓ BENIGN'}
                  </span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px 16px', ...S.mono, fontSize: 12, marginBottom: 12 }}>
                  {[
                    { k: 'Source IP',   v: last.ip_address,   c: '#22d3ee' },
                    { k: 'Attack Type', v: last.attack_type,   c: META[last.attack_type]?.color ?? '#94a3b8' },
                    { k: 'Detection',   v: last.matched_database ? 'DB Fast-Path' : 'ML + Rules', c: '#94a3b8' },
                    { k: 'Latency',     v: `${last.inference_latency_ms.toFixed(2)} ms`, c: '#4ade80' },
                  ].map(({ k, v, c }) => (
                    <div key={k}><div style={{ color: '#0f2030', fontSize: 9, marginBottom: 2, letterSpacing: 1.5 }}>{k.toUpperCase()}</div><div style={{ color: c, fontWeight: 700 }}>{v}</div></div>
                  ))}
                </div>
                <div style={{ fontSize: 9, color: '#0f2030', marginBottom: 5, letterSpacing: 1.5 }}>THREAT SCORE</div>
                <Bar v={last.threat_score} color={last.threat_score > 0.7 ? '#ef4444' : last.threat_score > 0.4 ? '#f59e0b' : '#4ade80'} />
                {last.message && <div style={{ marginTop: 12, padding: '9px 11px', borderRadius: 8, fontSize: 10, lineHeight: 1.6, background: 'rgba(0,0,0,0.4)', color: '#334155', border: '1px solid rgba(255,255,255,0.03)' }}>{last.message}</div>}
              </div>
            ) : (
              <div style={{ flex: 1, borderRadius: 18, padding: 20, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 10, background: 'rgba(5,10,18,0.5)', border: '1px solid rgba(255,255,255,0.04)' }}>
                <svg width="38" height="38" viewBox="0 0 40 40" fill="none" opacity="0.1"><path d="M20 3L4 9v11c0 9 6.6 17.4 16 19.9 9.4-2.5 16-11 16-19.9V9L20 3z" stroke="#00d4ff" strokeWidth="1.5" /></svg>
                <span style={{ fontSize: 10, color: '#0f2030', ...S.mono }}>Awaiting first event…</span>
              </div>
            )}

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 10 }}>
              {[
                { n: '01', t: 'Launch',   d: 'Portal or terminal cmd', c: '#f59e0b', icon: '⚡' },
                { n: '02', t: 'Detect',   d: 'ML model + rule engine', c: '#ef4444', icon: '🛡️' },
                { n: '03', t: 'Remember', d: 'Instant block on repeat', c: '#00d4ff', icon: '🗃️' },
              ].map(({ n, t, d, c, icon }) => (
                <div key={n} style={{ padding: '12px 13px', borderRadius: 12, background: 'rgba(6,10,18,0.8)', border: `1px solid ${c}14` }}>
                  <div style={{ fontSize: 9, color: c, fontWeight: 800, letterSpacing: 2, marginBottom: 5 }}>STEP {n}</div>
                  <div style={{ fontSize: 12, fontWeight: 700, color: '#cbd5e1', marginBottom: 3, display: 'flex', alignItems: 'center', gap: 5 }}>{icon} {t}</div>
                  <div style={{ fontSize: 9, color: '#1e3a4a', lineHeight: 1.5 }}>{d}</div>
                </div>
              ))}
            </div>
          </div>

          {/* COL 3: Live Feed */}
          {card(
            <div style={{ padding: '16px 14px', height: '100%', display: 'flex', flexDirection: 'column' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
                <span style={S.section}>Live Feed</span>
                <span style={{ fontSize: 10, ...S.mono, padding: '3px 10px', background: 'rgba(0,212,255,0.05)', border: '1px solid rgba(0,212,255,0.1)', borderRadius: 999, color: '#1e3a4a' }}>{feed.length} events</span>
              </div>
              <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 7 }}>
                {feed.length === 0 ? (
                  <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 8, opacity: 0.15 }}>
                    <svg width="40" height="40" viewBox="0 0 40 40" fill="none"><path d="M20 3L4 9v11c0 9 6.6 17.4 16 19.9 9.4-2.5 16-11 16-19.9V9L20 3z" stroke="#00d4ff" strokeWidth="1.2" /></svg>
                    <span style={{ fontSize: 10, ...S.mono, color: '#0f2030' }}>No events yet</span>
                  </div>
                ) : feed.map((ev, i) => {
                  const m = META[ev.attack_type] ?? META.DoS;
                  return (
                    <div key={ev.id} style={{ borderRadius: 11, padding: '10px 12px', border: `1px solid ${ev.matched_database ? 'rgba(0,212,255,0.18)' : ev.threat_detected ? 'rgba(239,68,68,0.18)' : 'rgba(34,197,94,0.18)'}`, background: ev.matched_database ? 'rgba(0,212,255,0.04)' : ev.threat_detected ? 'rgba(239,68,68,0.04)' : 'rgba(34,197,94,0.04)', animation: i === 0 ? 'slide-in 0.3s ease-out' : undefined }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                          <span style={{ fontSize: 12 }}>{ev.matched_database ? '⚡' : ev.threat_detected ? '🚨' : '✓'}</span>
                          <span style={{ fontSize: 9, fontWeight: 800, letterSpacing: 1.5, ...S.mono, color: ev.matched_database ? '#00d4ff' : ev.threat_detected ? '#f87171' : '#4ade80' }}>
                            {ev.matched_database ? 'INSTANT BLOCK' : ev.threat_detected ? 'THREAT' : 'BENIGN'}
                          </span>
                        </div>
                        <span style={{ fontSize: 9, color: '#0f2030', ...S.mono }}>{ev.timestamp}</span>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, ...S.mono }}>
                        <span style={{ color: '#22d3ee' }}>{ev.source_ip}</span>
                        <span style={{ color: m.color, fontWeight: 700 }}>{ev.attack_type}</span>
                        <span style={{ color: '#0f2030' }}>{ev.latency_ms.toFixed(2)}ms</span>
                      </div>
                      {ev.threat_score > 0 && (
                        <div style={{ marginTop: 6, height: 2, background: 'rgba(255,255,255,0.04)', borderRadius: 999, overflow: 'hidden' }}>
                          <div style={{ height: '100%', width: `${ev.threat_score * 100}%`, background: ev.threat_score > 0.7 ? '#ef4444' : ev.threat_score > 0.4 ? '#f59e0b' : '#4ade80', borderRadius: 999 }} />
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>,
            { minHeight: 560 }
          )}
        </div>

        {/* ── KNOWN ATTACKER DB TABLE ── */}
        {card(
          <div style={{ padding: '20px 24px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <span style={{ fontSize: 17 }}>🗃️</span>
                <span style={{ fontSize: 12, fontWeight: 700, color: '#94a3b8', letterSpacing: 1.5, textTransform: 'uppercase' }}>Known Attacker Database</span>
                <span style={{ fontSize: 10, padding: '3px 12px', borderRadius: 999, background: 'rgba(168,85,247,0.1)', border: '1px solid rgba(168,85,247,0.22)', color: '#a855f7', ...S.mono, fontWeight: 700 }}>{dbCount} entries</span>
              </div>
              {dbCount > 0 && (
                <button onClick={clearDB} style={{ fontSize: 10, padding: '6px 14px', borderRadius: 9, cursor: 'pointer', background: 'rgba(239,68,68,0.05)', border: '1px solid rgba(239,68,68,0.18)', color: '#f87171', ...S.mono, transition: 'all 0.2s' }}>Clear All</button>
              )}
            </div>

            {blockedIps.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '36px 0', fontSize: 10, ...S.mono, color: '#0f2030' }}>
                Database empty — fire an attack to populate it automatically
              </div>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid rgba(0,212,255,0.05)' }}>
                    {['Attacker IP', 'Attack Type', 'Threat Score', 'Hit Count', 'Last Seen', 'Action'].map(h => (
                      <th key={h} style={{ textAlign: 'left', padding: '7px 13px', fontSize: 9, color: '#0f2030', fontWeight: 700, letterSpacing: 2, textTransform: 'uppercase', ...S.mono, whiteSpace: 'nowrap' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {blockedIps.map(e => {
                    const m = META[e.attack_type] ?? META.DoS;
                    return (
                      <tr key={e.ip} style={{ borderBottom: '1px solid rgba(255,255,255,0.025)', transition: 'background 0.15s' }}
                        onMouseOver={ev => (ev.currentTarget as HTMLTableRowElement).style.background = 'rgba(255,255,255,0.018)'}
                        onMouseOut={ev => (ev.currentTarget as HTMLTableRowElement).style.background = 'transparent'}>
                        <td style={{ padding: '12px 13px', ...S.mono, fontWeight: 700, color: '#22d3ee' }}>{e.ip}</td>
                        <td style={{ padding: '12px 13px' }}>
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, padding: '3px 10px', borderRadius: 999, fontSize: 10, fontWeight: 700, background: m.bg, color: m.color, border: `1px solid ${m.color}2a`, ...S.mono }}>
                            {m.icon} {e.attack_type}
                          </span>
                        </td>
                        <td style={{ padding: '12px 13px', minWidth: 130 }}><Bar v={e.threat_score} color={e.threat_score > 0.7 ? '#ef4444' : '#f59e0b'} /></td>
                        <td style={{ padding: '12px 13px' }}>
                          <span style={{ padding: '3px 10px', borderRadius: 999, fontSize: 10, fontWeight: 800, background: 'rgba(0,212,255,0.07)', color: '#00d4ff', ...S.mono, border: '1px solid rgba(0,212,255,0.14)' }}>
                            {e.hit_count}×
                          </span>
                        </td>
                        <td style={{ padding: '12px 13px', ...S.mono, fontSize: 10, color: '#1e3a4a', whiteSpace: 'nowrap' }}>
                          {new Date(e.last_seen * 1000).toLocaleTimeString()}
                        </td>
                        <td style={{ padding: '12px 13px' }}>
                          <button onClick={() => doUnblock(e.ip)} style={{ fontSize: 10, padding: '5px 12px', borderRadius: 7, cursor: 'pointer', background: 'rgba(255,255,255,0.025)', border: '1px solid rgba(255,255,255,0.07)', color: '#334155', ...S.mono, transition: 'all 0.2s' }}
                            onMouseOver={ev => { (ev.target as HTMLButtonElement).style.color = '#94a3b8'; }}
                            onMouseOut={ev => { (ev.target as HTMLButtonElement).style.color = '#334155'; }}>
                            Unblock
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
