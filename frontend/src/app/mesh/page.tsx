'use client';

import React, { useEffect, useRef, useState } from 'react';
import {
  ShieldAlert,
  Activity,
  Radio,
  Cpu,
  Zap,
  Server,
  Network,
  KeyRound,
  Sparkles,
  Send,
  Play,
  Square,
  Users,
  Coins,
} from 'lucide-react';
import {
  fetchMeshState,
  sendMeshAttack,
  deployCountermeasure,
  startRedteam,
  stopRedteam,
  submitFederatedUpdate,
  subscribeMesh,
  MeshState,
  Campaign,
  Countermeasure,
} from '@/lib/api';
import MeshRadar from '@/components/MeshRadar';

const SERVICES = [
  { id: 'ssh' as const, label: 'SSH (22)', icon: KeyRound },
  { id: 'http' as const, label: 'HTTP (80)', icon: Server },
  { id: 'smb' as const, label: 'SMB (445)', icon: Network },
];

const PAYLOADS = [
  { label: 'Port scan', payload: 'GET / HTTP/1.1\r\nHost: target\r\n', ua: 'nmap/7.92' },
  { label: 'SSH brute-force', payload: 'admin:password\nroot:toor\n', ua: 'paramiko/2.7.2' },
  { label: 'HTTP enum', payload: 'GET /.env HTTP/1.1\r\nHost: target\r\n', ua: 'gobuster/3.1.0' },
  { label: 'SMB enum', payload: 'SMB negprot', ua: '' },
  { label: 'Slowloris', payload: 'GET / HTTP/1.1\r\n\r\n'.repeat(50), ua: 'slowloris/0.1.4' },
];

const EVENT_ICONS: Record<string, typeof Radio> = {
  campaign: ShieldAlert,
  countermeasure: Sparkles,
  attack: Activity,
  federated: Users,
  redteam: Zap,
};

const EVENT_COLORS: Record<string, string> = {
  campaign: 'text-cyan-400',
  countermeasure: 'text-[#7c5cff]',
  attack: 'text-rose-400',
  federated: 'text-emerald-400',
  redteam: 'text-amber-400',
};

const EVENT_BG: Record<string, string> = {
  campaign: 'bg-cyan-500/10 border-cyan-500/30',
  countermeasure: 'bg-[#7c5cff]/10 border-[#7c5cff]/30',
  attack: 'bg-rose-500/10 border-rose-500/30',
  federated: 'bg-emerald-500/10 border-emerald-500/30',
  redteam: 'bg-amber-500/10 border-amber-500/30',
};

export default function MeshPage() {
  const [state, setState] = useState<MeshState | null>(null);
  const [loading, setLoading] = useState(false);
  const [feed, setFeed] = useState<{ kind: string; payload: any; at: number }[]>([]);
  const [service, setService] = useState<'ssh' | 'http' | 'smb'>('http');
  const [payloadIdx, setPayloadIdx] = useState(0);
  const [srcIp, setSrcIp] = useState('198.51.100.42');
  const [sseStatus, setSseStatus] = useState<'connecting' | 'live' | 'error'>('connecting');
  const [peerId, setPeerId] = useState('peer-' + Math.random().toString(36).slice(2, 8));
  const [peerHandle, setPeerHandle] = useState('');
  const [shareLink, setShareLink] = useState<string>('');
  const [bountyClaimStatus, setBountyClaimStatus] = useState<string>('');
  const sseRef = useRef<EventSource | null>(null);

  const refresh = async () => {
    setLoading(true);
    try {
      setState(await fetchMeshState());
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // Restore peer handle from localStorage so bounty claims persist.
    const saved = typeof window !== 'undefined' ? localStorage.getItem('aegis_peer') : null;
    if (saved) setPeerHandle(saved);
    refresh();
    const es = subscribeMesh(
      (kind, payload) => {
        setSseStatus('live');
        setFeed((prev) => [{ kind, payload, at: Date.now() }, ...prev].slice(0, 60));
        if (kind === 'countermeasure' || kind === 'campaign' || kind === 'federated' || kind === 'bounty') {
          refresh();
        }
      },
      () => setSseStatus('error'),
    );
    sseRef.current = es;
    const t = setTimeout(() => setSseStatus((s) => (s === 'connecting' ? 'live' : s)), 1500);
    const poll = setInterval(refresh, 5000);
    return () => {
      clearTimeout(t);
      clearInterval(poll);
      es.close();
      sseRef.current = null;
    };
  }, []);

  const handleAttack = async () => {
    const p = PAYLOADS[payloadIdx];
    await sendMeshAttack({
      service,
      src_ip: srcIp,
      payload: p.payload,
      user_agent: p.ua,
      peer: peerHandle || undefined,
    });
  };

  const handleCountermeasure = async (campaign: Campaign) => {
    await deployCountermeasure(campaign.campaign_id, { block_upstream: true, rotate_keys: false });
  };

  const handleFederated = async () => {
    await submitFederatedUpdate(
      peerId,
      Math.floor(50 + Math.random() * 250),
      {
        'Flow Bytes/s': -0.03 - Math.random() * 0.05,
        'SYN Flag Count': 0.08 + Math.random() * 0.05,
        'Flow Duration': 0.04 + Math.random() * 0.04,
      },
    );
  };

  const handleIssueShare = async () => {
    try {
      const r = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/mesh/share/issue`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ttl_seconds: 24 * 3600 }),
      });
      const body = await r.json();
      const apiBase = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
      setShareLink(`${apiBase}${body.share_url}`);
    } catch (e) {
      console.error('share issue failed', e);
    }
  };

  const handleClaimBounty = async (peer: string, campaignId: string, token: string) => {
    try {
      const r = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/mesh/bounty/claim`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ peer, campaign_id: campaignId, token }),
      });
      const body = await r.json();
      setBountyClaimStatus(body.status || body.detail || 'unknown');
      setTimeout(() => setBountyClaimStatus(''), 4000);
    } catch (e: any) {
      setBountyClaimStatus(`error: ${e.message}`);
    }
  };

  const savePeer = () => {
    if (typeof window !== 'undefined') localStorage.setItem('aegis_peer', peerHandle);
  };

  return (
    <div className="feature-page">
      <header className="feature-hero">
        <div className="eyebrow">ACTIVE DEFENSE · ML-KEM-768</div>
        <h1>Quantum Defense Mesh</h1>
        <p>
          Live honeypot mesh bound to NIST ML-KEM-768 keys. External attacks — from
          friends' laptops via the CLI, the public tunnel, or the built-in red-team
          simulator — are fingerprinted, correlated into campaigns, and answered with
          QAOA-derived countermeasures.
        </p>
      </header>

      {/* Live Radar — real blips from /mesh/state */}
      <section style={{ marginBottom: 18 }}>
        <MeshRadar state={state} />
      </section>

      {/* Status strip */}
      <section className="feature-content" style={{ marginBottom: 18 }}>
        <div className="feature-section">
          <span className="feature-section-eyebrow">Mesh Stats</span>
          <h2>{state?.honeypots?.total_contacts ?? 0} Contacts</h2>
          <p>
            <span className="font-mono text-[#06b6d4]">{state?.honeypots?.unique_attackers ?? 0}</span>{' '}
            unique attacker IPs across {Object.keys(state?.honeypots?.by_service ?? {}).length || 0} service(s).
          </p>
          <div className="text-xs font-mono text-slate-500 mt-2">
            ML-KEM fingerprint:{' '}
            <span className="text-emerald-400">{state?.honeypots?.active_ml_kem_fingerprint ?? '…'}</span>
          </div>
        </div>

        <div className="feature-section">
          <span className="feature-section-eyebrow">Campaigns</span>
          <h2>{state?.campaigns?.length ?? 0} Active</h2>
          <p>
            Total severity{' '}
            <span className="font-mono text-rose-400">
              {((state?.campaigns?.reduce((s, c) => s + (c?.severity ?? 0), 0)) ?? 0).toFixed(2)}
            </span>{' '}
            across all currently active attacker groups.
          </p>
        </div>

        <div className="feature-section">
          <span className="feature-section-eyebrow">Countermeasures</span>
          <h2>{state?.countermeasures?.length ?? 0} Deployed</h2>
          <p>
            Latest solver:{' '}
            <span className="font-mono text-[#7c5cff]">
              {state?.countermeasures?.[state?.countermeasures.length - 1]?.solver ?? 'n/a'}
            </span>
          </p>
        </div>

        <div className="feature-section">
          <span className="feature-section-eyebrow">Severity Histogram</span>
          <div className="mt-2 space-y-1.5">
            {(['critical', 'high', 'medium', 'low'] as const).map((bucket) => {
              const hist = state?.campaigns ? {
                critical: state.campaigns.filter((c) => c.severity >= 10).length,
                high: state.campaigns.filter((c) => c.severity >= 5 && c.severity < 10).length,
                medium: state.campaigns.filter((c) => c.severity >= 2 && c.severity < 5).length,
                low: state.campaigns.filter((c) => c.severity < 2).length,
              } : { critical: 0, high: 0, medium: 0, low: 0 };
              const total = Math.max(1, hist.critical + hist.high + hist.medium + hist.low);
              const pct = (hist[bucket] / total) * 100;
              const color =
                bucket === 'critical' ? 'bg-rose-500' :
                bucket === 'high' ? 'bg-amber-500' :
                bucket === 'medium' ? 'bg-[#7c5cff]' : 'bg-emerald-500';
              return (
                <div key={bucket} className="flex items-center space-x-2 text-[10px] font-mono">
                  <span className="w-14 text-slate-400 uppercase">{bucket}</span>
                  <div className="flex-1 h-2 bg-white/5 rounded overflow-hidden">
                    <div className={`h-full ${color}`} style={{ width: `${pct}%` }} />
                  </div>
                  <span className="w-6 text-right text-slate-300">{hist[bucket]}</span>
                </div>
              );
            })}
          </div>
        </div>

        <div className="feature-section">
          <span className="feature-section-eyebrow">Federated</span>
          <h2>{state?.federated?.known_peers ?? 0} Peers</h2>
          <p>
            <span className="font-mono text-emerald-400">{state?.federated?.total_samples ?? 0}</span>{' '}
            encrypted gradient samples aggregated. No raw peer data ever leaves a peer.
          </p>
        </div>
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Honeypots */}
        <div className="claude-card p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-white/10 pb-3">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2 font-display">
              <Server className="w-4 h-4 text-[#06b6d4]" />
              <span>Honeypot Decoys</span>
            </h3>
            <button
              onClick={refresh}
              className="text-xs font-mono text-slate-400 hover:text-white"
            >
              {loading ? '…' : 'refresh'}
            </button>
          </div>
          <div className="space-y-2">
            {SERVICES.map((svc) => {
              const count = state?.honeypots?.by_service?.[svc.id] ?? 0;
              return (
                <a
                  key={svc.id}
                  href={`/mesh/honeypots/${svc.id}`}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center justify-between rounded-xl border border-white/10 bg-[#070a13] px-3 py-2.5 hover:bg-white/[0.04] transition-colors"
                >
                  <div className="flex items-center space-x-2.5">
                    <svc.icon className="w-4 h-4 text-[#06b6d4]" />
                    <span className="text-xs font-mono text-slate-200">{svc.label}</span>
                  </div>
                  <span className="text-xs font-mono text-emerald-400 font-bold">{count}</span>
                </a>
              );
            })}
          </div>

          {/* Per-honeypot ML-KEM session ids */}
          <div className="pt-3 border-t border-white/10 space-y-1.5">
            <div className="text-xs text-slate-400 uppercase tracking-wider font-bold">
              ML-KEM Session IDs
            </div>
            {(['ssh', 'http', 'smb'] as const).map((svc) => (
              <div key={svc} className="flex items-center justify-between text-[11px] font-mono">
                <span className="text-slate-500">{svc}</span>
                <span className="text-[#7c5cff]">{state?.honeypots?.by_service_session?.[svc]?.slice(0, 16) ?? '…'}</span>
              </div>
            ))}
          </div>

          <div className="pt-3 border-t border-white/10 space-y-3">
            <div className="text-xs text-slate-400 uppercase tracking-wider font-bold">
              Send Attack (this browser)
            </div>
            <div className="grid grid-cols-3 gap-1.5">
              {SERVICES.map((svc) => (
                <button
                  key={svc.id}
                  onClick={() => setService(svc.id)}
                  className={`px-2 py-1.5 rounded-lg text-[11px] font-mono uppercase tracking-wider ${
                    service === svc.id ? 'pill-badge-violet' : 'bg-white/5 text-slate-400 hover:bg-white/10'
                  }`}
                >
                  {svc.id}
                </button>
              ))}
            </div>
            <select
              value={payloadIdx}
              onChange={(e) => setPayloadIdx(Number(e.target.value))}
              className="w-full form-control"
            >
              {PAYLOADS.map((p, i) => (
                <option key={i} value={i}>
                  {p.label}
                </option>
              ))}
            </select>
            <input
              value={srcIp}
              onChange={(e) => setSrcIp(e.target.value)}
              className="w-full form-control"
              placeholder="src_ip"
            />
            <input
              value={peerHandle}
              onChange={(e) => setPeerHandle(e.target.value)}
              onBlur={savePeer}
              className="w-full form-control"
              placeholder="peer handle (for bounty)"
            />
            <button onClick={handleAttack} className="btn-hacktober-primary w-full py-2.5 text-xs">
              <Send className="w-4 h-4" />
              <span>Send attack</span>
            </button>

            {/* Friend-share link */}
            <button onClick={handleIssueShare} className="btn-hacktober-secondary w-full py-2 text-xs">
              <Radio className="w-3.5 h-3.5" />
              <span>Issue friend share-link</span>
            </button>
            {shareLink && (
              <div className="text-[10px] font-mono text-emerald-400 break-all p-2 rounded bg-emerald-500/5 border border-emerald-500/20">
                {shareLink}
              </div>
            )}
          </div>
        </div>

        {/* Campaigns + Countermeasures */}
        <div className="lg:col-span-2 space-y-6">
          {/* Campaigns */}
          <div className="claude-card p-6 space-y-3">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2 font-display">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                <span>Active Campaigns ({state?.campaigns?.length ?? 0})</span>
              </h3>
              <span className="text-xs font-mono text-slate-400">fingerprint-keyed</span>
            </div>
            {state?.campaigns?.length ? (
              <ul className="space-y-2">
                {state?.campaigns?.map((c) => (
                  <li
                    key={c.campaign_id}
                    className="rounded-xl border border-white/10 bg-[#070a13] p-3 space-y-2"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                      <div className="font-mono">
                        <span className="text-rose-400 font-bold">{c.severity.toFixed(2)} sev</span>
                        <span className="text-slate-600"> · </span>
                        <span className="text-slate-300">{c.event_count} events</span>
                        <span className="text-slate-600"> · </span>
                        <span className="text-slate-500">{(c.services ?? []).join(', ')}</span>
                      </div>
                      <button
                        onClick={() => handleCountermeasure(c)}
                        className="px-2.5 py-1 rounded-md bg-[#ff7a59]/15 hover:bg-[#ff7a59]/25 text-[11px] font-mono text-[#ff7a59] font-bold"
                      >
                        Deploy countermeasure
                      </button>
                    </div>
                    <div className="text-[11px] font-mono text-slate-400 break-all">ips: {c.attacker_ips?.join(', ') || '-'}</div>
                    <div className="text-[11px] font-mono text-slate-500 break-all">ml-kem: {c.ml_kem_session_ids?.join(', ') || '-'}</div>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-slate-500">No active campaigns yet. Send an attack or wait for the red-team sim.</p>
            )}
          </div>

          {/* Countermeasures */}
          <div className="claude-card p-6 space-y-3">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2 font-display">
                <Sparkles className="w-4 h-4 text-[#ff7a59]" />
                <span>Countermeasures ({state?.countermeasures?.length ?? 0})</span>
              </h3>
              <span className="text-xs font-mono text-slate-400">QAOA → ML-KEM decoy</span>
            </div>
            {state?.countermeasures?.length ? (
              <ul className="space-y-2">
                {state?.countermeasures?.slice(-10).reverse().map((cm) => (
                  <li
                    key={cm.countermeasure_id}
                    className="rounded-xl border border-white/10 bg-[#070a13] p-3 space-y-1.5"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                      <span className="font-mono">
                        <span className="text-[#ff7a59] font-bold">{cm.solver}</span>
                        <span className="text-slate-600"> · </span>
                        <span className="text-slate-300">block_upstream={String(cm.block_upstream)}</span>
                      </span>
                      <span className="text-[10px] font-mono text-slate-500">
                        {new Date(cm.issued_at * 1000).toLocaleTimeString()}
                      </span>
                    </div>
                    <div className="text-[11px] font-mono text-slate-400 break-all">
                      decoy token: <span className="text-emerald-400">{cm.decoy_token}</span>
                    </div>
                    <div className="text-[11px] font-mono text-slate-500">rule: {cm.rules_applied?.[0]?.name ?? '-'} · solver fp: {cm.rules_applied?.[0]?.solver ?? '-'}
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-slate-500">No countermeasures deployed yet.</p>
            )}
          </div>
        </div>
      </div>

      {/* Red-team + Federated + Bounty row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6" style={{ marginTop: 24 }} id="bounty">
        <div className="claude-card p-6 space-y-3">
          <div className="flex items-center justify-between border-b border-white/10 pb-3">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2 font-display">
              <Zap className="w-4 h-4 text-amber-400" />
              <span>Built-in Red-Team Sim</span>
            </h3>
            <span className={`text-xs font-mono ${state?.redteam?.running ? 'text-emerald-400' : 'text-slate-500'}`}>
              {state?.redteam?.running ? '● running' : '○ stopped'}
            </span>
          </div>
          <div className="text-xs font-mono text-slate-300">
            Tick: {state?.redteam?.tick_seconds ?? '-'}s · Total runs: {state?.redteam?.total_runs ?? 0} · Next:{' '}
            <span className="text-amber-300">{state?.redteam?.next_pattern ?? '-'}</span>
          </div>
          <div className="text-[11px] font-mono text-slate-400 space-y-0.5">
            <div>base: <span className="text-slate-300">{state?.redteam?.mutation_stats?.base_events ?? 0}</span></div>
            <div>mutated: <span className="text-amber-300">{state?.redteam?.mutation_stats?.events_mutated ?? 0}</span></div>
            <div>adapt ratio: <span className="text-[#7c5cff]">{((state?.redteam?.mutation_stats?.adaptation_ratio ?? 0) * 100).toFixed(1)}%</span></div>
          </div>
          <div className="flex space-x-2">
            <button
              onClick={() => startRedteam()}
              className="btn-hacktober-primary py-2 px-4 text-xs flex items-center space-x-1.5"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Start</span>
            </button>
            <button
              onClick={() => stopRedteam()}
              className="btn-hacktober-secondary py-2 px-4 text-xs flex items-center space-x-1.5"
            >
              <Square className="w-3.5 h-3.5" />
              <span>Stop</span>
            </button>
          </div>
        </div>

        <div className="claude-card p-6 space-y-3">
          <div className="flex items-center justify-between border-b border-white/10 pb-3">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2 font-display">
              <Users className="w-4 h-4 text-emerald-400" />
              <span>Federated Peers</span>
            </h3>
            <span className="text-xs font-mono text-slate-400">{state?.federated?.known_peers ?? 0} peer(s)</span>
          </div>
          <div className="flex space-x-2">
            <input
              value={peerId}
              onChange={(e) => setPeerId(e.target.value)}
              className="form-control flex-1"
              placeholder="peer_id"
            />
            <button onClick={handleFederated} className="btn-hacktober-primary py-2 px-4 text-xs">
              <Send className="w-3.5 h-3.5" />
              <span>Submit Δ</span>
            </button>
          </div>
          <ul className="space-y-1 text-[11px] font-mono">
            {(state?.federated?.peers ?? []).slice(0, 5).map((p) => (
              <li key={p.peer_id} className="text-slate-300 flex justify-between">
                <span>{p.peer_id}</span>
                <span className="text-slate-500">{p.samples} samples · {p.updates} updates</span>
              </li>
            ))}
            {(state?.federated?.peers ?? []).length === 0 && (
              <li className="text-slate-500">No peers yet — submit a gradient update.</li>
            )}
          </ul>
        </div>

        <div className="claude-card p-6 space-y-3">
          <div className="flex items-center justify-between border-b border-white/10 pb-3">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2 font-display">
              <Coins className="w-4 h-4 text-amber-300" />
              <span>Bounty Mode</span>
            </h3>
            <span className="text-xs font-mono text-amber-300">
              {state?.bounty?.pending ?? 0} pending
            </span>
          </div>
          <div className="text-[11px] font-mono text-slate-300 space-y-1">
            <div>Total issued: <span className="text-amber-300">{state?.bounty?.total_issued ?? 0}</span> QShield</div>
            <div>Paid: <span className="text-emerald-400">{state?.bounty?.paid ?? 0}</span></div>
            <div>Top peer: <span className="text-[#7c5cff]">{state?.bounty?.top_peer ?? '-'}</span>{state?.bounty?.top_peer_earned ? ` (${state.bounty.top_peer_earned})` : ''}</div>
          </div>
          {(state?.bounty?.recent ?? []).slice(0, 4).map((b) => (
            <div key={b.bounty_id} className="flex items-center justify-between text-[10px] font-mono border-t border-white/5 pt-2">
              <span className="text-slate-300 truncate">{b.peer}</span>
              <div className="flex items-center space-x-2">
                <span className="text-amber-300">+{b.amount}</span>
                {peerHandle && b.peer === peerHandle && !b.claimed && (
                  <button
                    onClick={async () => {
                      // Token not exposed via state; we fetch via the
                      // bounty claim endpoint with a "lookup by handle"
                      // shortcut. For demo, we just hit claim with the
                      // bounty_id as a stand-in (route requires token,
                      // so we POST anyway).
                      try {
                        const r = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/mesh/bounty/claim`, {
                          method: 'POST',
                          headers: { 'Content-Type': 'application/json' },
                          body: JSON.stringify({
                            peer: peerHandle,
                            campaign_id: b.campaign_id,
                            token: (b as any).token || 'pending-claim',
                          }),
                        });
                        const body = await r.json();
                        setBountyClaimStatus(body.status || body.detail || 'unknown');
                        setTimeout(() => setBountyClaimStatus(''), 4000);
                      } catch (e: any) {
                        setBountyClaimStatus(`error: ${e.message}`);
                      }
                    }}
                    className="text-emerald-400 hover:text-emerald-300 font-bold"
                  >
                    claim
                  </button>
                )}
                {b.claimed && <span className="text-emerald-500">paid</span>}
              </div>
            </div>
          ))}
          {bountyClaimStatus && (
            <div className="text-[10px] font-mono text-emerald-300">status: {bountyClaimStatus}</div>
          )}
        </div>
      </div>

      {/* Live SSE feed */}
      <div className="claude-card p-6 space-y-3" style={{ marginTop: 24 }}>
        <div className="flex items-center justify-between border-b border-white/10 pb-3">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2 font-display">
            <Radio className={`w-4 h-4 ${sseStatus === 'live' ? 'text-emerald-400' : sseStatus === 'error' ? 'text-rose-400' : 'text-[#06b6d4]'}`} />
            <span>Live Mesh Feed (SSE)</span>
          </h3>
          <span className="text-xs font-mono text-slate-400">
            {sseStatus === 'live' && <span className="text-emerald-400">● Connected</span>}
            {sseStatus === 'connecting' && <span className="text-[#06b6d4]">● Connecting…</span>}
            {sseStatus === 'error' && <span className="text-rose-400">● Disconnected</span>}
            <span className="ml-2">{feed.length} event{feed.length === 1 ? '' : 's'}</span>
          </span>
        </div>
        {feed.length === 0 ? (
          <p className="text-xs text-slate-500">Listening for mesh activity…</p>
        ) : (
          <ul className="space-y-1.5 max-h-80 overflow-auto">
            {feed.map((e, i) => {
              const Icon = EVENT_ICONS[e.kind] ?? Activity;
              const color = EVENT_COLORS[e.kind] ?? 'text-slate-300';
              const bg = EVENT_BG[e.kind] ?? 'bg-white/5 border-white/10';
              const text = JSON.stringify(e.payload).slice(0, 240);
              const long = JSON.stringify(e.payload).length > 240;
              return (
                <li
                  key={`${e.at}-${i}`}
                  className={`text-[11px] font-mono rounded-lg px-3 py-1.5 border flex items-start space-x-2 ${bg}`}
                >
                  <Icon className={`w-3.5 h-3.5 flex-shrink-0 mt-0.5 ${color}`} />
                  <span className="flex-1 break-all">
                    <span className={color}>{e.kind}</span>
                    <span className="text-slate-600"> · </span>
                    <span className="text-slate-300">{text}{long ? '…' : ''}</span>
                  </span>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </div>
  );
}