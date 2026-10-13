const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export interface BlockedIpEntry {
  ip: string;
  attack_type: string;
  threat_score: number;
  blocked_at: number;
  last_seen: number;
  hit_count: number;
  status: string;
}

export interface DetectionResult {
  fast_path: boolean;
  matched_database: boolean;
  status: string;
  message: string;
  threat_detected: boolean;
  threat_score: number;
  attack_type: string;
  inference_latency_ms: number;
  actions_taken: string[];
  database_updated: boolean;
  ip_address: string;
}

export async function detectThreat(
  traffic: Record<string, unknown>,
  sourceIp: string,
  attackType?: string
): Promise<DetectionResult> {
  const url = new URL(`${API_BASE}/detect`);
  url.searchParams.set('source_ip', sourceIp);
  url.searchParams.set('auto_respond', 'true');
  const res = await fetch(url.toString(), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(traffic),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function fetchBlockedIps(): Promise<{ count: number; blocked_ips: BlockedIpEntry[] }> {
  const res = await fetch(`${API_BASE}/blocked-ips`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function clearBlockedIps() {
  const res = await fetch(`${API_BASE}/blocked-ips/clear`, { method: 'POST' });
  return res.json();
}

export async function unblockIp(ip: string) {
  const res = await fetch(`${API_BASE}/blocked-ips/${encodeURIComponent(ip)}`, { method: 'DELETE' });
  return res.json();
}

export async function fetchHealth(): Promise<{ status: string; database_size: number; timestamp: number }> {
  const res = await fetch(`${API_BASE}/health`);
  return res.json();
}