const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export interface DetectionResult {
  threat_detected: boolean;
  threat_score: number;
  attack_type: string;
  confidence: string;
  top_features: Array<{ feature: string; value: number; shap_value: number }>;
  inference_latency_ms: number;
  model_version: string;
}

export interface CryptoStatus {
  algorithm: string;
  standard: string;
  security_level: string;
  implementation: string;
  active_sessions: number;
  last_rotation_time: number;
  last_rotation_reason: string;
  total_rotations: number;
  public_key_fingerprint: string;
}

export interface OptimizationResult {
  selected_rules: Array<{
    rule_id: string;
    name: string;
    action: string;
    block_probability: number;
    false_positive_rate: number;
    cost: number;
    scope: string;
  }>;
  total_block_probability: number;
  total_fpr: number;
  total_cost: number;
  optimization_time_ms: number;
  solver: string;
  n_rules_evaluated: number;
  n_rules_selected: number;
}

export interface LedgerVerification {
  valid: boolean;
  chain_length: number;
  first_entry: number;
  last_entry: number;
  broken_at?: string | null;
}

export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/health`);
  return res.json();
}

export async function detectThreat(traffic: Record<string, any>): Promise<DetectionResult> {
  const res = await fetch(`${API_BASE}/detect`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(traffic),
  });
  return res.json();
}

export async function respondToThreat(detection: DetectionResult) {
  const res = await fetch(`${API_BASE}/respond`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(detection),
  });
  return res.json();
}

export async function optimizeRules(fprBudget = 0.1, costBudget = 10, nRules = 15): Promise<OptimizationResult> {
  const res = await fetch(`${API_BASE}/optimize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fpr_budget: fprBudget, cost_budget: costBudget, n_rules: nRules }),
  });
  return res.json();
}

export async function fetchCryptoStatus(): Promise<CryptoStatus> {
  const res = await fetch(`${API_BASE}/crypto/status`);
  return res.json();
}

export async function triggerKeyRotation() {
  const res = await fetch(`${API_BASE}/crypto/rotate`);
  return res.json();
}

export async function verifyLedgerChain(): Promise<LedgerVerification> {
  const res = await fetch(`${API_BASE}/ledger/verify`);
  return res.json();
}

export async function fetchLedgerEntries(limit = 20, offset = 0) {
  const res = await fetch(`${API_BASE}/ledger/entries?limit=${limit}&offset=${offset}`);
  return res.json();
}
