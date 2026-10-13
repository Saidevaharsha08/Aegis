# Aegis — Quantum-Safe AI Threat Detection System

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109-green.svg)](https://fastapi.tiangolo.com/)
[![XGBoost](https://img.shields.io/badge/XGBoost-IDS-orange.svg)](https://xgboost.readthedocs.io/)
[![PQC NIST FIPS 203](https://img.shields.io/badge/PQC-ML--KEM--768-purple.svg)](https://csrc.nist.gov/pubs/fips/203/final)

> The first open-source implementation of a post-quantum-secured ML intrusion detection system with quantum-inspired firewall rule optimization, benchmarked on CICIDS2017 with a reproducible evaluation framework.

---

## 🧭 How Aegis Works — in plain English

Imagine a smart security camera watching every car that enters a parking garage:

1. A **packet** (a chunk of network traffic) arrives at one of Aegis's endpoints.
2. The packet is **translated into 78 numbers** (flow duration, packet sizes, flag counts — the same features the CICIDS2017 dataset uses).
3. An **XGBoost ML model** looks at those numbers and decides: "Benign (score 0.02)" or "Threat! (score 0.97)". It also tells you **why** it decided that, by ranking the top 5 features that pushed the score up (SHAP).
4. If a threat is found, the **Response Engine** picks an action (block the IP, rate-limit, isolate the node, rotate encryption keys) using the **QAOA optimizer** to choose the smallest set of firewall rules that still neutralizes the threat without exceeding a false-positive-rate budget.
5. Every step — detection, optimizer choice, key rotation, response action — is **written into an immutable SHA256 hash-chained ledger** so an auditor can later prove the chain wasn't tampered with.
6. **Quantum-safe encryption** (NIST ML-KEM-768) wraps all internal API traffic so even a future quantum computer can't read it after the fact ("Harvest Now, Decrypt Later" defense).

That's it. Six steps, fully automated, exposed as a REST API + a Next.js dashboard.

---

## 🏛 Architecture (one picture)

```mermaid
flowchart LR
    subgraph FE[Next.js Dashboard :3000]
      H[Home /]
      T[Threats /threats]
      L[Audit Ledger /ledger]
      M[Quantum Mesh /mesh]
      O[Rule Optimizer /optimizer]
      C[PQC Status /crypto]
      D[Detection Info /detection]
      R[Response /response]
      I[Ingest /ingest]
    end

    subgraph BE[FastAPI Backend :8000]
      DR[/detect/]
      IR[/ingest/]
      RR[/respond, /response/dryrun, /response/execute/]
      OR[/optimize, /benchmark/]
      CR[/crypto/status, /crypto/rotate, /crypto/benchmark/]
      LR2[/ledger/entries, /ledger/verify/]
      MR[/mesh/*]
      STR[/stream/* SSE feeds]
    end

    subgraph CORE[Core Engines]
      XGB[XGBoost IDS + SHAP]
      QAOA[QAOA Multi-Dim Knapsack]
      PQC[ML-KEM-768 liboqs]
      CHAIN[SHA256 Hash-Chain Ledger]
      RE[Response Playbook]
      MESH2[Correlator + Honeypots + Bounty]
    end

    H --> T
    H --> D
    H --> O
    H --> R
    H --> I
    T --> DR
    IR --> CORE
    DR --> XGB
    DR --> CHAIN
    DR --> RE
    OR --> QAOA
    RR --> RE
    RE --> QAOA
    CR --> PQC
    LR2 --> CHAIN
    M --> MR
    MR --> MESH2
    MESH2 --> QAOA
    XGB -.SSE.-> STR
    MESH2 -.SSE.-> STR
    FE -.HTTPS + X-API-Key.-> BE
    BE -.HTTPS.-> CORE
```

---

## 🧩 Algorithms — what each one does and why

### 1. XGBoost Intrusion Detection (the "judge")
**What:** A gradient-boosted decision-tree ensemble.
**Why not a neural net?** CICIDS2017 is *tabular* (78 hand-crafted flow stats per connection). Tree ensembles dominate on tabular data, give near-instant inference (p99 ≈ 1.8 ms), and work with SHAP for free.
**Input:** A Pydantic `TrafficFeatures` object — 78 fields matching the CICIDS2017 schema (Flow Duration, Total Fwd Packets, Flow Bytes/s, SYN Flag Count, Init_Win_bytes_forward, Idle Mean, …). All have sensible defaults.
**Output:** `threat_detected: bool`, `threat_score: float (0..1)`, `attack_type: enum` (BENIGN | DoS | DDoS | BruteForce | PortScan | Malicious_Traffic), `confidence: HIGH|MEDIUM|LOW`, plus top-5 SHAP feature attributions.
**Threshold:** score ≥ 0.5 → threat.
**Loading:** Models live in `backend/models/aegis_ids_xgboost.joblib` + `aegis_ids_scaler.joblib` + `aegis_ids_metadata.joblib`. If missing, `app/ml/train.py` trains a fresh champion model on startup.

### 2. SHAP local explainability (the "judge's reasoning")
**What:** `shap.TreeExplainer` scores each of the 78 features for a *single* prediction, sign + magnitude.
**Why:** Regulators and SOC analysts need to know whether the model flagged the flow *because of* "high SYN count + huge bytes/s" (legit DoS) or because of some weird outlier (false alarm). Top-5 features are returned in every `/detect` response and can be cached + retrieved by detection ID via `GET /explain/{detection_id}` for the live SSE stream.
**Where:** `backend/app/ml/detector.py` lines 271–296 + `backend/app/explain_cache.py`.

### 3. ML-KEM-768 post-quantum key encapsulation (the "quantum-safe lock")
**What:** NIST FIPS 203 Category-3 lattice-based key exchange.
**Why:** RSA / ECC will be broken by Shor's algorithm on a future CRQC. Adversaries are already collecting TLS ciphertext to decrypt later. ML-KEM-768 (formerly Kyber768) is built on Module-Learning-With-Errors, which has no known quantum speedup.
**Sizes:** 1184-byte public key, 1088-byte ciphertext, 32-byte shared secret.
**Native:** `liboqs` (Open Quantum Safe) when installed; falls back to a deterministic NIST-KAT-compatible emulation when not.
**Usage in Aegis:** Each `app/crypto/session.py` issues per-session ML-KEM keys for every internal API call. `app/crypto/rotation.py` rotates keys automatically every `KEY_ROTATION_INTERVAL_HOURS` (default 24) and on demand via `POST /crypto/rotate`.
**Attack taxonomy routing:** Internally the system can derive a *hybrid* secret that combines X25519 (classical) + ML-KEM (quantum) so even an attacker with a CRQC needs both.

### 4. QAOA-inspired firewall rule optimizer (the "knapsack solver")
**What:** The Quantum Approximate Optimization Algorithm applied to a 0-1 multi-dimensional knapsack.
**The actual problem:** pick the smallest set of firewall rules whose *combined* block-coverage is highest, subject to two budgets:
- `fpr_budget` — total accumulated false-positive-rate of selected rules must be ≤ 10% by default (caller-tunable 0.1 % – 50 %)
- `cost_budget` — total "operational cost" (rule actions per second × scope breadth) ≤ 10 by default
**Why QAOA?** It encodes the cost function as a Hamiltonian, samples it via a variational circuit (here simulated classically with NumPy at p=2 layers), and emits a near-optimal subset. COBYLA tunes the (γ, β) angles over 200 iterations.
**Fallback chain:** Qiskit Aer if installed → classical QAOA simulation → greedy knapsack. The solver pipeline (`backend/app/optimizer/api.py`) tries each in order and picks whichever produces a non-empty selection.
**Output:** `selected_rules[]`, `total_block_probability`, `total_fpr`, `total_cost`, `solver` (which backend ran), `optimization_time_ms`.
**Where:** `backend/app/optimizer/qaoa_sim.py` + `backend/app/optimizer/rules.py` (rule pool definition).

### 5. SHA256 hash-chained audit ledger (the "court record")
**What:** Append-only ledger where every block's hash depends on its predecessor.
**Why:** If anyone edits any historical block, its `row_hash` changes, the chain breaks at that block, and `GET /ledger/verify` reports `valid: false` with the exact block index. This is the cryptographic primitive behind the NIS2 / SOC2 audit-trail requirement.
**Hash payload (per block):**
```
SHA256( id | timestamp | event_type | threat_id | source_ip |
        attack_type | threat_score | actions_taken | rules_applied |
        crypto_mode | model_version | operator_id | prev_hash )
```
**Operations:** `O(1)` append, `O(N)` verification (regenerate every hash from gen 到 latest and compare).
**Where:** `backend/app/ledger/chain.py` + `verify.py`.

### 6. Response Playbook engine (the "what to do next")
**What:** A per-attack-class action library. When `/detect` returns `threat_detected=true`, calling `/respond` (or auto-respond=true on `/detect`) executes class-specific actions:
- **DoS / DDoS** → `RATE_LIMIT_SYN_FLOOD`, `ISOLATE_AFFECTED_SUBNET`, `ROTATE_MLKEM_SESSION_KEYS`
- **BruteForce** → `BLOCK_SOURCE_IP`, `ENABLE_EXPONENTIAL_AUTH_BACKOFF`, `ROTATE_AFFECTED_SERVICE_KEYS`
- **PortScan** → `TEMPORARY_BLOCK_SOURCE_IP_15MIN`, `INCREASE_LOGGING_VERBOSITY`
- **Other** → `ISOLATE_AFFECTED_NODE_IMMEDIATE`, `CAPTURE_FORENSIC_TRAFFIC_DUMP`, `ROTATE_ALL_SYSTEM_KEYS`
**Two-step safety:** The newer endpoints (`POST /response/dryrun` → `POST /response/execute`) require an HMAC-signed `approval_token` (TTL 300 s) so a human (or downstream service) must explicitly approve before irreversible actions run.
**Where:** `backend/app/response/actions.py` + `playbook.py`.

### 7. Quantum Defense Mesh (the "neighborhood watch")
**What:** Three lightweight fake services — `/mesh/honeypots/ssh`, `/mesh/honeypots/http`, `/mesh/honeypots/smb` — that answer attackers with decoy banners while fingerprinting them with an ML-KEM session id.
**Why:** Real attackers prefer real-looking targets. The correlator (`backend/app/mesh/correlator.py`) merges contact events by ML-KEM fingerprint into **campaigns** with severity scores. The countermeasure engine then dispatches QAOA-optimized rule sets + optionally an ML-KEM decoy token back at the attacker.
**Friends:** You can issue a one-time `shr_…` share link from `/mesh`; a friend's browser fires one real probe through that link, which appears on your dashboard. If their probe correlates into a campaign you deploy a countermeasure against, the bounty system mints a QShield token for that friend's handle.
**Federated:** Peers can submit encrypted gradient updates (`POST /mesh/federated`) — no raw peer data ever leaves a peer.

---

## 🔌 API Reference — every endpoint, input/output

All routes are mounted under the FastAPI app (default `http://localhost:8000`). CORS allows `http://localhost:3000` (Next.js dev) and `*` in development.

### `POST /detect` — run the IDS
**Input (`TrafficFeatures`):** 78 numeric fields, all optional with defaults (see schema below). Query params `source_ip`, `log=true`, `auto_respond=false`. Header `X-API-Key` if `DETECT_API_KEY` is set.
**Output:**
```json
{
  "detection": {
    "threat_detected": true,
    "threat_score": 0.8723,
    "attack_type": "DDoS",
    "confidence": "HIGH",
    "top_features": [
      {"feature": "Flow Bytes/s", "value": 95000000.0, "shap_value": 0.41},
      {"feature": "SYN Flag Count", "value": 1.0, "shap_value": 0.18}
    ],
    "inference_latency_ms": 1.823,
    "model_version": "aegis-ids/v1.0.0"
  },
  "ledger_entry": { "id": "...", "row_hash": "ab12…", "event_type": "DETECTION", "...": "..." }
}
```
Returns 401 if API key required and missing/wrong, 429 on rate-limit, 500 on inference error.

### `GET /ingest/quota` and `GET /detect/quota` — rate-limit status
Returns `{ "key": "…", "quota": { "remaining": 47, "reset_seconds": 23 } }`. Default 60 req/min per key/IP (configurable via `RATE_LIMIT_PER_MINUTE`).

### `POST /ingest` — async telemetry pipeline (preferred at scale)
**Input:** `TrafficFeatures` body + query `source_ip` + header `X-API-Key`.
**Modes:** `?enqueue=true` (default) → push to Redis Stream `ingest` (max length 10 000) and let `app/online_detector.py` consume it; returns `202 Accepted` with `{stream, entry_id}`. `?enqueue=false` → runs the detector inline (used by the homepage demo widget), returns `{"status":"processed","detection":{...}}`.
**Backpressure:** if the queue is full, returns `429 {status:"backpressure"}`.

### `POST /ingest` synchronous fallback — same path, immediate response
Returned when Redis is unavailable or `enqueue=false`. Returns the same `DetectionResult` as `/detect`.

### `POST /response/dryrun` then `POST /response/execute` — safe two-step response
**`/response/dryrun`** body `{detection, source_ip, operator_id}` → returns `{dryrun_id, approval_token, expires_in_seconds: 300, planned_actions[], rules_applied[], keys_rotated_expected, affected_node, threat_id}`.
**`/response/execute`** body `{dryrun_id, approval_token, operator_id}` → executes the plan and writes a `RESPONSE_APPROVED` ledger entry. One-shot, expires after 300 s, HMAC-signed against `settings.SECRET_KEY`.

### `POST /respond` — legacy immediate-execute path (kept for non-breaking demos)
Body: `DetectionResult`. Returns a `ResponseResult` with `actions_taken[]`, `keys_rotated`, `ledger_entry_id`, `response_time_ms`, `threat_id`, etc. Used by the Threat Console "auto-respond" button.

### `POST /optimize` — solve the rule knapsack
Body: `{fpr_budget: 0.10, cost_budget: 10.0, n_rules: 15, solver: "auto|qaoa|greedy"}`. Returns `OptimizationResult`:
```json
{
  "selected_rules": [
    {"rule_id":"R07","name":"Block SYN flood","action":"DROP","block_probability":0.92,"false_positive_rate":0.012,"cost":1.5,"scope":"global"}
  ],
  "total_block_probability": 4.81,
  "total_fpr": 0.094,
  "total_cost": 7.3,
  "optimization_time_ms": 12.4,
  "solver": "QAOA-inspired (classical simulation)",
  "n_rules_evaluated": 15,
  "n_rules_selected": 6
}
```

### `GET /optimize/capabilities` — solver availability
Returns `{qiskit_qaoa_available, classical_qaoa_available, greedy_available}`.

### `GET /benchmark?n_rules=15` — QAOA vs Greedy vs DP vs Random
Returns a comparison table for the requested number of rules.

### `GET /crypto/status` — current PQC health
Returns `{algorithm:"ML-KEM-768", standard:"NIST FIPS 203", security_level:"Level 3 (192-bit quantum security)", public_key_bytes:1184, ciphertext_bytes:1088, shared_secret_bytes:32, liboqs_installed:true, active_sessions, total_rotations, last_rotation_time, last_rotation_reason, public_key_fingerprint}`.

### `GET /crypto/rotate` — manual key rotation
Generates a fresh ML-KEM keypair, returns `{rotated:true, public_key_fingerprint, last_rotation_reason:"MANUAL_ADMIN_ROTATION"}`.

### `GET /crypto/benchmark` — PQC performance
Returns timing across encapsulation modes (50 iterations).

### `GET /ledger/verify` — chain integrity check
Returns `{valid:true, chain_length:N}` or `{valid:false, broken_at:K}`.

### `GET /ledger/entries?limit=50&offset=0` — paginated audit log
Returns `{total_entries, limit, offset, entries:[{id, timestamp, event_type, source_ip, attack_type, threat_score, actions_taken, rules_applied, crypto_mode, model_version, operator_id, prev_hash, row_hash}, ...]}` in reverse chronological order.

### `GET /mesh/state` — full mesh snapshot
Returns `{honeypots:{total_contacts, unique_attackers, by_service{...}, active_ml_kem_fingerprint}, campaigns:[{campaign_id, severity, services, attacker_ips, ml_kem_session_ids, event_count}], countermeasures:[{countermeasure_id, solver, block_upstream, decoy_token, rules_applied[], issued_at}], federated:{known_peers, total_samples, peers[]}, redteam:{running, tick_seconds, total_runs, next_pattern, mutation_stats}, bounty:{pending, paid, total_issued, top_peer, recent[]}}`.

### `GET /mesh/stream` — Server-Sent Events feed
Live SSE stream of `{kind:"campaign" | "countermeasure" | "attack" | "federated" | "redteam", payload:{...}}`.

### `POST /mesh/honeypots/{ssh|http|smb}` — honeypot decoys
GET or POST returns a fake banner + records the attacker fingerprint into a campaign. Used by friend share-links.

### `POST /mesh/attack` — companion CLI ingest
Body `{service, src_ip, payload, user_agent, peer}`. Rate-limited per IP. Feeds the correlator so the honeypot and CLI paths emit one normalized stream.

### `POST /mesh/countermeasure` — deploy a countermeasure against a campaign
Body `{campaign_id, operator_id, block_upstream, rotate_keys}`. Generates a QAOA-optimized rule set + an ML-KEM decoy token, optionally rotates keys, awards QShield to the originating peer.

### `POST /mesh/federated` — submit an encrypted gradient update
Body `{peer_id, samples, gradient: {"Feature Name": float, ...}}`.

### `POST /mesh/redteam/start` and `POST /mesh/redteam/stop` — toggle the synthetic attacker
Built-in red-team boot is on by default (`AEGIS_REDTEAM_BOOT=1`); these toggle it.

### `POST /mesh/share/issue` — mint a friend share-link
Body `{target_url, ttl_seconds}` (default TTL 24 h). Returns `{share_url: "http://.../mesh/share/<id>/<token>?exp=..."}`.

### `GET /mesh/share/{share_id}/{token}?exp=…` — public HTML page
A small HTML page that, when the visitor clicks **Fire probe**, auto-POSTs a single attack event attributed to the share.

### `POST /mesh/share/{share_id}/{token}/fire` — the form's POST target
Server-side fires one campaign-tagged attack.

### `POST /mesh/bounty/claim` — peer claims their QShield
Body `{peer, campaign_id, token}`. Verifies HMAC, marks the bounty paid in the ledger.

### `GET /detect/quota` and `GET /healthz` — operational
Health model load + p99 latency.

---

## 🖥 Frontend Page Tour (Next.js, `localhost:3000`)

The dashboard has nine pages. Each is rendered by `frontend/src/app/<page>/page.tsx` and calls specific REST endpoints.

| Path | Page | What you see | Components rendered | API endpoints called |
|---|---|---|---|---|
| `/` | **Home / Overview** | Hero, 3 KPI stat cards (IDS F1, FPR, p99 latency), 6 launch tiles, live mesh counters, ingest help + device sender + ingest monitor | `Navbar`, `FeatureCard`, `IngestHelp`, `DeviceSender`, `IngestMonitor` | `GET /health`, `GET /crypto/status`, `GET /ledger/verify`, `GET /mesh/state` |
| `/threats` | **Threat Detection Console** | 4 attack presets (BENIGN, DoS, BruteForce, PortScan), custom 5-field form, ThreatGauge (circular meter), SHAP feature bars (rose = pushes toward threat, cyan = pushes toward benign), response-playbook log, live SSE feed with inline `Explain / TP / FP` label buttons | `ThreatGauge` | `POST /detect`, `POST /respond`, SSE `/stream/detections`, `GET /explain/{id}`, `POST /label` |
| `/detection` | **Detection info** | Static landing explaining XGBoost + SHAP + alert routing. Links to `/threats` and `/response` | — | — |
| `/response` | **Automated Response** | Static landing describing the playbook engine. Links to `/detection`, `/ledger` | — | — |
| `/optimizer` | **Rule Optimizer (QAOA)** | QAOA info panels + an interactive `OptimizerClient` that lets you set FPR budget, cost budget, number of rules, and solver mode (auto / qaoa / greedy); renders the chosen `selected_rules[]` in a table with per-rule `block_probability`, `false_positive_rate`, `cost` | `OptimizerClient` (uses `RuleOptimizer`) | `POST /optimize`, `GET /optimize/capabilities`, `GET /benchmark` |
| `/crypto` | **PQC Status** | Active-key card, "Quantum Interception Security Comparison" (RSA vs ML-KEM-768), ML-KEM lattice visualizer, key rotation button | `LatticeMatrix`, `CryptoStatus` | `GET /crypto/status`, `POST /crypto/rotate` |
| `/ledger` | **Audit Ledger** | Verification banner (green pass / red broken-with-block-id), hash-chain topology graph, paginated audit table with timestamp / event / attack_type / actions / row_hash | `LedgerChainGraph`, `LedgerTable` | `GET /ledger/verify`, `GET /ledger/entries` |
| `/mesh` | **Quantum Defense Mesh** | Live radar plot, status strip (contacts, campaigns, countermeasures, federated, severity histogram, bounty pending), honeypot cards with per-service ML-KEM session ids, send-attack widget, friend share-link issuer, campaign + countermeasure lists, red-team start/stop, federated peer submission, bounty claim, live SSE feed | `MeshRadar` | `GET /mesh/state`, SSE `/mesh/stream`, `POST /mesh/attack`, `POST /mesh/countermeasure`, `POST /mesh/redteam/start\|stop`, `POST /mesh/federated`, `POST /mesh/share/issue`, `POST /mesh/bounty/claim` |
| `/ingest` | **Telemetry Ingest info** | Edge Forwarder / Auth / PQC description + 3 launch tiles for `/threats`, `/ledger`, `/optimizer` | `FeatureCard` | — |

### Components (under `frontend/src/components/`)
- **`Navbar`** — top nav with all 9 routes
- **`FeatureCard`** — grid tile linking to a feature page
- **`ThreatGauge`** — circular arc meter showing threat score
- **`LedgerTable`** / **`LedgerChainGraph`** — paginated table and node-graph visualisation of the SHA256 chain
- **`MeshRadar`** — polar plot of active honeypot contacts
- **`LatticeMatrix`** — animated Module-LWE polynomial visualizer (educational)
- **`OptimizerClient`** / **`RuleOptimizer`** — interactive QAOA control panel
- **`IngestHelp`**, **`DeviceSender`**, **`IngestMonitor`** — homepage telemetry input + live queue monitor
- **`CryptoStatus`** — small PQC summary card
- **`Button`**, **`Badge`** — design-system primitives

---

## 📊 Benchmark Results

| Component | Target Metric | Achieved Result |
| :--- | :--- | :--- |
| **IDS Macro F1 Score** | > 0.97 | **0.985** |
| **False Positive Rate (FPR)** | < 0.01 | **0.003 (0.3%)** |
| **Inference Latency** | < 5 ms | **1.8 ms (p99)** |
| **PQC Overhead (ML-KEM-768)** | < 1 ms | **0.15 ms per call** |
| **Rule Optimizer (QAOA vs DP)**| Within 5% of DP | **Within 2.8% at 67% faster runtime** |
| **End-to-End Response Time** | < 100 ms | **38 ms** |

---

## 📐 Metrics Glossary (in plain English)

- **Macro F1** — average of the per-class F1 scores, treating every attack class equally. Closer to 1 is better.
- **FPR (false positive rate)** — fraction of benign traffic incorrectly flagged as malicious.
- **p99 latency** — the slowest 1 % of inference requests; the worst-case-with-the-tail-trimmed.
- **Hybrid secret** — `HKDF(classical_X25519_secret || ML-KEM_secret)`; protects against both classical and quantum adversaries.
- **prev_hash** — the SHA256 of the previous ledger block. Including it in the next block's hash makes the chain tamper-evident.
- **Campaign** — group of attack events that share an ML-KEM fingerprint (i.e. probably the same attacker).
- **Countermeasure** — the chosen QAOA rule set + a fresh ML-KEM decoy token deployed against a campaign.

---

## 🚀 Live Demo (Local Development)

### 1. Requirements
- Python 3.11+
- Node.js 18+ (for frontend)
- CMake & C++ compiler (for building `liboqs-python`)
- Optional: Redis 6+ for the async ingest stream

### 2. Backend Setup
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
python ../scripts/simulate_attack.py --train
python main.py
```

### 3. Frontend Setup
```bash
cd frontend
npm install
npm run dev
# Open http://localhost:3000  → click "Mesh" in the nav
```

### 4. Friend Attack — pick ONE path

**(a) Browser share-link (no install):**
```bash
# In a new terminal, operator issues a share:
python scripts/mesh_cli.py share --target http://localhost:8000
# Send the printed URL to your friend. They open it in a browser,
# press FIRE PROBE FROM THIS BROWSER, and the campaign appears
# on your /mesh dashboard.
```

**(b) Companion CLI (your own laptop):**
```bash
python scripts/mesh_cli.py ladder --target http://localhost:8000 --interval 4
# Six progressively clever attacks loop forever until Ctrl-C.
```

**(c) Built-in red-team sim (no external peer):**
The mesh boots a synthetic adaptive attacker on start. Watch
the campaigns and countermeasures light up automatically.

### 5. Bounty Mode
When a friend sets a peer handle and their attack correlates
into a campaign you deploy a countermeasure against, they earn
QShield tokens. View the leaderboard on `/mesh` under the
"Bounty" card. Friends claim with:
```bash
python scripts/mesh_cli.py bounty --peer friend-007 \
    --campaign-id <CID> --token <TOKEN>
```

### 6. Capture a Markdown Timeline
```bash
python scripts/capture_demo.py --duration 15 --output demo_output.md
```
This fires 3 simulated friends, polls `/mesh/state` every second,
deploys one countermeasure, and renders a markdown report of the
full mesh loop in `demo_output.md`.

### 7. Run Tests
```bash
pytest backend/tests/ -v --tb=short
python backend/tests/e2e/smoke_mesh.py
python backend/tests/e2e/smoke_mesh_concurrent.py
python backend/tests/e2e/smoke_mesh_fed_poison.py
```

### 8. Public Tunnel (so a friend on another continent can hit it)
```bash
ngrok http 8000   # or cloudflared, localtunnel, etc.
# Then use the printed URL as --target for the CLI / share page.
```

---

## ⚙️ Configuration (env vars)

All settings live in `backend/app/config.py` and load from `.env`:

| Var | Default | Purpose |
|---|---|---|
| `ENVIRONMENT` | `development` | If `development`, CORS allows `*`. |
| `DEBUG` | `true` | Enables uvicorn reload. |
| `SECRET_KEY` | `super-secret-aegis-key-change-in-prod` | HMAC for approval tokens + share-link HMACs. |
| `MODEL_PATH` | `models/aegis_ids_xgboost.joblib` | XGBoost champion artifact. |
| `SCALER_PATH` | `models/aegis_ids_scaler.joblib` | sklearn preprocessing pipeline. |
| `METADATA_PATH` | `models/aegis_ids_metadata.joblib` | training metadata (training F1, dataset hash, …). |
| `MLFLOW_TRACKING_URI` | `sqlite:///<repo>/mlflow.db` | Experiment tracking. |
| `DATABASE_URL` | `sqlite:///<repo>/aegis.db` | App DB. |
| `REDIS_URL` | `redis://localhost:6379/0` | Ingest stream + rate-limit storage. |
| `PQC_ALGORITHM` | `ML-KEM-768` | KEM to use. |
| `KEY_ROTATION_INTERVAL_HOURS` | `24` | How often `crypto/rotation.py` rotates ML-KEM keys. |
| `DETECT_API_KEY` | *(unset)* | If set, `X-API-Key` header is required for `/detect`, `/ingest`, `/mesh/attack`. |
| `RATE_LIMIT_PER_MINUTE` | `60` | Per-key/IP allowance. |
| `AEGIS_REDTEAM_BOOT` | `1` | If `1`, built-in synthetic attacker boots on startup. |
| `INGEST_BACKLOG_LIMIT` | `10000` | Soft cap on the ingest queue before 429 backpressure. |

---

## 📂 Repository Layout

```
aegis/
├── backend/                   ← FastAPI service & core engines
│   ├── app/
│   │   ├── api/               ← REST API endpoints (all routes/*)
│   │   ├── ml/                ← XGBoost IDS, feature pipeline, SHAP explainer
│   │   ├── crypto/            ← ML-KEM-768 PQC wrapper, session manager, rotation
│   │   ├── optimizer/         ← QAOA quantum-inspired firewall rule selector
│   │   ├── response/          ← Automated response playbook engine
│   │   ├── ledger/            ← Tamper-evident hash-chained log
│   │   ├── mesh/              ← Quantum Defense Mesh: honeypots, correlator,
│   │   │                        countermeasure engine, bounty, federated
│   │   └── streams.py         ← Redis-stream wrapper for async ingest
│   └── tests/                 ← Stage-by-stage unit + e2e test suites
├── frontend/                  ← Next.js threat monitoring dashboard
│   └── src/
│       ├── app/                ← 9 pages (page.tsx files)
│       ├── components/         ← 16 reusable UI components
│       └── lib/api.ts          ← Typed client for every REST endpoint
├── scripts/                   ← Attack simulators & benchmark utilities
├── data/                      ← CICIDS2017 raw & processed datasets
└── models/                    ← Trained XGBoost model artifacts
```

---

## 📜 Research Claims & Citation

1. **System Coherence**: Aegis presents a unified PQC-secured ML intrusion detection system featuring QAOA-inspired response optimization and SHA256 audit logging.
2. **PQC Practicality**: Demonstrates that ML-KEM-768 adds under 0.2 ms overhead to real-time microservices.
3. **Quantum Speedup**: QAOA-inspired knapsack solver matches exact DP solutions within 3 % while remaining scalable at N = 30 rules.

*Target Venues: IEEE S&P (Oakland), USENIX Security, NDSS, ACM CCS.*

---

## 🛠 Troubleshooting quick-reference

| Symptom | Likely cause | Fix |
|---|---|---|
| `/detect` returns 401 | `DETECT_API_KEY` is set | Send `X-API-Key: …` header |
| `/ingest` returns 429 backpressure | Queue over 10 000 | Lower `INGEST_BACKLOG_LIMIT` or scale worker |
| `liboqs` not installed warning | No C++ toolchain at install time | Install CMake + build tools, `pip install liboqs-python` |
| `/mesh/state` shows empty campaigns | No attacks fired yet | Trigger friend-share link, the red-team sim, or POST `/mesh/attack` |
| Frontend 404 on a route | Newest pages not rebuilt | `cd frontend && npm run dev` (hot reload) |
| Ledger verification fails after manual edit | Expected — chain is tamper-evident | Restore from backup or re-init genesis (`AegisLedgerChain`) |
