# Aegis — A Plain-English Guide

> **Read this if you've never seen the project before.**
> The [README.md](README.md) is for engineers; this guide is for everyone.

---

## 1. What is Aegis, in one paragraph?

Aegis is a **security system you run on a server** that watches the
network traffic coming at it, decides whether each piece of traffic
is **normal or an attack**, and — if it's an attack — automatically
**fights back** with a tailored response. It's built around three
ideas from 2024-era research:

1. **A smart AI classifier** (XGBoost) trained on a famous network-attack
   dataset (CICIDS2017) that can tell attacks from normal traffic
   in under 2 milliseconds.
2. **Post-quantum encryption** (ML-KEM-768) so that even a future
   quantum computer can't read the keys Aegis uses to sign its own
   internal messages.
3. **A quantum-inspired optimizer** (QAOA) that picks the best
   firewall rule to deploy against an attacker — like solving a
   tiny "knapsack" puzzle.

The twist on top of all that is the **Quantum Defense Mesh**: instead
of Aegis just *reacting* to attacks on your own network, it also
runs **fake-looking decoy services** (a fake SSH port, a fake admin
page, a fake file share). Real attackers eventually find these
decoys and try to break in. Aegis fingerprints them, groups repeat
visits into "campaigns", and issues **countermeasures** — synthetic
firewall rules, decoy tokens, and key rotations — against the
campaign as a whole.

A friend with a laptop anywhere in the world can attack the mesh
through a public share-link, and the dashboard updates in real time.
If they attach a peer handle and a countermeasure fires against
their attack, they earn **bounty tokens**. It is, intentionally, a
little bit of a game.

---

## 2. What can you do with the website?

The frontend is a Next.js dashboard at `http://localhost:3000` once
the app is running. The top navigation has 7 pages. Each page is a
window onto one part of Aegis. Here is every page, what you see
on it, what you put in, what comes out, and why it matters.

### 2.1 Overview (`/`)

The homepage. Big hero headline ("Quantum-Safe AI Threat Detection
Grid"), six feature cards you can click into, and a strip of
live statistics.

- **Inputs:** nothing — it polls the backend every 5 seconds.
- **Outputs you see:**
  - **IDS Macro F1**: a 0-1 score for how accurate the AI classifier
    is (0.985 = excellent).
  - **False Positive Rate**: how often normal traffic gets flagged
    as an attack (0.3% = very low).
  - **P99 Latency**: how long the worst 1% of detections take
    (1.8 ms = fast).
  - **Mesh Contacts / Active Campaigns / Countermeasures Deployed**:
    live counts from the Quantum Defense Mesh.
- **Why it matters:** a one-glance health check. If any of these
  numbers is "bad" (F1 drops, FPR spikes, latency explodes), the
  whole system needs attention.

### 2.2 Threat Console (`/threats`)

The "demo everything" page. You can hand-craft a network-flow
vector, hit "Detect", and watch Aegis score it. There are also
presets (Port Scan, DoS, Brute Force, BENIGN) so you don't have to
type values. Underneath, a **Live SSE feed** shows every detection
the system has made in the last minute; each row has buttons
"Explain / TP / FP" so you can inspect why a decision was made
and feed corrections back to the model.

- **Inputs (custom mode):** five numeric fields representing one
  network flow: duration, packet count, bytes/sec, SYN flag count,
  ACK flag count.
- **Inputs (preset mode):** click a card — the page fills in
  reasonable values for that attack type.
- **Inputs (label mode):** click "TP" or "FP" on a live feed row
  to mark it as a true positive or false positive.
- **Outputs:**
  - **Threat Score** (0-1), **Attack Type** (e.g. `DoS`,
    `BruteForce`), **Confidence** (High / Medium / Low).
  - **Top Features** ranked by SHAP value — these are the exact
    signals that pushed the AI's decision one way or the other
    (e.g. "Flow Bytes/s = 0.92 pushed towards ATTACK").
  - When a threat is detected, a **response action** is also
    automatically triggered (firewall rule, block upstream, log).
- **Why it matters:** lets you poke the AI, see *why* it made a
  decision, and correct it. The corrections feed the retrain
  worker (see `retrain_job.py`) so the model improves over time.

### 2.3 Ingest (`/ingest`)

The "data entry" page. Three side-by-side panels:

1. **Send one event manually** — fill in a JSON body representing
   one network flow and POST it to `/ingest`. Tells you the
   detection-id that came back.
2. **Send from a device** — gives you a `curl` command you can
   copy/paste on another machine (e.g. a friend's laptop) so they
   can send traffic at your Aegis from outside.
3. **Live ingest monitor** — a real-time list of every event that
   hit `/ingest` in the last minute, including the source IP and
   whether it got accepted or backpressured.

- **Inputs:** one JSON body per call. The minimum is something like
  `{"Flow Duration": 95000, "Total Fwd Packets": 3000, ...}` — any
  subset of the 70+ CICIDS2017 feature columns.
- **Outputs:** a 202 response with `entry_id`, plus the detection
  on the live monitor once the online detector processes it.
- **Why it matters:** shows the *transport* layer. The mesh is a
  special case of this — same `/ingest` engine, different
  fingerprinting.

### 2.4 Detection & Explainability (`/detection`)

A more detail-oriented cousin of the Threat Console. Lets you
paste in a single detection-id and pull up its full SHAP breakdown:
which features mattered, by how much, in which direction.

- **Inputs:** a detection-id (UUID) — usually copied from the
  Threat Console's live feed.
- **Outputs:** the same top-features waterfall you'd see inline,
  but as a standalone, focused view.
- **Why it matters:** when an analyst needs to defend a decision
  to a manager or a regulator, "the model said so" isn't enough.
  This page is the receipt.

### 2.5 Audit Ledger (`/ledger`)

A chronological, append-only list of every significant event Aegis
has emitted. Each row is one block in a SHA256 hash chain — if
anyone tampers with one entry, the entire chain breaks at that
point and `verify` reports the bad entry by id.

- **Inputs:** a refresh button (it auto-polls every few seconds).
  Optional filters by `event_type` (DETECTION, COUNTERMEASURE,
  KEY_ROTATION, BOUNTY_AWARDED, MODEL_SWAP, …).
- **Outputs:**
  - A paginated table (newest first) with one row per event:
    id, timestamp, event type, threat id, source IP, actions taken.
  - A **chain length** counter (Genesis + every event ever).
  - A **verify** button that re-walks the entire chain and reports
    `valid: true/false` plus the exact entry that broke if invalid.
- **Why it matters:** regulators (NIS2, SOC2) and auditors want to
  know "who did what when". A hash chain gives you that, plus a
  proof that nobody edited history.

### 2.6 Rule Optimizer (`/optimizer`)

Lets you re-run the QAOA-inspired firewall rule solver with custom
budgets and see what it picks.

- **Inputs:** three sliders —
  - **False Positive Rate budget** (0-1, e.g. 0.1 = 10%).
  - **Cost budget** (relative cost of deploying rules).
  - **Number of candidate rules** to consider.
  - **Solver toggle**: auto / qaoa / greedy. Auto picks the best
    available; `qaoa` runs the QAOA-inspired simulation;
    `greedy` falls back to a deterministic knapsack.
- **Outputs:** a list of `selected_rules` with their
  `block_probability`, `false_positive_rate`, and `cost`. Totals
  for the whole selection. The solver used and how long it took.
- **Why it matters:** operators want to know "if I deploy *these*
  rules, am I safe, and how many false alarms will I get?" This
  page answers that before you deploy anything.

### 2.7 Automated Response (`/response`)

A "stage then execute" workflow so you don't accidentally deploy a
harsh countermeasure on the wrong target.

- **Inputs:** a detection (or paste an existing detection-id). Click
  **Dry-run** to see what *would* happen (which rules, which key
  rotation, which upstream block signal). Click **Approve & Execute**
  to actually do it.
- **Outputs:**
  - The **dryrun envelope** lists planned actions, an
    `approval_token` (HMAC), and a 5-minute TTL.
  - The execute endpoint requires the matching token — without it,
    the countermeasure won't fire.
  - On success, a `RESPONSE_APPROVED` block is appended to the
    audit ledger.
- **Why it matters:** a single mistaken click could block a real
  customer. The dry-run / approval-token split makes that mistake
  impossible without explicitly signing for it.

### 2.8 Post-Quantum Crypto (`/crypto`)

A status panel for the ML-KEM-768 keypairs Aegis uses internally.
Shows the public key fingerprint, total rotations, time of last
rotation and why, number of active sessions.

- **Inputs:** a **Rotate now** button that forces an immediate key
  rotation (the new key is bound to a new fingerprint; all decoy
  tokens issued under the old key become invalid).
- **Outputs:** a panel with the standard NIST FIPS 203 metadata
  (algorithm, security level, implementation).
- **Why it matters:** "harvest now, decrypt later" is the
  quantum-era threat. If an adversary records today's encrypted
  traffic, they can decrypt it later with a quantum computer.
  Aegis rotates keys every 24 hours by default so the window of
  exposure is small. This page is the operator's knob on that.

### 2.9 Quantum Defense Mesh (`/mesh`) — the new big one

The most interactive page in the dashboard. It is split into
several panels:

1. **Live radar** — radar canvas with a blip for each unique
   attacker IP × campaign. Watch blips appear as friends connect.
2. **Status strip** — five stat cards: mesh contacts, active
   campaigns (with a 4-bar severity histogram), countermeasures
   deployed, federated peers, ML-KEM fingerprint.
3. **Honeypot decoys** — three clickable links (SSH:22, HTTP:80,
   SMB:445). Open in a new tab to see what an attacker would
   see when they banner-grab the decoy. Underneath, the live
   `by_service_session` shows each honeypot's current ML-KEM id.
4. **Send attack** — pick a service, a payload preset, a source IP,
   an optional peer handle, and click. The attack immediately
   appears in the correlator.
5. **Issue friend share-link** — generates a URL you can copy and
   text to a friend. They open it, press one button, and their
   browser fires an attack that shows up in your dashboard.
6. **Active campaigns** — every group of correlated attacks,
   with a "Deploy countermeasure" button per row.
7. **Countermeasures** — the last 10 deployed, showing the solver
   used (QAOA / greedy), the decoy token, and the rule name.
8. **Red-team sim** — start/stop the built-in synthetic attacker
   (it cycles through six attack patterns every 8 seconds and
   adapts when you fire back). Shows how many of its attacks
   were forced to mutate because of a countermeasure.
9. **Federated peers** — submit a gradient update from "another
   model" and watch it aggregate. No raw peer data ever leaves
   the peer.
10. **Bounty Mode** — top peer by earned QShield, pending vs paid
    counters, recent awards with per-row claim buttons.
11. **Live SSE feed** — last 60 mesh events with per-kind icons
    (shield / sparkles / activity / users / zap) and color-coded
    borders so you can scan visually.

- **Inputs:** everything is point-and-click; the only text inputs
  are `src_ip`, `peer_handle`, and (for federated) the gradient
  numbers in the component.
- **Outputs:** as above. The dashboard updates within ~1 second of
  any state change because it subscribes via SSE.
- **Why it matters:** this is the showcase. The whole point of the
  Quantum Defense Mesh is that it **looks alive, behaves live,
  and defends live**. This page is where you see that.

---

## 3. How do all these pieces fit together?

A real attack chain looks like this:

```
   attacker's laptop
        │
        │  POST /mesh/attack  (or click the share-link button)
        ▼
   ┌─────────────────────────────────────┐
   │  Aegis backend  (FastAPI, port 8000)│
   │                                     │
   │  ┌──────────────┐   fingerprint     │
   │  │ HoneypotMesh │ ──────────────────┐
   │  └──────────────┘                  │
   │          │                          ▼
   │          ▼               ┌────────────────────┐
   │  ┌──────────────────┐    │ AttackCorrelator   │
   │  │ ingest → Redis   │ →  │  groups events into │
   │  │ stream "ingest"  │    │  CAMPAIGNS by (svc, │
   │  └──────────────────┘    │  src_ip+UA, time)  │
   │          │               └────────────────────┘
   │          ▼                          │
   │  ┌──────────────────┐               │ severity >
   │  │ Online detector  │               │ threshold
   │  │ (XGBoost+SHAP)   │               ▼
   │  └──────────────────┘      ┌──────────────────┐
   │          │                  │ Countermeasure    │
   │          ▼                  │ Engine:           │
   │     /detection              │  • QAOA pick rule │
   │     /explain                │  • rotate ML-KEM  │
   │     /labels (TP/FP)         │  • mint decoy tok │
   │                             │  • ledger append  │
   │                             └──────────────────┘
   │                                     │
   │                                     ▼
   │                          ┌──────────────────┐
   │                          │ Ledger (hash     │
   │                          │ chain, tamper-   │
   │                          │ evident)         │
   │                          └──────────────────┘
   │                                     │
   └─────────────────────────────────────┘
                                         │
              SSE: campaign/             │
              countermeasure/attack/     │
              federated/bounty           │
                                         ▼
                                ┌────────────────────┐
                                │ Frontend dashboard │
                                │  /mesh, /threats,  │
                                │  /ledger, ...      │
                                └────────────────────┘
```

So in one sentence: **attack comes in → AI scores it → events are
grouped into campaigns → a countermeasure fires → a tamper-evident
audit row is appended → the dashboard updates in real time**.

---

## 4. Where do the inputs come from?

Three places:

1. **Real friends' laptops.** You give them a URL (the share-link
   in `/mesh`, or an `ngrok http 8000` tunnel). Their browser fires
   one attack per click; their IP and User-Agent become their
   fingerprint.
2. **The built-in red-team simulator.** Boots on backend start
   (toggleable via `AEGIS_REDTEAM_BOOT=0`). Fires one attack every
   8 seconds through six progressively clever patterns. It *adapts*
   when you deploy countermeasures — the next attack from it will
   have a different User-Agent and a nonce appended.
3. **The companion CLI.** `python scripts/mesh_cli.py ladder` runs
   the same six patterns in a loop. Useful when you want to test
   from your own machine.

All three paths land in the **same** ingest pipeline. The correlator
groups them the same way. The countermeasure engine fires the same
way. There is no "real vs fake" distinction — the mesh treats every
incoming attack identically, which is the whole point.

---

## 5. What are the outputs?

Four kinds:

1. **Decisions.** For every attack: threat score, attack type,
   confidence. These flow out through `/stream/detections` (SSE)
   and appear on `/threats`.
2. **Countermeasures.** Tailored firewall rules (selected by the
   QAOA solver), fresh ML-KEM keys, and HMAC-bound decoy tokens.
   These flow out through `/mesh/stream` (SSE) and appear on `/mesh`.
3. **Bounty tokens.** When a countermeasure fires against a
   campaign attributed to a peer handle, a QShield token is minted.
   Friends claim via `/mesh/bounty/claim`.
4. **Audit rows.** Every one of the above — and key rotations,
   model swaps, federated updates — appends to the hash-chained
   ledger at `/ledger`. Operators and regulators can verify the
   chain at any time.

---

## 6. Glossary for newcomers

- **XGBoost** — a popular gradient-boosted decision-tree library
  for tabular data. Think of it as "very good at scoring whether
  a row of numbers looks like attack or normal."
- **SHAP** — a way to explain, per prediction, which input columns
  mattered and by how much. "Flow Bytes/s = 95M pushed this toward
  DoS by +0.6."
- **ML-KEM-768** — the NIST-standard post-quantum key encapsulation
  mechanism (FIPS 203, formerly known as Kyber). Two parties can
  agree on a shared secret over an insecure channel, and the
  resulting secret is safe even against future quantum computers.
- **QAOA** — Quantum Approximate Optimization Algorithm. A
  near-term quantum algorithm for combinatorial optimization. In
  Aegis we use a *classical simulation* of QAOA for picking firewall
  rules, because real quantum hardware isn't practical at this
  scale yet. The point is the algorithmic shape, not the hardware.
- **Knapsack problem** — "given items with weights and values, pick
  a subset that maximizes value while staying under a weight limit."
  Firewall rule selection maps to this: each rule has a "block
  probability" (value) and a "false-positive rate" (cost).
- **Hash chain** — a sequence of records where each record's hash
  depends on the previous record's hash. If you change any record,
  every subsequent hash becomes wrong — instant tamper detection.
- **FPR / F1** — standard ML evaluation metrics. F1 is the
  harmonic mean of precision and recall. FPR (false-positive rate)
  is "of all normal things, what fraction got wrongly flagged."
- **SSE** — Server-Sent Events. A simple HTTP streaming protocol
  for pushing live updates to a browser. EventSource on the
  client, `StreamingResponse` on the server.
- **JA4 / JA4-ish** — modern TLS client fingerprints. We don't
  parse real TLS, but we hash the order of HTTP header keys to
  approximate a JA4 hint for grouping attackers across contacts.
- **Honeypot** — a service that looks legitimate but is actually
  bait. Aegis runs fake SSH / HTTP / SMB services on `/mesh/honeypots/{svc}`
  so attackers reveal themselves by trying to break in.
- **Federated learning** — train a shared model without anyone
  sending raw data. Each peer submits only a *gradient delta*
  (the direction their local model wants to move). Aegis aggregates
  these. No raw peer data ever leaves a peer.

---

## 7. How do I try it?

1. **Read the [README.md](README.md)** for setup commands.
2. **Run `python main.py`** in `backend/`, **`npm run dev`** in
   `frontend/`, open `http://localhost:3000`.
3. **Click Mesh** in the navigation. You'll see the live radar and
   empty campaigns.
4. **Issue a friend share-link** from the Honeypot Decoys panel.
   Text it to yourself (open the link on your phone), press the
   button. Watch a blip appear on the radar and a campaign spawn
   in the SSE feed within ~1 second.
5. **Hit "Deploy countermeasure"** on that campaign. Watch the
   countermeasure appear below, the bounty mint, and the audit
   ledger grow by 2 rows.
6. **Run the capture script** to generate a markdown timeline of
   everything that just happened:
   ```
   python scripts/capture_demo.py --duration 15 --output demo_output.md
   ```
7. **Open the notebook** `notebooks/05_mesh_attack_walkthrough.ipynb`
   for a step-by-step walk-through with explanations.

That's the whole project. Welcome to the mesh.