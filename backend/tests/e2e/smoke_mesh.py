"""End-to-end mesh smoke test.

Drives the full Quantum Defense Mesh loop:
  1. Friend laptop sends a port scan via /mesh/attack
  2. Friend laptop banner-grabs the SSH honeypot
  3. Same friend sends a brute-force via /mesh/attack
  4. Correlator groups events into a campaign
  5. /mesh/countermeasure generates a QAOA-derived rule + ML-KEM
     decoy token + ledger entry
  6. Federated peer sends a gradient update; aggregator records it
  7. Red-team driver can be toggled on/off
  8. /mesh/state snapshot reflects everything

Run with:
    python backend/tests/e2e/smoke_mesh.py
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("REDIS_URL", "")
os.environ.setdefault("AEGIS_REDTEAM_BOOT", "0")  # we drive the sim manually


def step(msg: str) -> None:
    safe = msg.replace("✓", "[OK]").replace("�", "[FAIL]")
    print(f"[mesh] {safe}", flush=True)


def main() -> int:
    from fastapi.testclient import TestClient
    from main import app
    from app.mesh import correlator, honeypots, countermeasure, federated, redteam

    # Reset in-memory state so the test is deterministic.
    correlator.correlator._campaigns.clear()
    honeypots.honeypot_mesh.recent.clear()
    countermeasure.countermeasure_engine.deployed.clear()
    federated.federated_aggregator._updates.clear()
    federated.federated_aggregator._global.clear()
    federated.federated_aggregator._sample_total = 0
    federated.federated_aggregator._known_peers.clear()

    with TestClient(app) as client:
        # 1. Send a port scan via /mesh/attack
        step("POST /mesh/attack (port scan)")
        r = client.post(
            "/mesh/attack",
            headers={"x-forwarded-for": "198.51.100.10"},
            json={
                "service": "http",
                "src_ip": "198.51.100.10",
                "payload": "GET / HTTP/1.1",
                "user_agent": "nmap/7.92",
            },
        )
        assert r.status_code == 202, r.text
        out = r.json()
        campaign_a = out["campaign"]["campaign_id"]
        step(f"  [OK] campaign={campaign_a[:10]} fp={out['attack_event']['fingerprint'][:8]}")

        # 2. Banner-grab the SSH honeypot
        step("GET /mesh/honeypots/ssh")
        r = client.get("/mesh/honeypots/ssh", headers={"x-forwarded-for": "198.51.100.10"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["service"] == "ssh"
        assert body["ml_kem_session_id"]
        assert body["countermeasure_token"]
        step(f"  [OK] session={body['ml_kem_session_id'][:10]} token={body['countermeasure_token'][:10]}")

        # 3. Same attacker sends a second event against the SAME
        # service + UA so the correlator fingerprints them together.
        step("POST /mesh/attack (second http event, same UA)")
        r = client.post(
            "/mesh/attack",
            headers={"x-forwarded-for": "198.51.100.10"},
            json={
                "service": "http",
                "src_ip": "198.51.100.10",
                "payload": "POST /admin HTTP/1.1\r\nHost: target\r\n",
                "user_agent": "nmap/7.92",
            },
        )
        assert r.status_code == 202
        out = r.json()
        # Same fingerprint + same JA4-ish hint → same campaign
        assert out["campaign"]["campaign_id"] == campaign_a, "expected same campaign"
        assert out["campaign"]["event_count"] >= 2
        step(f"  [OK] merged into campaign event_count={out['campaign']['event_count']}")

        # 4. Deploy countermeasure against the campaign
        step("POST /mesh/countermeasure")
        r = client.post(
            "/mesh/countermeasure",
            json={
                "campaign_id": campaign_a,
                "operator_id": "smoke_test",
                "block_upstream": True,
                "rotate_keys": False,  # keep the test deterministic
            },
        )
        assert r.status_code == 200, r.text
        cm = r.json()
        assert cm["campaign_id"] == campaign_a
        assert cm["rules_applied"], "expected at least one rule"
        assert cm["decoy_token"]
        assert cm["block_upstream"] is True
        step(
            f"  [OK] cm_id={cm['countermeasure_id'][:8]} solver={cm['solver']} "
            f"rule={cm['rules_applied'][0]['name']}"
        )

        # 5. Federated gradient update
        step("POST /mesh/federated")
        r = client.post(
            "/mesh/federated",
            json={
                "peer_id": "friend-laptop-01",
                "samples": 256,
                "gradient": {
                    "Flow Bytes/s": -0.04,
                    "SYN Flag Count": 0.12,
                    "Flow Duration": 0.07,
                },
            },
        )
        assert r.status_code == 202, r.text
        step(f"  [OK] {r.json()}")

        # 6. Toggle red-team
        step("POST /mesh/redteam/start")
        r = client.post("/mesh/redteam/start")
        assert r.status_code == 200, r.text
        step(f"  [OK] {r.json()}")

        # 7. Full state snapshot
        step("GET /mesh/state")
        r = client.get("/mesh/state")
        assert r.status_code == 200, r.text
        state = r.json()
        assert state["honeypots"]["total_contacts"] >= 2
        assert state["campaigns"], "expected at least one active campaign"
        assert state["countermeasures"], "expected at least one deployed countermeasure"
        assert state["federated"]["known_peers"] == 1
        assert state["redteam"]["running"] is True
        step(
            f"  [OK] honeypots={state['honeypots']['total_contacts']} "
            f"campaigns={len(state['campaigns'])} cm={len(state['countermeasures'])} "
            f"peers={state['federated']['known_peers']}"
        )

        step("POST /mesh/redteam/stop")
        r = client.post("/mesh/redteam/stop")
        assert r.status_code == 200

    step("All mesh e2e checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
