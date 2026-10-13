"""Federated poisoning smoke.

Submits 10 clean gradients + 1 fully-NaN gradient + 1 gradient with
an inf value, and asserts:
  * Clean entries accumulate into the global delta.
  * The NaN-only gradient is REJECTED entirely (poison guard).
  * The gradient with inf has its bad entries stripped and the
    remaining keys still contribute.
  * Stats surface the rejected counts so operators can see poison
    attempts in the dashboard.

Run with:
    python backend/tests/e2e/smoke_mesh_fed_poison.py
"""

from __future__ import annotations

import math
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("REDIS_URL", "")
os.environ.setdefault("AEGIS_REDTEAM_BOOT", "0")


def step(msg: str) -> None:
    safe = msg.replace("✓", "[OK]").replace("✗", "[FAIL]")
    print(f"[poison] {safe}", flush=True)


def main() -> int:
    from fastapi.testclient import TestClient
    from main import app
    from app.mesh.federated import federated_aggregator

    # Reset
    federated_aggregator._updates.clear()
    federated_aggregator._global.clear()
    federated_aggregator._sample_total = 0
    federated_aggregator._known_peers.clear()
    federated_aggregator._rejected_nan = 0
    federated_aggregator._rejected_nonfinite = 0

    with TestClient(app) as client:
        step("POST 10 clean gradients")
        for i in range(10):
            r = client.post(
                "/mesh/federated",
                json={
                    "peer_id": f"peer-{i}",
                    "samples": 50,
                    "gradient": {
                        "Flow Bytes/s": 0.01 * (i + 1),
                        "SYN Flag Count": 0.02 * (i + 1),
                    },
                },
            )
            assert r.status_code == 202, r.text
        step(f"  [OK] 10 accepted")

        step("POST a fully-NaN gradient (poison attempt)")
        # Send raw JSON because httpx refuses to encode NaN. The
        # route's _sanitize_gradient must reject these as bad values.
        raw_nan = b'{"peer_id":"attacker-1","samples":9999,"gradient":{"Flow Bytes/s":"NaN","SYN Flag Count":"NaN"}}'
        r = client.post(
            "/mesh/federated",
            content=raw_nan,
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 202, r.text
        body = r.json()
        assert body["status"] == "rejected", body
        step(f"  [OK] rejected: {body['reason']}")

        step("POST a gradient with mixed valid + inf values")
        raw_inf = b'{"peer_id":"attacker-2","samples":1,"gradient":{"Flow Bytes/s":0.5,"Bogus Feature":"Infinity"}}'
        r = client.post(
            "/mesh/federated",
            content=raw_inf,
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 202, r.text
        body = r.json()
        assert body["status"] == "accepted", body
        # The inf entry was stripped; only "Flow Bytes/s" should
        # have been credited.
        step(f"  [OK] accepted with stripped inf entries")

        r = client.get("/mesh/state")
        state = r.json()
        fed = state["federated"]
        step(f"  state.federated = known_peers={fed['known_peers']} "
             f"rejected_nan={fed.get('rejected_nan')} "
             f"rejected_inf={fed.get('rejected_inf')}")

        # 10 clean peers + 1 attacker-2 (which had at least one valid
        # entry) = 11 known peers. attacker-1 was fully rejected and
        # should NOT be in the known peers set.
        if fed["known_peers"] != 11:
            step(f"  [FAIL] expected 11 known_peers, got {fed['known_peers']}")
            return 1
        step(f"  [OK] 11 known peers (poison peer excluded)")

        if fed.get("rejected_nan", 0) < 2:
            step(f"  [FAIL] expected >=2 rejected_nan, got {fed.get('rejected_nan')}")
            return 1
        step(f"  [OK] {fed['rejected_nan']} NaN entries stripped")

        if fed.get("rejected_inf", 0) < 1:
            step(f"  [FAIL] expected >=1 rejected_inf, got {fed.get('rejected_inf')}")
            return 1
        step(f"  [OK] {fed['rejected_inf']} inf entries stripped")

        # Global delta should reflect the 10 clean contributions +
        # the 0.5 from attacker-2's valid entry.
        snap = fed.get("global_delta_keys") or []
        if "Flow Bytes/s" not in snap:
            step(f"  [FAIL] Flow Bytes/s missing from global_delta_keys={snap}")
            return 1
        step(f"  [OK] global_delta_keys={snap}")

        # Confirm retrain_job can read the same snapshot.
        try:
            from retrain_job import global_delta_snapshot
            snap_dict = global_delta_snapshot()
            if "Flow Bytes/s" not in snap_dict:
                step("  [FAIL] retrain_job global_delta_snapshot missing Flow Bytes/s")
                return 1
            step(f"  [OK] retrain_job sees global_delta with "
                 f"{len(snap_dict)} key(s)")
        except Exception as exc:
            step(f"  [FAIL] retrain_job global_delta_snapshot raised: {exc}")
            return 1

    step("All federated-poisoning smoke checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())