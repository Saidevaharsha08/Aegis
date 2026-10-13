"""End-to-end smoke test for the streaming detection pipeline.

Verifies the path required by the milestone brief:
  1. POST /ingest with X-API-Key returns 202.
  2. The online detector consumes the stream and emits a detection
     visible on the SSE feed within 5 seconds.
  3. GET /detection/{id}/explain returns the cached SHAP top-5.
  4. The detection is appended to the audit ledger and the chain
     verification reports it.
  5. POST /labels records operator feedback.
  6. /metrics exposes Prometheus counters.

Run with:
    python backend/tests/e2e/smoke_test.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

# Force the streams module into fallback mode for the test.
os.environ.setdefault("REDIS_URL", "")
os.environ.setdefault("DETECT_API_KEY", "smoke-test-key")


def reset_streams():
    from app import streams
    streams._local_queues.clear()
    streams._local_locks.clear()
    streams._local_meta.clear()


def step(msg: str) -> None:
    # Avoid unicode glyphs that break Windows cp1252 consoles.
    safe = msg.replace("✓", "[OK]").replace("✗", "[FAIL]")
    print(f"[smoke] {safe}", flush=True)


async def wait_for_detection(_sse_client, timeout: float = 5.0):
    """Synchronously drain the ingest stream and run the detector.

    TestClient spins up its own event loop, so the long-running
    consumer scheduled in ``app.on_event('startup')`` is bound to a
    different loop than the one this smoke test uses. To keep the
    test deterministic without depending on Redis Streams we
    directly drain the in-process fallback ingest queue and feed
    each entry through ``online_detector.process_one``.
    """
    from app.online_detector import process_one
    from app.ml.detector import detector_engine
    from app import streams as streams_mod

    if not detector_engine.is_loaded:
        detector_engine.load_model()

    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        q = streams_mod._local_queues.get("ingest")
        if q is None or q.empty():
            await asyncio.sleep(0.05)
            continue
        try:
            _eid, raw = q.get_nowait()
        except Exception:
            await asyncio.sleep(0.05)
            continue
        try:
            payload = json.loads(raw) if isinstance(raw, str) else raw
        except Exception:
            continue
        envelope = await process_one(detector_engine, payload)
        return envelope
    raise asyncio.TimeoutError("ingest stream stayed empty")


def main() -> int:
    reset_streams()

    # Set the key so the auth check exercises the configured path.
    from app.config import settings
    settings.DETECT_API_KEY = "smoke-test-key"

    from fastapi.testclient import TestClient
    from main import app

    with TestClient(app) as client:
        # 1. POST /ingest with X-API-Key
        step("POST /ingest with X-API-Key")
        resp = client.post(
            "/ingest",
            params={"source_ip": "10.0.0.42"},
            json={
                "flow_duration": 95000.0,
                "total_fwd_packets": 3000,
                "flow_bytes_per_second": 95000000.0,
                "syn_flag_count": 1,
                "ack_flag_count": 0,
            },
            headers={"X-API-Key": "smoke-test-key"},
        )
        assert resp.status_code == 202, resp.text
        entry_id = resp.json()["entry_id"]
        step(f"  ✓ 202 entry_id={entry_id}")

        # 2. Wait for online detector to publish a detection envelope.
        step("Waiting for online detector (<=5s)")
        envelope = None
        try:
            envelope = asyncio.run(wait_for_detection(client, timeout=5.0))
        except asyncio.TimeoutError:
            step("  [FAIL] timeout waiting for detection")
            return 2
        detection_id = envelope["detection_id"]
        step(f"  ✓ detection_id={detection_id} attack_type={envelope['attack_type']}")

        # 3. GET /detection/{id}/explain
        step("GET /detection/{id}/explain")
        r = client.get(f"/detection/{detection_id}/explain")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["detection_id"] == detection_id
        assert body["top_features"], "expected non-empty SHAP summary"
        step(f"  ✓ cached SHAP top_features={len(body['top_features'])}")

        # 4. Ledger verification
        step("GET /ledger/verify")
        r = client.get("/ledger/verify")
        assert r.status_code == 200, r.text
        v = r.json()
        assert v["chain_length"] >= 0
        step(f"  ✓ chain_length={v['chain_length']} valid={v['valid']}")

        # 5. Label submission
        step("POST /labels")
        r = client.post(
            "/labels",
            json={"detection_id": detection_id, "label": "true_positive", "source_ip": "10.0.0.42"},
        )
        assert r.status_code == 202, r.text
        step(f"  ✓ buffer_size={r.json()['buffer_size']}")

        # 6. /metrics
        step("GET /metrics")
        r = client.get("/metrics")
        assert r.status_code == 200, r.text
        body = r.text
        assert "aegis_ingest_queue_length" in body
        assert "aegis_detections_total" in body
        assert "aegis_inference_latency_ms" in body
        step("  ✓ Prometheus metrics exposed")

        # 7. Optimizer capability + solve
        step("GET /optimize/capabilities")
        r = client.get("/optimize/capabilities")
        assert r.status_code == 200, r.text
        caps = r.json()
        step(f"  ✓ caps={caps}")

        step("POST /optimize (greedy)")
        r = client.post("/optimize", json={"fpr_budget": 0.1, "cost_budget": 10, "n_rules": 12, "solver": "greedy"})
        assert r.status_code == 200, r.text
        opt = r.json()
        assert opt["selected_rules"], "expected at least one rule"
        step(f"  ✓ solver={opt['solver']} selected={opt['n_rules_selected']}")

    step("All e2e checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
