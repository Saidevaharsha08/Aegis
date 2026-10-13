"""Smoke test for milestone 1: Redis Streams wrapper + ingest endpoint.

Covers:
  1. streams.append() / streams.length() round-trip via the in-process
     fallback (no Redis required).
  2. POST /ingest returns 202 + entry_id and increments the stream.
  3. POST /ingest enforces X-API-Key when DETECT_API_KEY is configured.
  4. POST /ingest returns 429 with backpressure when the soft limit
     is exceeded.
  5. GET /ingest/quota returns the per-key quota envelope.

Run with:
    pytest backend/tests/test_ingest_streams.py -v
or:
    python backend/tests/test_ingest_streams.py
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

# Allow running this file directly without installing the package.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Force the streams module into fallback mode for the test.
os.environ.setdefault("REDIS_URL", "")

from fastapi.testclient import TestClient  # noqa: E402

from app.config import settings  # noqa: E402
from app.streams import append, length  # noqa: E402
from main import app  # noqa: E402


def _reset_streams() -> None:
    """Reset the in-process fallback queues between tests."""
    from app import streams
    streams._local_queues.clear()
    streams._local_locks.clear()
    streams._local_meta.clear()


def test_streams_append_and_length_roundtrip() -> None:
    _reset_streams()
    assert asyncio.run(length("smoke")) == 0
    eid = asyncio.run(append("smoke", {"hello": "world"}))
    assert eid, "expected non-empty entry id"
    assert asyncio.run(length("smoke")) == 1


def test_ingest_returns_202_and_increments_stream(monkeypatch=None) -> None:
    _reset_streams()
    # Ensure auth is disabled for the happy-path test.
    settings.DETECT_API_KEY = None
    with TestClient(app) as client:
        resp = client.post(
            "/ingest",
            json={
                "flow_duration": 95000.0,
                "total_fwd_packets": 3000,
                "flow_bytes_per_second": 95000000.0,
                "syn_flag_count": 1,
                "ack_flag_count": 0,
            },
            params={"source_ip": "10.0.0.5"},
        )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["status"] == "enqueued"
    assert body["stream"] == "ingest"
    assert body["entry_id"]
    assert asyncio.run(length("ingest")) >= 1


def test_ingest_rejects_bad_api_key() -> None:
    _reset_streams()
    settings.DETECT_API_KEY = "test-key-123"
    try:
        with TestClient(app) as client:
            resp = client.post(
                "/ingest",
                json={
                    "flow_duration": 100.0,
                    "total_fwd_packets": 5,
                    "flow_bytes_per_second": 12000.0,
                    "syn_flag_count": 0,
                    "ack_flag_count": 1,
                },
                headers={"X-API-Key": "wrong"},
            )
        assert resp.status_code == 401, resp.text

        # And the right key works
        with TestClient(app) as client:
            ok = client.post(
                "/ingest",
                json={
                    "flow_duration": 100.0,
                    "total_fwd_packets": 5,
                    "flow_bytes_per_second": 12000.0,
                    "syn_flag_count": 0,
                    "ack_flag_count": 1,
                },
                headers={"X-API-Key": "test-key-123"},
            )
        assert ok.status_code == 202, ok.text
    finally:
        settings.DETECT_API_KEY = None


def test_ingest_backpressure_returns_429(monkeypatch=None) -> None:
    _reset_streams()
    settings.DETECT_API_KEY = None
    # Patch INGEST_BACKLOG_LIMIT down to 2 for the duration of the test.
    import app.streams as streams
    original = streams._BACKLOG_LIMIT
    streams._BACKLOG_LIMIT = 2
    try:
        with TestClient(app) as client:
            for _ in range(2):
                r = client.post(
                    "/ingest",
                    json={
                        "flow_duration": 100.0,
                        "total_fwd_packets": 5,
                        "flow_bytes_per_second": 12000.0,
                        "syn_flag_count": 0,
                        "ack_flag_count": 1,
                    },
                )
                assert r.status_code == 202, r.text
            # Third call hits backpressure.
            blocked = client.post(
                "/ingest",
                json={
                    "flow_duration": 100.0,
                    "total_fwd_packets": 5,
                    "flow_bytes_per_second": 12000.0,
                    "syn_flag_count": 0,
                    "ack_flag_count": 1,
                },
            )
        assert blocked.status_code == 429, blocked.text
        body = blocked.json()
        assert body["status"] == "backpressure"
        assert "quota" in body
    finally:
        streams._BACKLOG_LIMIT = original


def test_ingest_quota_endpoint() -> None:
    _reset_streams()
    with TestClient(app) as client:
        resp = client.get("/ingest/quota")
    assert resp.status_code == 200
    quota = resp.json()["quota"]
    assert {"limit", "used", "remaining", "reset_seconds"} <= set(quota.keys())


if __name__ == "__main__":
    # Allow `python backend/tests/test_ingest_streams.py` for quick checks.
    test_streams_append_and_length_roundtrip()
    print("[OK] streams round-trip")

    test_ingest_returns_202_and_increments_stream()
    print("[OK] POST /ingest returns 202")

    test_ingest_rejects_bad_api_key()
    print("[OK] POST /ingest enforces X-API-Key")

    test_ingest_backpressure_returns_429()
    print("[OK] POST /ingest returns 429 on backpressure")

    test_ingest_quota_endpoint()
    print("[OK] GET  /ingest/quota returns quota envelope")

    print("\nAll milestone-1 smoke checks passed.")
