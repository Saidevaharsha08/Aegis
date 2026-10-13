"""Concurrent-friends stress smoke for the Quantum Defense Mesh.

Spawns N concurrent attack POSTs from the SAME attacker fingerprint
(same X-Forwarded-For, same User-Agent) and asserts:
  * All N return 202.
  * The correlator groups them into exactly ONE active campaign.
  * That campaign's event_count equals N.
  * No race in the correlator's lock — duplicates don't appear.

Run with:
    python backend/tests/e2e/smoke_mesh_concurrent.py --count 50
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("REDIS_URL", "")
os.environ.setdefault("AEGIS_REDTEAM_BOOT", "0")


def step(msg: str) -> None:
    safe = msg.replace("✓", "[OK]").replace("✗", "[FAIL]")
    print(f"[concurrent] {safe}", flush=True)


async def fire_one(client, idx: int, xff: str, payload: str, ua: str) -> int:
    r = client.post(
        "/mesh/attack",
        headers={"x-forwarded-for": xff, "user-agent": ua},
        json={
            "service": "http",
            "src_ip": xff,
            "payload": payload,
            "user_agent": ua,
        },
    )
    return r.status_code


async def run(count: int) -> int:
    from fastapi.testclient import TestClient
    from main import app
    from app.mesh import correlator, honeypots, countermeasure, federated

    # Fresh state.
    correlator.correlator._campaigns.clear()
    honeypots.honeypot_mesh.recent.clear()
    countermeasure.countermeasure_engine.deployed.clear()
    federated.federated_aggregator._updates.clear()
    federated.federated_aggregator._global.clear()
    federated.federated_aggregator._sample_total = 0
    federated.federated_aggregator._known_peers.clear()

    xff = "198.51.100.55"
    ua = "concurrent-tester/1.0"
    payloads = [f"GET /probe-{i} HTTP/1.1" for i in range(count)]

    # TestClient is sync + thread-safe; asyncio.gather with threadpool
    # would serialize on the GIL anyway. Use a real thread pool to
    # exercise the route's async path properly.
    import httpx
    from concurrent.futures import ThreadPoolExecutor

    # We need to call the FastAPI app over its ASGI transport so the
    # app's async handlers run inside a real event loop.
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        step(f"Firing {count} concurrent /mesh/attack POSTs (same fingerprint)")

        async def post(idx: int) -> int:
            r = await ac.post(
                "/mesh/attack",
                headers={"x-forwarded-for": xff, "user-agent": ua},
                json={
                    "service": "http",
                    "src_ip": xff,
                    "payload": payloads[idx],
                    "user_agent": ua,
                },
            )
            return r.status_code

        codes = await asyncio.gather(*[post(i) for i in range(count)])
        accepted = sum(1 for c in codes if c == 202)
        step(f"  [OK] {accepted}/{count} returned 202")

        if accepted != count:
            step(f"  [FAIL] expected all {count} accepted, got codes {set(codes)}")
            return 1

        r = await ac.get("/mesh/state")
        assert r.status_code == 200, r.text
        state = r.json()
        campaigns = state["campaigns"]
        step(f"  [OK] /mesh/state reports {len(campaigns)} active campaign(s)")
        if len(campaigns) != 1:
            step(f"  [FAIL] expected exactly 1 campaign, got {len(campaigns)}")
            for c in campaigns:
                step(f"    - {c['campaign_id'][:10]} events={c['event_count']}")
            return 1
        c = campaigns[0]
        if c["event_count"] != count:
            step(f"  [FAIL] campaign event_count={c['event_count']}, expected {count}")
            return 1
        step(f"  [OK] campaign {c['campaign_id'][:10]} merged all {count} events")
        # Spot-check additive state fields.
        hs = state.get("honeypots", {}).get("by_service_session")
        if not hs:
            step("  [FAIL] by_service_session missing from honeypot stats")
            return 1
        step(f"  [OK] by_service_session={list(hs.keys())}")
        bounty = state.get("bounty", {})
        if "pending" not in bounty:
            step("  [FAIL] bounty block missing from /mesh/state")
            return 1
        step(f"  [OK] bounty block present (pending={bounty['pending']})")
    step("All concurrent-friends smoke checks passed.")
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--count", type=int, default=50)
    args = p.parse_args()
    return asyncio.run(run(args.count))


if __name__ == "__main__":
    sys.exit(main())