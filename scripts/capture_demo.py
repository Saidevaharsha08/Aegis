#!/usr/bin/env python3
"""Aegis Mesh demo capture script.

Drives the full mesh loop in ``--duration`` seconds and emits a
markdown timeline + final state snapshot to ``--output``.

What it does:
  1. POST /mesh/share/issue -> capture a share-link the operator
     could forward to a friend.
  2. Fire 3 friends' worth of attacks (different fingerprints) so
     the correlator groups them into 3 separate campaigns.
  3. Poll /mesh/state every 1s, recording campaign severity and
     countermeasure count.
  4. Manually deploy a countermeasure against the largest campaign
     so a bounty mints.
  5. Submit 5 federated gradient updates.
  6. Render a markdown table of the timeline + final /mesh state.

Run with::

    python scripts/capture_demo.py --duration 12 --output demo_output.md
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")


def _post(client: httpx.Client, path: str, body: dict | None = None, **kw) -> dict:
    r = client.post(path, json=body or {}, **kw)
    r.raise_for_status()
    return r.json()


def _get(client: httpx.Client, path: str) -> dict:
    r = client.get(path)
    r.raise_for_status()
    return r.json()


def run(target: str, duration: int, output: Path) -> int:
    target = target.rstrip("/")
    c = httpx.Client(base_url=target, timeout=10.0)
    timeline: list[tuple[float, str, str]] = []
    t0 = time.monotonic()

    def log(event: str, detail: str = "") -> None:
        elapsed = time.monotonic() - t0
        timeline.append((elapsed, event, detail))

    log("start", f"target={target} duration={duration}s")

    # 1. Issue share
    try:
        share = _post(c, "/mesh/share/issue", {"ttl_seconds": 3600})
        log("share_issued", f"{share['share_url']}")
    except Exception as exc:
        log("share_failed", str(exc))
        share = None

    # 2. Three friends firing attacks from different fingerprints.
    friends = [
        ("203.0.113.10", "nmap/7.92", "http", "GET / HTTP/1.1\r\nHost: target\r\n"),
        ("203.0.113.20", "paramiko/2.7.2", "ssh", "admin:password\n"),
        ("203.0.113.30", "gobuster/3.1.0", "http", "GET /.env HTTP/1.1\r\nHost: target\r\n"),
    ]
    campaign_ids: set[str] = set()
    for i, (xff, ua, svc, payload) in enumerate(friends):
        try:
            r = _post(
                c,
                "/mesh/attack",
                {"service": svc, "src_ip": xff, "payload": payload, "user_agent": ua,
                 "peer": f"friend-{i+1}"},
                headers={"x-forwarded-for": xff, "user-agent": ua},
            )
            cid = (r.get("campaign") or {}).get("campaign_id")
            if cid:
                campaign_ids.add(cid)
            log("attack_ingested", f"friend-{i+1} campaign={cid[:10] if cid else '-'}")
        except Exception as exc:
            log("attack_failed", f"friend-{i+1}: {exc}")

    # 3. Poll /mesh/state once a second for `duration` seconds.
    deadline = t0 + duration
    snapshots = []
    while time.monotonic() < deadline:
        try:
            s = _get(c, "/mesh/state")
            snapshots.append((time.monotonic() - t0, s))
        except Exception as exc:
            log("state_poll_failed", str(exc))
        time.sleep(1.0)

    # 4. Deploy countermeasure against the highest-severity campaign.
    try:
        if snapshots:
            latest = snapshots[-1][1]
            if latest.get("campaigns"):
                top = max(latest["campaigns"], key=lambda c: c.get("severity", 0))
                cm = _post(c, "/mesh/countermeasure",
                           {"campaign_id": top["campaign_id"], "block_upstream": True, "rotate_keys": False})
                log("countermeasure_deployed",
                    f"campaign={top['campaign_id'][:10]} solver={cm.get('solver')}")
                if cm.get("bounty"):
                    log("bounty_awarded",
                        f"peer={cm['bounty']['peer']} amount={cm['bounty']['amount']}")
    except Exception as exc:
        log("countermeasure_failed", str(exc))

    # 5. Federated updates.
    for i in range(5):
        try:
            _post(
                c,
                "/mesh/federated",
                {"peer_id": f"fed-peer-{i}", "samples": 50,
                 "gradient": {"Flow Bytes/s": 0.01 * (i + 1),
                              "SYN Flag Count": 0.02 * (i + 1)}},
            )
            log("federated_accepted", f"fed-peer-{i}")
        except Exception as exc:
            log("federated_failed", f"fed-peer-{i}: {exc}")

    # 6. Final state.
    final = _get(c, "/mesh/state")

    # Render markdown.
    lines: list[str] = []
    lines.append("# Aegis Mesh — Live Demo Capture")
    lines.append("")
    lines.append(f"**Generated:** {_now_iso()}")
    lines.append(f"**Target:** `{target}`")
    lines.append(f"**Duration:** {duration}s")
    lines.append("")
    lines.append("## Timeline")
    lines.append("")
    lines.append("| t (s) | event | detail |")
    lines.append("|------:|-------|--------|")
    for elapsed, event, detail in timeline:
        lines.append(f"| {elapsed:>5.1f} | `{event}` | {detail} |")
    lines.append("")
    lines.append("## Per-second Snapshot")
    lines.append("")
    lines.append("| t (s) | contacts | campaigns | cm | federated peers | bounty issued |")
    lines.append("|------:|---------:|----------:|---:|----------------:|--------------:|")
    for elapsed, s in snapshots:
        fed = s.get("federated", {})
        bounty = s.get("bounty", {})
        lines.append(
            f"| {elapsed:>5.1f} | "
            f"{s.get('honeypots', {}).get('total_contacts', 0)} | "
            f"{len(s.get('campaigns', []))} | "
            f"{len(s.get('countermeasures', []))} | "
            f"{fed.get('known_peers', 0)} | "
            f"{bounty.get('total_issued', 0)} |"
        )
    lines.append("")
    lines.append("## Final State")
    lines.append("")
    lines.append("```json")
    lines.append(json.dumps(final, indent=2, default=str)[:3500])
    lines.append("```")
    lines.append("")
    output.write_text("\n".join(lines), encoding="utf-8")
    print(f"[capture_demo] wrote {output} ({output.stat().st_size} bytes)")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--target", default=os.getenv("AEGIS_TARGET", "http://localhost:8000"))
    p.add_argument("--duration", type=int, default=12, help="seconds to poll")
    p.add_argument("--output", type=Path, default=Path("demo_output.md"))
    args = p.parse_args(argv)
    return run(args.target, args.duration, args.output)


if __name__ == "__main__":
    sys.exit(main())