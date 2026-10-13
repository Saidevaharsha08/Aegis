"""Built-in red-team driver.

Synthesizes increasingly clever attack patterns against the honeypot
mesh on a schedule so the dashboard stays "alive" without external
peers. Each tick:

  1. Picks the next pattern in the campaign ladder.
  2. Mutates the pattern based on the last countermeasure applied
     (so it looks like an adaptive attacker).
  3. Posts the attack to the local honeypot endpoints via HTTPX
     (in-process — uses TestClient-friendly loop).

This intentionally runs inside the same process so it works under
``TestClient`` and against the in-process fallback queues without
needing real network I/O.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from typing import Any, Optional

from app.mesh.events import publish_redteam

log = logging.getLogger(__name__)


_LADDER = [
    "port_scan",
    "ssh_bruteforce",
    "http_path_enum",
    "smb_enum",
    "low_volume_dos",
    "credential_stuffing",
]


_PAYLOADS = {
    "port_scan": {"payload": "nmap -sS 10.0.0.0/24", "user_agent": ""},
    "ssh_bruteforce": {
        "payload": "admin:password\nroot:toor\nuser:12345\n",
        "user_agent": "paramiko/2.7.2",
    },
    "http_path_enum": {
        "payload": "GET /.env HTTP/1.1\r\nHost: target\r\n",
        "user_agent": "gobuster/3.1.0",
    },
    "smb_enum": {"payload": "SMB negprot", "user_agent": ""},
    "low_volume_dos": {
        "payload": "GET / HTTP/1.1\r\nHost: target\r\n\r\n" * 200,
        "user_agent": "slowloris/0.1.4",
    },
    "credential_stuffing": {
        "payload": "username=admin&password=admin\r\n",
        "user_agent": "Mozilla/5.0",
    },
}


class RedTeamDriver:
    """Drives a synthetic adaptive attacker against the local mesh."""

    def __init__(self, tick_seconds: float = 8.0) -> None:
        self.tick_seconds = tick_seconds
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()
        self.step_index = 0
        self.last_countermeasure_signature: str = ""
        self.total_runs = 0
        # Adaptive-attacker telemetry: how many events had to mutate
        # because the mesh deployed a countermeasure against us.
        self.events_mutated = 0
        self.base_events = 0

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._loop(), name="red-team-driver")

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=2.0)
            except asyncio.TimeoutError:
                self._task.cancel()

    def next_step(self) -> str:
        return _LADDER[self.step_index % len(_LADDER)]

    def _mutate_payload(self, kind: str) -> dict[str, Any]:
        base = dict(_PAYLOADS[kind])
        ua = base.get("user_agent", "")
        body = base.get("payload", "")
        # Adapt to last countermeasure: rotate user agent + append a
        # nonce so the correlator sees "different but related" events.
        if self.last_countermeasure_signature:
            ua = f"{ua}-adapt-{self.last_countermeasure_signature[:6]}".strip("-")
            body = f"{body}\n# nonce:{random.randint(0, 99999)}"
        return {"payload": body, "user_agent": ua or f"redteam/{kind}"}

    async def _loop(self) -> None:
        log.info("redteam: starting (tick=%.1fs)", self.tick_seconds)
        while not self._stop.is_set():
            try:
                await self._tick()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.warning("redteam: tick failed: %s", exc)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.tick_seconds)
            except asyncio.TimeoutError:
                continue
        log.info("redteam: stopped")

    async def _tick(self) -> None:
        kind = self.next_step()
        self.step_index += 1
        self.total_runs += 1
        attacker_ip = f"203.0.113.{random.randint(1, 254)}"
        was_mutated = bool(self.last_countermeasure_signature)
        body = self._mutate_payload(kind)
        # Bookkeeping: a "base" event is one fired without a recent
        # countermeasure; a "mutated" event is one that had to adapt.
        if was_mutated:
            self.events_mutated += 1
        else:
            self.base_events += 1
        envelope = {
            "kind": kind,
            "src_ip": attacker_ip,
            "service": {"port_scan": "http", "ssh_bruteforce": "ssh", "http_path_enum": "http",
                        "smb_enum": "smb", "low_volume_dos": "http", "credential_stuffing": "http"}[kind],
            "payload": body["payload"],
            "user_agent": body["user_agent"],
            "timestamp": time.time(),
        }
        await publish_redteam(envelope)
        # Drive the local honeypot via the route handler so the
        # correlator sees the same path as an external attacker.
        try:
            from app.mesh.routes import ingest_external_attack
            await ingest_external_attack(envelope)
        except Exception as exc:
            log.debug("redteam: ingest_external_attack skipped: %s", exc)

    def status(self) -> dict[str, Any]:
        total = self.base_events + self.events_mutated
        adapt_ratio = round(self.events_mutated / total, 3) if total else 0.0
        return {
            "running": self._task is not None and not self._task.done(),
            "tick_seconds": self.tick_seconds,
            "step_index": self.step_index,
            "total_runs": self.total_runs,
            "next_pattern": self.next_step(),
            "last_countermeasure_signature": self.last_countermeasure_signature,
            "mutation_stats": {
                "base_events": self.base_events,
                "events_mutated": self.events_mutated,
                "adaptation_ratio": adapt_ratio,
            },
        }


redteam = RedTeamDriver()


__all__ = ["redteam", "RedTeamDriver"]
