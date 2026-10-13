"""Attack correlator — groups attack events into campaigns.

A campaign is a set of attack events sharing the same JA4 hint or
fingerprint within a sliding time window. Each campaign accumulates
a severity score (sum of weighted event counts), an attacker IP set,
and a list of ML-KEM session ids the attacker contacted.

Campaigns are persisted to a Redis Stream named ``campaigns`` and
fanned out to in-process subscribers for the SSE feed.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from typing import Any, Optional

from app.mesh.honeypots import HoneypotRecord, honeypot_mesh
from app.streams import append, length

log = logging.getLogger(__name__)


# Window (seconds) within which two events with the same JA4 hint
# are considered part of the same campaign.
WINDOW_SECONDS = 600

# Severity weights per service.
_WEIGHTS = {"ssh": 1.0, "http": 1.0, "smb": 1.5}


class Campaign:
    __slots__ = (
        "campaign_id",
        "ja4_hint",
        "fingerprint",
        "first_seen",
        "last_seen",
        "events",
        "attacker_ips",
        "ml_kem_session_ids",
        "services",
        "severity",
        "peer",
    )

    def __init__(self, event: HoneypotRecord) -> None:
        self.campaign_id = event.fingerprint  # stable id derived from fingerprint
        self.ja4_hint = event.ja4_hint
        self.fingerprint = event.fingerprint
        self.first_seen = event.timestamp
        self.last_seen = event.timestamp
        self.events: list[HoneypotRecord] = [event]
        self.attacker_ips: set[str] = {event.src_ip}
        self.ml_kem_session_ids: set[str] = {event.ml_kem_session_id}
        self.services: set[str] = {event.honeypot}
        self.severity = _WEIGHTS.get(event.honeypot, 1.0)
        # Bounty attribution — first peer to claim this campaign.
        self.peer: str = ""

    def add(self, event: HoneypotRecord) -> None:
        self.events.append(event)
        self.attacker_ips.add(event.src_ip)
        self.ml_kem_session_ids.add(event.ml_kem_session_id)
        self.services.add(event.honeypot)
        self.last_seen = event.timestamp
        self.severity += _WEIGHTS.get(event.honeypot, 1.0)

    def is_stale(self, now: float) -> bool:
        return (now - self.last_seen) > WINDOW_SECONDS

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "ja4_hint": self.ja4_hint,
            "fingerprint": self.fingerprint,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_count": len(self.events),
            "attacker_ips": sorted(self.attacker_ips),
            "ml_kem_session_ids": sorted(self.ml_kem_session_ids),
            "services": sorted(self.services),
            "severity": round(self.severity, 3),
            "status": "active" if not self.is_stale(time.time()) else "stale",
            "peer": self.peer,
        }


class AttackCorrelator:
    """Groups events into campaigns keyed by fingerprint."""

    def __init__(self) -> None:
        self._campaigns: dict[str, Campaign] = {}
        self._subscribers: set[asyncio.Queue] = set()
        self._lock = asyncio.Lock()

    async def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=64)
        async with self._lock:
            self._subscribers.add(q)
        return q

    async def unsubscribe(self, q: asyncio.Queue) -> None:
        async with self._lock:
            self._subscribers.discard(q)

    async def ingest(
        self, event: HoneypotRecord, peer: str = ""
    ) -> Optional[Campaign]:
        now = time.time()
        # Drop stale campaigns to keep memory bounded.
        stale = [cid for cid, c in self._campaigns.items() if c.is_stale(now)]
        for cid in stale:
            self._campaigns.pop(cid, None)

        campaign = self._campaigns.get(event.fingerprint)
        if campaign is None:
            campaign = Campaign(event)
            self._campaigns[event.fingerprint] = campaign
        else:
            campaign.add(event)
        # Bounty: first peer to fire an event for this fingerprint
        # is the one we'll reward on countermeasure.
        if peer and not campaign.peer:
            campaign.peer = peer

        envelope = campaign.to_dict()
        try:
            await append("campaigns", envelope, maxlen=2_000)
        except Exception as exc:
            log.warning("correlator: stream append failed: %s", exc)

        # Fan out to SSE subscribers.
        async with self._lock:
            dead = []
            for q in self._subscribers:
                try:
                    q.put_nowait(envelope)
                except asyncio.QueueFull:
                    dead.append(q)
            for q in dead:
                self._subscribers.discard(q)
        return campaign

    def list_active(self) -> list[dict[str, Any]]:
        now = time.time()
        return [
            c.to_dict()
            for c in sorted(
                self._campaigns.values(), key=lambda x: x.severity, reverse=True
            )
            if not c.is_stale(now)
        ]

    def stats(self) -> dict[str, Any]:
        now = time.time()
        active = [c for c in self._campaigns.values() if not c.is_stale(now)]
        # Severity histogram bucketed by campaign.total_severity:
        #   low      = 0..1.99
        #   medium   = 2..4.99
        #   high     = 5..9.99
        #   critical = 10+
        histogram = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for c in active:
            sev = c.severity
            if sev >= 10:
                histogram["critical"] += 1
            elif sev >= 5:
                histogram["high"] += 1
            elif sev >= 2:
                histogram["medium"] += 1
            else:
                histogram["low"] += 1
        return {
            "active_campaigns": len(active),
            "total_campaigns_tracked": len(self._campaigns),
            "total_severity": round(sum(c.severity for c in active), 3),
            "severity_histogram": histogram,
            "stream_length": 0,  # filled by caller with await length()
        }


correlator = AttackCorrelator()


async def record_honeypot_hit(event: HoneypotRecord) -> Optional[Campaign]:
    """Convenience wrapper used by routes."""
    return await correlator.ingest(event, peer=event.peer or "")


async def campaigns_stream_length() -> int:
    return await length("campaigns")


__all__ = [
    "correlator",
    "Campaign",
    "AttackCorrelator",
    "record_honeypot_hit",
    "campaigns_stream_length",
]
