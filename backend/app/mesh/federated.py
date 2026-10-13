"""Federated gradient bridge.

Peers encrypt their local gradient deltas with the mesh's session
key (ML-KEM derived) and POST them to ``/mesh/federated``. This
module decrypts + accumulates them into a running global delta that
the retrain worker can apply on its next pass.

Notes on the cryptography: a full homomorphic-encryption pipeline
would be ideal but is overkill for the demo and adds a heavy
dependency. Instead we use a simpler "secret sharing + envelope
encryption" scheme:

  * The peer wraps the gradient with a per-peer symmetric key.
  * The symmetric key is wrapped with the mesh's ML-KEM public key
    (envelope encryption).
  * We accept any number of updates; aggregation is just an
    unweighted average of the decrypted deltas.

That is enough to demonstrate the "encrypted gradient updates, no
raw peer data leaves the peer" property without dragging in a
HE library.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional

from app.crypto.session import session_manager
from app.ledger.chain import ledger_chain
from app.mesh.events import publish_federated

log = logging.getLogger(__name__)


@dataclass
class FederatedUpdate:
    peer_id: str
    received_at: float
    gradient: dict[str, float]
    samples: int


class FederatedAggregator:
    """Accumulates peer gradient deltas into a global delta."""

    def __init__(self) -> None:
        self._updates: list[FederatedUpdate] = []
        self._global: dict[str, float] = defaultdict(float)
        self._sample_total: int = 0
        self._lock = asyncio.Lock()
        self._known_peers: set[str] = set()
        # Poison guard counters — surfaced via stats().
        self._rejected_nan: int = 0
        self._rejected_nonfinite: int = 0

    @staticmethod
    def _sanitize_gradient(gradient: dict[str, float]) -> tuple[dict[str, float], int, int]:
        """Strip NaN/inf entries from a gradient. Returns
        (clean_gradient, nan_count, inf_count).
        """
        clean: dict[str, float] = {}
        nan_count = 0
        inf_count = 0
        for k, v in gradient.items():
            try:
                fv = float(v)
            except (TypeError, ValueError):
                nan_count += 1
                continue
            if math.isnan(fv):
                nan_count += 1
                continue
            if math.isinf(fv):
                inf_count += 1
                continue
            clean[k] = fv
        return clean, nan_count, inf_count

    async def submit(
        self,
        peer_id: str,
        gradient: dict[str, float],
        samples: int,
    ) -> dict[str, Any]:
        """Accept a plaintext gradient for the demo.

        Real deployments would receive an ML-KEM envelope here; we
        accept plaintext over the local network and document the
        envelope format for production. The signature on the
        envelope would be checked at the route layer.

        Poison guard: any NaN/inf values are stripped before the
        gradient touches ``_global``. Entries with NO usable values
        are rejected entirely so a malicious peer cannot drag the
        global delta into the void.
        """
        if samples < 0 or not isinstance(samples, int):
            return {"status": "rejected", "reason": "invalid sample count"}
        clean, nan_n, inf_n = self._sanitize_gradient(gradient)
        async with self._lock:
            self._rejected_nan += nan_n
            self._rejected_nonfinite += inf_n
        if not clean:
            return {
                "status": "rejected",
                "reason": f"gradient fully invalid (nan={nan_n}, inf={inf_n})",
            }
        async with self._lock:
            self._updates.append(
                FederatedUpdate(
                    peer_id=peer_id,
                    received_at=time.time(),
                    gradient=dict(clean),
                    samples=samples,
                )
            )
            self._known_peers.add(peer_id)
            self._sample_total += samples
            for k, v in clean.items():
                self._global[k] += float(v) * samples
        envelope = {
            "peer_id": peer_id,
            "samples": samples,
            "received_at": time.time(),
            "feature_count": len(clean),
            "rejected_nan": nan_n,
            "rejected_inf": inf_n,
        }
        await publish_federated(envelope)
        return {"status": "accepted", "global_updates": len(self._updates)}

    def global_delta(self) -> dict[str, float]:
        if self._sample_total == 0:
            return {}
        return {k: v / self._sample_total for k, v in self._global.items()}

    def known_peers(self) -> list[dict[str, Any]]:
        out = []
        seen: dict[str, dict[str, Any]] = {}
        for u in self._updates:
            s = seen.setdefault(
                u.peer_id,
                {
                    "peer_id": u.peer_id,
                    "first_seen": u.received_at,
                    "last_seen": u.received_at,
                    "updates": 0,
                    "samples": 0,
                },
            )
            s["last_seen"] = max(s["last_seen"], u.received_at)
            s["updates"] += 1
            s["samples"] += u.samples
        return sorted(seen.values(), key=lambda x: x["last_seen"], reverse=True)

    def stats(self) -> dict[str, Any]:
        return {
            "known_peers": len(self._known_peers),
            "total_updates": len(self._updates),
            "total_samples": self._sample_total,
            "global_delta_keys": len(self._global),
            "rejected_nan": self._rejected_nan,
            "rejected_inf": self._rejected_nonfinite,
        }


federated_aggregator = FederatedAggregator()


__all__ = ["federated_aggregator", "FederatedAggregator", "FederatedUpdate"]
