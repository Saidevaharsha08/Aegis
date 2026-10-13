"""Bounty Mode — reward friends whose attacks are correlated and answered.

When a countermeasure fires against a campaign whose fingerprint
traces back to a peer (via share-link or ``X-Aegis-Peer`` header),
the bounty ledger mints a token for that peer. The token is an HMAC
the peer can later ``POST /mesh/bounty/claim`` to verify they really
were the attacker.

Why bother: turns the demo from "passive observation" into a game.
Friends race to fire attacks that get correlated into the highest-
severity campaign; the operator sees the mesh light up in real time.

Security model
--------------
* Token = HMAC-SHA256(secret, peer || campaign_id || amount || ts).
* One token per countermeasure deployment (no double-spend).
* Tokens are single-use: claim invalidates the token_id.
* Claim appends ``BOUNTY_CLAIM`` to the audit ledger.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from app.config import settings
from app.ledger.chain import ledger_chain
from app.mesh.events import publish_campaign as _publish_campaign  # noqa: F401  (re-export)

log = logging.getLogger(__name__)


# Reward scale — keeps the demo deterministic.
_BASE_REWARD = 10          # QShield tokens per countermeasure
_SEVERITY_BONUS = 2.0      # extra per severity point


@dataclass
class BountyEntry:
    bounty_id: str
    peer: str
    campaign_id: str
    severity: float
    amount: int
    issued_at: float
    token: str  # HMAC hex
    claimed: bool = False
    claimed_at: Optional[float] = None


class BountyLedger:
    def __init__(self) -> None:
        self._entries: dict[str, BountyEntry] = {}
        self._peer_totals: dict[str, int] = {}

    # ---- minting --------------------------------------------------

    def _sign(self, peer: str, campaign_id: str, amount: int, ts: float) -> str:
        msg = f"{peer}|{campaign_id}|{amount}|{ts:.0f}".encode()
        return hmac.new(settings.SECRET_KEY.encode(), msg, hashlib.sha256).hexdigest()[:32]

    def award(self, campaign_id: str, peer: str, severity: float) -> Optional[BountyEntry]:
        """Mint a bounty for the peer if the campaign traces to them."""
        if not peer or not campaign_id:
            return None
        amount = int(_BASE_REWARD + max(0.0, severity) * _SEVERITY_BONUS)
        bounty_id = "bty_" + uuid.uuid4().hex[:10]
        ts = time.time()
        token = self._sign(peer, campaign_id, amount, ts)
        entry = BountyEntry(
            bounty_id=bounty_id,
            peer=peer,
            campaign_id=campaign_id,
            severity=round(severity, 3),
            amount=amount,
            issued_at=ts,
            token=token,
        )
        self._entries[bounty_id] = entry
        self._peer_totals[peer] = self._peer_totals.get(peer, 0) + amount
        # Best-effort ledger append.
        try:
            ledger_chain.append_event(
                event_type="BOUNTY_AWARDED",
                actions_taken=[
                    f"bounty_id={bounty_id}",
                    f"peer={peer}",
                    f"amount={amount}",
                    f"campaign_id={campaign_id}",
                ],
                threat_id=campaign_id,
                source_ip=peer,
                attack_type="MESH_BOUNTY",
                threat_score=severity,
                rules_applied=[],
                crypto_mode="ML-KEM-768",
                operator_id="bounty_ledger",
            )
        except Exception as exc:
            log.warning("bounty: ledger append failed: %s", exc)
        return entry

    # ---- claiming -------------------------------------------------

    def claim(self, peer: str, campaign_id: str, token: str) -> Optional[dict[str, Any]]:
        """Verify token + mark entry as claimed. Returns payout envelope or None."""
        for entry in self._entries.values():
            if entry.peer != peer or entry.campaign_id != campaign_id:
                continue
            if entry.claimed:
                return None  # already claimed
            if not hmac.compare_digest(entry.token, token):
                continue
            entry.claimed = True
            entry.claimed_at = time.time()
            try:
                ledger_chain.append_event(
                    event_type="BOUNTY_CLAIM",
                    actions_taken=[
                        f"bounty_id={entry.bounty_id}",
                        f"peer={peer}",
                        f"amount={entry.amount}",
                    ],
                    threat_id=campaign_id,
                    source_ip=peer,
                    attack_type="MESH_BOUNTY",
                    threat_score=entry.severity,
                    rules_applied=[],
                    crypto_mode="ML-KEM-768",
                    operator_id="peer",
                )
            except Exception as exc:
                log.warning("bounty: claim ledger append failed: %s", exc)
            return {
                "status": "claimed",
                "bounty_id": entry.bounty_id,
                "amount": entry.amount,
                "peer": peer,
            }
        return None

    # ---- snapshot -------------------------------------------------

    def stats(self) -> dict[str, Any]:
        total = sum(e.amount for e in self._entries.values())
        paid = sum(e.amount for e in self._entries.values() if e.claimed)
        pending = total - paid
        # Top peer by earned (claimed + unclaimed).
        top_peer = None
        top_earned = 0
        for peer, amt in self._peer_totals.items():
            if amt > top_earned:
                top_peer = peer
                top_earned = amt
        recent = sorted(self._entries.values(), key=lambda e: e.issued_at, reverse=True)[:10]
        return {
            "pending": pending,
            "paid": paid,
            "total_issued": total,
            "top_peer": top_peer,
            "top_peer_earned": top_earned,
            "entry_count": len(self._entries),
            "peer_count": len(self._peer_totals),
            "recent": [
                {
                    "bounty_id": e.bounty_id,
                    "peer": e.peer,
                    "campaign_id": e.campaign_id,
                    "amount": e.amount,
                    "severity": e.severity,
                    "claimed": e.claimed,
                    "issued_at": e.issued_at,
                }
                for e in recent
            ],
        }


bounty_ledger = BountyLedger()


def award_for_countermeasure(campaign_id: str, peer: Optional[str], severity: float) -> Optional[dict[str, Any]]:
    """Award helper — only mints if a peer handle is attached."""
    if not peer:
        return None
    entry = bounty_ledger.award(campaign_id=campaign_id, peer=peer, severity=severity)
    if entry is None:
        return None
    return {
        "bounty_id": entry.bounty_id,
        "peer": entry.peer,
        "campaign_id": entry.campaign_id,
        "amount": entry.amount,
        "token": entry.token,
    }


__all__ = ["BountyLedger", "BountyEntry", "bounty_ledger", "award_for_countermeasure"]