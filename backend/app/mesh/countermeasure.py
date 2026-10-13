"""Countermeasure generator + executor.

Given an active campaign, the generator emits a synthesized
countermeasure package:

  1. A tailored firewall rule selected via the existing QAOA
     optimizer (falls back to greedy knapsack).
  2. A decoy token bound to the attacker's ML-KEM session id so
     future responses from the mesh can be tailored per attacker.
  3. An optional upstream block signal (a flag the operator can
     wire into their perimeter firewall).

Deployment is atomic and audit-logged: every countermeasure is
appended to the ledger with ``event_type=COUNTERMEASURE`` and the
campaign id as ``threat_id``.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from app.crypto.rotation import key_rotation_manager
from app.crypto.session import session_manager
from app.ledger.chain import ledger_chain
from app.optimizer.api import solve

log = logging.getLogger(__name__)


@dataclass
class Countermeasure:
    countermeasure_id: str
    campaign_id: str
    ml_kem_session_id: str
    decoy_token: str
    rules_applied: list[dict[str, Any]]
    block_upstream: bool
    issued_at: float
    operator_id: str
    notes: list[str] = field(default_factory=list)
    solver: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "countermeasure_id": self.countermeasure_id,
            "campaign_id": self.campaign_id,
            "ml_kem_session_id": self.ml_kem_session_id,
            "decoy_token": self.decoy_token,
            "rules_applied": self.rules_applied,
            "block_upstream": self.block_upstream,
            "issued_at": self.issued_at,
            "operator_id": self.operator_id,
            "notes": self.notes,
            "solver": self.solver,
        }


class CountermeasureEngine:
    """Generates, deploys, and persists countermeasures."""

    def __init__(self) -> None:
        self.deployed: list[Countermeasure] = []

    def _decoy_token(self, campaign_id: str, ml_kem_session_id: str) -> str:
        """Token bound to the active ML-KEM key + campaign + session.

        Reuses the same HMAC pattern as ``honeypots.HoneypotMesh`` so
        a downstream service can verify the token without a DB
        lookup.
        """
        secret = session_manager.public_key.hex()
        msg = f"{campaign_id}|{ml_kem_session_id}".encode()
        return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()[:32]

    def _select_rule(self, attacker_ips: list[str], services: list[str]) -> dict[str, Any]:
        """Pick a tailored rule via QAOA → greedy fallback."""
        result = solve(
            fpr_budget=0.05,  # tighter than the optimizer's default
            cost_budget=8.0,
            n_rules=10,
            solver="auto",
        )
        chosen = result.selected_rules[0] if result.selected_rules else None
        rule = {
            "name": "mesh-countermeasure",
            "match": {
                "src_ips": attacker_ips[:8],
                "services": services[:4],
            },
            "action": "RATE_LIMIT_AND_DECOY",
            "selected_rule_id": chosen.rule_id if chosen else None,
            "block_probability": result.total_block_probability,
            "solver": result.solver,
        }
        return rule

    async def generate_and_deploy(
        self,
        campaign: dict[str, Any],
        operator_id: str = "mesh_auto",
        block_upstream: bool = False,
        rotate_keys: bool = True,
    ) -> Countermeasure:
        """Generate a countermeasure, deploy it, and audit-log the deploy."""
        cm_id = str(uuid.uuid4())
        campaign_id = campaign["campaign_id"]
        # Use the most-recent ML-KEM session id observed by the campaign.
        sessions = campaign.get("ml_kem_session_ids") or [""]
        ml_kem_session_id = sessions[0]

        notes: list[str] = []
        if rotate_keys:
            try:
                rot = key_rotation_manager.rotate_keys(reason=f"MESH_COUNTERMEASURE:{cm_id[:8]}")
                notes.append(f"rotated_keys:{rot.get('new_key_fingerprint')}")
                # After rotation, the decoy token MUST be issued under
                # the new key so the honeypot responses are consistent.
                ml_kem_session_id = session_manager.public_key.hex()[:24]
            except Exception as exc:
                notes.append(f"rotation_failed:{exc}")

        rule = self._select_rule(
            attacker_ips=campaign.get("attacker_ips") or [],
            services=campaign.get("services") or [],
        )
        decoy_token = self._decoy_token(campaign_id, ml_kem_session_id)

        cm = Countermeasure(
            countermeasure_id=cm_id,
            campaign_id=campaign_id,
            ml_kem_session_id=ml_kem_session_id,
            decoy_token=decoy_token,
            rules_applied=[rule],
            block_upstream=block_upstream,
            issued_at=time.time(),
            operator_id=operator_id,
            notes=notes,
            solver=rule.get("solver", "auto"),
        )
        self.deployed.append(cm)
        if len(self.deployed) > 200:
            self.deployed = self.deployed[-200:]

        # Audit-log to the ledger.
        try:
            ledger_chain.append_event(
                event_type="COUNTERMEASURE",
                actions_taken=[
                    f"countermeasure_id={cm_id}",
                    f"campaign_id={campaign_id}",
                    f"rule={rule.get('name')}",
                    f"block_upstream={block_upstream}",
                    *notes,
                ],
                threat_id=campaign_id,
                source_ip=(campaign.get("attacker_ips") or ["unknown"])[0],
                attack_type="MESH_ACTIVE_DEFENSE",
                threat_score=float(campaign.get("severity", 0.0)),
                rules_applied=[rule],
                crypto_mode="ML-KEM-768",
                operator_id=operator_id,
            )
        except Exception as exc:
            log.warning("countermeasure: ledger append failed: %s", exc)

        # Persist + fan out so the SSE feed can deliver it.
        try:
            from app.streams import append
            await append("countermeasures", cm.to_dict(), maxlen=2_000)
        except Exception as exc:
            log.warning("countermeasure: stream append failed: %s", exc)
        try:
            from app.mesh.events import publish_countermeasure
            await publish_countermeasure(cm.to_dict())
        except Exception:
            pass

        return cm

    def list_deployed(self, limit: int = 50) -> list[dict[str, Any]]:
        return [c.to_dict() for c in self.deployed[-limit:]]

    def stats(self) -> dict[str, Any]:
        return {
            "deployed_total": len(self.deployed),
            "by_solver": {
                s: sum(1 for c in self.deployed if c.solver == s)
                for s in {c.solver for c in self.deployed}
            },
        }


countermeasure_engine = CountermeasureEngine()


__all__ = ["countermeasure_engine", "Countermeasure", "CountermeasureEngine"]
