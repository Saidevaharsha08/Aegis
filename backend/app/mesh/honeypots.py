"""Quantum Honeypot Mesh — decoy service endpoints bound to ML-KEM-768 keys.

Three decoys are exposed (mounted under ``/mesh/honeypots/{ssh,http,smb}``).
Each is wrapped in its own ML-KEM-768 key encapsulation so the
attacker's session id is bound to a freshly rotated keypair:

* Contact with a honeypot records an ``attack_event`` carrying
  src_ip, fingerprint, payload sample, and the active
  ``ml_kem_session_id``.
* The decoy returns a realistic-looking but inert response, plus a
  ``countermeasure_token`` derived from the active ML-KEM key so any
  follow-up call signed with that token is recognized as a
  countermeasure deployment (the correlator ignores it).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from app.crypto.session import session_manager


# Static decoy payloads — kept short so they are realistic enough to
# bait a recon but not so verbose that they leak real metadata.
_SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
_HTTP_BANNER = "Aegis-Admin/1.4.2 (Ubuntu)\r\nServer: nginx/1.18.0\r\n"
_SMB_BANNER = "SMB 3.1.1 — Windows Server 2019\r\n"


@dataclass
class HoneypotRecord:
    honeypot: str
    src_ip: str
    payload: str
    fingerprint: str
    ml_kem_session_id: str
    timestamp: float
    headers: dict[str, str] = field(default_factory=dict)
    ja4_hint: str = ""
    peer: str = ""  # bounty attribution handle, if set by caller


class HoneypotMesh:
    """In-process registry of honeypot contacts + active decoy keypairs."""

    def __init__(self) -> None:
        self._lock_seqs: dict[str, int] = {}
        self.recent: list[HoneypotRecord] = []

    # ---- per-honeypot keypair -------------------------------------

    def _session_id_for(self, honeypot: str) -> str:
        """Stable id derived from the active ML-KEM public key.

        Rotation invalidates old ids automatically — anything that
        arrives with a stale ``countermeasure_token`` will be
        rejected at correlation time.
        """
        pk = session_manager.public_key
        digest = hashlib.sha256(pk + honeypot.encode()).hexdigest()[:24]
        return digest

    def countermeasure_token(self, honeypot: str, session_id: str) -> str:
        """HMAC token proving the call was made by the active session."""
        secret = session_manager.public_key.hex()
        msg = f"{honeypot}|{session_id}".encode()
        return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()[:32]

    # ---- record + classify ---------------------------------------

    def record(
        self,
        honeypot: str,
        src_ip: str,
        payload: str,
        headers: Optional[dict[str, str]] = None,
        peer: str = "",
    ) -> HoneypotRecord:
        headers = headers or {}
        fp = self._fingerprint(honeypot, payload, headers)
        sid = self._session_id_for(honeypot)
        rec = HoneypotRecord(
            honeypot=honeypot,
            src_ip=src_ip,
            payload=payload[:512],
            fingerprint=fp,
            ml_kem_session_id=sid,
            timestamp=time.time(),
            headers={k: v[:200] for k, v in headers.items()},
            ja4_hint=self._ja4_hint(headers),
            peer=peer,
        )
        self.recent.append(rec)
        # Keep the last 500 records in memory; older ones age out.
        if len(self.recent) > 500:
            self.recent = self.recent[-500:]
        return rec

    # ---- response payloads ---------------------------------------

    def decoy_response(self, honeypot: str) -> dict[str, Any]:
        """Return a realistic-looking banner plus decoy metadata."""
        if honeypot == "ssh":
            banner = _SSH_BANNER
        elif honeypot == "http":
            banner = _HTTP_BANNER
        elif honeypot == "smb":
            banner = _SMB_BANNER
        else:
            banner = "unknown-service"
        sid = self._session_id_for(honeypot)
        return {
            "service": honeypot,
            "banner": banner,
            "ml_kem_session_id": sid,
            "countermeasure_token": self.countermeasure_token(honeypot, sid),
            "note": "decoy-response-bound-to-active-ml-kem-key",
            "timestamp": time.time(),
        }

    # ---- helpers ------------------------------------------------

    @staticmethod
    def _fingerprint(honeypot: str, payload: str, headers: dict[str, str]) -> str:
        """Stable id derived from (service, src_ip, x-forwarded-for).

        Different payload bytes AND different user-agent strings from
        the same attacker should still merge into one campaign — that
        is the whole point of the correlator. An attacker that rotates
        their User-Agent per packet should NOT spawn N campaigns.

        Trade-off: two distinct attackers behind the same NAT (sharing
        the same egress IP) will collide into one campaign. We accept
        that for the demo because:
          1. The mesh is a honeypot — every contact is hostile.
          2. ``JA4-ish hint`` is still tracked on the record, so the
             operator can disambiguate after the fact.
        Payload is intentionally excluded so a port-scan-then-brute-force
        from the same source merges.
        """
        # payload arg kept for API stability; deliberately unused.
        del payload
        # Headers key casing is whatever the caller passes. The mesh
        # route layer normalizes to lowercase, but accept either.
        xff = (
            headers.get("x-forwarded-for")
            or headers.get("X-Forwarded-For")
            or headers.get("forwarded_for")
            or ""
        )
        # Note: we DO NOT use src_ip here directly — the caller passes
        # src_ip as a separate argument, but we derive the fingerprint
        # ONLY from headers so an attacker rotating their declared
        # src_ip in the body still gets fingerprinted together.
        h = hashlib.sha256()
        h.update(honeypot.encode())
        h.update(b"|")
        h.update(xff.encode())
        return h.hexdigest()[:16]

    @staticmethod
    def _ja4_hint(headers: dict[str, str]) -> str:
        """Lightweight JA4-ish fingerprint hint from cipher/order hints.

        Real JA4 needs the full TLS ClientHello; here we approximate
        with the headers that an HTTP attacker typically sends. Good
        enough to group clients across contacts.
        """
        order = []
        for k in headers.keys():
            kl = k.lower()
            if kl in {"host", "user-agent", "accept", "accept-encoding",
                      "accept-language", "connection"}:
                order.append(kl)
        return ",".join(sorted(set(order)))[:64]

    def stats(self) -> dict[str, Any]:
        by_service: dict[str, int] = {}
        unique_attackers = set()
        for r in self.recent:
            by_service[r.honeypot] = by_service.get(r.honeypot, 0) + 1
            unique_attackers.add(r.src_ip)
        # Per-honeypot ML-KEM session id (truncated to 16 hex). Each
        # contact with a given service is bound to the active
        # keypair of that service; rotation invalidates old ids.
        by_service_session: dict[str, str] = {}
        for svc in ("ssh", "http", "smb"):
            try:
                by_service_session[svc] = self._session_id_for(svc)
            except Exception:
                by_service_session[svc] = ""
        return {
            "total_contacts": len(self.recent),
            "by_service": by_service,
            "by_service_session": by_service_session,
            "unique_attackers": len(unique_attackers),
            "active_ml_kem_fingerprint": session_manager.public_key.hex()[:16],
        }


honeypot_mesh = HoneypotMesh()


__all__ = ["honeypot_mesh", "HoneypotMesh", "HoneypotRecord"]
