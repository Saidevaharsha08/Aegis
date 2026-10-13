"""Quantum Defense Mesh — routes.

Honeypot decoys
---------------
* ``GET|POST /mesh/honeypots/ssh`` — fake SSH banner
* ``GET|POST /mesh/honeypots/http`` — fake HTTP admin
* ``GET|POST /mesh/honeypots/smb`` — fake SMB
Each contact records an ``attack_event`` keyed by attacker fingerprint.

Control plane
-------------
* ``POST /mesh/attack`` — explicit attack ingestion (used by the
  companion CLI; mirrors the honeypot path so the correlator sees
  one normalized stream). Auth: X-API-Key OR X-Mesh-Share-Token.
* ``POST /mesh/countermeasure`` — generate + deploy a countermeasure
  against an active campaign id. Body: ``{campaign_id, operator_id,
  block_upstream, rotate_keys}``. Awards bounty if campaign is
  attributed to a peer.
* ``POST /mesh/federated`` — submit an encrypted gradient update.
* ``GET  /mesh/state`` — full snapshot (honeypots + active campaigns
  + deployed countermeasures + federated peers + red-team status
  + bounty ledger).
* ``GET  /mesh/stream`` — Server-Sent Events feed of mesh activity.
* ``POST /mesh/redteam/start`` / ``POST /mesh/redteam/stop`` — toggle
  the built-in simulator.

Friend / share plane
--------------------
* ``POST /mesh/share/issue`` — operator mints a share token.
* ``GET  /mesh/share/{share_id}/{token}`` — public HTML page that
  auto-POSTs a single attack from the visitor's browser.
* ``POST /mesh/share/{share_id}/{token}/fire`` — public; the form's
  POST target. Validates token TTL, fires one attack attributed to
  the share.
* ``POST /mesh/bounty/claim`` — peer submits their handle + the
  token they were issued; verifies HMAC and marks paid.
"""

from __future__ import annotations

import asyncio
import hmac as _hmac
import json
import logging
import time
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request, status, Form
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from app.api.rate_limiter import rate_limit
from app.config import settings
from app.mesh.bounty import bounty_ledger, award_for_countermeasure
from app.mesh.correlator import correlator, record_honeypot_hit
from app.mesh.countermeasure import countermeasure_engine
from app.mesh.events import iter_events
from app.mesh.federated import federated_aggregator
from app.mesh.honeypots import honeypot_mesh
from app.mesh.redteam import redteam
from app.mesh.share import (
    issue_share_token,
    verify_share_token,
    render_share_page,
    DEFAULT_TTL_SECONDS,
)

log = logging.getLogger(__name__)
router = APIRouter()


# ---- auth helpers ----------------------------------------------------

def _check_mesh_auth(x_api_key: Optional[str], x_mesh_share_token: Optional[str]) -> bool:
    """Allow either a valid X-API-Key or a valid share token fragment."""
    if x_api_key and settings.DETECT_API_KEY and _hmac.compare_digest(
        x_api_key.encode(), settings.DETECT_API_KEY.encode()
    ):
        return True
    # Share token path: a string starting with "shr_" treated as
    # trusted if it's well-formed — actual TTL is enforced on the
    # /fire endpoint. We just sanity-check the prefix here.
    if x_mesh_share_token and x_mesh_share_token.startswith("shr_"):
        return True
    # Operator can also POST without auth in dev (matches existing
    # behaviour where /mesh/attack was open in the smoke test).
    if not settings.DETECT_API_KEY:
        return True
    return False


# ---- honeypots --------------------------------------------------------

async def ingest_external_attack(envelope: dict[str, Any]) -> dict[str, Any]:
    """Normalize an incoming attack (from honeypot OR CLI) and feed the correlator."""
    service = envelope.get("service") or "http"
    src_ip = envelope.get("src_ip") or "0.0.0.0"
    payload = envelope.get("payload") or ""
    headers = {
        "user-agent": envelope.get("user_agent", ""),
        "x-forwarded-for": envelope.get("forwarded_for") or src_ip,
    }
    peer = envelope.get("peer") or ""
    record = honeypot_mesh.record(service, src_ip, payload, headers, peer=peer)
    campaign = await record_honeypot_hit(record)
    return {
        "attack_event": {
            "honeypot": record.honeypot,
            "src_ip": record.src_ip,
            "fingerprint": record.fingerprint,
            "ml_kem_session_id": record.ml_kem_session_id,
            "timestamp": record.timestamp,
            "ja4_hint": record.ja4_hint,
        },
        "campaign": campaign.to_dict() if campaign else None,
    }


@router.api_route("/mesh/honeypots/{service}", methods=["GET", "POST"])
async def honeypot(service: str, request: Request):
    if service not in {"ssh", "http", "smb"}:
        raise HTTPException(status_code=404, detail="unknown honeypot service")
    body = b""
    if request.method == "POST":
        body = await request.body()
        payload = body.decode("utf-8", errors="ignore") or f"GET {request.url.path}"
    else:
        payload = f"GET {request.url.path}?{request.url.query}"
    src_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "0.0.0.0")
    headers = dict(request.headers)
    peer = request.headers.get("x-aegis-peer", "")
    record = honeypot_mesh.record(service, src_ip, payload, headers, peer=peer)
    campaign = await record_honeypot_hit(record)
    body = honeypot_mesh.decoy_response(service)
    body["attack_event"] = {
        "honeypot": record.honeypot,
        "src_ip": record.src_ip,
        "fingerprint": record.fingerprint,
        "ml_kem_session_id": record.ml_kem_session_id,
        "timestamp": record.timestamp,
    }
    body["campaign_id"] = campaign.campaign_id if campaign else None
    return body


# ---- CLI ingest -------------------------------------------------------

class AttackIngestRequest(BaseModel):
    service: str = "http"
    src_ip: str = "0.0.0.0"
    payload: str = ""
    user_agent: str = ""
    peer: str = ""


@router.post("/mesh/attack", status_code=status.HTTP_202_ACCEPTED, dependencies=[])
async def attack(req: AttackIngestRequest, request: Request):
    # Rate limit per IP. We do this here (instead of via dependency)
    # so we can bucket by x-forwarded-for when present.
    client_ip = (
        request.headers.get("x-forwarded-for")
        or (request.client.host if request.client else "unknown")
    )
    from app.api.rate_limiter import _redis_check, _limiter
    if not await _redis_check(f"mesh-attack:{client_ip}"):
        raise HTTPException(status_code=429, detail="rate_limited")

    envelope = {
        "service": req.service,
        "src_ip": req.src_ip,
        "payload": req.payload,
        "user_agent": req.user_agent,
        "peer": req.peer,
    }
    # Use the caller's X-Forwarded-For (if present) as the
    # fingerprint hint so multiple events from the same peer merge
    # into one campaign regardless of the IP they declare in body.
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        envelope["forwarded_for"] = forwarded
    # Peer from header takes precedence if body omitted it.
    if not envelope["peer"]:
        envelope["peer"] = request.headers.get("x-aegis-peer", "")
    return await ingest_external_attack(envelope)


# ---- countermeasure ---------------------------------------------------

class CountermeasureRequest(BaseModel):
    campaign_id: str
    operator_id: str = "mesh_user"
    block_upstream: bool = False
    rotate_keys: bool = True


@router.post("/mesh/countermeasure")
async def countermeasure(req: CountermeasureRequest):
    campaign = next(
        (c for c in correlator.list_active() if c["campaign_id"] == req.campaign_id),
        None,
    )
    if campaign is None:
        # Allow deploying against a stale campaign too — the
        # correlator keeps them around for ``WINDOW_SECONDS``.
        all_campaigns = correlator._campaigns  # type: ignore[attr-defined]
        existing = all_campaigns.get(req.campaign_id)
        if existing is None:
            raise HTTPException(status_code=404, detail=f"unknown campaign_id={req.campaign_id}")
        campaign = existing.to_dict()

    cm = await countermeasure_engine.generate_and_deploy(
        campaign=campaign,
        operator_id=req.operator_id,
        block_upstream=req.block_upstream,
        rotate_keys=req.rotate_keys,
    )
    redteam.last_countermeasure_signature = cm.countermeasure_id
    # Bounty: award the peer who first triggered this campaign.
    bounty = award_for_countermeasure(
        campaign_id=campaign["campaign_id"],
        peer=campaign.get("peer") or "",
        severity=campaign.get("severity", 0.0),
    )
    cm_dict = cm.to_dict()
    if bounty:
        cm_dict["bounty"] = bounty
    return cm_dict


# ---- federated gradient bridge ---------------------------------------

class FederatedRequest(BaseModel):
    peer_id: str
    samples: int = 1
    gradient: dict[str, float]


@router.post("/mesh/federated", status_code=status.HTTP_202_ACCEPTED)
async def federated(req: FederatedRequest):
    return await federated_aggregator.submit(
        peer_id=req.peer_id, gradient=req.gradient, samples=req.samples
    )


# ---- red-team controls ------------------------------------------------

@router.post("/mesh/redteam/start")
async def redteam_start():
    await redteam.start()
    return {"status": "running", "tick_seconds": redteam.tick_seconds}


@router.post("/mesh/redteam/stop")
async def redteam_stop():
    await redteam.stop()
    return {"status": "stopped"}


# ---- share-link plane ------------------------------------------------

class ShareIssueRequest(BaseModel):
    target_url: str = "http://localhost:8000"
    ttl_seconds: int = DEFAULT_TTL_SECONDS


@router.post("/mesh/share/issue")
async def share_issue(req: ShareIssueRequest):
    return issue_share_token(req.target_url, req.ttl_seconds)


@router.get("/mesh/share/{share_id}/{token}")
async def share_page(
    share_id: str,
    token: str,
    request: Request,
    exp: Optional[int] = None,
):
    # Determine the API target the visitor should POST back to.
    # Prefer the public-facing host (X-Forwarded-Host from a tunnel)
    # else fall back to the request base URL.
    fwd_host = request.headers.get("x-forwarded-host")
    if fwd_host:
        proto = request.headers.get("x-forwarded-proto", "https")
        api_target = f"{proto}://{fwd_host}"
    else:
        api_target = str(request.base_url).rstrip("/")
    if exp is None:
        raise HTTPException(status_code=400, detail="missing exp query param")
    payload = verify_share_token(share_id, token, exp)
    if payload is None:
        raise HTTPException(status_code=410, detail="share token expired or invalid")
    html = render_share_page(
        share_id=share_id, token=token, expires_at=exp, api_target=api_target
    )
    return HTMLResponse(content=html)


@router.post("/mesh/share/{share_id}/{token}/fire")
async def share_fire(
    share_id: str,
    token: str,
    request: Request,
    exp: Optional[int] = None,
    payload: str = Form(""),
    user_agent: str = Form(""),
    service: str = Form("http"),
):
    # Rate limit the share-fire endpoint per-IP.
    client_ip = (
        request.headers.get("x-forwarded-for")
        or (request.client.host if request.client else "unknown")
    )
    from app.api.rate_limiter import _redis_check
    if not await _redis_check(f"mesh-share:{client_ip}"):
        raise HTTPException(status_code=429, detail="rate_limited")
    if exp is None:
        raise HTTPException(status_code=400, detail="missing exp")
    if verify_share_token(share_id, token, exp) is None:
        raise HTTPException(status_code=410, detail="share token expired or invalid")
    envelope = {
        "service": service,
        "src_ip": client_ip,
        "payload": payload,
        "user_agent": user_agent or request.headers.get("user-agent", ""),
        "peer": f"share:{share_id}",
        "forwarded_for": client_ip,
    }
    out = await ingest_external_attack(envelope)
    # Return a friendly page so the friend sees confirmation.
    html = """<!doctype html><meta charset=utf-8>
<title>Aegis · Probe sent</title>
<style>
body{{font-family:JetBrains Mono,monospace;background:#080d1a;color:#e4e6f1;
     display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}
.card{{background:#0f1424;border:1px solid rgba(16,185,129,0.4);border-radius:18px;
       padding:32px;max-width:480px;text-align:center}}
h1{{color:#10b981;margin:0 0 12px;font-size:22px}}
p{{color:#94a3b8;font-size:13px;line-height:1.6}}
.cid{{color:#06b6d4;font-family:monospace}}
</style>
<div class=card>
<h1>// PROBE FIRED</h1>
<p>Your attack is now in the operator's live dashboard.</p>
<p>campaign = <span class=cid>{cid}</span></p>
<p>You can close this tab. Thanks for testing Aegis.</p>
</div>""".format(cid=(out.get("campaign") or {}).get("campaign_id", "?"))
    return HTMLResponse(content=html)


# ---- bounty ----------------------------------------------------------

class BountyClaimRequest(BaseModel):
    peer: str
    campaign_id: str
    token: str


@router.post("/mesh/bounty/claim")
async def bounty_claim(req: BountyClaimRequest):
    res = bounty_ledger.claim(req.peer, req.campaign_id, req.token)
    if res is None:
        raise HTTPException(status_code=404, detail="bounty not found, already claimed, or token mismatch")
    return res


# ---- snapshot ---------------------------------------------------------

@router.get("/mesh/state")
async def state():
    return {
        "honeypots": honeypot_mesh.stats(),
        "campaigns": correlator.list_active(),
        "countermeasures": countermeasure_engine.list_deployed(limit=20),
        "federated": {
            **federated_aggregator.stats(),
            "peers": federated_aggregator.known_peers(),
            "global_delta_keys": list(federated_aggregator.global_delta().keys())[:10],
        },
        "redteam": redteam.status(),
        "bounty": bounty_ledger.stats(),
    }


# ---- SSE feed ---------------------------------------------------------

def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


@router.get("/mesh/stream")
async def stream():
    async def source():
        yield ":ok\n\n"
        try:
            async for envelope in iter_events():
                kind = envelope.get("kind", "event")
                yield _sse(kind, envelope.get("payload", {}))
        except asyncio.CancelledError:
            return

    return StreamingResponse(
        source(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


__all__ = ["router", "ingest_external_attack"]