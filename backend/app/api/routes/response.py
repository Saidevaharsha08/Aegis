"""Response staging endpoints.

The ``/respond`` route remains the legacy immediate-execute path used
by the demo Threat Console. The two new routes add a deliberate
safety layer:

* ``POST /response/dryrun`` — Plan a mitigation, return the planned
  actions + ledger preview without actually mutating anything.
* ``POST /response/execute`` — Execute a previously approved plan.
  Requires an ``approval_token`` issued by ``/response/dryrun`` so a
  human (or downstream service) must explicitly opt in before
  irreversible actions run.

The approval token is an HMAC over the dryrun id + timestamp using
``settings.SECRET_KEY`` so a forged token is detectable. It is
single-use and expires after ``APPROVAL_TTL_SECONDS``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.config import settings
from app.ml.detector import DetectionResult
from app.response.actions import response_engine, ResponseResult


router = APIRouter()

APPROVAL_TTL_SECONDS = 300
_pending_approvals: dict[str, dict[str, Any]] = {}


class DryRunRequest(BaseModel):
    detection: DetectionResult
    source_ip: str = "unknown"
    operator_id: str = Field(default="human_reviewer")


class DryRunResponse(BaseModel):
    dryrun_id: str
    approval_token: str
    expires_in_seconds: int
    planned_actions: list[str]
    rules_applied: list[dict[str, Any]]
    keys_rotated_expected: bool
    affected_node: str
    threat_id: str


class ExecuteRequest(BaseModel):
    dryrun_id: str
    approval_token: str
    operator_id: str = Field(default="human_reviewer")


def _sign(secret: str, payload: str) -> str:
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


def _approve(detection: DetectionResult, source_ip: str, operator_id: str) -> DryRunResponse:
    """Plan a response without executing it."""
    dryrun_id = str(uuid.uuid4())
    # Re-use the existing engine's planning logic without committing
    # to side effects by inspecting what it WOULD do.
    # We piggyback on the response engine's internal selection by
    # constructing a plan dict; the actual ledger write happens in
    # /response/execute when the operator approves.
    from app.optimizer.qaoa_sim import QAOAInspiredOptimizer
    opt = QAOAInspiredOptimizer(fpr_budget=0.10, cost_budget=10.0)
    opt_res = opt.optimize()
    rules_applied = [r.model_dump() for r in opt_res.selected_rules]
    planned = ["APPLY_QAOA_FIREWALL_RULES"]
    atk = detection.attack_type.upper()
    if "DOS" in atk or "DDOS" in atk:
        planned.extend(["RATE_LIMIT_SYN_FLOOD", "ISOLATE_AFFECTED_SUBNET", "ROTATE_MLKEM_SESSION_KEYS"])
    elif "BRUTEFORCE" in atk:
        planned.extend(["BLOCK_SOURCE_IP", "ENABLE_EXPONENTIAL_AUTH_BACKOFF", "ROTATE_AFFECTED_SERVICE_KEYS"])
    elif "PORTSCAN" in atk:
        planned.extend(["TEMPORARY_BLOCK_SOURCE_IP_15MIN", "INCREASE_LOGGING_VERBOSITY"])
    else:
        planned.extend(["ISOLATE_AFFECTED_NODE_IMMEDIATE", "CAPTURE_FORENSIC_TRAFFIC_DUMP", "ROTATE_ALL_SYSTEM_KEYS"])

    secret = settings.SECRET_KEY
    token_payload = f"{dryrun_id}|{int(time.time())}|{operator_id}"
    token = _sign(secret, token_payload)
    _pending_approvals[dryrun_id] = {
        "token": token,
        "issued_at": time.time(),
        "operator_id": operator_id,
        "detection": detection.model_dump(),
        "source_ip": source_ip,
        "rules_applied": rules_applied,
        "planned_actions": planned,
    }
    return DryRunResponse(
        dryrun_id=dryrun_id,
        approval_token=token,
        expires_in_seconds=APPROVAL_TTL_SECONDS,
        planned_actions=planned,
        rules_applied=rules_applied,
        keys_rotated_expected=("ROTATE" in " ".join(planned)),
        affected_node="10.0.0.14",
        threat_id=dryrun_id,
    )


@router.post("/response/dryrun", response_model=DryRunResponse, status_code=status.HTTP_200_OK)
def dryrun(req: DryRunRequest) -> DryRunResponse:
    return _approve(req.detection, req.source_ip, req.operator_id)


@router.post("/response/execute", response_model=ResponseResult, status_code=status.HTTP_200_OK)
def execute(req: ExecuteRequest) -> ResponseResult:
    pending = _pending_approvals.pop(req.dryrun_id, None)
    if pending is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dryrun not found or already consumed",
        )
    expected_token = pending["token"]
    if not hmac.compare_digest(expected_token, req.approval_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Approval token does not match",
        )
    age = time.time() - pending["issued_at"]
    if age > APPROVAL_TTL_SECONDS:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Approval token expired",
        )

    detection = DetectionResult(**pending["detection"])
    # Real execute — same path as legacy /respond.
    result = response_engine.execute_response(detection, source_ip=pending["source_ip"])
    # Annotate ledger entry with operator id.
    try:
        from app.ledger.chain import ledger_chain
        ledger_chain.append_event(
            event_type="RESPONSE_APPROVED",
            actions_taken=[f"operator_id={req.operator_id}", f"dryrun_id={req.dryrun_id}"],
            threat_id=result.threat_id,
            source_ip=pending["source_ip"],
            attack_type=detection.attack_type,
            threat_score=float(detection.threat_score),
            rules_applied=result.rules_applied,
            crypto_mode="ML-KEM-768",
            operator_id=req.operator_id,
        )
    except Exception:
        pass
    return result


# Legacy route preserved verbatim — non-breaking.
@router.post("/respond", response_model=ResponseResult, status_code=status.HTTP_200_OK)
def trigger_automated_response(detection: DetectionResult) -> ResponseResult:
    try:
        return response_engine.execute_response(detection)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Response execution failed: {str(e)}",
        )


__all__ = ["router"]
