"""Telemetry ingest endpoint.

POST /api/ingest accepts a ``TrafficFeatures`` payload (optionally
enriched with raw device metadata), validates the caller's
``X-API-Key``, applies the per-key/IP rate limit, and pushes the
event onto the ``ingest`` Redis Stream (or the in-process fallback
queue when Redis is unavailable).

Behaviour:
  * 202 Accepted — event successfully enqueued
  * 401 Unauthorized — missing/invalid ``X-API-Key`` (when one is
    configured via ``DETECT_API_KEY``)
  * 429 Too Many Requests — over rate limit OR backlog exceeds the
    ``INGEST_BACKLOG_LIMIT`` threshold (backpressure)
  * 500 Internal Server Error — unhandled validation/error

The endpoint deliberately does NOT run the detector inline — that is
the responsibility of ``backend/online_detector.py`` (milestone 3).
For local dev where no Redis is available, ``?enqueue=false`` still
runs the model synchronously and returns the detection result, so
the page-level "Send Event" demo flow keeps working.
"""

from __future__ import annotations

import hmac
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from fastapi.responses import JSONResponse

from app.api.deps import get_detector
from app.api.rate_limiter import get_quota_for_key, rate_limit
from app.config import settings
from app.ml.detector import AegisIDSDetector, TrafficFeatures
from app.streams import append, is_overloaded

router = APIRouter()


def _check_api_key(x_api_key: Optional[str]) -> None:
    """Validate the ``X-API-Key`` header against ``settings.DETECT_API_KEY``.

    Uses ``hmac.compare_digest`` for constant-time comparison.
    If ``DETECT_API_KEY`` is unset (typical for local dev) the check
    is skipped so the demo page still works — but operators should
    always set one in non-dev environments.
    """
    expected = settings.DETECT_API_KEY
    if not expected:
        return
    if not x_api_key or not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key",
            headers={"WWW-Authenticate": "ApiKey"},
        )


@router.post("/ingest", status_code=status.HTTP_202_ACCEPTED)
async def ingest_event(
    traffic: TrafficFeatures,
    source_ip: Optional[str] = Query(default="unknown"),
    enqueue: Optional[bool] = Query(default=True),
    x_api_key: Optional[str] = Header(default=None, convert_underscores=False, alias="X-API-Key"),
    _: None = Depends(rate_limit),
    detector: AegisIDSDetector = Depends(get_detector),
):
    """Push the telemetry event onto the ingest stream.

    Query params:
      * ``source_ip`` — caller-supplied source IP for audit logging
      * ``enqueue=true`` (default) — async via Redis Stream
      * ``enqueue=false`` — run the detector inline (sync fallback
        used by the homepage "Send Event" widget)
    """
    _check_api_key(x_api_key)

    payload = {
        "features": traffic.model_dump(),
        "meta": {"source_ip": source_ip},
    }

    if enqueue:
        # Backpressure: refuse new work when the queue is already at
        # the soft limit. Keeps the worker from drowning.
        if await is_overloaded("ingest"):
            quota = await get_quota_for_key(x_api_key or source_ip or "unknown")
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "status": "backpressure",
                    "detail": "Ingest stream is full; retry later.",
                    "quota": quota,
                },
            )
        try:
            entry_id = await append("ingest", payload, maxlen=10_000)
            return {
                "status": "enqueued",
                "stream": "ingest",
                "entry_id": entry_id,
            }
        except Exception as exc:
            # Stream write failed — fall through to synchronous path
            # so the caller still gets a result.
            print(f"[!] ingest stream append failed: {exc}; running sync")

    # Synchronous fallback (also the path used when enqueue=false)
    try:
        result = detector.predict(traffic)
        return {"status": "processed", "detection": result.dict()}
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )


@router.get("/ingest/quota")
async def quota(x_api_key: Optional[str] = Header(default=None, convert_underscores=False, alias="X-API-Key")):
    """Return rate-limit quota for the caller (key or IP)."""
    return {"quota": await get_quota_for_key(x_api_key or "ip")}


# Re-export the router so ``main.py`` can include it.
__all__ = ["router"]
