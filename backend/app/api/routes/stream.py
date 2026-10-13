"""SSE + explain endpoints for the streaming detection pipeline.

* ``GET /stream/detections`` — Server-Sent Events feed of detection
  envelopes as they are produced by ``online_detector.consume_forever``.
  Each event is JSON-encoded and prefixed with ``event: detection``.
* ``GET /detection/{detection_id}/explain`` — Returns the cached SHAP
  top-5 summary for the given detection id (404 if evicted or never
  seen).
* ``POST /labels`` — Accept operator True/False labels for a detection.
  The label is appended to a Redis Stream named ``labels`` so the
  retrain worker can consume it.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Optional

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.explain_cache import explain_cache
from app.online_detector import iter_detections
from app.streams import append, length

log = logging.getLogger(__name__)

router = APIRouter()


def _sse(event: str, data: dict) -> str:
    """Format a single SSE frame."""
    payload = json.dumps(data, default=str)
    return f"event: {event}\ndata: {payload}\n\n"


@router.get("/stream/detections")
async def stream_detections():
    """Tail the live detection stream as SSE."""
    async def event_source():
        # Initial comment to force headers through some proxies.
        yield ":ok\n\n"
        try:
            async for envelope in iter_detections():
                yield _sse("detection", envelope)
        except asyncio.CancelledError:
            log.info("SSE client disconnected")
            return

    return StreamingResponse(
        event_source(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@router.get("/detection/{detection_id}/explain")
async def get_explain(detection_id: str):
    entry = explain_cache.get(detection_id)
    if entry is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No explanation cached for detection_id={detection_id}",
        )
    return entry


class LabelRequest(BaseModel):
    detection_id: str
    label: str  # 'true_positive' | 'false_positive'
    source_ip: str = "unknown"
    operator_id: str = "frontend_user"


@router.post("/labels", status_code=status.HTTP_202_ACCEPTED)
async def submit_label(req: LabelRequest):
    if req.label not in {"true_positive", "false_positive"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="label must be 'true_positive' or 'false_positive'",
        )
    payload = {
        "detection_id": req.detection_id,
        "label": req.label,
        "source_ip": req.source_ip,
        "operator_id": req.operator_id,
        "timestamp": time.time(),
    }
    try:
        from app.metrics import record_label
        record_label(req.label)
    except Exception:
        pass
    try:
        await append("labels", payload, maxlen=50_000)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"failed to append label: {exc}",
        )
    return {
        "status": "enqueued",
        "buffer_size": await length("labels"),
    }


@router.get("/metrics")
async def metrics_endpoint():
    """Prometheus metrics (text/plain; version=0.0.4)."""
    from fastapi.responses import Response
    from app.metrics import INGEST_QUEUE_LENGTH, render
    # Update the queue-length gauge eagerly so dashboards are not
    # stale; cheap XLEN on Redis / qsize() on fallback.
    try:
        INGEST_QUEUE_LENGTH.set(await length("ingest"))
    except Exception:
        pass
    body, content_type = render()
    return Response(content=body, media_type=content_type)


__all__ = ["router"]
