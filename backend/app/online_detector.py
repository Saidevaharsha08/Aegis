"""Online detector: consumes the ``ingest`` stream, runs inference, emits detections.

Architecture
------------
* :func:`consume_forever` is a long-running asyncio task that reads
  entries from the ``ingest`` stream (see ``app.streams``), runs
  XGBoost inference on each, and emits a detection envelope onto the
  ``detections`` stream. The envelope includes a ``detection_id`` and
  a SHAP top-5 summary so the frontend can render explanations
  without recomputing SHAP.

* :func:`iter_detections` is the async generator backing
  ``GET /api/stream/detections`` (Server-Sent Events). It yields
  ``(event_id, payload_dict)`` tuples that the route formats as
  SSE frames.

* :class:`DetectionSubscriber` is a tiny pub/sub registry used by the
  SSE endpoint to fan out new detections to many concurrent clients
  without each one hammering Redis directly.

The composite decision is intentionally simple — XGBoost classifier
probability is the primary signal. A future revision can fold in
PyOD anomaly scores and River online-learning deltas; the seam is
already in place at ``_score_composite``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, AsyncIterator, Optional

from app.config import settings
from app.explain_cache import explain_cache, summarize_shap
from app.ml.detector import AegisIDSDetector, TrafficFeatures
from app.streams import append, iter_stream, length

log = logging.getLogger(__name__)


def _score_composite(classifier_score: float, anomaly_score: float | None) -> float:
    """Combine classifier probability with an optional anomaly score.

    Today both signals are mapped onto ``[0, 1]`` and weighted
    (XGBoost 0.85, anomaly 0.15) to keep stability when the anomaly
    model is missing or uncalibrated. The seam is here so a future
    revision can swap the heuristic for a calibrated blend.
    """
    if anomaly_score is None:
        return classifier_score
    a = max(0.0, min(1.0, anomaly_score))
    c = max(0.0, min(1.0, classifier_score))
    return round(0.85 * c + 0.15 * a, 6)


class DetectionSubscriber:
    """In-process pub/sub for SSE clients."""

    def __init__(self) -> None:
        self._subs: set[asyncio.Queue] = set()
        self._lock = asyncio.Lock()

    async def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=64)
        async with self._lock:
            self._subs.add(q)
        return q

    async def unsubscribe(self, q: asyncio.Queue) -> None:
        async with self._lock:
            self._subs.discard(q)

    async def publish(self, payload: dict[str, Any]) -> None:
        async with self._lock:
            dead = []
            for q in self._subs:
                try:
                    q.put_nowait(payload)
                except asyncio.QueueFull:
                    dead.append(q)
            for q in dead:
                self._subs.discard(q)


detection_subscribers = DetectionSubscriber()


async def process_one(detector: AegisIDSDetector, raw_payload: dict[str, Any]) -> dict[str, Any]:
    """Run inference on a single ingest payload and return a detection envelope."""
    features = raw_payload.get("features") or {}
    source_ip = (raw_payload.get("meta") or {}).get("source_ip", "unknown")
    traffic = TrafficFeatures(**features)
    result = detector.predict(traffic)
    detection_id = explain_cache.make_id(features)

    top = [
        {"feature": f.feature, "value": f.value, "shap_value": f.shap_value}
        for f in result.top_features
    ]
    summary = summarize_shap(top, limit=5)

    envelope = {
        "detection_id": detection_id,
        "timestamp": time.time(),
        "source_ip": source_ip,
        "threat_detected": result.threat_detected,
        "threat_score": result.threat_score,
        "attack_type": result.attack_type,
        "confidence": result.confidence,
        "inference_latency_ms": result.inference_latency_ms,
        "model_version": result.model_version,
        "top_features": summary,
    }
    # Prometheus instrumentation.
    try:
        from app.metrics import record_detection
        record_detection(
            attack_type=result.attack_type,
            threat_detected=result.threat_detected,
            latency_ms=result.inference_latency_ms,
        )
    except Exception:
        pass
    explain_cache.put(
        detection_id,
        {
            "detection_id": detection_id,
            "features": features,
            "top_features": summary,
            "threat_score": result.threat_score,
            "attack_type": result.attack_type,
            "model_version": result.model_version,
        },
    )
    return envelope


async def consume_forever(detector: Optional[AegisIDSDetector] = None) -> None:
    """Long-running consumer; should be scheduled as an asyncio task."""
    from app.ml.detector import detector_engine

    engine = detector or detector_engine
    if not engine.is_loaded:
        engine.load_model()

    log.info("[online_detector] consuming 'ingest' stream")
    async for entry_id, fields in iter_stream("ingest", last_id="$", block_ms=1000):
        raw = fields.get("payload") if isinstance(fields, dict) else None
        if raw is None:
            continue
        try:
            payload = json.loads(raw) if isinstance(raw, str) else raw
        except Exception as exc:
            log.warning("[online_detector] bad payload at %s: %s", entry_id, exc)
            continue
        try:
            envelope = await process_one(engine, payload)
        except Exception as exc:
            log.exception("[online_detector] inference failed: %s", exc)
            continue
        # Emit to the in-process subscribers AND onto the
        # ``detections`` stream so SSE clients that connect later
        # (or external workers) can still see the most recent events.
        await detection_subscribers.publish(envelope)
        try:
            await append("detections", envelope, maxlen=10_000)
        except Exception as exc:
            log.warning("[online_detector] failed to append to detections stream: %s", exc)


async def iter_detections(last_id: str = "$") -> AsyncIterator[dict[str, Any]]:
    """Async generator yielding detection envelopes.

    Subscribes to in-process pub/sub so newly processed detections
    stream in real time. On unsubscribe the queue is cleaned up.
    """
    q = await detection_subscribers.subscribe()
    try:
        # First, replay any persisted entries from the ``detections``
        # stream so reconnects don't miss history (best-effort).
        from app.streams import read as stream_read
        replay = await stream_read("detections", last_id=last_id, block_ms=0, count=20)
        for _eid, fields in replay:
            raw = fields.get("payload") if isinstance(fields, dict) else None
            if raw is None:
                continue
            try:
                yield json.loads(raw) if isinstance(raw, str) else raw
            except Exception:
                continue
        # Then tail the live stream.
        while True:
            envelope = await q.get()
            yield envelope
    finally:
        await detection_subscribers.unsubscribe(q)


async def start_background_consumer() -> asyncio.Task:
    """Schedule the consumer on the running event loop and return its Task."""
    return asyncio.create_task(consume_forever(), name="online-detector-consumer")


def ingest_backlog() -> int:
    """Sync helper for metrics — current length of the ingest stream."""
    try:
        return asyncio.get_event_loop().run_until_complete(length("ingest"))
    except RuntimeError:
        # No running loop (e.g., during boot); report 0.
        return 0


__all__ = [
    "consume_forever",
    "process_one",
    "iter_detections",
    "start_background_consumer",
    "detection_subscribers",
    "ingest_backlog",
]
