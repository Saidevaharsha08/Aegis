"""Prometheus metrics for the streaming detection pipeline.

Exposed via ``GET /metrics`` (text/plain; version=0.0.4). The
counters and gauges are deliberately small — the goal is observability
for the pipeline, not a full APM replacement.

Metrics:
  * ``aegis_ingest_queue_length`` — current length of the ``ingest``
    Redis Stream (or in-process fallback).
  * ``aegis_detections_total{attack_type,threat}`` — count of
    detections processed, labeled by ``attack_type`` and the boolean
    ``threat`` (``true``/``false``).
  * ``aegis_inference_latency_ms`` — histogram of inference latency
    per detection.
  * ``aegis_fpr_total`` / ``aegis_tpr_total`` — running counts fed by
    the retrain worker and the labels stream.
"""

from __future__ import annotations

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest


INGEST_QUEUE_LENGTH = Gauge(
    "aegis_ingest_queue_length",
    "Current number of entries in the ingest stream",
)

DETECTIONS_TOTAL = Counter(
    "aegis_detections_total",
    "Total detections processed by the online detector",
    ["attack_type", "threat"],
)

INFERENCE_LATENCY_MS = Histogram(
    "aegis_inference_latency_ms",
    "Per-detection inference latency in milliseconds",
    buckets=(0.5, 1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500),
)

FPR_TOTAL = Counter(
    "aegis_fpr_total",
    "Operator-labeled false positives (feedback)",
)

TPR_TOTAL = Counter(
    "aegis_tpr_total",
    "Operator-labeled true positives (feedback)",
)


def record_detection(attack_type: str, threat_detected: bool, latency_ms: float) -> None:
    DETECTIONS_TOTAL.labels(attack_type=attack_type or "UNKNOWN", threat=str(bool(threat_detected)).lower()).inc()
    INFERENCE_LATENCY_MS.observe(float(latency_ms or 0.0))


def record_label(label: str) -> None:
    if label == "true_positive":
        TPR_TOTAL.inc()
    elif label == "false_positive":
        FPR_TOTAL.inc()


def render() -> tuple[bytes, str]:
    """Return ``(body, content_type)`` for the FastAPI route."""
    return generate_latest(), CONTENT_TYPE_LATEST


__all__ = [
    "INGEST_QUEUE_LENGTH",
    "DETECTIONS_TOTAL",
    "INFERENCE_LATENCY_MS",
    "FPR_TOTAL",
    "TPR_TOTAL",
    "record_detection",
    "record_label",
    "render",
]
