"""Explain cache: precomputed SHAP top-N summaries keyed by detection id.

The online detector (milestone 3) emits each detection with a unique
``detection_id`` and a SHAP summary. Storing the summary in a small
in-memory cache keeps the GET endpoint fast and avoids re-running
SHAP for already-explained detections.

Capacity: ``MAX_ENTRIES`` most-recently-used entries are kept. When
the cap is hit, the oldest entry is evicted. This is intentional —
the cache is sized for a working set (typically the last few minutes
of detections), not for replaying history.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import OrderedDict
from typing import Any, Optional


MAX_ENTRIES = 1024


class ExplainCache:
    """Thread-safe LRU cache for detection explanations."""

    def __init__(self, capacity: int = MAX_ENTRIES):
        self.capacity = capacity
        self._lock = threading.Lock()
        self._store: "OrderedDict[str, dict[str, Any]]" = OrderedDict()

    def make_id(self, features: dict[str, Any]) -> str:
        """Derive a stable id from a feature vector."""
        h = hashlib.sha256()
        h.update(json.dumps(features, sort_keys=True, default=str).encode("utf-8"))
        return h.hexdigest()[:16]

    def put(self, detection_id: str, payload: dict[str, Any]) -> None:
        with self._lock:
            if detection_id in self._store:
                # Refresh recency
                self._store.move_to_end(detection_id)
                self._store[detection_id].update(payload)
                self._store[detection_id]["updated_at"] = time.time()
                return
            self._store[detection_id] = {**payload, "created_at": time.time()}
            self._store.move_to_end(detection_id)
            while len(self._store) > self.capacity:
                self._store.popitem(last=False)

    def get(self, detection_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            entry = self._store.get(detection_id)
            if entry is None:
                return None
            self._store.move_to_end(detection_id)
            return dict(entry)

    def delete(self, detection_id: str) -> bool:
        with self._lock:
            return self._store.pop(detection_id, None) is not None

    def size(self) -> int:
        with self._lock:
            return len(self._store)


# Module-level singleton.
explain_cache = ExplainCache()


def summarize_shap(top_features: list[dict[str, Any]], limit: int = 5) -> list[dict[str, Any]]:
    """Pick the top-N features by absolute SHAP value.

    ``top_features`` is a list of dicts shaped like:
        {"feature": str, "value": float, "shap_value": float}
    """
    if not top_features:
        return []
    ranked = sorted(top_features, key=lambda f: abs(f.get("shap_value", 0.0)), reverse=True)
    return [
        {
            "feature": str(f.get("feature", "")),
            "value": float(f.get("value", 0.0)),
            "shap_value": float(f.get("shap_value", 0.0)),
        }
        for f in ranked[:limit]
    ]


__all__ = ["ExplainCache", "explain_cache", "summarize_shap"]
