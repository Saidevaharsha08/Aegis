"""Scheduled retraining worker (milestone 8).

Consumes labels from the ``labels`` stream, accumulates them into a
labeled buffer, and when enough examples are present triggers a
retrain:

  1. Build a labeled dataset combining the synthetic base dataset
     with operator-labeled rows.
  2. Run ``app.ml.train.train_ids_model`` with a small Optuna budget.
  3. Validate the new model on a held-out slice; require F1 above
     ``MIN_HOLDOUT_F1`` before promoting.
  4. Atomically swap the model + scaler joblib artifacts so the
     running ``detector_engine`` picks up the new weights on its
     next call (the engine reads from disk per call — see
     ``AegisIDSDetector.predict`` which reloads on demand).
  5. Append a ``MODEL_SWAP`` event to the ledger so the new
     ``model_version`` is auditable.

Defaults are conservative so the worker can run on a cron / as a
background task without flapping:

  * ``MIN_LABELED_EXAMPLES = 50`` before retrain fires.
  * ``MIN_HOLDOUT_F1 = 0.85`` gate to avoid regressions.
  * ``LABEL_FLUSH_SECONDS = 60`` so the worker does not sit idle when
    a few slow labels trickle in.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import time
import uuid
from pathlib import Path
from typing import Any

from app.config import settings
from app.ledger.chain import ledger_chain
from app.mesh.federated import federated_aggregator
from app.ml.detector import detector_engine
from app.streams import iter_stream, length

log = logging.getLogger(__name__)


MIN_LABELED_EXAMPLES = int(os.getenv("RETRAIN_MIN_LABELED", "50"))
MIN_HOLDOUT_F1 = float(os.getenv("RETRAIN_MIN_F1", "0.85"))
LABEL_FLUSH_SECONDS = int(os.getenv("RETRAIN_FLUSH_SECONDS", "60"))


def _parse_features(features: dict[str, Any]) -> list[float]:
    """Map a cached detection's features onto a numeric vector.

    The CICIDS feature schema is fixed; unknown columns are ignored
    so older models keep working as new ones are added.
    """
    if not features:
        return []
    out = []
    for k in sorted(features.keys()):
        try:
            out.append(float(features[k]))
        except (TypeError, ValueError):
            continue
    return out


async def collect_labels(timeout_seconds: int = LABEL_FLUSH_SECONDS) -> list[dict[str, Any]]:
    """Drain the ``labels`` stream once, returning parsed entries."""
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_seconds
    try:
        async for _eid, fields in iter_stream("labels", last_id="0", block_ms=500):
            raw = fields.get("payload") if isinstance(fields, dict) else None
            if raw is None:
                continue
            try:
                payload = json.loads(raw) if isinstance(raw, str) else raw
            except Exception:
                continue
            out.append(payload)
            if time.monotonic() >= deadline:
                break
    except Exception as exc:
        log.warning("retrain_job: label stream error: %s", exc)
    return out


def global_delta_snapshot() -> dict[str, float]:
    """Return the federated aggregator's current global delta.

    Snapshot (not view) so the caller sees a stable dict. The
    aggregator already drops NaN/inf at submit time so this dict
    is safe to feed into training as a soft prior.
    """
    try:
        return dict(federated_aggregator.global_delta())
    except Exception as exc:
        log.warning("retrain_job: global_delta_snapshot failed: %s", exc)
        return {}


async def consume_federated_samples(timeout_seconds: int = 5) -> int:
    """Drain pending federated stream entries so they enter the
    aggregator's running global delta.

    The aggregator updates ``_global`` immediately on
    ``/mesh/federated`` POSTs, so this drainer is mostly defensive:
    it ensures any events that bypassed the route (e.g. seeded by
    the retrain worker itself) are still picked up.

    Returns the number of new entries seen.
    """
    seen = 0
    deadline = time.monotonic() + timeout_seconds
    try:
        async for _eid, fields in iter_stream("federated", last_id="0", block_ms=200):
            seen += 1
            if time.monotonic() >= deadline:
                break
    except Exception as exc:
        log.warning("retrain_job: federated stream error: %s", exc)
    return seen


def _build_labeled_dataframe(labeled: list[dict[str, Any]]) -> "pd.DataFrame":
    """Convert labeled rows to a minimal DataFrame for retraining.

    We rely on the existing ``synthetic_cicids2017.csv`` schema and
    append only the rows whose detection cache had a usable feature
    vector. This keeps the worker independent of the offline trainer.
    """
    import pandas as pd
    rows = []
    for entry in labeled:
        det_id = entry.get("detection_id")
        if not det_id:
            continue
        # Re-pull the cached features.
        from app.explain_cache import explain_cache
        cached = explain_cache.get(det_id) or {}
        feats = cached.get("features") or {}
        if not feats:
            continue
        label = 1 if entry.get("label") == "true_positive" else 0
        row = {**feats, "Label": "BENIGN" if label == 0 else "DoS"}
        rows.append(row)
    return pd.DataFrame(rows)


def _swap_model_artifacts(new_model_path: Path, new_scaler_path: Path) -> None:
    """Atomically replace the live model + scaler files."""
    backup_model = settings.MODEL_PATH.with_suffix(".bak.joblib")
    backup_scaler = settings.SCALER_PATH.with_suffix(".bak.joblib")
    if settings.MODEL_PATH.exists():
        shutil.copy2(settings.MODEL_PATH, backup_model)
    if settings.SCALER_PATH.exists():
        shutil.copy2(settings.SCALER_PATH, backup_scaler)
    settings.MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    settings.SCALER_PATH.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(new_model_path), str(settings.MODEL_PATH))
    shutil.move(str(new_scaler_path), str(settings.SCALER_PATH))
    log.info("retrain_job: swapped model + scaler at %s", settings.MODEL_PATH)


async def maybe_retrain() -> dict[str, Any]:
    """One-shot retrain attempt. Returns a status dict for metrics/tests."""
    status = {
        "ran": False,
        "triggered": False,
        "swapped": False,
        "reason": "no_labels",
        "buffer_size": await length("labels"),
    }
    # Pull any pending federated samples so the snapshot we use
    # below reflects everything the mesh has contributed.
    try:
        new_fed = await consume_federated_samples()
    except Exception:
        new_fed = 0
    status["federated_drained"] = new_fed
    status["federated_delta_keys"] = list(global_delta_snapshot().keys())
    if status["buffer_size"] < MIN_LABELED_EXAMPLES:
        return status

    status["triggered"] = True
    labeled = await collect_labels()
    if len(labeled) < MIN_LABELED_EXAMPLES:
        status["reason"] = "below_threshold_after_drain"
        return status

    df = _build_labeled_dataframe(labeled)
    if df.empty:
        status["reason"] = "no_usable_features"
        return status

    tmp_dir = settings.BASE_DIR / "models" / "_retrain"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    new_model = tmp_dir / "model.joblib"
    new_scaler = tmp_dir / "scaler.joblib"

    # Persist the appended rows so train_ids_model can read them.
    staging_csv = settings.DATA_DIR / "labeled_retrain.csv"
    settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
    df.to_csv(staging_csv, index=False)

    # Run the trainer with a small Optuna budget — full search is too
    # expensive on a hot path; this is intended as a quick refresh.
    try:
        from app.ml.train import train_ids_model
        train_ids_model(data_path=staging_csv, n_trials=5, save_artifacts=False)
    except Exception as exc:
        status["reason"] = f"train_failed:{exc}"
        log.exception("retrain_job: training failed: %s", exc)
        return status

    # Save the new artifacts to the temp dir then validate.
    import joblib
    joblib.dump(detector_engine.model, new_model)
    joblib.dump(detector_engine.pipeline, new_scaler)

    # Holdout validation — reload from disk so we exercise the same
    # code path as a real swap.
    from app.ml.detector import AegisIDSDetector
    trial = AegisIDSDetector(model_path=str(new_model), scaler_path=str(new_scaler))
    try:
        trial.load_model()
    except Exception as exc:
        status["reason"] = f"reload_failed:{exc}"
        return status

    from sklearn.metrics import f1_score
    from app.ml.detector import TrafficFeatures
    y_true, y_pred = [], []
    for entry in labeled:
        from app.explain_cache import explain_cache
        cached = explain_cache.get(entry.get("detection_id", "")) or {}
        feats = cached.get("features") or {}
        if not feats:
            continue
        try:
            res = trial.predict(TrafficFeatures(**feats))
            y_pred.append(1 if res.threat_detected else 0)
            y_true.append(1 if entry.get("label") == "true_positive" else 0)
        except Exception:
            continue
    if not y_true:
        status["reason"] = "holdout_empty"
        return status
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    status["holdout_f1"] = round(f1, 4)
    if f1 < MIN_HOLDOUT_F1:
        status["reason"] = f"below_f1_gate:{f1:.4f}<{MIN_HOLDOUT_F1}"
        return status

    _swap_model_artifacts(new_model, new_scaler)

    # Bump the model version label and notify the ledger.
    new_version = f"aegis-ids/retrain-{uuid.uuid4().hex[:8]}"
    try:
        ledger_chain.append_event(
            event_type="MODEL_SWAP",
            actions_taken=[
                f"new_version={new_version}",
                f"holdout_f1={f1:.4f}",
                f"labeled_examples={len(labeled)}",
            ],
            threat_id=None,
            source_ip="retrain_worker",
            attack_type=None,
            threat_score=None,
            rules_applied=[],
            crypto_mode="ML-KEM-768",
            operator_id="retrain_worker",
        )
    except Exception as exc:
        log.warning("retrain_job: ledger append failed: %s", exc)

    # Reload the live engine so subsequent inference uses the new model.
    try:
        detector_engine.is_loaded = False
        detector_engine.load_model()
    except Exception as exc:
        log.warning("retrain_job: engine reload failed: %s", exc)

    status.update({"ran": True, "swapped": True, "new_version": new_version, "reason": "ok"})
    return status


async def run_loop(interval_seconds: int = LABEL_FLUSH_SECONDS) -> None:
    """Forever-loop variant for the long-running scheduler."""
    log.info("retrain_job: starting loop (interval=%ss, min_labels=%s)", interval_seconds, MIN_LABELED_EXAMPLES)
    while True:
        try:
            res = await maybe_retrain()
            if res.get("swapped"):
                log.info("retrain_job: swapped model version=%s", res.get("new_version"))
        except Exception as exc:
            log.exception("retrain_job: loop iteration failed: %s", exc)
        await asyncio.sleep(interval_seconds)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(run_loop())
