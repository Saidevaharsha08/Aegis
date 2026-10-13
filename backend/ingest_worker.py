#!/usr/bin/env python3
"""Telemetry Ingest Worker for Aegis IDS.

Consumes telemetry events from Redis Streams / Queues (or in-process fallback)
and runs online XGBoost IDS inference, SHAP explanations, hash ledger logging,
and response playbooks.

Usage:
  python backend/ingest_worker.py
"""
import sys
from pathlib import Path

# Ensure backend folder is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import asyncio
import json
import logging
import time
from typing import Any, Dict

from app.config import settings

log = logging.getLogger("ingest_worker")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


async def process_payload(raw_data: Any) -> None:
    """Processes a single ingest telemetry event."""
    try:
        if isinstance(raw_data, str):
            payload = json.loads(raw_data)
        elif isinstance(raw_data, dict):
            payload = raw_data
        else:
            return

        features = payload.get("features", {})
        source_ip = (payload.get("meta") or {}).get("source_ip", "ingest_worker")

        from app.ml.detector import TrafficFeatures, detector_engine
        from app.ledger.chain import ledger_chain
        from app.response.actions import response_engine

        if not detector_engine.is_loaded:
            detector_engine.load_model()

        tf = TrafficFeatures(**features)
        result = detector_engine.predict(tf)

        ledger_entry = ledger_chain.append_event(
            event_type="INGEST_WORKER_DETECTION",
            actions_taken=["MODEL_INFERENCE"],
            threat_id=None,
            source_ip=source_ip,
            attack_type=result.attack_type,
            threat_score=float(result.threat_score),
            rules_applied=[],
            crypto_mode="ML-KEM-768",
            operator_id="ingest_worker"
        )

        if result.threat_detected:
            resp = response_engine.execute_response(result, source_ip=source_ip)
            resp_id = getattr(resp, "threat_id", "executed")
            log.info("THREAT DETECTED [%s | Score: %.3f] -> Response Playbook Executed (%s)", result.attack_type, result.threat_score, resp_id)
        else:
            log.info("BENIGN EVENT [Score: %.3f] -> Ledger Entry #%s", result.threat_score, ledger_entry.id)

    except Exception as e:
        log.error("Failed to process event payload: %s", e)


async def run_redis_stream_worker():
    """Consumes telemetry events using app.streams (Redis or in-process fallback)."""
    from app.streams import iter_stream, is_redis_backed

    redis_active = False
    redis_url = getattr(settings, "REDIS_URL", "redis://localhost:6379/0")

    # Try connecting to Redis first
    try:
        import redis.asyncio as aioredis
        client = aioredis.from_url(redis_url, decode_responses=True)
        await asyncio.wait_for(client.ping(), timeout=1.5)
        redis_active = True
        log.info("[+] Successfully connected to Redis at %s", redis_url)
        await client.close()
    except Exception as exc:
        log.warning("[!] Redis server is NOT reachable on %s (%s)", redis_url, exc)
        log.info("[*] Aegis fallback mode ACTIVE: consuming in-process fallback stream.")
        log.info("[*] (To use standalone Redis, launch Redis via Docker: 'docker-compose up -d redis')")

    log.info("Ingest worker started. Listening for telemetry events on 'ingest' stream...")

    # Consume stream (works transparently for both Redis Streams and in-process shim)
    async for entry_id, fields in iter_stream("ingest", last_id="$", block_ms=2000):
        raw_payload = fields.get("payload") if isinstance(fields, dict) else None
        if raw_payload:
            await process_payload(raw_payload)


if __name__ == "__main__":
    try:
        asyncio.run(run_redis_stream_worker())
    except KeyboardInterrupt:
        log.info("Ingest worker stopped by user.")
