#!/usr/bin/env python3
"""
Simplified Aegis Backend - Core Attack Detection Flow
- Attack generation through terminal or portal
- ML detection + Known Attacker IP Database
- Attack storage and repeat detection
- Simple defense actions
"""

import asyncio
import os
import time
import math
from typing import Dict, Any, Optional, Tuple

from fastapi import FastAPI, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.config import settings
from app.ml.detector import TrafficFeatures, AegisIDSDetector, DetectionResult
from app.api.deps import get_detector
from app.ledger.chain import ledger_chain
from app.response.actions import response_engine

app = FastAPI(
    title="Aegis - Simple Attack Detection Portal",
    description="Interactive attack detection portal focusing on core threat detection flow",
    version="1.0.0"
)

# CORS middleware for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Persistent in-memory Known Attacker IP Database Store
BLOCKED_IPS_DB: Dict[str, Dict[str, Any]] = {}

# ─── Rule-Based Detection Engine ──────────────────────────────────────────────
def rule_based_detect(traffic: TrafficFeatures) -> Tuple[bool, float, str]:
    """
    Reliable rule-based detection using real CICIDS2017 attack signatures.
    Returns (threat_detected, threat_score, attack_type).
    Runs alongside ML to ensure real attacks are never missed.
    """
    f = traffic
    bps = f.flow_bytes_per_second
    pps = f.flow_packets_per_second
    fwd = f.total_fwd_packets
    dur = max(f.flow_duration, 1.0)
    syn = f.syn_flag_count
    rst = f.rst_flag_count
    psh = f.psh_flag_count
    ack = f.ack_flag_count
    fin = f.fin_flag_count
    urg = f.urg_flag_count
    bwd_len_max = f.bwd_packet_length_max
    bwd_mean = f.bwd_packet_length_mean
    bwd_hdr = f.bwd_header_length
    fwd_hdr = f.fwd_header_length
    len_fwd = f.total_length_fwd
    len_bwd = f.total_length_bwd
    bwd_pkts = f.total_bwd_packets
    pkt_mean = f.packet_length_mean
    iat_mean = f.flow_iat_mean
    pkt_std = f.packet_length_std

    # DDoS — very high rate, many packets, almost no responses
    if bps > 50_000_000 and pps > 100_000 and fwd > 5000 and bwd_pkts <= 5:
        score = min(0.99, 0.7 + (bps / 500_000_000) * 0.3)
        return True, round(score, 4), "DDoS"

    # DoS — high rate SYN flood, few backward packets
    if bps > 10_000_000 and fwd > 500 and bwd_pkts <= 10 and (syn > 0 or rst > 0):
        score = min(0.97, 0.65 + (fwd / 5000) * 0.3)
        return True, round(score, 4), "DoS"

    # Heartbleed — tiny fwd, huge bwd packet (>32KB), very short flow
    if bwd_len_max > 30000 and fwd <= 5 and dur < 5000 and bps > 500_000:
        return True, 0.98, "Heartbleed"

    # Port Scan — very short flows, minimal data, SYN+FIN or SYN only
    if dur < 500 and fwd <= 3 and len_fwd < 500 and (syn > 0 or fin > 0) and bps < 20_000:
        return True, 0.92, "PortScan"

    # Brute Force — repeated small PSH packets, moderate rate
    if psh > 5 and fwd > 20 and len_fwd < 10_000 and pps > 2000 and bps < 5_000_000:
        return True, 0.88, "BruteForce"

    # Web Attack — large fwd payload, small bwd, many PSH
    if len_fwd > 200_000 and psh > 5 and bwd_pkts < 30 and fwd > 10:
        return True, 0.91, "WebAttack"

    # Bot / C2 — symmetric bidirectional traffic, URG flag, long flow
    if urg > 0 and fwd > 30 and bwd_pkts > 20 and dur > 10000:
        return True, 0.85, "Bot"

    # Infiltration / Lateral Movement — large bidirectional, long duration
    if dur > 50000 and len_fwd > 500_000 and len_bwd > 400_000 and bwd_mean > 1000:
        return True, 0.87, "Infiltration"

    return False, 0.05, "BENIGN"

class SimpleDetectionResponse(BaseModel):
    """Simplified response model for the portal"""
    fast_path: bool
    matched_database: bool
    status: str
    message: str
    threat_detected: bool
    threat_score: float
    attack_type: str
    inference_latency_ms: float
    actions_taken: list
    database_updated: bool
    ip_address: str

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "Aegis Simple Detection Portal",
        "database_size": len(BLOCKED_IPS_DB),
        "timestamp": time.time()
    }

@app.get("/blocked-ips")
async def get_blocked_ips():
    """Returns all stored known attacker IPs from the Aegis database."""
    return {
        "count": len(BLOCKED_IPS_DB),
        "blocked_ips": list(BLOCKED_IPS_DB.values())
    }

@app.post("/blocked-ips/clear")
async def clear_blocked_ips():
    """Clears the Known Attacker IP database for fresh testing."""
    BLOCKED_IPS_DB.clear()
    return {"status": "success", "message": "Known Attacker IP database cleared."}

@app.delete("/blocked-ips/{ip}")
async def unblock_ip(ip: str):
    """Remove a specific IP from the Known Attacker database (unblock it)."""
    if ip in BLOCKED_IPS_DB:
        del BLOCKED_IPS_DB[ip]
        return {"status": "success", "message": f"IP {ip} removed from blocked database."}
    return {"status": "not_found", "message": f"IP {ip} was not in the blocked database."}

@app.post("/detect", response_model=SimpleDetectionResponse)
async def detect_threat_simple(
    traffic: TrafficFeatures,
    source_ip: Optional[str] = Query(default="unknown"),
    auto_respond: bool = Query(default=True),
    detector: AegisIDSDetector = Depends(get_detector)
):
    """
    Simple detect endpoint focusing on core flow:
    1. Check Known Attacker IP Database (fast-path for repeat attacks)
    2. If new IP: Run ML detection
    3. If threat: Store IP in database and execute defense
    4. Return simplified response for portal display
    """
    try:
        ip_key = (source_ip or "unknown").strip()

        # STEP 1: KNOWN ATTACKER DATABASE LOOKUP (Repeat Attack Fast-Path)
        if ip_key != "unknown" and ip_key in BLOCKED_IPS_DB:
            entry = BLOCKED_IPS_DB[ip_key]
            entry["hit_count"] += 1
            entry["last_seen"] = time.time()

            # Instant detection result for repeat attackers
            instant_result = DetectionResult(
                threat_detected=True,
                threat_score=1.0,
                attack_type=entry["attack_type"],
                confidence="HIGH (KNOWN_DB_MATCH)",
                inference_latency_ms=0.12,
                model_version="aegis_fast_path_v1",
                top_features=[
                    {
                        "feature": "Known Attacker Database Match",
                        "value": 1.0,
                        "shap_value": 1.0
                    },
                    {
                        "feature": f"Previous Attacks Blocked: {entry['hit_count'] - 1}",
                        "value": float(entry['hit_count']),
                        "shap_value": 0.9
                    }
                ]
            )

            # Log to ledger
            ledger_chain.append_event(
                event_type="KNOWN_ATTACKER_FAST_BLOCK",
                actions_taken=["INSTANT_EDGE_BLOCK", "REJECT_CONNECTION"],
                source_ip=ip_key,
                attack_type=entry["attack_type"],
                threat_score=1.0,
                crypto_mode="ML-KEM-768",
                operator_id="aegis_db_fast_path"
            )

            return SimpleDetectionResponse(
                fast_path=True,
                matched_database=True,
                status="INSTANT_EDGE_BLOCK",
                message=f"Source IP {ip_key} is a recognized malicious system. Connection instantly terminated at edge.",
                threat_detected=True,
                threat_score=1.0,
                attack_type=entry["attack_type"],
                inference_latency_ms=0.12,
                actions_taken=["INSTANT_EDGE_BLOCK", "FIREWALL_DROP_PACKET"],
                database_updated=False,
                ip_address=ip_key
            )

        # STEP 2: NEW TRAFFIC ANALYSIS
        # 2a. Rule-based detection (reliable, fast)
        rule_threat, rule_score, rule_attack = rule_based_detect(traffic)

        # 2b. ML Inference
        result: DetectionResult = detector.predict(traffic)

        # 2c. Merge: rule-based wins if it finds a threat (ML can miss due to model drift)
        # ML wins if it's more confident than rules for threat cases
        if rule_threat and not result.threat_detected:
            # Rule found threat, ML missed — trust rules for real attacks
            from dataclasses import replace as dc_replace
            result = DetectionResult(
                threat_detected=True,
                threat_score=rule_score,
                attack_type=rule_attack,
                confidence="HIGH (RULE_ENGINE)",
                top_features=result.top_features,
                inference_latency_ms=result.inference_latency_ms,
                model_version=result.model_version
            )
        elif rule_threat and result.threat_detected:
            # Both agree — use highest score and rule's attack type (more specific)
            result = DetectionResult(
                threat_detected=True,
                threat_score=max(rule_score, float(result.threat_score)),
                attack_type=rule_attack,
                confidence="HIGH (ML+RULE)",
                top_features=result.top_features,
                inference_latency_ms=result.inference_latency_ms,
                model_version=result.model_version
            )

        database_updated = False
        response_actions = []

        # If threat detected on new IP, store it in database
        if result.threat_detected and ip_key != "unknown":
            BLOCKED_IPS_DB[ip_key] = {
                "ip": ip_key,
                "attack_type": result.attack_type,
                "threat_score": float(result.threat_score),
                "blocked_at": time.time(),
                "last_seen": time.time(),
                "hit_count": 1,
                "status": "BLOCKED"
            }
            database_updated = True

            # Execute defense response
            if auto_respond:
                resp = response_engine.execute_response(result, source_ip=ip_key)
                response_actions = resp.model_dump().get("actions_taken", []) if hasattr(resp, "model_dump") else resp.dict().get("actions_taken", [])

            # Log detection to ledger
            ledger_chain.append_event(
                event_type="DETECTION",
                actions_taken=["DETECT_EVENT"] + response_actions,
                source_ip=ip_key,
                attack_type=result.attack_type,
                threat_score=float(result.threat_score),
                crypto_mode="ML-KEM-768",
                operator_id="api_detect"
            )

        # Build simplified response
        status_msg = "THREAT_DETECTED_AND_BLOCKED" if result.threat_detected else "BENIGN_TRAFFIC_ALLOWED"
        if ip_key != "unknown" and result.threat_detected and not database_updated:
            status_msg = "IP_ALREADY_IN_DATABASE"

        return SimpleDetectionResponse(
            fast_path=False,
            matched_database=False,
            status=status_msg,
            message=f"Attack from {ip_key} analyzed. {'Threat blocked and IP stored.' if result.threat_detected and database_updated else 'Benign traffic allowed.' if not result.threat_detected else 'IP already in database.'}",
            threat_detected=result.threat_detected,
            threat_score=float(result.threat_score),
            attack_type=result.attack_type,
            inference_latency_ms=result.inference_latency_ms,
            actions_taken=response_actions,
            database_updated=database_updated,
            ip_address=ip_key
        )

    except Exception as e:
        # Return error in simplified format
        return SimpleDetectionResponse(
            fast_path=False,
            matched_database=False,
            status="ERROR",
            message=f"Detection error: {str(e)}",
            threat_detected=False,
            threat_score=0.0,
            attack_type="UNKNOWN",
            inference_latency_ms=0.0,
            actions_taken=[],
            database_updated=False,
            ip_address=source_ip or "unknown"
        )

@app.on_event("startup")
async def startup_event():
    """Initialize the system on startup"""
    print(f"[*] Starting {settings.PROJECT_NAME} Simple Detection Portal...")
    detector = get_detector()
    detector.load_model()
    print("[+] ML Model loaded successfully")

    # Start online detector consumer in background
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            from app.online_detector import start_background_consumer
            task = start_background_consumer()
            app.state.online_detector_task = task
            print("[+] Online detector consumer scheduled.")
    except RuntimeError:
        pass

    # Boot redteam for mesh simulation if enabled
    if os.getenv("AEGIS_REDTEAM_BOOT", "1") == "1":
        try:
            from app.mesh.redteam import redteam
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(redteam.start(), name="redteam-boot")
        except Exception:
            pass

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main_simple:app",
        host=settings.BACKEND_HOST,
        port=settings.BACKEND_PORT,
        reload=settings.DEBUG
    )