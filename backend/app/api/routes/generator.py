"""
Attack Generator Route.

Provides synthetic attack vector generation for all 10 attack categories:
BENIGN, DoS, DDoS, PortScan, BruteForce, Bot, Web Attack, Infiltration, Heartbleed, Malicious_Traffic.

Runs the generated vector through Aegis:
  1. XGBoost Threat Classification & Confidence Scoring
  2. Local SHAP Feature Explanations
  3. Hash-Chained Audit Ledger Logging
  4. QAOA Quantum Firewall Rule Optimization
  5. Automated Defense Response & PQC ML-KEM-768 Key Rotation
"""

from __future__ import annotations

import random
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.deps import get_detector
from app.ml.detector import AegisIDSDetector, TrafficFeatures, DetectionResult
from app.ledger.chain import ledger_chain
from app.response.actions import response_engine
from app.optimizer.api import solve

router = APIRouter()

ATTACK_PROFILES: Dict[str, Dict[str, Any]] = {
    "BENIGN": {
        "name": "Benign Web Traffic",
        "description": "Standard encrypted HTTPS/HTTP web browsing flow with normal TCP handshake.",
        "category": "BENIGN",
        "severity": "INFORMATIONAL",
        "target_port": 443,
        "features": {
            "flow_duration": 1200.0,
            "total_fwd_packets": 5,
            "total_bwd_packets": 4,
            "flow_bytes_per_second": 12000.0,
            "syn_flag_count": 0,
            "ack_flag_count": 1,
            "psh_flag_count": 1,
            "rst_flag_count": 0,
            "packet_length_mean": 180.0
        }
    },
    "DoS": {
        "name": "Denial of Service (DoS)",
        "description": "High-volume SYN flood designed to exhaust server socket buffers.",
        "category": "ATTACK",
        "severity": "HIGH",
        "target_port": 80,
        "features": {
            "flow_duration": 95000.0,
            "total_fwd_packets": 3500,
            "total_bwd_packets": 1,
            "flow_bytes_per_second": 95000000.0,
            "flow_packets_per_second": 120000.0,
            "syn_flag_count": 1,
            "ack_flag_count": 0,
            "rst_flag_count": 0,
            "psh_flag_count": 0
        }
    },
    "DDoS": {
        "name": "Distributed Denial of Service (DDoS)",
        "description": "Multi-vector volumetric flood bursting millions of packets per second.",
        "category": "ATTACK",
        "severity": "CRITICAL",
        "target_port": 443,
        "features": {
            "flow_duration": 180000.0,
            "total_fwd_packets": 15000,
            "total_bwd_packets": 0,
            "flow_bytes_per_second": 450000000.0,
            "flow_packets_per_second": 350000.0,
            "syn_flag_count": 1,
            "ack_flag_count": 0,
            "rst_flag_count": 1,
            "psh_flag_count": 0
        }
    },
    "PortScan": {
        "name": "Reconnaissance Port Scan",
        "description": "Rapid stealth SYN/FIN scan probing open ports across subnets.",
        "category": "ATTACK",
        "severity": "MEDIUM",
        "target_port": 22,
        "features": {
            "flow_duration": 150.0,
            "total_fwd_packets": 1,
            "total_bwd_packets": 1,
            "flow_bytes_per_second": 3500.0,
            "flow_packets_per_second": 2500.0,
            "syn_flag_count": 1,
            "fin_flag_count": 1,
            "ack_flag_count": 0,
            "rst_flag_count": 0
        }
    },
    "BruteForce": {
        "name": "SSH/FTP Credential Brute Force",
        "description": "High-frequency password guessing attempt targeting authentication ports.",
        "category": "ATTACK",
        "severity": "HIGH",
        "target_port": 22,
        "features": {
            "flow_duration": 8500.0,
            "total_fwd_packets": 45,
            "total_bwd_packets": 12,
            "flow_bytes_per_second": 250000.0,
            "flow_packets_per_second": 8000.0,
            "psh_flag_count": 8,
            "syn_flag_count": 1,
            "ack_flag_count": 1
        }
    },
    "Bot": {
        "name": "C2 Botnet Telemetry",
        "description": "Periodic beaconing and encrypted command-and-control communication.",
        "category": "ATTACK",
        "severity": "HIGH",
        "target_port": 8080,
        "features": {
            "flow_duration": 45000.0,
            "total_fwd_packets": 80,
            "total_bwd_packets": 65,
            "flow_bytes_per_second": 180000.0,
            "packet_length_std": 850.0,
            "urg_flag_count": 1,
            "fin_flag_count": 1,
            "flow_iat_mean": 1200.0
        }
    },
    "Web Attack": {
        "name": "Web Application Attack (SQLi/XSS)",
        "description": "Malicious HTTP payload injection targeting vulnerable web APIs.",
        "category": "ATTACK",
        "severity": "HIGH",
        "target_port": 80,
        "features": {
            "flow_duration": 3200.0,
            "total_fwd_packets": 18,
            "total_bwd_packets": 14,
            "flow_bytes_per_second": 850000.0,
            "packet_length_mean": 1450.0,
            "psh_flag_count": 7,
            "fwd_header_length": 480.0
        }
    },
    "Infiltration": {
        "name": "Internal Network Infiltration",
        "description": "Lateral movement and data exfiltration across internal network segments.",
        "category": "ATTACK",
        "severity": "CRITICAL",
        "target_port": 445,
        "features": {
            "flow_duration": 150000.0,
            "total_fwd_packets": 320,
            "total_bwd_packets": 280,
            "flow_bytes_per_second": 1200000.0,
            "bwd_packet_length_mean": 1950.0,
            "psh_flag_count": 14,
            "idle_mean": 45000.0
        }
    },
    "Heartbleed": {
        "name": "TLS Heartbleed Vulnerability Exploit",
        "description": "Malformed SSL/TLS heartbeat request attempting memory buffer leakage.",
        "category": "ATTACK",
        "severity": "CRITICAL",
        "target_port": 443,
        "features": {
            "flow_duration": 850.0,
            "total_fwd_packets": 2,
            "total_bwd_packets": 1,
            "bwd_packet_length_max": 65535.0,
            "flow_bytes_per_second": 950000.0,
            "psh_flag_count": 1
        }
    },
    "Malicious_Traffic": {
        "name": "Generic Malicious Traffic Anomaly",
        "description": "Unclassified abnormal traffic pattern exhibiting suspicious flag combinations.",
        "category": "ATTACK",
        "severity": "MEDIUM",
        "target_port": 8443,
        "features": {
            "flow_duration": 25000.0,
            "total_fwd_packets": 120,
            "total_bwd_packets": 95,
            "flow_bytes_per_second": 3500000.0,
            "rst_flag_count": 4,
            "packet_length_variance": 45000.0
        }
    }
}


class GenerateAttackRequest(BaseModel):
    attack_type: str = Field(default="DoS", description="Type of attack to generate")
    source_ip: Optional[str] = Field(default="203.0.113.42", description="Simulated attacker IP")
    auto_respond: bool = Field(default=True, description="Execute defense playbook if threat detected")
    optimize_rules: bool = Field(default=True, description="Run QAOA firewall rule optimizer")


class BarrageRequest(BaseModel):
    count: int = Field(default=10, ge=1, le=50, description="Number of attacks to generate in barrage")
    auto_respond: bool = Field(default=True)


@router.get("/generator/attack-types")
def get_attack_types() -> List[Dict[str, Any]]:
    """Return all supported attack types, severity, descriptions, and feature profiles."""
    return [
        {
            "key": k,
            "name": v["name"],
            "description": v["description"],
            "category": v["category"],
            "severity": v["severity"],
            "target_port": v["target_port"]
        }
        for k, v in ATTACK_PROFILES.items()
    ]


@router.post("/generator/attack")
def generate_single_attack(
    req: GenerateAttackRequest,
    detector: AegisIDSDetector = Depends(get_detector)
) -> Dict[str, Any]:
    """
    Generate an attack vector for the specified type and run it through:
      1. XGBoost Detection
      2. SHAP Explainability
      3. Ledger Hash Logging
      4. QAOA Rule Optimization
      5. Automated Response Execution
    """
    attack_key = req.attack_type if req.attack_type in ATTACK_PROFILES else "DoS"
    profile = ATTACK_PROFILES[attack_key]

    # Build Pydantic TrafficFeatures with defaults + injected profile features
    feature_kwargs = dict(profile["features"])
    traffic = TrafficFeatures(**feature_kwargs)

    # 1. Run XGBoost Inference + SHAP
    detection_result: DetectionResult = detector.predict(traffic)

    # 2. Append to Audit Ledger
    ledger_entry = ledger_chain.append_event(
        event_type="GENERATED_ATTACK_TEST",
        actions_taken=["INSPECT_PACKET", "XGBOOST_INFERENCE"],
        threat_id=None,
        source_ip=req.source_ip,
        attack_type=detection_result.attack_type,
        threat_score=float(detection_result.threat_score),
        rules_applied=[],
        crypto_mode="ML-KEM-768",
        operator_id="attack_generator_studio"
    )

    # 3. QAOA Optimization (if requested)
    qaoa_result = None
    if req.optimize_rules:
        qaoa_sol = solve(
            fpr_budget=0.08,
            cost_budget=6.0,
            n_rules=15,
            solver="auto"
        )
        qaoa_result = {
            "selected_rules": [r["name"] for r in qaoa_sol.get("selected_rules", [])],
            "total_block_probability": qaoa_sol.get("total_block_probability", 0.95),
            "total_fpr": qaoa_sol.get("total_fpr", 0.02),
            "total_cost": qaoa_sol.get("total_cost", 4.5),
            "solver": qaoa_sol.get("solver", "qaoa"),
            "optimization_time_ms": qaoa_sol.get("optimization_time_ms", 3.2)
        }

    # 4. Automated Response Execution (if threat detected and auto_respond is enabled)
    response_result = None
    if req.auto_respond and detection_result.threat_detected:
        resp = response_engine.execute_response(
            detection_result,
            source_ip=req.source_ip
        )
        response_result = resp.model_dump() if hasattr(resp, "model_dump") else resp.dict()

    return {
        "status": "success",
        "attack_profile": {
            "key": attack_key,
            "name": profile["name"],
            "severity": profile["severity"],
            "target_port": profile["target_port"],
            "source_ip": req.source_ip
        },
        "detection": detection_result.dict(),
        "ledger_entry": ledger_entry.__dict__,
        "qaoa_optimization": qaoa_result,
        "response": response_result
    }


@router.post("/generator/barrage")
def generate_attack_barrage(
    req: BarrageRequest,
    detector: AegisIDSDetector = Depends(get_detector)
) -> Dict[str, Any]:
    """
    Generate a multi-vector attack barrage across all attack types.
    Evaluates each attack, collects performance stats, and returns full campaign analytics.
    """
    attack_keys = list(ATTACK_PROFILES.keys())
    results = []
    threats_detected = 0
    total_latency_ms = 0.0

    for i in range(req.count):
        # Pick attack type (mix of attacks and benign)
        atk_key = random.choice(attack_keys)
        profile = ATTACK_PROFILES[atk_key]
        src_ip = f"198.51.100.{random.randint(10, 250)}"

        traffic = TrafficFeatures(**profile["features"])
        det = detector.predict(traffic)

        if det.threat_detected:
            threats_detected += 1
        total_latency_ms += det.inference_latency_ms

        ledger_entry = ledger_chain.append_event(
            event_type="BARRAGE_ATTACK",
            actions_taken=["STREAM_INSPECT"],
            threat_id=None,
            source_ip=src_ip,
            attack_type=det.attack_type,
            threat_score=float(det.threat_score),
            rules_applied=[],
            crypto_mode="ML-KEM-768",
            operator_id="attack_barrage_generator"
        )

        results.append({
            "step": i + 1,
            "attack_type": atk_key,
            "source_ip": src_ip,
            "threat_detected": det.threat_detected,
            "threat_score": det.threat_score,
            "confidence": det.confidence,
            "ledger_hash": ledger_entry.current_hash[:12]
        })

    avg_latency = round(total_latency_ms / req.count, 2) if req.count > 0 else 0.0
    detection_rate = round((threats_detected / req.count) * 100, 1) if req.count > 0 else 0.0

    return {
        "status": "completed",
        "total_attacks_generated": req.count,
        "threats_detected": threats_detected,
        "detection_rate_percent": detection_rate,
        "avg_inference_latency_ms": avg_latency,
        "ledger_chain_length": ledger_chain.get_chain_length(),
        "attacks": results
    }


__all__ = ["router"]
