import sys
import pytest
from pathlib import Path

project_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "backend"))

from app.ml.detector import DetectionResult, FeatureAttribution
from app.response.actions import response_engine, ResponseResult
from app.ledger.chain import ledger_chain

def test_automated_response_dos():
    detection = DetectionResult(
        threat_detected=True,
        threat_score=0.98,
        attack_type="DoS",
        confidence="HIGH",
        top_features=[FeatureAttribution(feature="Flow Bytes/s", value=85000000.0, shap_value=0.8)],
        inference_latency_ms=1.2,
        model_version="aegis-ids/v1.0.0"
    )
    
    res = response_engine.execute_response(detection, source_ip="192.168.1.200")
    assert isinstance(res, ResponseResult)
    assert res.keys_rotated is True
    assert "APPLY_QAOA_FIREWALL_RULES" in res.actions_taken
    assert res.response_time_ms < 100.0  # < 100ms target requirement
    assert len(res.ledger_entry_id) > 0

def test_automated_response_bruteforce():
    detection = DetectionResult(
        threat_detected=True,
        threat_score=0.92,
        attack_type="BruteForce",
        confidence="HIGH",
        top_features=[],
        inference_latency_ms=1.5,
        model_version="aegis-ids/v1.0.0"
    )
    
    res = response_engine.execute_response(detection, source_ip="10.0.0.55")
    assert "ENABLE_EXPONENTIAL_AUTH_BACKOFF" in res.actions_taken
    assert res.keys_rotated is True
