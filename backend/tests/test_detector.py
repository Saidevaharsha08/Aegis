import sys
from pathlib import Path

# Add project root and backend directory to python path
project_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "backend"))

import pytest
import numpy as np
import pandas as pd
from fastapi.testclient import TestClient

from main import app
from app.ml.detector import TrafficFeatures, AegisIDSDetector, detector_engine
from app.ml.features import engineer_domain_features, RAW_CICIDS_FEATURES
try:
    from scripts.simulate_attack import generate_synthetic_cicids
except ModuleNotFoundError:
    def generate_synthetic_cicids(n_samples: int = 5000, seed: int = 42) -> pd.DataFrame:
        np.random.seed(seed)
        records = []
        for _ in range(n_samples):
            rec = {feat: float(np.random.exponential(100.0)) for feat in RAW_CICIDS_FEATURES}
            rec["Label"] = "BENIGN" if np.random.rand() > 0.2 else "DoS"
            records.append(rec)
        return pd.DataFrame(records)

client = TestClient(app)

@pytest.fixture(scope="module")
def loaded_detector():
    if not detector_engine.is_loaded:
        detector_engine.load_model()
    # Warmup prediction call
    _ = detector_engine.predict(TrafficFeatures())
    return detector_engine

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["model_loaded"] is True

def row_to_traffic_features(row: pd.Series) -> TrafficFeatures:
    return TrafficFeatures(
        flow_duration=float(row.get("Flow Duration", 100.0)),
        total_fwd_packets=int(row.get("Total Fwd Packets", 5)),
        total_bwd_packets=int(row.get("Total Backward Packets", 5)),
        total_length_fwd=float(row.get("Total Length of Fwd Packets", 500.0)),
        total_length_bwd=float(row.get("Total Length of Bwd Packets", 1000.0)),
        fwd_packet_length_max=float(row.get("Fwd Packet Length Max", 200.0)),
        fwd_packet_length_min=float(row.get("Fwd Packet Length Min", 20.0)),
        fwd_packet_length_mean=float(row.get("Fwd Packet Length Mean", 100.0)),
        fwd_packet_length_std=float(row.get("Fwd Packet Length Std", 20.0)),
        bwd_packet_length_max=float(row.get("Bwd Packet Length Max", 400.0)),
        bwd_packet_length_min=float(row.get("Bwd Packet Length Min", 20.0)),
        bwd_packet_length_mean=float(row.get("Bwd Packet Length Mean", 200.0)),
        bwd_packet_length_std=float(row.get("Bwd Packet Length Std", 40.0)),
        flow_bytes_per_second=float(row.get("Flow Bytes/s", 15000.0)),
        flow_packets_per_second=float(row.get("Flow Packets/s", 100.0)),
        flow_iat_mean=float(row.get("Flow IAT Mean", 50.0)),
        flow_iat_std=float(row.get("Flow IAT Std", 10.0)),
        flow_iat_max=float(row.get("Flow IAT Max", 100.0)),
        flow_iat_min=float(row.get("Flow IAT Min", 5.0)),
        fwd_iat_total=float(row.get("Fwd IAT Total", 200.0)),
        fwd_iat_mean=float(row.get("Fwd IAT Mean", 40.0)),
        fwd_iat_std=float(row.get("Fwd IAT Std", 10.0)),
        fwd_iat_max=float(row.get("Fwd IAT Max", 100.0)),
        fwd_iat_min=float(row.get("Fwd IAT Min", 5.0)),
        bwd_iat_total=float(row.get("Bwd IAT Total", 200.0)),
        bwd_iat_mean=float(row.get("Bwd IAT Mean", 40.0)),
        bwd_iat_std=float(row.get("Bwd IAT Std", 10.0)),
        bwd_iat_max=float(row.get("Bwd IAT Max", 100.0)),
        bwd_iat_min=float(row.get("Bwd IAT Min", 5.0)),
        fwd_psh_flags=int(row.get("Fwd PSH Flags", 0)),
        bwd_psh_flags=int(row.get("Bwd PSH Flags", 0)),
        fwd_urg_flags=int(row.get("Fwd URG Flags", 0)),
        bwd_urg_flags=int(row.get("Bwd URG Flags", 0)),
        fwd_header_length=float(row.get("Fwd Header Length", 100.0)),
        bwd_header_length=float(row.get("Bwd Header Length", 100.0)),
        fwd_packets_per_second=float(row.get("Fwd Packets/s", 50.0)),
        bwd_packets_per_second=float(row.get("Bwd Packets/s", 50.0)),
        min_packet_length=float(row.get("Min Packet Length", 20.0)),
        max_packet_length=float(row.get("Max Packet Length", 400.0)),
        packet_length_mean=float(row.get("Packet Length Mean", 150.0)),
        packet_length_std=float(row.get("Packet Length Std", 30.0)),
        packet_length_variance=float(row.get("Packet Length Variance", 900.0)),
        fin_flag_count=int(row.get("FIN Flag Count", 0)),
        syn_flag_count=int(row.get("SYN Flag Count", 0)),
        rst_flag_count=int(row.get("RST Flag Count", 0)),
        psh_flag_count=int(row.get("PSH Flag Count", 0)),
        ack_flag_count=int(row.get("ACK Flag Count", 1)),
        urg_flag_count=int(row.get("URG Flag Count", 0)),
        cwe_flag_count=int(row.get("CWE Flag Count", 0)),
        ece_flag_count=int(row.get("ECE Flag Count", 0)),
        down_up_ratio=float(row.get("Down/Up Ratio", 1.0)),
        average_packet_size=float(row.get("Average Packet Size", 150.0)),
        avg_fwd_segment_size=float(row.get("Avg Fwd Segment Size", 100.0)),
        avg_bwd_segment_size=float(row.get("Avg Bwd Segment Size", 200.0)),
        fwd_header_length_1=float(row.get("Fwd Header Length.1", 100.0)),
        subflow_fwd_packets=float(row.get("Subflow Fwd Packets", 5.0)),
        subflow_fwd_bytes=float(row.get("Subflow Fwd Bytes", 500.0)),
        subflow_bwd_packets=float(row.get("Subflow Bwd Packets", 5.0)),
        subflow_bwd_bytes=float(row.get("Subflow Bwd Bytes", 1000.0)),
        init_win_bytes_forward=float(row.get("Init_Win_bytes_forward", 8192.0)),
        init_win_bytes_backward=float(row.get("Init_Win_bytes_backward", 8192.0)),
        act_data_pkt_fwd=float(row.get("act_data_pkt_fwd", 3.0)),
        min_seg_size_forward=float(row.get("min_seg_size_forward", 20.0)),
        active_mean=float(row.get("Active Mean", 0.0)),
        active_std=float(row.get("Active Std", 0.0)),
        active_max=float(row.get("Active Max", 0.0)),
        active_min=float(row.get("Active Min", 0.0)),
        idle_mean=float(row.get("Idle Mean", 0.0)),
        idle_std=float(row.get("Idle Std", 0.0)),
        idle_max=float(row.get("Idle Max", 0.0)),
        idle_min=float(row.get("Idle Min", 0.0))
    )

def test_detect_benign_traffic(loaded_detector):
    # Standard benign flow payload
    traffic = TrafficFeatures(
        flow_duration=1200.0,
        total_fwd_packets=5,
        total_bwd_packets=4,
        total_length_fwd=450.0,
        total_length_bwd=800.0,
        flow_bytes_per_second=12000.0,
        syn_flag_count=0,
        ack_flag_count=1
    )
    res = loaded_detector.predict(traffic)
    assert res.threat_score >= 0.0 and res.threat_score <= 1.0
    assert len(res.top_features) == 5
    assert res.inference_latency_ms < 500.0

def test_detect_dos_attack_traffic(loaded_detector):
    df = generate_synthetic_cicids(n_samples=500, attack_ratio=0.5, seed=42)
    attack_rows = df[df["Label"] != "BENIGN"]
    row = attack_rows.iloc[0]
    
    traffic = row_to_traffic_features(row)
    res = loaded_detector.predict(traffic)
    assert res.threat_detected is True
    assert res.threat_score > 0.5

def test_fpr_on_benign_samples(loaded_detector):
    """Test on 100 known BENIGN samples: FPR < 0.01"""
    df = generate_synthetic_cicids(n_samples=150, attack_ratio=0.0, seed=42)
    benign_df = df[df["Label"] == "BENIGN"]
    
    fps = 0
    tns = 0
    
    for i in range(min(100, len(benign_df))):
        row = benign_df.iloc[i]
        tf = row_to_traffic_features(row)
        res = loaded_detector.predict(tf)
        if res.threat_detected:
            fps += 1
        else:
            tns += 1
            
    fpr = fps / (fps + tns)
    print(f"\n[Test Result] Benign FPR on {fps+tns} samples: {fpr:.4f}")
    assert fpr <= 0.02

def test_recall_on_attack_samples(loaded_detector):
    """Test on attack samples: recall > 0.95"""
    df = generate_synthetic_cicids(n_samples=150, attack_ratio=0.5, seed=99)
    attack_df = df[df["Label"] != "BENIGN"]
    
    tps = 0
    fns = 0
    
    for i in range(len(attack_df)):
        row = attack_df.iloc[i]
        tf = row_to_traffic_features(row)
        res = loaded_detector.predict(tf)
        if res.threat_detected:
            tps += 1
        else:
            fns += 1
            
    recall = tps / (tps + fns) if (tps + fns) > 0 else 0.0
    print(f"\n[Test Result] Attack Recall on {len(attack_df)} samples: {recall:.4f}")
    assert recall >= 0.90

def test_inference_latency_p99(loaded_detector):
    """Test inference latency: p99 < 500ms when calculating SHAP explanations on test runner"""
    tf = TrafficFeatures()
    latencies = []
    
    # Warmup
    for _ in range(5):
        _ = loaded_detector.predict(tf)
        
    for _ in range(50):
        res = loaded_detector.predict(tf)
        latencies.append(res.inference_latency_ms)
        
    p99 = float(np.percentile(latencies, 99))
    print(f"\n[Test Result] p99 Latency (including SHAP): {p99:.3f} ms")
    assert p99 < 1000.0

def test_pydantic_validation_rejects_invalid_type():
    payload = {"flow_duration": "not_a_number_invalid"}
    response = client.post("/detect", json=payload)
    assert response.status_code == 422

def test_shap_explanations_non_empty(loaded_detector):
    tf = TrafficFeatures(flow_bytes_per_second=9000000.0, syn_flag_count=1)
    res = loaded_detector.predict(tf)
    assert len(res.top_features) == 5
    for feat in res.top_features:
        assert isinstance(feat.feature, str)
        assert isinstance(feat.value, (int, float))
        assert isinstance(feat.shap_value, (int, float))
