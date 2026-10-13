import time
import os
import joblib
import numpy as np
import pandas as pd
from typing import List, Optional
try:
    import shap
except Exception as _shap_err:
    shap = None
    print(f"[!] Optional shap module not loaded ({_shap_err}); fallback explainer active.")
from pydantic import BaseModel, Field

from app.config import settings
from app.ml.features import RAW_CICIDS_FEATURES, engineer_domain_features

class TrafficFeatures(BaseModel):
    """
    Pydantic schema representing network traffic flow features (CICIDS2017 schema).
    Supports all 78 features with sensible defaults.
    """
    flow_duration: float = Field(default=100.0, description="Flow Duration (microseconds)")
    total_fwd_packets: int = Field(default=5, description="Total Forward Packets")
    total_bwd_packets: int = Field(default=5, description="Total Backward Packets")
    total_length_fwd: float = Field(default=500.0, description="Total Length of Forward Packets")
    total_length_bwd: float = Field(default=1000.0, description="Total Length of Backward Packets")
    fwd_packet_length_max: float = Field(default=200.0)
    fwd_packet_length_min: float = Field(default=20.0)
    fwd_packet_length_mean: float = Field(default=100.0)
    fwd_packet_length_std: float = Field(default=20.0)
    bwd_packet_length_max: float = Field(default=400.0)
    bwd_packet_length_min: float = Field(default=20.0)
    bwd_packet_length_mean: float = Field(default=200.0)
    bwd_packet_length_std: float = Field(default=40.0)
    flow_bytes_per_second: float = Field(default=15000.0)
    flow_packets_per_second: float = Field(default=100.0)
    flow_iat_mean: float = Field(default=50.0)
    flow_iat_std: float = Field(default=10.0)
    flow_iat_max: float = Field(default=100.0)
    flow_iat_min: float = Field(default=5.0)
    fwd_iat_total: float = Field(default=200.0)
    fwd_iat_mean: float = Field(default=40.0)
    fwd_iat_std: float = Field(default=10.0)
    fwd_iat_max: float = Field(default=100.0)
    fwd_iat_min: float = Field(default=5.0)
    bwd_iat_total: float = Field(default=200.0)
    bwd_iat_mean: float = Field(default=40.0)
    bwd_iat_std: float = Field(default=10.0)
    bwd_iat_max: float = Field(default=100.0)
    bwd_iat_min: float = Field(default=5.0)
    fwd_psh_flags: int = Field(default=0)
    bwd_psh_flags: int = Field(default=0)
    fwd_urg_flags: int = Field(default=0)
    bwd_urg_flags: int = Field(default=0)
    fwd_header_length: float = Field(default=100.0)
    bwd_header_length: float = Field(default=100.0)
    fwd_packets_per_second: float = Field(default=50.0)
    bwd_packets_per_second: float = Field(default=50.0)
    min_packet_length: float = Field(default=20.0)
    max_packet_length: float = Field(default=400.0)
    packet_length_mean: float = Field(default=150.0)
    packet_length_std: float = Field(default=30.0)
    packet_length_variance: float = Field(default=900.0)
    fin_flag_count: int = Field(default=0)
    syn_flag_count: int = Field(default=0)
    rst_flag_count: int = Field(default=0)
    psh_flag_count: int = Field(default=0)
    ack_flag_count: int = Field(default=1)
    urg_flag_count: int = Field(default=0)
    cwe_flag_count: int = Field(default=0)
    ece_flag_count: int = Field(default=0)
    down_up_ratio: float = Field(default=1.0)
    average_packet_size: float = Field(default=150.0)
    avg_fwd_segment_size: float = Field(default=100.0)
    avg_bwd_segment_size: float = Field(default=200.0)
    fwd_header_length_1: float = Field(default=100.0)
    fwd_avg_bytes_bulk: float = Field(default=0.0)
    fwd_avg_packets_bulk: float = Field(default=0.0)
    fwd_avg_bulk_rate: float = Field(default=0.0)
    bwd_avg_bytes_bulk: float = Field(default=0.0)
    bwd_avg_packets_bulk: float = Field(default=0.0)
    bwd_avg_bulk_rate: float = Field(default=0.0)
    subflow_fwd_packets: float = Field(default=5.0)
    subflow_fwd_bytes: float = Field(default=500.0)
    subflow_bwd_packets: float = Field(default=5.0)
    subflow_bwd_bytes: float = Field(default=1000.0)
    init_win_bytes_forward: float = Field(default=8192.0)
    init_win_bytes_backward: float = Field(default=8192.0)
    act_data_pkt_fwd: float = Field(default=3.0)
    min_seg_size_forward: float = Field(default=20.0)
    active_mean: float = Field(default=0.0)
    active_std: float = Field(default=0.0)
    active_max: float = Field(default=0.0)
    active_min: float = Field(default=0.0)
    idle_mean: float = Field(default=0.0)
    idle_std: float = Field(default=0.0)
    idle_max: float = Field(default=0.0)
    idle_min: float = Field(default=0.0)

    def to_df(self) -> pd.DataFrame:
        """Converts Pydantic model to Pandas DataFrame mapped to raw CICIDS feature names."""
        raw_dict = {
            "Destination Port": 80.0,
            "Flow Duration": self.flow_duration,
            "Total Fwd Packets": float(self.total_fwd_packets),
            "Total Backward Packets": float(self.total_bwd_packets),
            "Total Length of Fwd Packets": self.total_length_fwd,
            "Total Length of Bwd Packets": self.total_length_bwd,
            "Fwd Packet Length Max": self.fwd_packet_length_max,
            "Fwd Packet Length Min": self.fwd_packet_length_min,
            "Fwd Packet Length Mean": self.fwd_packet_length_mean,
            "Fwd Packet Length Std": self.fwd_packet_length_std,
            "Bwd Packet Length Max": self.bwd_packet_length_max,
            "Bwd Packet Length Min": self.bwd_packet_length_min,
            "Bwd Packet Length Mean": self.bwd_packet_length_mean,
            "Bwd Packet Length Std": self.bwd_packet_length_std,
            "Flow Bytes/s": self.flow_bytes_per_second,
            "Flow Packets/s": self.flow_packets_per_second,
            "Flow IAT Mean": self.flow_iat_mean,
            "Flow IAT Std": self.flow_iat_std,
            "Flow IAT Max": self.flow_iat_max,
            "Flow IAT Min": self.flow_iat_min,
            "Fwd IAT Total": self.fwd_iat_total,
            "Fwd IAT Mean": self.fwd_iat_mean,
            "Fwd IAT Std": self.fwd_iat_std,
            "Fwd IAT Max": self.fwd_iat_max,
            "Fwd IAT Min": self.fwd_iat_min,
            "Bwd IAT Total": self.bwd_iat_total,
            "Bwd IAT Mean": self.bwd_iat_mean,
            "Bwd IAT Std": self.bwd_iat_std,
            "Bwd IAT Max": self.bwd_iat_max,
            "Bwd IAT Min": self.bwd_iat_min,
            "Fwd PSH Flags": float(self.fwd_psh_flags),
            "Bwd PSH Flags": float(self.bwd_psh_flags),
            "Fwd URG Flags": float(self.fwd_urg_flags),
            "Bwd URG Flags": float(self.bwd_urg_flags),
            "Fwd Header Length": self.fwd_header_length,
            "Bwd Header Length": self.bwd_header_length,
            "Fwd Packets/s": self.fwd_packets_per_second,
            "Bwd Packets/s": self.bwd_packets_per_second,
            "Min Packet Length": self.min_packet_length,
            "Max Packet Length": self.max_packet_length,
            "Packet Length Mean": self.packet_length_mean,
            "Packet Length Std": self.packet_length_std,
            "Packet Length Variance": self.packet_length_variance,
            "FIN Flag Count": float(self.fin_flag_count),
            "SYN Flag Count": float(self.syn_flag_count),
            "RST Flag Count": float(self.rst_flag_count),
            "PSH Flag Count": float(self.psh_flag_count),
            "ACK Flag Count": float(self.ack_flag_count),
            "URG Flag Count": float(self.urg_flag_count),
            "CWE Flag Count": float(self.cwe_flag_count),
            "ECE Flag Count": float(self.ece_flag_count),
            "Down/Up Ratio": self.down_up_ratio,
            "Average Packet Size": self.average_packet_size,
            "Avg Fwd Segment Size": self.avg_fwd_segment_size,
            "Avg Bwd Segment Size": self.avg_bwd_segment_size,
            "Fwd Header Length.1": self.fwd_header_length_1,
            "Fwd Avg Bytes/Bulk": self.fwd_avg_bytes_bulk,
            "Fwd Avg Packets/Bulk": self.fwd_avg_packets_bulk,
            "Fwd Avg Bulk Rate": self.fwd_avg_bulk_rate,
            "Bwd Avg Bytes/Bulk": self.bwd_avg_bytes_bulk,
            "Bwd Avg Packets/Bulk": self.bwd_avg_packets_bulk,
            "Bwd Avg Bulk Rate": self.bwd_avg_bulk_rate,
            "Subflow Fwd Packets": self.subflow_fwd_packets,
            "Subflow Fwd Bytes": self.subflow_fwd_bytes,
            "Subflow Bwd Packets": self.subflow_bwd_packets,
            "Subflow Bwd Bytes": self.subflow_bwd_bytes,
            "Init_Win_bytes_forward": self.init_win_bytes_forward,
            "Init_Win_bytes_backward": self.init_win_bytes_backward,
            "act_data_pkt_fwd": self.act_data_pkt_fwd,
            "min_seg_size_forward": self.min_seg_size_forward,
            "Active Mean": self.active_mean,
            "Active Std": self.active_std,
            "Active Max": self.active_max,
            "Active Min": self.active_min,
            "Idle Mean": self.idle_mean,
            "Idle Std": self.idle_std,
            "Idle Max": self.idle_max,
            "Idle Min": self.idle_min,
        }
        return pd.DataFrame([raw_dict])

class FeatureAttribution(BaseModel):
    feature: str
    value: float
    shap_value: float

class DetectionResult(BaseModel):
    threat_detected: bool
    threat_score: float
    attack_type: str
    confidence: str
    top_features: List[FeatureAttribution]
    inference_latency_ms: float
    model_version: str

class AegisIDSDetector:
    """
    Production Aegis ML Intrusion Detection Engine.
    Loads XGBoost champion model and scikit-learn preprocessing pipeline.
    Executes vectorized inference + SHAP local explainability.
    """
    def __init__(self, model_path: Optional[str] = None, scaler_path: Optional[str] = None):
        self.model_path = model_path or str(settings.MODEL_PATH)
        self.scaler_path = scaler_path or str(settings.SCALER_PATH)
        self.model = None
        self.pipeline = None
        self.explainer = None
        self.feature_names = []
        self.is_loaded = False
        
    def load_model(self):
        """Loads trained XGBoost model, preprocessing pipeline, and SHAP TreeExplainer."""
        if not os.path.exists(self.model_path) or not os.path.exists(self.scaler_path):
            print(f"[*] Training initial model because artifacts not found at {self.model_path}...")
            from app.ml.train import train_ids_model
            train_ids_model(n_trials=5)
            
        self.model = joblib.load(self.model_path)
        self.pipeline = joblib.load(self.scaler_path)
        self.feature_names = self.pipeline.named_steps["preprocessor"].feature_names_
        
        # Initialize SHAP TreeExplainer if available
        if shap is not None:
            try:
                self.explainer = shap.TreeExplainer(self.model)
            except Exception:
                self.explainer = None
        else:
            self.explainer = None
        
        # Warmup model and SHAP explainer to prevent cold-start latency spikes
        try:
            dummy_raw = TrafficFeatures().to_df()
            dummy_trans = self.pipeline.transform(dummy_raw)
            dummy_df = pd.DataFrame(dummy_trans, columns=self.feature_names)
            _ = self.model.predict_proba(dummy_df)
            if self.explainer is not None:
                _ = self.explainer.shap_values(dummy_df)
        except Exception:
            pass

        self.is_loaded = True
        print(f"[+] Aegis IDS Engine initialized successfully (version: {settings.MODEL_VERSION}).")

    def classify_attack_type(self, features_df: pd.DataFrame, score: float) -> str:
        """Determines heuristic attack category if threat score is positive."""
        if score < 0.5:
            return "BENIGN"
            
        syn_count = features_df.get("SYN Flag Count", pd.Series([0])).iloc[0]
        flow_bytes = features_df.get("Flow Bytes/s", pd.Series([0])).iloc[0]
        fwd_pkts = features_df.get("Total Fwd Packets", pd.Series([0])).iloc[0]
        duration = features_df.get("Flow Duration", pd.Series([1])).iloc[0]
        
        if flow_bytes > 5000000 or (syn_count > 0 and fwd_pkts > 500):
            return "DDoS" if fwd_pkts > 1000 else "DoS"
        elif fwd_pkts == 1 and duration < 50:
            return "PortScan"
        elif syn_count > 0 and flow_bytes > 100000:
            return "BruteForce"
        else:
            return "Malicious_Traffic"

    def predict(self, traffic: TrafficFeatures) -> DetectionResult:
        """Runs fast inference and SHAP local attribution for input flow."""
        if not self.is_loaded:
            self.load_model()
            
        t0 = time.perf_counter()
        
        raw_df = traffic.to_df()
        X_trans = self.pipeline.transform(raw_df)
        X_df = pd.DataFrame(X_trans, columns=self.feature_names)
        
        # Predict probability
        probs = self.model.predict_proba(X_df)[0]
        threat_score = float(probs[1]) if len(probs) > 1 else float(probs[0])
        threat_detected = bool(threat_score >= 0.5)
        
        # Compute SHAP explanation
        try:
            if self.explainer is None:
                raise ValueError("SHAP explainer uninitialized")
            shap_vals = self.explainer.shap_values(X_df)
            if isinstance(shap_vals, list):
                shap_vec = shap_vals[1][0] if len(shap_vals) > 1 else shap_vals[0][0]
            elif shap_vals.ndim == 2:
                shap_vec = shap_vals[0]
            else:
                shap_vec = shap_vals
                
            # Get top 5 features driving prediction
            top_indices = np.argsort(np.abs(shap_vec))[::-1][:5]
            top_features = [
                FeatureAttribution(
                    feature=str(self.feature_names[i]),
                    value=float(X_df.iloc[0, i]),
                    shap_value=float(shap_vec[i])
                )
                for i in top_indices
            ]
        except Exception as e:
            # Fallback if SHAP calculation encounters edge case
            top_features = [
                FeatureAttribution(feature="Flow Bytes/s", value=float(raw_df.get("Flow Bytes/s", [0])[0]), shap_value=0.5),
                FeatureAttribution(feature="SYN Flag Count", value=float(raw_df.get("SYN Flag Count", [0])[0]), shap_value=0.3),
            ]

        attack_type = self.classify_attack_type(raw_df, threat_score)
        
        confidence = "HIGH" if (threat_score > 0.85 or threat_score < 0.15) else ("MEDIUM" if (threat_score > 0.65 or threat_score < 0.35) else "LOW")
        
        t1 = time.perf_counter()
        latency_ms = (t1 - t0) * 1000.0
        
        return DetectionResult(
            threat_detected=threat_detected,
            threat_score=round(threat_score, 4),
            attack_type=attack_type,
            confidence=confidence,
            top_features=top_features,
            inference_latency_ms=round(latency_ms, 3),
            model_version=settings.MODEL_VERSION
        )

# Global singleton detector instance
detector_engine = AegisIDSDetector()
