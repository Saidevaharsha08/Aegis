import numpy as np
import pandas as pd
from typing import Tuple, List, Dict, Any, Optional
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.pipeline import Pipeline

# 78 standard CICIDS2017 feature names
RAW_CICIDS_FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean",
    "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
    "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
    "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "URG Flag Count", "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio",
    "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Header Length.1", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward",
    "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean",
    "Idle Std", "Idle Max", "Idle Min"
]

LEAKAGE_COLUMNS = [
    "Flow ID", "Source IP", "Src IP", "Destination IP", "Dst IP",
    "Timestamp", "Unnamed: 0"
]

ENGINEERED_FEATURES = [
    "byte_ratio",
    "packet_ratio",
    "flow_efficiency",
    "flag_anomaly_score",
    "size_entropy"
]

def engineer_domain_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Computes custom domain features for network traffic flows.
    """
    data = df.copy()
    
    # Safely extract base fields (support variations in column names)
    fwd_bytes = data.get("Total Length of Fwd Packets", data.get("total_length_fwd", 0.0))
    bwd_bytes = data.get("Total Length of Bwd Packets", data.get("total_length_bwd", 0.0))
    fwd_pkts = data.get("Total Fwd Packets", data.get("total_fwd_packets", 0.0))
    bwd_pkts = data.get("Total Backward Packets", data.get("total_bwd_packets", 0.0))
    flow_bytes_sec = data.get("Flow Bytes/s", data.get("flow_bytes_per_second", 0.0))
    duration = data.get("Flow Duration", data.get("flow_duration", 1.0))
    
    fin_flag = data.get("FIN Flag Count", data.get("fin_flag_count", 0))
    syn_flag = data.get("SYN Flag Count", data.get("syn_flag_count", 0))
    rst_flag = data.get("RST Flag Count", data.get("rst_flag_count", 0))
    psh_flag = data.get("PSH Flag Count", data.get("psh_flag_count", 0))
    ack_flag = data.get("ACK Flag Count", data.get("ack_flag_count", 0))

    pkt_std = data.get("Packet Length Std", data.get("packet_length_std", 0.0))
    pkt_mean = data.get("Packet Length Mean", data.get("packet_length_mean", 1.0))
    
    # 1. Byte ratio: total_fwd_bytes / (total_bwd_bytes + 1)
    data["byte_ratio"] = fwd_bytes / (bwd_bytes + 1.0)
    
    # 2. Packet ratio: fwd_packets / (bwd_packets + 1)
    data["packet_ratio"] = fwd_pkts / (bwd_pkts + 1.0)
    
    # 3. Flow efficiency: flow_bytes_per_second / (flow_duration + 1e-5)
    data["flow_efficiency"] = flow_bytes_sec / (np.maximum(duration, 1.0) + 1e-5)
    
    # 4. Flag anomaly score: detection of illegal/suspicious TCP flag combinations
    syn_fin = ((syn_flag > 0) & (fin_flag > 0)).astype(float)
    syn_rst = ((syn_flag > 0) & (rst_flag > 0)).astype(float)
    null_flags = ((syn_flag == 0) & (fin_flag == 0) & (rst_flag == 0) & (psh_flag == 0) & (ack_flag == 0)).astype(float)
    xmas_flags = ((fin_flag > 0) & (psh_flag > 0) & (data.get("URG Flag Count", 0) > 0)).astype(float)
    
    data["flag_anomaly_score"] = (syn_fin * 3.0) + (syn_rst * 2.0) + (null_flags * 2.5) + (xmas_flags * 3.0)
    
    # 5. Size entropy: estimated packet length variation ratio
    data["size_entropy"] = np.log1p(pkt_std) / (np.log1p(pkt_mean) + 1e-5)
    
    return data

def check_data_leakage(df: pd.DataFrame, label_col: str = "Label", threshold: float = 0.95) -> Dict[str, Any]:
    """
    Scans dataset for leakage columns (IPs, timestamps) and high-correlation features (|r| > threshold).
    """
    dropped_leakage = []
    high_corr_features = []
    
    # Identify known leakage columns
    for col in df.columns:
        if any(leak.lower() in col.lower() for leak in LEAKAGE_COLUMNS):
            dropped_leakage.append(col)
            
    # Check correlation with binary target if label exists
    if label_col in df.columns:
        numeric_df = df.select_dtypes(include=[np.number]).copy()
        binary_target = (df[label_col].astype(str).str.upper() != "BENIGN").astype(int)
        
        for col in numeric_df.columns:
            if col != label_col:
                corr = numeric_df[col].corr(binary_target)
                if abs(corr) >= threshold:
                    high_corr_features.append({"feature": col, "correlation": float(corr)})
                    
    return {
        "dropped_leakage_columns": dropped_leakage,
        "suspected_leakage_features": high_corr_features
    }

class AegisPreprocessTransformer(BaseEstimator, TransformerMixin):
    """
    Robust Scikit-Learn transformer that handles infinite values, missing values,
    percentile outlier capping, and feature engineering.
    """
    def __init__(self, clip_percentile: float = 99.9):
        self.clip_percentile = clip_percentile
        self.upper_bounds_: Dict[str, float] = {}
        self.medians_: Dict[str, float] = {}
        self.feature_names_: List[str] = []

    def fit(self, X: pd.DataFrame, y=None):
        df = X.copy()
        
        # Drop leakage columns if present
        df = df.drop(columns=[c for c in LEAKAGE_COLUMNS if c in df.columns], errors="ignore")
        
        # Engineer domain features
        df = engineer_domain_features(df)
        
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        self.feature_names_ = numeric_cols
        
        for col in numeric_cols:
            vals = df[col].replace([np.inf, -np.inf], np.nan)
            med = vals.median()
            self.medians_[col] = 0.0 if np.isnan(med) else float(med)
            
            # Compute percentile bound for clipping
            non_null = vals.dropna()
            if len(non_null) > 0:
                self.upper_bounds_[col] = float(np.percentile(non_null, self.clip_percentile))
            else:
                self.upper_bounds_[col] = 1e6
                
        return self

    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        df = X.copy()
        df = df.drop(columns=[c for c in LEAKAGE_COLUMNS if c in df.columns], errors="ignore")
        df = engineer_domain_features(df)
        
        # Fill missing features with default 0 if not present during transform
        for col in self.feature_names_:
            if col not in df.columns:
                df[col] = 0.0
                
        df = df[self.feature_names_]
        
        # 1. Clean inf / NaN
        df = df.replace([np.inf, -np.inf], np.nan)
        for col in self.feature_names_:
            df[col] = df[col].fillna(self.medians_.get(col, 0.0))
            
            # 2. Outlier capping
            upper = self.upper_bounds_.get(col, 1e6)
            df[col] = np.clip(df[col], a_min=-1e6, a_max=upper)
            
        return df

def build_preprocessing_pipeline() -> Pipeline:
    """
    Constructs complete scikit-learn preprocessing pipeline.
    """
    return Pipeline([
        ("preprocessor", AegisPreprocessTransformer(clip_percentile=99.9)),
        ("scaler", StandardScaler())
    ])
