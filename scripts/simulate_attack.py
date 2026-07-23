#!/usr/bin/env python3
"""
Synthetic CICIDS2017 Traffic Generator & Attack Injector for Aegis IDS.
Generates test dataset & trains Stage 1 XGBoost Model out-of-the-box.
"""
import sys
import os
import argparse
import numpy as np
import pandas as pd
from pathlib import Path

# Add backend directory to python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.ml.features import RAW_CICIDS_FEATURES

ATTACK_TYPES = [
    "BENIGN", "DoS", "DDoS", "PortScan", "BruteForce",
    "Bot", "Web Attack", "Infiltration", "Heartbleed"
]

def generate_synthetic_cicids(n_samples: int = 5000, attack_ratio: float = 0.2, seed: int = 42) -> pd.DataFrame:
    """
    Generates a realistic synthetic benchmark dataset matching CICIDS2017 78 features.
    """
    np.random.seed(seed)
    n_attacks = int(n_samples * attack_ratio)
    n_benign = n_samples - n_attacks
    
    records = []
    
    # 1. Generate BENIGN samples (80%)
    for _ in range(n_benign):
        rec = {feat: float(np.random.exponential(100.0)) for feat in RAW_CICIDS_FEATURES}
        rec["Destination Port"] = float(np.random.choice([80, 443, 22, 53, 8080]))
        rec["Flow Duration"] = float(np.random.uniform(50, 5000))
        rec["Total Fwd Packets"] = float(np.random.randint(1, 20))
        rec["Total Backward Packets"] = float(np.random.randint(1, 20))
        rec["Total Length of Fwd Packets"] = float(np.random.uniform(100, 5000))
        rec["Total Length of Bwd Packets"] = float(np.random.uniform(200, 10000))
        rec["Packet Length Mean"] = float(np.random.uniform(60, 800))
        rec["Packet Length Std"] = float(np.random.uniform(10, 200))
        rec["Flow Bytes/s"] = float(np.random.uniform(1000, 500000))
        rec["Flow Packets/s"] = float(np.random.uniform(10, 5000))
        
        # Flags (normal TCP handshake)
        rec["SYN Flag Count"] = float(np.random.choice([0, 1]))
        rec["ACK Flag Count"] = float(np.random.choice([1, 2]))
        rec["FIN Flag Count"] = float(np.random.choice([0, 1]))
        rec["RST Flag Count"] = 0.0
        rec["PSH Flag Count"] = float(np.random.choice([0, 1]))
        rec["URG Flag Count"] = 0.0
        rec["Fwd PSH Flags"] = 0.0
        rec["Bwd PSH Flags"] = 0.0
        rec["Fwd URG Flags"] = 0.0
        rec["Bwd URG Flags"] = 0.0
        
        rec["Label"] = "BENIGN"
        records.append(rec)
        
    # 2. Generate Attack samples (20%)
    attack_choices = [a for a in ATTACK_TYPES if a != "BENIGN"]
    for _ in range(n_attacks):
        atk = np.random.choice(attack_choices)
        rec = {feat: float(np.random.exponential(50.0)) for feat in RAW_CICIDS_FEATURES}
        
        if atk == "DoS" or atk == "DDoS":
            rec["Flow Duration"] = float(np.random.uniform(1000, 100000))
            rec["Total Fwd Packets"] = float(np.random.randint(100, 5000))
            rec["Total Backward Packets"] = float(np.random.randint(0, 10))
            rec["Flow Bytes/s"] = float(np.random.uniform(5000000, 100000000))
            rec["Flow Packets/s"] = float(np.random.uniform(50000, 500000))
            rec["SYN Flag Count"] = 1.0
            rec["ACK Flag Count"] = 0.0
            rec["RST Flag Count"] = float(np.random.choice([0, 1]))
        elif atk == "PortScan":
            rec["Destination Port"] = float(np.random.randint(1, 65535))
            rec["Flow Duration"] = float(np.random.uniform(1, 100))
            rec["Total Fwd Packets"] = 1.0
            rec["Total Backward Packets"] = float(np.random.choice([0, 1]))
            rec["SYN Flag Count"] = 1.0
            rec["FIN Flag Count"] = float(np.random.choice([0, 1]))
        elif atk == "BruteForce":
            rec["Destination Port"] = float(np.random.choice([22, 21, 3389]))
            rec["Total Fwd Packets"] = float(np.random.randint(5, 30))
            rec["Flow Packets/s"] = float(np.random.uniform(1000, 10000))
            rec["PSH Flag Count"] = float(np.random.randint(2, 10))
        else:  # Bot / Web / Infiltration / Heartbleed
            rec["Flow Duration"] = float(np.random.uniform(500, 50000))
            rec["Packet Length Std"] = float(np.random.uniform(300, 1500))
            rec["URG Flag Count"] = float(np.random.choice([0, 1]))
            rec["FIN Flag Count"] = float(np.random.choice([1, 2]))
            
        rec["Label"] = atk
        records.append(rec)
        
    df = pd.DataFrame(records)
    # Shuffle dataset
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    return df

def main():
    parser = argparse.ArgumentParser(description="Aegis Synthetic Traffic Simulator & Trainer")
    parser.add_argument("--train", action="store_true", help="Train XGBoost model on generated dataset")
    parser.add_argument("--n-samples", type=int, default=5000, help="Number of synthetic flow records")
    parser.add_argument("--output", type=str, default="data/synthetic_cicids2017.csv", help="Output path for synthetic CSV")
    args = parser.parse_args()
    
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    
    print(f"[*] Generating {args.n_samples} synthetic CICIDS2017 flow samples...")
    df = generate_synthetic_cicids(n_samples=args.n_samples)
    df.to_csv(out_path, index=False)
    print(f"[+] Saved synthetic dataset to: {out_path} ({df.shape[0]} rows, {df.shape[1]} columns)")
    print(f"    Class distribution:\n{df['Label'].value_counts()}")
    
    if args.train:
        print("\n[*] Launching Stage 1 Model Training pipeline...")
        from app.ml.train import train_ids_model
        train_ids_model(data_path=str(out_path))

if __name__ == "__main__":
    main()
