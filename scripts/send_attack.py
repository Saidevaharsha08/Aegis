#!/usr/bin/env python3
"""
Attack Simulator for Aegis Simple Detection Portal.

Fire a simulated network attack from the terminal. This script generates
synthetic traffic matching real attack patterns and sends it to the Aegis
detection portal.

First attack: Detected by ML -> Blocked -> IP stored in database
Repeat attack (same IP): Detected via database -> Instant edge block

Usage:
    python scripts/send_attack.py --ip 203.0.113.42 --type DoS
    python scripts/send_attack.py --ip 203.0.113.42 --type BruteForce
    python scripts/send_attack.py --ip 198.51.100.15 --type DDoS
"""

import sys
import os
import json
import argparse
import time
from pathlib import Path

# Add backend directory to python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.ml.features import RAW_CICIDS_FEATURES

ATTACK_TYPES = [
    "DoS", "DDoS", "BruteForce", "PortScan", "WebAttack",
    "Bot", "Infiltration", "Heartbleed", "BENIGN"
]

# API base URL - configurable via env var
API_URL = os.getenv("AEGIS_API_URL", "http://localhost:8000")


def generate_attack_features(attack_type: str):
    """
    Generate realistic traffic features for a given attack type.
    These values are based on real network attack signatures.
    """
    import random

    base = {
        "flow_duration": 0.0,
        "total_fwd_packets": 0,
        "total_bwd_packets": 0,
        "total_length_fwd": 0.0,
        "total_length_bwd": 0.0,
        "fwd_packet_length_max": 1460.0,
        "fwd_packet_length_min": 40.0,
        "fwd_packet_length_mean": 500.0,
        "fwd_packet_length_std": 300.0,
        "bwd_packet_length_max": 500.0,
        "bwd_packet_length_min": 40.0,
        "bwd_packet_length_mean": 100.0,
        "bwd_packet_length_std": 50.0,
        "flow_bytes_per_second": 0.0,
        "flow_packets_per_second": 0.0,
        "flow_iat_mean": 0.0,
        "flow_iat_std": 0.0,
        "flow_iat_max": 1000.0,
        "flow_iat_min": 1.0,
        "fwd_iat_total": 0.0,
        "fwd_iat_mean": 0.0,
        "fwd_iat_std": 0.0,
        "fwd_iat_max": 100.0,
        "fwd_iat_min": 1.0,
        "bwd_iat_total": 0.0,
        "bwd_iat_mean": 0.0,
        "bwd_iat_std": 0.0,
        "bwd_iat_max": 100.0,
        "bwd_iat_min": 1.0,
        "fwd_psh_flags": 0,
        "bwd_psh_flags": 0,
        "fwd_urg_flags": 0,
        "bwd_urg_flags": 0,
        "fwd_header_length": 20.0,
        "bwd_header_length": 20.0,
        "fwd_packets_per_second": 0.0,
        "bwd_packets_per_second": 0.0,
        "min_packet_length": 40.0,
        "max_packet_length": 1460.0,
        "packet_length_mean": 500.0,
        "packet_length_std": 300.0,
        "packet_length_variance": 90000.0,
        "fin_flag_count": 0,
        "syn_flag_count": 0,
        "rst_flag_count": 0,
        "psh_flag_count": 0,
        "ack_flag_count": 0,
        "urg_flag_count": 0,
        "cwe_flag_count": 0,
        "ece_flag_count": 0,
        "down_up_ratio": 1.0,
        "average_packet_size": 500.0,
        "avg_fwd_segment_size": 400.0,
        "avg_bwd_segment_size": 100.0,
        "fwd_header_length_1": 20.0,
        "fwd_avg_bytes_bulk": 0.0,
        "fwd_avg_packets_bulk": 0.0,
        "fwd_avg_bulk_rate": 0.0,
        "bwd_avg_bytes_bulk": 0.0,
        "bwd_avg_packets_bulk": 0.0,
        "bwd_avg_bulk_rate": 0.0,
    }

    if attack_type == "DoS":
        # SYN flood - high volume, short duration, many SYN flags
        base.update({
            "flow_duration": 95000.0,
            "total_fwd_packets": 3500,
            "total_bwd_packets": 1,
            "total_length_fwd": 95000.0,
            "total_length_bwd": 60.0,
            "flow_bytes_per_second": 95000000.0,
            "flow_packets_per_second": 120000.0,
            "syn_flag_count": 1,
            "ack_flag_count": 0,
            "fin_flag_count": 0,
            "rst_flag_count": 1,
            "psh_flag_count": 0,
            "fwd_iat_total": 95000.0,
            "avg_fwd_segment_size": 1460.0,
        })
    elif attack_type == "DDoS":
        # DDoS - massive volume from distributed sources
        base.update({
            "flow_duration": 180000.0,
            "total_fwd_packets": 15000,
            "total_bwd_packets": 0,
            "total_length_fwd": 450000000.0,
            "total_length_bwd": 0.0,
            "flow_bytes_per_second": 450000000.0,
            "flow_packets_per_second": 350000.0,
            "syn_flag_count": 1,
            "ack_flag_count": 0,
            "fin_flag_count": 0,
            "rst_flag_count": 1,
            "psh_flag_count": 0,
        })
    elif attack_type == "BruteForce":
        # SSH/FTP credential brute force - many short attempts
        base.update({
            "flow_duration": 8500.0,
            "total_fwd_packets": 45,
            "total_bwd_packets": 12,
            "total_length_fwd": 2500.0,
            "total_length_bwd": 700.0,
            "flow_bytes_per_second": 250000.0,
            "flow_packets_per_second": 8000.0,
            "psh_flag_count": 8,
            "syn_flag_count": 1,
            "ack_flag_count": 1,
            "fin_flag_count": 0,
        })
    elif attack_type == "PortScan":
        # Reconnaissance - single packets to many ports
        base.update({
            "flow_duration": 150.0,
            "total_fwd_packets": 1,
            "total_bwd_packets": 1,
            "total_length_fwd": 60.0,
            "total_length_bwd": 60.0,
            "flow_bytes_per_second": 3500.0,
            "flow_packets_per_second": 2500.0,
            "syn_flag_count": 1,
            "fin_flag_count": 1,
            "ack_flag_count": 0,
            "rst_flag_count": 0,
        })
    elif attack_type == "WebAttack":
        # SQL injection / XSS - malformed requests
        base.update({
            "flow_duration": 3200.0,
            "total_fwd_packets": 18,
            "total_bwd_packets": 14,
            "total_length_fwd": 850000.0,
            "total_length_bwd": 500.0,
            "flow_bytes_per_second": 850000.0,
            "packet_length_mean": 1450.0,
            "packet_length_std": 500.0,
            "psh_flag_count": 7,
            "fwd_header_length": 480.0,
        })
    elif attack_type == "Bot":
        # C2 beaconing - periodic small packets
        base.update({
            "flow_duration": 45000.0,
            "total_fwd_packets": 80,
            "total_bwd_packets": 65,
            "total_length_fwd": 180000.0,
            "total_length_bwd": 145000.0,
            "flow_bytes_per_second": 180000.0,
            "packet_length_std": 850.0,
            "flow_iat_mean": 1200.0,
            "fwd_iat_mean": 1200.0,
            "urg_flag_count": 1,
        })
    elif attack_type == "Infiltration":
        # Lateral movement - large data transfer
        base.update({
            "flow_duration": 150000.0,
            "total_fwd_packets": 320,
            "total_bwd_packets": 280,
            "total_length_fwd": 1200000.0,
            "total_length_bwd": 1050000.0,
            "flow_bytes_per_second": 1200000.0,
            "bwd_packet_length_mean": 1950.0,
            "bwd_header_length": 1200.0,
            "psh_flag_count": 14,
        })
    elif attack_type == "Heartbleed":
        # TLS exploit - malformed heartbeat
        base.update({
            "flow_duration": 850.0,
            "total_fwd_packets": 2,
            "total_bwd_packets": 1,
            "total_length_fwd": 190.0,
            "total_length_bwd": 65535.0,
            "flow_bytes_per_second": 950000.0,
            "bwd_packet_length_max": 65535.0,
            "psh_flag_count": 1,
        })
    elif attack_type == "BENIGN":
        # Normal web traffic
        base.update({
            "flow_duration": 1200.0,
            "total_fwd_packets": 5,
            "total_bwd_packets": 4,
            "total_length_fwd": 12000.0,
            "total_length_bwd": 8000.0,
            "flow_bytes_per_second": 12000.0,
            "flow_packets_per_second": 500.0,
            "syn_flag_count": 0,
            "ack_flag_count": 1,
            "fin_flag_count": 1,
            "psh_flag_count": 1,
        })

    return base


def main():
    parser = argparse.ArgumentParser(
        description="Fire a simulated network attack against the Aegis detection portal."
    )
    parser.add_argument(
        "--ip", type=str, default="203.0.113.42",
        help="Source IP address of the attacking system (default: 203.0.113.42)"
    )
    parser.add_argument(
        "--type", type=str, default="DoS",
        choices=ATTACK_TYPES,
        help=f"Attack type to simulate. Available: {', '.join(ATTACK_TYPES)}"
    )
    parser.add_argument(
        "--url", type=str, default=None,
        help=f"Detection API URL (default: {API_URL}/detect)"
    )
    parser.add_argument(
        "--interval", type=float, default=2.0,
        help="Time interval between repeated attacks (default: 2.0s)"
    )
    parser.add_argument(
        "--count", type=int, default=1,
        help="Number of times to send the attack (default: 1)"
    )

    args = parser.parse_args()

    # Determine API URL
    url = args.url or f"{API_URL}/detect"

    print(f"\n{'='*70}")
    print(f"  AEGIS ATTACK SIMULATOR")
    print(f"{'='*70}")
    print(f"  Target:     {url}")
    print(f"  Attacker:   {args.ip}")
    print(f"  Attack:     {args.type}")
    print(f"{'='*70}\n")

    # Generate attack features
    features = generate_attack_features(args.type)

    for i in range(1, args.count + 1):
        if args.count > 1:
            print(f"\n>>> Attack attempt {i}/{args.count}")

        try:
            response = None
            import urllib.request
            data = json.dumps(features).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST"
            )

            start_time = time.time()
            with urllib.request.urlopen(req, timeout=15) as res:
                response = json.loads(res.read().decode("utf-8"))
            elapsed_ms = round((time.time() - start_time) * 1000, 2)

            # Print result
            print(f"  [RESPONSE] Status: {response.get('status')}")
            print(f"  [DETECT]    Threat Detected: {response.get('threat_detected')}")
            print(f"  [DETECT]    Attack Type: {response.get('attack_type')}")
            print(f"  [DETECT]    Threat Score: {response.get('threat_score')}")
            print(f"  [DETECT]    Latency: {response.get('inference_latency_ms')} ms")
            print(f"  [DB]        Repeated IP: {response.get('matched_database')}")
            print(f"  [DB]        Stored in Database: {response.get('database_updated')}")
            print(f"  [RESPONSE]  Actions Taken: {', '.join(response.get('actions_taken', []))}")
            print(f"  [MSG]       {response.get('message')}")

        except Exception as e:
            print(f"\n  [ERROR]   Failed to send attack: {e}")
            print(f"  [TIP]     Make sure the Aegis backend is running on {url}")

        if i < args.count and args.interval > 0:
            print(f"  [WAIT]    Sleeping {args.interval}s before next attack...")
            time.sleep(args.interval)

    print(f"\n{'='*70}\n")
    print(f"Attack simulation complete. IP {args.ip} logged in the Aegis database")
    print(f"Run the simulator again with the SAME IP to see the fast-path detection!\n")
    print(f"Tip: Try different attack types and repeat to see repeat detection:\n")
    print(f"  python scripts/send_attack.py --ip {args.ip} --type BruteForce")
    print(f"  python scripts/send_attack.py --ip {args.ip} --type DDoS\n")


if __name__ == "__main__":
    main()
