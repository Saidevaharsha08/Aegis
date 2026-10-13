#!/usr/bin/env python3
"""
Aegis Multi-Vector Attack Generator CLI.

Generates attack payloads across all 10 attack categories and dispatches them
to the local Aegis REST API engine:
  - BENIGN
  - DoS
  - DDoS
  - PortScan
  - BruteForce
  - Bot
  - Web Attack
  - Infiltration
  - Heartbleed
  - Malicious_Traffic

Usage:
  python scripts/generate_all_attacks.py --type DoS
  python scripts/generate_all_attacks.py --all
  python scripts/generate_all_attacks.py --barrage --count 20
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error

API_HOST = "localhost"
API_PORT = 8000


def post_json(url: str, payload: dict) -> dict:
    data_bytes = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data_bytes,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8")
        print(f"[!] HTTP {e.code} Error: {err_msg}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Connection failed: {e}", file=sys.stderr)
        print("[!] Ensure the Aegis backend is running on http://localhost:8000", file=sys.stderr)
        sys.exit(1)


def generate_single(attack_type: str, source_ip: str = "203.0.113.88"):
    url = f"http://{API_HOST}:{API_PORT}/api/v1/generator/attack"
    payload = {
        "attack_type": attack_type,
        "source_ip": source_ip,
        "auto_respond": True,
        "optimize_rules": True
    }
    print(f"\n[*] Injecting Attack Vector: {attack_type} (Source IP: {source_ip})...")
    start = time.time()
    res = post_json(url, payload)
    elapsed = round((time.time() - start) * 1000, 2)

    det = res.get("detection", {})
    ledger = res.get("ledger_entry", {})
    qaoa = res.get("qaoa_optimization", {})
    resp = res.get("response", {})

    print(f" [+] Status: {res.get('status')}")
    print(f" [+] Threat Detected: {det.get('threat_detected')} (Score: {det.get('threat_score')})")
    print(f" [+] Attack Classification: {det.get('attack_type')} [Confidence: {det.get('confidence')}]")
    print(f" [+] SHAP Top Feature: {det.get('top_features', [{}])[0].get('feature')} (+{det.get('top_features', [{}])[0].get('shap_value')})")
    print(f" [+] QAOA Solver: {qaoa.get('solver')} ({len(qaoa.get('selected_rules', []))} rules selected)")
    print(f" [+] Audit Ledger Hash: {ledger.get('current_hash', '')[:16]}...")
    if resp and resp.get("actions_taken"):
        print(f" [+] Defense Playbook Executed: {', '.join(resp.get('actions_taken', []))}")
    print(f" [+] Roundtrip Latency: {elapsed} ms")


def generate_barrage(count: int = 15):
    url = f"http://{API_HOST}:{API_PORT}/api/v1/generator/barrage"
    payload = {"count": count, "auto_respond": True}
    print(f"\n[*] Launching {count}-Attack Multi-Vector Barrage Campaign...")
    res = post_json(url, payload)

    print(f" [+] Total Attacks Generated: {res.get('total_attacks_generated')}")
    print(f" [+] Threats Detected: {res.get('threats_detected')}")
    print(f" [+] Detection Rate: {res.get('detection_rate_percent')}%")
    print(f" [+] Avg Inference Latency: {res.get('avg_inference_latency_ms')} ms")
    print(f" [+] Audit Ledger Chain Length: {res.get('ledger_chain_length')} blocks")

    print("\n [Campaign Log Snippet]")
    for item in res.get("attacks", [])[:10]:
        status_flag = "ALERT" if item["threat_detected"] else "PASS"
        print(f"  [{status_flag}] #{item['step']} {item['attack_type']:<18} | IP: {item['source_ip']:<15} | Score: {item['threat_score']:.3f} | Hash: {item['ledger_hash']}")


def main():
    parser = argparse.ArgumentParser(description="Aegis Multi-Vector Attack Generator CLI")
    parser.add_argument("--type", type=str, default="DoS", help="Attack type (e.g., DoS, DDoS, PortScan, BruteForce, Bot, Heartbleed)")
    parser.add_argument("--all", action="store_true", help="Generate all 10 attack profiles sequentially")
    parser.add_argument("--barrage", action="store_true", help="Launch multi-vector attack barrage campaign")
    parser.add_argument("--count", type=int, default=15, help="Number of attacks for barrage campaign")
    parser.add_argument("--ip", type=str, default="203.0.113.42", help="Source IP to simulate")
    args = parser.parse_args()

    if args.barrage:
        generate_barrage(count=args.count)
    elif args.all:
        attack_list = ["BENIGN", "DoS", "DDoS", "PortScan", "BruteForce", "Bot", "Web Attack", "Infiltration", "Heartbleed", "Malicious_Traffic"]
        for atk in attack_list:
            generate_single(atk, source_ip=args.ip)
            time.sleep(0.3)
    else:
        generate_single(args.type, source_ip=args.ip)


if __name__ == "__main__":
    main()
