#!/usr/bin/env python3
"""Simple device forwarder to send feature JSON to the Aegis `/api/detect` endpoint.

Usage examples:
  python scripts/device_forwarder.py --host localhost --port 8000 --file scripts/example_event.json
  cat scripts/example_event.json | python scripts/device_forwarder.py --host 1.2.3.4 --port 80
"""
import argparse
import json
import sys

try:
    import requests
except Exception:
    requests = None
    import urllib.request
    import urllib.error


def send_with_requests(url, data, headers):
    resp = requests.post(url, json=data, headers=headers, timeout=10)
    print(resp.status_code)
    print(resp.text)


def send_with_urllib(url, data, headers):
    data_bytes = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(resp.status)
            print(resp.read().decode())
    except urllib.error.HTTPError as e:
        print(e.code, e.read().decode(), file=sys.stderr)
        sys.exit(1)


def main():
    p = argparse.ArgumentParser(description="Send a JSON feature event to /api/detect")
    p.add_argument("--host", default="localhost", help="Server host")
    p.add_argument("--port", default="8000", help="Server port")
    p.add_argument("--path", default="/api/detect", help="API path")
    p.add_argument("--file", help="Path to JSON file to send (or read from stdin if omitted)")
    p.add_argument("--insecure", action="store_true", help="Use http instead of https")
    args = p.parse_args()

    if args.file:
        with open(args.file, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    else:
        try:
            data = json.load(sys.stdin)
        except Exception:
            print("No input JSON provided (use --file or pipe JSON to stdin)")
            sys.exit(2)

    scheme = "http" if args.insecure else "http"
    url = f"{scheme}://{args.host}:{args.port}{args.path}"
    headers = {"Content-Type": "application/json"}

    if requests:
        send_with_requests(url, data, headers)
    else:
        send_with_urllib(url, data, headers)


if __name__ == "__main__":
    main()
