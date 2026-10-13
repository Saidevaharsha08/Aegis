#!/usr/bin/env python3
"""Aegis Mesh Companion CLI.

Friends run this on their laptop to send attack traffic against the
Aegis mesh. The CLI posts a single normalized event to the public
Aegis URL — the mesh does the rest (fingerprint, correlate,
countermeasure).

Examples
--------
    # Send a port scan from this machine
    python scripts/mesh_cli.py send \\
        --target https://aegis.example.com \\
        --service http --type port_scan \\
        --apikey $AEGIS_KEY

    # Run the "ladder" — six progressively clever attacks on a loop
    python scripts/mesh_cli.py ladder \\
        --target https://aegis.example.com \\
        --apikey $AEGIS_KEY \\
        --interval 6

Environment
-----------
    AEGIS_TARGET   default target URL (overridden by --target)
    AEGIS_API_KEY  default API key (overridden by --apikey)
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from typing import Any

import urllib.request
import urllib.error


LADDER = [
    ("http", "port_scan", "GET / HTTP/1.1\r\nHost: target\r\n", "nmap/7.92"),
    ("ssh", "ssh_bruteforce", "admin:password\nroot:toor\n", "paramiko/2.7.2"),
    ("http", "http_path_enum", "GET /.env HTTP/1.1\r\nHost: target\r\n", "gobuster/3.1.0"),
    ("smb", "smb_enum", "SMB negprot", ""),
    ("http", "low_volume_dos", "GET / HTTP/1.1\r\n\r\n" * 50, "slowloris/0.1.4"),
    ("http", "credential_stuffing", "username=admin&password=admin", "Mozilla/5.0"),
]


def _post(url: str, body: dict[str, Any], apikey: str | None, timeout: float = 5.0) -> dict[str, Any]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": body.get("user_agent", "aegis-mesh-cli/1.0"),
            **({"X-API-Key": apikey} if apikey else {}),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        return {"error": f"HTTP {exc.code}: {exc.reason}"}
    except urllib.error.URLError as exc:
        return {"error": f"connection failed: {exc.reason}"}


def _honeypot_get(url: str, apikey: str | None, timeout: float = 5.0) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        method="GET",
        headers={**({"X-API-Key": apikey} if apikey else {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        return {"error": f"HTTP {exc.code}: {exc.reason}"}
    except urllib.error.URLError as exc:
        return {"error": f"connection failed: {exc.reason}"}


def cmd_send(args: argparse.Namespace) -> int:
    target = args.target.rstrip("/")
    url = f"{target}/mesh/attack"
    body = {
        "service": args.service,
        "src_ip": args.src_ip,
        "payload": args.payload,
        "user_agent": args.user_agent,
    }
    out = _post(url, body, args.apikey)
    print(json.dumps(out, indent=2))
    return 0 if "error" not in out else 1


def cmd_honeypot(args: argparse.Namespace) -> int:
    """Hit the decoy endpoint directly (banner-grab style)."""
    target = args.target.rstrip("/")
    url = f"{target}/mesh/honeypots/{args.service}"
    out = _honeypot_get(url, args.apikey)
    print(json.dumps(out, indent=2))
    return 0 if "error" not in out else 1


def cmd_ladder(args: argparse.Namespace) -> int:
    target = args.target.rstrip("/")
    src_ip = args.src_ip
    print(f"[*] ladder attack against {target} every {args.interval}s — Ctrl-C to stop")
    try:
        i = 0
        while True:
            service, kind, payload, ua = LADDER[i % len(LADDER)]
            out = _post(
                f"{target}/mesh/attack",
                {
                    "service": service,
                    "src_ip": src_ip,
                    "payload": payload,
                    "user_agent": ua,
                },
                args.apikey,
            )
            campaign_id = (out.get("campaign") or {}).get("campaign_id") or "-"
            print(f"  [{i+1:>3}] {kind:<20} campaign={campaign_id[:10]}")
            i += 1
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[!] stopped")
        return 0


def cmd_state(args: argparse.Namespace) -> int:
    target = args.target.rstrip("/")
    url = f"{target}/mesh/state"
    req = urllib.request.Request(
        url,
        headers={**({"X-API-Key": args.apikey} if args.apikey else {})},
    )
    with urllib.request.urlopen(req, timeout=5.0) as resp:
        print(json.dumps(json.loads(resp.read().decode()), indent=2))
    return 0


def cmd_share(args: argparse.Namespace) -> int:
    """Mint a public share-link the operator can hand to friends."""
    target = args.target.rstrip("/")
    url = f"{target}/mesh/share/issue"
    body = json.dumps({"ttl_seconds": args.ttl}).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            out = json.loads(resp.read().decode())
    except urllib.error.URLError as exc:
        print(f"connection failed: {exc.reason}", file=sys.stderr)
        return 1
    share_url = f"{target}{out['share_url']}"
    print(json.dumps(out, indent=2))
    print(f"\n[+] Send your friend this URL:\n    {share_url}")
    print(f"[+] Expires: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(out['expires_at']))}")
    return 0


def cmd_bounty(args: argparse.Namespace) -> int:
    """Claim an outstanding bounty."""
    target = args.target.rstrip("/")
    url = f"{target}/mesh/bounty/claim"
    body = json.dumps({
        "peer": args.peer,
        "campaign_id": args.campaign_id,
        "token": args.token,
    }).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            print(json.dumps(json.loads(resp.read().decode()), indent=2))
    except urllib.error.URLError as exc:
        print(f"claim failed: {exc.reason}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="aegis-mesh", description="Send traffic to the Aegis Quantum Defense Mesh")
    sub = p.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--target", default=os.getenv("AEGIS_TARGET", "http://localhost:8000"))
    common.add_argument("--apikey", default=os.getenv("AEGIS_API_KEY"))
    common.add_argument("--src-ip", default=f"198.51.100.{random.randint(2, 254)}")

    sp = sub.add_parser("send", parents=[common], help="send a single attack event")
    sp.add_argument("--service", choices=["ssh", "http", "smb"], default="http")
    sp.add_argument("--type", default="custom")
    sp.add_argument("--payload", default="")
    sp.add_argument("--user-agent", default="aegis-mesh-cli/1.0")
    sp.set_defaults(func=cmd_send)

    hp = sub.add_parser("honeypot", parents=[common], help="hit a decoy endpoint")
    hp.add_argument("--service", choices=["ssh", "http", "smb"], default="http")
    hp.set_defaults(func=cmd_honeypot)

    ld = sub.add_parser("ladder", parents=[common], help="loop through the attack ladder")
    ld.add_argument("--interval", type=float, default=5.0)
    ld.set_defaults(func=cmd_ladder)

    st = sub.add_parser("state", parents=[common], help="fetch mesh state snapshot")
    st.set_defaults(func=cmd_state)

    sh = sub.add_parser("share", parents=[common], help="issue a public share-link for friends")
    sh.add_argument("--ttl", type=int, default=24*3600, help="seconds until token expires")
    sh.set_defaults(func=cmd_share)

    bn = sub.add_parser("bounty", parents=[common], help="claim a peer bounty")
    bn.add_argument("--peer", required=True, help="your peer handle (must match the award)")
    bn.add_argument("--campaign-id", required=True)
    bn.add_argument("--token", required=True, help="HMAC token from /mesh/state -> bounty.recent")
    bn.set_defaults(func=cmd_bounty)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
