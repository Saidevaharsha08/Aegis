#!/usr/bin/env python3
"""Generate a random API key for Aegis and optionally write it to backend/.env

Usage:
  python backend/generate_api_key.py
  python backend/generate_api_key.py --write
"""
import secrets
import argparse
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description="Generate DETECT_API_KEY for Aegis backend")
    p.add_argument("--write", action="store_true", help="Write key to backend/.env (overwrites if exists)")
    args = p.parse_args()

    key = secrets.token_urlsafe(32)
    print(key)

    if args.write:
        env_path = Path(__file__).resolve().parent / ".env"
        with env_path.open("w", encoding="utf-8") as fh:
            fh.write(f"DETECT_API_KEY={key}\n")
        print(f"Wrote key to {env_path}")


if __name__ == "__main__":
    main()
