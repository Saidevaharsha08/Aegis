#!/usr/bin/env bash
# Training Trigger Script for Aegis IDS Model
set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="$PROJECT_ROOT/backend:$PROJECT_ROOT"

echo "=== Aegis IDS Training Trigger ==="
python "$PROJECT_ROOT/scripts/simulate_attack.py" --train
python "$PROJECT_ROOT/backend/app/ml/evaluate.py"

echo "[+] Training and Benchmark completed successfully."
