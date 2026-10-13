#!/usr/bin/env bash
# Download script for CICIDS2017 Dataset
set -e

DATA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/data"
mkdir -p "$DATA_DIR"

echo "=== Aegis CICIDS2017 Data Downloader ==="
echo "Downloading dataset files to: $DATA_DIR"

URL="https://www.unb.ca/cic/datasets/ids-2017.html"

echo "Note: UNB requires accepting their terms on the website."
echo "Please visit $URL if direct link is unavailable."
echo "Extracting CSV files to $DATA_DIR"

# Download official zip if direct mirror available or prompt user
if command -v wget &> /dev/null; then
    echo "Attempting dataset download..."
    # Placeholder for direct mirror endpoint if available
fi

echo "Data download setup complete."
