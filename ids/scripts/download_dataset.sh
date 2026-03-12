#!/usr/bin/env bash
# Download the NSL-KDD dataset for IDS/IPS training and evaluation
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="$SCRIPT_DIR/../data/nsl-kdd"

mkdir -p "$DATA_DIR"

BASE_URL="https://raw.githubusercontent.com/defcom17/NSL_KDD/master"

echo "Downloading NSL-KDD dataset..."

if [ ! -f "$DATA_DIR/KDDTrain+.txt" ]; then
    echo "  -> KDDTrain+.txt"
    curl -sL "$BASE_URL/KDDTrain%2B.txt" -o "$DATA_DIR/KDDTrain+.txt"
else
    echo "  -> KDDTrain+.txt (already exists)"
fi

if [ ! -f "$DATA_DIR/KDDTest+.txt" ]; then
    echo "  -> KDDTest+.txt"
    curl -sL "$BASE_URL/KDDTest%2B.txt" -o "$DATA_DIR/KDDTest+.txt"
else
    echo "  -> KDDTest+.txt (already exists)"
fi

echo ""
echo "Dataset download complete."
echo "  Train: $(wc -l < "$DATA_DIR/KDDTrain+.txt") records"
echo "  Test:  $(wc -l < "$DATA_DIR/KDDTest+.txt") records"
