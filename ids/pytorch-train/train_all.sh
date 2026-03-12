#!/usr/bin/env bash
# Autonomous overnight training — runs Models A→D sequentially.
# Works over SSH (no GUI needed). Use with tmux/screen to detach.
#
# Usage:
#   tmux                    # optional: lets you detach and reconnect
#   ./train_all.sh          # runs all 4 models A→B→C→D
#   # Ctrl+B, D to detach   # come back later with: tmux attach
#
# Each model's output is logged to data/logs/model-{a,b,c,d}.log
# and also printed to the terminal in real time.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VENV="$SCRIPT_DIR/.venv/bin/activate"
LOG_DIR="$SCRIPT_DIR/data/logs"
mkdir -p "$LOG_DIR"

# --- Activate venv ---
source "$VENV"

# --- Dataset paths ---
NSL_TRAIN="$REPO_ROOT/NSL-KDD-Dataset/KDDTrain+.txt"
NSL_TEST="$REPO_ROOT/NSL-KDD-Dataset/KDDTest+.txt"
CICIDS_DIR="$REPO_ROOT/CIC-IDS2017-Dataset/CSVs/MachineLearningCSV/MachineLearningCVE/"
UNSW_DATA="$REPO_ROOT/CIC-UNSW-NB15-Dataset/Data.csv"
UNSW_LABEL="$REPO_ROOT/CIC-UNSW-NB15-Dataset/Label.csv"

cd "$SCRIPT_DIR"

echo ""
echo "=========================================="
echo "[+] CNN+LSTM Autonomous Training Pipeline"
echo "=========================================="
echo ""
echo "  Model A (NSL-KDD) → B (CIC-IDS2017) → C (UNSW-NB15) → D (Combined)"
echo "  Sequential: each model gets full GPU"
echo "  Logs: $LOG_DIR/"
echo ""
echo "  Tip: run inside tmux to safely detach from SSH"
echo ""

START_TIME=$(date +%s)

# --- Model A ---
echo "=========================================="
echo "  [1/4] Model A: NSL-KDD"
echo "  Started: $(date)"
echo "=========================================="
echo ""

python train.py --dataset nsl-kdd \
    --nsl-train "$NSL_TRAIN" \
    --nsl-test "$NSL_TEST" \
    --output-dir data/models/model-a \
    2>&1 | tee "$LOG_DIR/model-a.log"

echo ""
echo "[+] Model A complete at $(date)"
echo ""

# --- Model B ---
echo "=========================================="
echo "  [2/4] Model B: CIC-IDS2017"
echo "  Started: $(date)"
echo "=========================================="
echo ""

python train.py --dataset cicids2017 \
    --cicids-dir "$CICIDS_DIR" \
    --output-dir data/models/model-b --no-smote \
    2>&1 | tee "$LOG_DIR/model-b.log"

echo ""
echo "[+] Model B complete at $(date)"
echo ""

# --- Model C ---
echo "=========================================="
echo "  [3/4] Model C: UNSW-NB15"
echo "  Started: $(date)"
echo "=========================================="
echo ""

python train.py --dataset unsw-nb15 \
    --unsw-data "$UNSW_DATA" \
    --unsw-label "$UNSW_LABEL" \
    --output-dir data/models/model-c \
    2>&1 | tee "$LOG_DIR/model-c.log"

echo ""
echo "[+] Model C complete at $(date)"
echo ""

# --- Model D ---
echo "=========================================="
echo "  [4/4] Model D: Combined (NSL-KDD + CIC-IDS2017 + UNSW-NB15)"
echo "  Started: $(date)"
echo "=========================================="
echo ""

python train.py --dataset combined \
    --nsl-train "$NSL_TRAIN" \
    --nsl-test "$NSL_TEST" \
    --cicids-dir "$CICIDS_DIR" \
    --unsw-data "$UNSW_DATA" \
    --unsw-label "$UNSW_LABEL" \
    --output-dir data/models/model-d --no-smote \
    2>&1 | tee "$LOG_DIR/model-d.log"

END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))
HOURS=$(( ELAPSED / 3600 ))
MINS=$(( (ELAPSED % 3600) / 60 ))

echo ""
echo "=========================================="
echo "  ALL 4 MODELS COMPLETE"
echo "  Finished: $(date)"
echo "  Total time: ${HOURS}h ${MINS}m"
echo "=========================================="
echo ""
echo "  Logs:"
echo "    $LOG_DIR/model-a.log"
echo "    $LOG_DIR/model-b.log"
echo "    $LOG_DIR/model-c.log"
echo "    $LOG_DIR/model-d.log"
echo ""
echo "  Models:"
echo "    data/models/model-a/"
echo "    data/models/model-b/"
echo "    data/models/model-c/"
echo "    data/models/model-d/"
echo ""
