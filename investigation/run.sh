#!/usr/bin/env bash
# ============================================================
#  CPS-IDS Forensic Investigation — tmux Orchestrator
#
#  Creates a 4-pane tmux session and starts:
#    Top-left:      Plant Dashboard
#    Top-right:     IDS Monitor (rule engine + CNN+LSTM)
#    Bottom-left:   tcpdump packet capture
#    Bottom-right:  Attack runner (auto-sequences all 7 attacks)
#
#  Usage:  ./investigation/run.sh
#  Stop:   tmux kill-session -t cps-investigation
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
EVIDENCE="$REPO/evidence"
SESSION="cps-investigation"

echo "=============================================="
echo "  CPS-IDS Forensic Investigation"
echo "=============================================="
echo

# ----------------------------------------------------------
#  Prerequisites
# ----------------------------------------------------------
errors=0

if [[ ! -f "$REPO/ids/target/release/monitor" ]]; then
    echo "ERROR: Monitor binary not found."
    echo "  Fix: cd ids && cargo build --release -p ids-engine --bin monitor"
    errors=1
fi

if [[ ! -f "$REPO/ids/pytorch-train/data/models/model-b/cnn_lstm_model.onnx" ]]; then
    echo "ERROR: ONNX model (model-b) not found."
    echo "  Fix: cd ids/pytorch-train && python3 export_onnx.py"
    errors=1
fi

if [[ ! -f "$REPO/ids/pytorch-train/data/models/model-b/scaler.json" ]]; then
    echo "ERROR: Scaler JSON (model-b) not found."
    errors=1
fi

python3 -c "import pymodbus" 2>/dev/null || { echo "ERROR: pip install pymodbus"; errors=1; }
python3 -c "import onnxruntime" 2>/dev/null || { echo "ERROR: pip install onnxruntime"; errors=1; }
command -v tmux  >/dev/null || { echo "ERROR: install tmux";   errors=1; }
command -v tcpdump >/dev/null || { echo "ERROR: install tcpdump"; errors=1; }

if [[ $errors -ne 0 ]]; then
    echo
    echo "Fix the above errors and re-run."
    exit 1
fi

echo "[+] All prerequisites OK"

# ----------------------------------------------------------
#  Evidence directories
# ----------------------------------------------------------
mkdir -p "$EVIDENCE"/{pcaps,logs,screenshots}
rm -f "$EVIDENCE/logs/alerts.jsonl"   # fresh investigation
echo "[+] Evidence dir: $EVIDENCE"

# ----------------------------------------------------------
#  Sudo credentials
# ----------------------------------------------------------
echo
echo "sudo is required for tcpdump and the IDS monitor."
sudo -v

# Keep sudo alive in background until this script exits
( while true; do sudo -n -v 2>/dev/null; sleep 50; done ) &
SUDO_PID=$!
trap 'kill $SUDO_PID 2>/dev/null' EXIT

echo "[+] sudo cached"

# ----------------------------------------------------------
#  tmux session
# ----------------------------------------------------------
tmux kill-session -t "$SESSION" 2>/dev/null || true

# Create session with first pane (will be top-left = Dashboard)
tmux new-session -d -s "$SESSION" -n main

# Split into 2x2 grid
W="$SESSION:main"
tmux split-window -h  -t "$W"          # right pane (pane 1)
tmux split-window -v  -t "$W.0"        # bottom-left (pane 2, pushes original 0 up)
tmux split-window -v  -t "$W.1"        # bottom-right (pane 3, pushes original 1 up)

# After splits the pane layout is:
#   .0 = top-left      → Dashboard
#   .1 = top-right     → IDS Monitor
#   .2 = bottom-left   → tcpdump
#   .3 = bottom-right  → Attack Runner

# ----------------------------------------------------------
#  Start services
# ----------------------------------------------------------

# Top-left — Dashboard
tmux send-keys -t "$W.0" \
  "cd '$REPO/plant/dashboard' && python3 app.py" Enter

# Bottom-left — tcpdump
tmux send-keys -t "$W.2" \
  "sudo tcpdump -i lo tcp port 5502 -w '$EVIDENCE/pcaps/full-session.pcap' -U" Enter

# Top-right — IDS Monitor
tmux send-keys -t "$W.1" \
  "cd '$REPO/ids' && sudo ./target/release/monitor --interface lo --modbus-port 5502 --log-file '$EVIDENCE/logs/alerts.jsonl' --model pytorch-train/data/models/model-b/cnn_lstm_model.onnx --scaler pytorch-train/data/models/model-b/scaler.json --ml-threshold 0.5 --flow-timeout 15" Enter

# Bottom-right — Attack runner (waits for dashboard, starts simulation, runs attacks)
tmux send-keys -t "$W.3" \
  "python3 '$REPO/investigation/attack-runner.py' --evidence-dir '$EVIDENCE' --repo-dir '$REPO'" Enter

# Focus attack runner pane
tmux select-pane -t "$W.3"

echo
echo "[+] tmux session '$SESSION' created"
echo
echo "  ┌──────────────────┬──────────────────┐"
echo "  │  Dashboard       │  IDS Monitor     │"
echo "  │  (top-left)      │  (top-right)     │"
echo "  ├──────────────────┼──────────────────┤"
echo "  │  tcpdump         │  Attack Runner   │"
echo "  │  (bottom-left)   │  (bottom-right)  │"
echo "  └──────────────────┴──────────────────┘"
echo
echo "  Attaching now. Detach: Ctrl+B then D"
echo "  Kill session:  tmux kill-session -t $SESSION"
echo

exec tmux attach -t "$SESSION"
