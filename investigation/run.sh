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

# When run via sudo, check Python packages as the real user
if [[ -n "${SUDO_USER:-}" ]]; then
    REAL_USER="$SUDO_USER"
    PY_CHECK="sudo -u $REAL_USER python3"
else
    REAL_USER="$(whoami)"
    PY_CHECK="python3"
fi

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

$PY_CHECK -c "import pymodbus" 2>/dev/null || { echo "ERROR: pip install pymodbus"; errors=1; }
$PY_CHECK -c "import onnxruntime" 2>/dev/null || { echo "ERROR: pip install onnxruntime"; errors=1; }
command -v tmux  >/dev/null || { echo "ERROR: install tmux";   errors=1; }
command -v tcpdump >/dev/null || { echo "ERROR: install tcpdump"; errors=1; }

if [[ $errors -ne 0 ]]; then
    echo
    echo "Fix the above errors and re-run."
    exit 1
fi

echo "[+] All prerequisites OK (user: $REAL_USER)"

# ----------------------------------------------------------
#  Evidence directories (timestamped per run)
# ----------------------------------------------------------
RUN_TS="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$EVIDENCE/run-$RUN_TS"
mkdir -p "$RUN_DIR"/{pcaps,logs}
mkdir -p "$EVIDENCE/screenshots"

# Symlink "latest" for easy access
ln -sfn "run-$RUN_TS" "$EVIDENCE/latest"

echo "[+] Evidence dir: $RUN_DIR"
echo "[+] Symlink:      $EVIDENCE/latest -> run-$RUN_TS"

# ----------------------------------------------------------
#  Sudo check
# ----------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo
    echo "This script needs root for tcpdump and the IDS monitor."
    echo "Re-run with: sudo ./investigation/run.sh"
    exit 1
fi
echo "[+] Running as root"

# ----------------------------------------------------------
#  tmux session — 2x2 grid
# ----------------------------------------------------------
# Ghostty (and other modern terminals) set TERM values tmux doesn't recognise
export TERM="${TERM/ghostty/256color}"
[[ "$TERM" == *256color* || "$TERM" == screen* || "$TERM" == tmux* ]] || export TERM=xterm-256color
tmux kill-session -t "$SESSION" 2>/dev/null || true

tmux new-session  -d -s "$SESSION"              # pane 1 (full window)
tmux split-window -h -t "$SESSION"              # pane 1=left, 2=right
tmux split-window -v -t "$SESSION"              # split right → 2=top-right, 3=bottom-right
tmux select-pane  -L -t "$SESSION"              # move to left pane (1)
tmux split-window -v -t "$SESSION"              # split left → 1=top-left, 4=bottom-left

# Pane layout:
#   .1 = top-left      → Dashboard
#   .2 = top-right     → IDS Monitor
#   .4 = bottom-left   → tcpdump
#   .3 = bottom-right  → Attack Runner

TGT="$SESSION"

# ----------------------------------------------------------
#  Start services
# ----------------------------------------------------------

# Top-left — Dashboard
tmux send-keys -t "$TGT.1" \
  "cd '$REPO/plant/dashboard' && python3 app.py" Enter

# Bottom-left — tcpdump
tmux send-keys -t "$TGT.4" \
  "tcpdump -i lo tcp port 5502 -w '$RUN_DIR/pcaps/full-session.pcap' -U" Enter

# Top-right — IDS Monitor
tmux send-keys -t "$TGT.2" \
  "cd '$REPO/ids' && ./target/release/monitor --interface lo --modbus-port 5502 --log-file '$RUN_DIR/logs/alerts.jsonl' --model pytorch-train/data/models/model-b/cnn_lstm_model.onnx --scaler pytorch-train/data/models/model-b/scaler.json --ml-threshold 0.5 --flow-timeout 5" Enter

# Bottom-right — Attack runner
tmux send-keys -t "$TGT.3" \
  "python3 '$REPO/investigation/attack-runner.py' --evidence-dir '$RUN_DIR' --repo-dir '$REPO'" Enter

# Focus attack runner pane
tmux select-pane -t "$TGT.3"

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
