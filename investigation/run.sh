#!/usr/bin/env bash
# ============================================================
#  CPS-IDS Forensic Investigation — tmux Orchestrator
#
#  Creates a 4-pane tmux session and starts:
#    Top-left:      Plant Dashboard
#    Top-right:     IDS Monitor (rule engine + CNN+LSTM)
#    Bottom-left:   tcpdump packet capture
#    Bottom-right:  Attack runner (auto-sequences all 8 attacks incl. Stuxnet rootkit)
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
chown -R "$REAL_USER":"$REAL_USER" "$EVIDENCE"

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

# Create session and 2x2 grid, capturing actual pane IDs
tmux new-session -d -s "$SESSION" -P -F '#{pane_id}' > /dev/null
tmux split-window -h -t "$SESSION"
tmux split-window -v -t "$SESSION"
tmux select-pane  -L -t "$SESSION"
tmux split-window -v -t "$SESSION"

# Read the actual pane IDs by position (top/left coordinates)
# Sort: top-left, top-right, bottom-left, bottom-right
mapfile -t PANES < <(tmux list-panes -t "$SESSION" -F '#{pane_top} #{pane_left} #{pane_id}' | sort -n -k1 -k2 | awk '{print $3}')

P_TL="${PANES[0]}"   # top-left     → Dashboard
P_TR="${PANES[1]}"   # top-right    → IDS Monitor
P_BL="${PANES[2]}"   # bottom-left  → tcpdump
P_BR="${PANES[3]}"   # bottom-right → Attack Runner

# ----------------------------------------------------------
#  Start services
# ----------------------------------------------------------

# Commands that need user Python packages run as the real user
RUN_AS="sudo -u $REAL_USER"

# Top-left — Dashboard (needs fastapi — run as user)
tmux send-keys -t "$P_TL" \
  "cd '$REPO/plant/dashboard' && $RUN_AS python3 app.py" Enter

# Bottom-left — tcpdump (needs root)
tmux send-keys -t "$P_BL" \
  "tcpdump -i lo tcp port 5502 -w '$RUN_DIR/pcaps/full-session.pcap' -U" Enter

# Top-right — IDS Monitor (needs root for packet capture)
# Set PYTHONPATH so the monitor's Python subprocess can find user-installed packages
# (onnxruntime is in ~/.local/lib/python3.*/site-packages, invisible to root)
USER_SITE="$(sudo -u "$REAL_USER" python3 -m site --user-site 2>/dev/null)"
tmux send-keys -t "$P_TR" \
  "cd '$REPO/ids' && PYTHONPATH='$USER_SITE' ./target/release/monitor --interface lo --modbus-port 5502 --log-file '$RUN_DIR/logs/alerts.jsonl' --model pytorch-train/data/models/model-b/cnn_lstm_model.onnx --scaler pytorch-train/data/models/model-b/scaler.json --ml-threshold 0.5 --flow-timeout 5" Enter

# Bottom-right — Attack runner (needs pymodbus — run as user)
tmux send-keys -t "$P_BR" \
  "$RUN_AS python3 '$REPO/investigation/attack-runner.py' --evidence-dir '$RUN_DIR' --repo-dir '$REPO'" Enter

# Focus attack runner pane
tmux select-pane -t "$P_BR"

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
