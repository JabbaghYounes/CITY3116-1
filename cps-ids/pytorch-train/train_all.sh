#!/usr/bin/env bash
# Autonomous overnight training — runs Models A→D sequentially,
# each in its own terminal so you can review output per-model.
#
# Usage:
#   chmod +x train_all.sh && ./train_all.sh
#
# What happens:
#   1. Model A starts immediately in a new terminal
#   2. When A finishes, it spawns Model B in a new terminal
#   3. When B finishes, it spawns Model C, etc.
#   4. Come back to 4 terminals, each showing one model's full output

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VENV="$SCRIPT_DIR/.venv/bin/activate"
LOG_DIR="$SCRIPT_DIR/data/logs"
mkdir -p "$LOG_DIR"

# Detect terminal emulator
detect_terminal() {
    for term in gnome-terminal konsole xfce4-terminal mate-terminal xterm; do
        if command -v "$term" &>/dev/null; then
            echo "$term"
            return
        fi
    done
    echo ""
}

TERM_EMU=$(detect_terminal)
if [ -z "$TERM_EMU" ]; then
    echo "[x] No supported terminal emulator found (tried gnome-terminal, konsole, xfce4-terminal, mate-terminal, xterm)"
    echo "    Install one or run train_all_bg.sh for background mode instead."
    exit 1
fi
echo "[+] Using terminal: $TERM_EMU"

# --- Dataset paths ---
NSL_TRAIN="$REPO_ROOT/NSL-KDD-Dataset/KDDTrain+.txt"
NSL_TEST="$REPO_ROOT/NSL-KDD-Dataset/KDDTest+.txt"
CICIDS_DIR="$REPO_ROOT/CIC-IDS2017-Dataset/CSVs/MachineLearningCSV/MachineLearningCVE/"
UNSW_DATA="$REPO_ROOT/CIC-UNSW-NB15-Dataset/Data.csv"
UNSW_LABEL="$REPO_ROOT/CIC-UNSW-NB15-Dataset/Label.csv"

# --- Helper to open a command in a new terminal that stays open ---
run_in_terminal() {
    local title="$1"
    local cmd="$2"
    case "$TERM_EMU" in
        gnome-terminal)
            gnome-terminal --title="$title" -- bash -c "$cmd; echo ''; echo 'Press Enter to close...'; read"
            ;;
        konsole)
            konsole --new-tab -p tabtitle="$title" -e bash -c "$cmd; echo ''; echo 'Press Enter to close...'; read"
            ;;
        xfce4-terminal)
            xfce4-terminal --title="$title" -e "bash -c \"$cmd; echo ''; echo 'Press Enter to close...'; read\""
            ;;
        mate-terminal)
            mate-terminal --title="$title" -e "bash -c \"$cmd; echo ''; echo 'Press Enter to close...'; read\""
            ;;
        xterm)
            xterm -title "$title" -hold -e bash -c "$cmd" &
            ;;
    esac
}

# --- Generate the chained training scripts ---
# Each script runs one model then spawns the next in a new terminal.

cat > "$SCRIPT_DIR/_train_d.sh" <<'OUTER'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "VENV_PLACEHOLDER"
# HSA_OVERRIDE_GFX_VERSION for RDNA 4 compatibility (uncomment if needed)
# export HSA_OVERRIDE_GFX_VERSION=11.0.0
cd "$SCRIPT_DIR"
echo "=========================================="
echo "  Model D: Combined (NSL-KDD + CIC-IDS2017 + UNSW-NB15)"
echo "=========================================="
echo ""
python train.py --dataset combined \
    --nsl-train "NSL_TRAIN_PLACEHOLDER" \
    --nsl-test "NSL_TEST_PLACEHOLDER" \
    --cicids-dir "CICIDS_DIR_PLACEHOLDER" \
    --unsw-data "UNSW_DATA_PLACEHOLDER" \
    --unsw-label "UNSW_LABEL_PLACEHOLDER" \
    --output-dir data/models/model-d --no-smote \
    2>&1 | tee "LOG_DIR_PLACEHOLDER/model-d.log"
echo ""
echo "=========================================="
echo "  ALL 4 MODELS COMPLETE"
echo "=========================================="
OUTER

cat > "$SCRIPT_DIR/_train_c.sh" <<'OUTER'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "VENV_PLACEHOLDER"
# export HSA_OVERRIDE_GFX_VERSION=11.0.0
cd "$SCRIPT_DIR"
echo "=========================================="
echo "  Model C: UNSW-NB15"
echo "=========================================="
echo ""
python train.py --dataset unsw-nb15 \
    --unsw-data "UNSW_DATA_PLACEHOLDER" \
    --unsw-label "UNSW_LABEL_PLACEHOLDER" \
    --output-dir data/models/model-c \
    2>&1 | tee "LOG_DIR_PLACEHOLDER/model-c.log"
echo ""
echo "Model C done. Spawning Model D..."
SPAWN_D_PLACEHOLDER
OUTER

cat > "$SCRIPT_DIR/_train_b.sh" <<'OUTER'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "VENV_PLACEHOLDER"
# export HSA_OVERRIDE_GFX_VERSION=11.0.0
cd "$SCRIPT_DIR"
echo "=========================================="
echo "  Model B: CIC-IDS2017"
echo "=========================================="
echo ""
python train.py --dataset cicids2017 \
    --cicids-dir "CICIDS_DIR_PLACEHOLDER" \
    --output-dir data/models/model-b --no-smote \
    2>&1 | tee "LOG_DIR_PLACEHOLDER/model-b.log"
echo ""
echo "Model B done. Spawning Model C..."
SPAWN_C_PLACEHOLDER
OUTER

cat > "$SCRIPT_DIR/_train_a.sh" <<'OUTER'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "VENV_PLACEHOLDER"
# export HSA_OVERRIDE_GFX_VERSION=11.0.0
cd "$SCRIPT_DIR"
echo "=========================================="
echo "  Model A: NSL-KDD"
echo "=========================================="
echo ""
python train.py --dataset nsl-kdd \
    --nsl-train "NSL_TRAIN_PLACEHOLDER" \
    --nsl-test "NSL_TEST_PLACEHOLDER" \
    --output-dir data/models/model-a \
    2>&1 | tee "LOG_DIR_PLACEHOLDER/model-a.log"
echo ""
echo "Model A done. Spawning Model B..."
SPAWN_B_PLACEHOLDER
OUTER

# --- Fill in placeholders with actual paths ---
for f in "$SCRIPT_DIR"/_train_{a,b,c,d}.sh; do
    sed -i "s|VENV_PLACEHOLDER|$VENV|g" "$f"
    sed -i "s|NSL_TRAIN_PLACEHOLDER|$NSL_TRAIN|g" "$f"
    sed -i "s|NSL_TEST_PLACEHOLDER|$NSL_TEST|g" "$f"
    sed -i "s|CICIDS_DIR_PLACEHOLDER|$CICIDS_DIR|g" "$f"
    sed -i "s|UNSW_DATA_PLACEHOLDER|$UNSW_DATA|g" "$f"
    sed -i "s|UNSW_LABEL_PLACEHOLDER|$UNSW_LABEL|g" "$f"
    sed -i "s|LOG_DIR_PLACEHOLDER|$LOG_DIR|g" "$f"
done

# --- Build spawn commands based on detected terminal ---
spawn_cmd() {
    local title="$1"
    local script="$2"
    case "$TERM_EMU" in
        gnome-terminal)
            echo "gnome-terminal --title='$title' -- bash -c 'bash $script; echo \"\"; echo \"Press Enter to close...\"; read'"
            ;;
        konsole)
            echo "konsole --new-tab -p tabtitle='$title' -e bash -c 'bash $script; echo \"\"; echo \"Press Enter to close...\"; read'"
            ;;
        xfce4-terminal)
            echo "xfce4-terminal --title='$title' -e \"bash -c 'bash $script; echo \\\"\\\"; echo \\\"Press Enter to close...\\\"; read'\""
            ;;
        mate-terminal)
            echo "mate-terminal --title='$title' -e \"bash -c 'bash $script; echo \\\"\\\"; echo \\\"Press Enter to close...\\\"; read'\""
            ;;
        xterm)
            echo "xterm -title '$title' -hold -e bash $script &"
            ;;
    esac
}

SPAWN_B=$(spawn_cmd "CNN+LSTM Model B" "$SCRIPT_DIR/_train_b.sh")
SPAWN_C=$(spawn_cmd "CNN+LSTM Model C" "$SCRIPT_DIR/_train_c.sh")
SPAWN_D=$(spawn_cmd "CNN+LSTM Model D" "$SCRIPT_DIR/_train_d.sh")

sed -i "s|SPAWN_B_PLACEHOLDER|$SPAWN_B|g" "$SCRIPT_DIR/_train_a.sh"
sed -i "s|SPAWN_C_PLACEHOLDER|$SPAWN_C|g" "$SCRIPT_DIR/_train_b.sh"
sed -i "s|SPAWN_D_PLACEHOLDER|$SPAWN_D|g" "$SCRIPT_DIR/_train_c.sh"

chmod +x "$SCRIPT_DIR"/_train_{a,b,c,d}.sh

# --- Launch Model A ---
echo ""
echo "=========================================="
echo "[+] Starting autonomous training pipeline"
echo "=========================================="
echo ""
echo "  Model A → Model B → Model C → Model D"
echo "  Each model runs in its own terminal."
echo "  Logs saved to: $LOG_DIR/"
echo ""
echo "  Launching Model A now..."
echo ""

run_in_terminal "CNN+LSTM Model A" "bash $SCRIPT_DIR/_train_a.sh"

echo "[+] Model A launched. The chain will continue automatically."
echo "    Come back tomorrow to find 4 terminal windows with results."
echo ""
echo "    Logs:"
echo "      $LOG_DIR/model-a.log"
echo "      $LOG_DIR/model-b.log"
echo "      $LOG_DIR/model-c.log"
echo "      $LOG_DIR/model-d.log"
echo ""
