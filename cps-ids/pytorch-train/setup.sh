#!/usr/bin/env bash
# Setup script for Python PyTorch CNN+LSTM IDS training.
# Supports AMD GPUs (ROCm) and NVIDIA GPUs (CUDA).
#
# Usage:
#   chmod +x setup.sh && ./setup.sh

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[x]${NC} $*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

# --- Detect distro ---
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}

DISTRO=$(detect_distro)
info "Detected distro: $DISTRO"

# --- Install system packages ---
install_packages() {
    case "$DISTRO" in
        ubuntu|debian|pop|linuxmint|elementary)
            info "Installing Python + venv via apt..."
            sudo apt update
            sudo apt install -y python3 python3-venv python3-pip
            ;;
        fedora)
            info "Installing Python + venv via dnf..."
            sudo dnf install -y python3 python3-pip
            ;;
        centos|rhel|rocky|almalinux)
            info "Installing Python + venv via yum..."
            sudo yum install -y python3 python3-pip
            ;;
        arch|manjaro|endeavouros)
            info "Installing Python via pacman..."
            sudo pacman -Syu --noconfirm python python-pip
            ;;
        *)
            warn "Unknown distro '$DISTRO'. Ensure you have python3 and python3-venv."
            ;;
    esac
}

install_packages

# --- Create virtual environment ---
if [ -d "$VENV_DIR" ]; then
    info "Virtual environment already exists at $VENV_DIR"
else
    info "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
    info "Virtual environment created at $VENV_DIR"
fi

# Activate venv
source "$VENV_DIR/bin/activate"
info "Python: $(python --version) at $(which python)"

# Upgrade pip
pip install --upgrade pip

# --- Detect GPU ---
HAS_CUDA=false
HAS_ROCM=false

if command -v nvidia-smi &>/dev/null; then
    if nvidia-smi &>/dev/null; then
        HAS_CUDA=true
        info "NVIDIA GPU detected"
    fi
fi

if command -v rocminfo &>/dev/null; then
    if rocminfo &>/dev/null 2>&1; then
        HAS_ROCM=true
        info "AMD ROCm detected"
    fi
elif [ -d /opt/rocm ]; then
    HAS_ROCM=true
    info "AMD ROCm detected (via /opt/rocm)"
fi

# --- Install PyTorch ---
if [ "$HAS_ROCM" = true ]; then
    info "Installing PyTorch with ROCm support..."
    pip install torch --index-url https://download.pytorch.org/whl/rocm6.2
elif [ "$HAS_CUDA" = true ]; then
    info "Installing PyTorch with CUDA support..."
    pip install torch
else
    info "Installing PyTorch (CPU only)..."
    pip install torch --index-url https://download.pytorch.org/whl/cpu
fi

# --- Install other dependencies ---
info "Installing numpy, pandas, tqdm..."
pip install -r "$SCRIPT_DIR/requirements.txt"

# --- Verify PyTorch ---
info "Verifying PyTorch installation..."
python -c "
import torch
print(f'  PyTorch version: {torch.__version__}')
print(f'  CUDA available:  {torch.cuda.is_available()}')
if torch.cuda.is_available():
    print(f'  GPU device:      {torch.cuda.get_device_name(0)}')
    print(f'  GPU memory:      {torch.cuda.get_device_properties(0).total_mem / 1e9:.1f} GB')
else:
    print('  Running on CPU (no GPU detected)')
"

# --- Save env.sh ---
ENV_FILE="$SCRIPT_DIR/env.sh"
cat > "$ENV_FILE" <<ENVEOF
#!/usr/bin/env bash
source "$VENV_DIR/bin/activate"
# RX 9700 XT (gfx1201 / RDNA 4) may need this for ROCm compatibility:
# export HSA_OVERRIDE_GFX_VERSION=11.0.0
ENVEOF
chmod +x "$ENV_FILE"

# --- Check datasets ---
echo ""
info "Checking datasets..."

DATASETS_OK=true

check_dataset() {
    local name="$1"
    local path="$2"
    if [ -e "$path" ]; then
        info "  $name: found"
    else
        warn "  $name: NOT FOUND at $path"
        DATASETS_OK=false
    fi
}

check_dataset "NSL-KDD train" "$REPO_ROOT/NSL-KDD-Dataset/KDDTrain+.txt"
check_dataset "NSL-KDD test"  "$REPO_ROOT/NSL-KDD-Dataset/KDDTest+.txt"
check_dataset "CIC-IDS2017"   "$REPO_ROOT/CIC-IDS2017-Dataset/CSVs/MachineLearningCSV/MachineLearningCVE/"
check_dataset "UNSW-NB15 Data"  "$REPO_ROOT/CIC-UNSW-NB15-Dataset/Data.csv"
check_dataset "UNSW-NB15 Label" "$REPO_ROOT/CIC-UNSW-NB15-Dataset/Label.csv"

if [ "$DATASETS_OK" = false ]; then
    echo ""
    warn "Some datasets are missing. Place them relative to the repo root."
fi

# --- Summary ---
echo ""
echo "=========================================="
info "Setup complete!"
echo "=========================================="
echo ""
echo "Before running, activate the environment:"
echo "  source env.sh"
echo ""
echo "Training commands (run from cps-ids/pytorch-train/):"
echo ""
echo "  # Model A: NSL-KDD"
echo "  python train.py --dataset nsl-kdd \\"
echo "      --nsl-train ../../NSL-KDD-Dataset/KDDTrain+.txt \\"
echo "      --nsl-test ../../NSL-KDD-Dataset/KDDTest+.txt \\"
echo "      --output-dir data/models/model-a"
echo ""
echo "  # Model B: CIC-IDS2017"
echo "  python train.py --dataset cicids2017 \\"
echo "      --cicids-dir ../../CIC-IDS2017-Dataset/CSVs/MachineLearningCSV/MachineLearningCVE/ \\"
echo "      --output-dir data/models/model-b --no-smote"
echo ""
echo "  # Model C: UNSW-NB15"
echo "  python train.py --dataset unsw-nb15 \\"
echo "      --unsw-data ../../CIC-UNSW-NB15-Dataset/Data.csv \\"
echo "      --unsw-label ../../CIC-UNSW-NB15-Dataset/Label.csv \\"
echo "      --output-dir data/models/model-c"
echo ""
echo "  # Model D: All three combined"
echo "  python train.py --dataset combined \\"
echo "      --nsl-train ../../NSL-KDD-Dataset/KDDTrain+.txt \\"
echo "      --nsl-test ../../NSL-KDD-Dataset/KDDTest+.txt \\"
echo "      --cicids-dir ../../CIC-IDS2017-Dataset/CSVs/MachineLearningCSV/MachineLearningCVE/ \\"
echo "      --unsw-data ../../CIC-UNSW-NB15-Dataset/Data.csv \\"
echo "      --unsw-label ../../CIC-UNSW-NB15-Dataset/Label.csv \\"
echo "      --output-dir data/models/model-d --no-smote"
echo ""
echo "Hyperparameter tuning:"
echo "  --batch-size 256 --epochs 100 --learning-rate 0.0005 --patience 10"
echo "  --lstm-hidden 256 --lstm-layers 3 --dropout 0.4"
echo ""
echo "For AMD RX 9700 XT, if GPU isn't detected, try:"
echo "  export HSA_OVERRIDE_GFX_VERSION=11.0.0"
echo ""
