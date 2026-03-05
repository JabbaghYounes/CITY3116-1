#!/usr/bin/env bash
# Setup script for CNN+LSTM IDS model training.
# Installs Rust toolchain, downloads libtorch, builds the training binary.
#
# Usage:
#   chmod +x setup.sh && ./setup.sh
#
# Supports: Debian/Ubuntu, Fedora/RHEL, Arch Linux

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
LIBTORCH_DIR="$SCRIPT_DIR/libtorch"

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
            info "Installing build tools via apt..."
            sudo apt update
            sudo apt install -y build-essential curl git unzip
            ;;
        fedora)
            info "Installing build tools via dnf..."
            sudo dnf install -y gcc gcc-c++ make curl git unzip
            ;;
        centos|rhel|rocky|almalinux)
            info "Installing build tools via yum..."
            sudo yum groupinstall -y "Development Tools"
            sudo yum install -y curl git unzip
            ;;
        arch|manjaro|endeavouros)
            info "Installing build tools via pacman..."
            sudo pacman -Syu --noconfirm base-devel curl git unzip
            ;;
        *)
            warn "Unknown distro '$DISTRO'. Ensure you have: gcc, make, curl, git, unzip"
            ;;
    esac
}

install_packages

# --- Install Rust toolchain ---
if command -v rustc &>/dev/null; then
    info "Rust already installed: $(rustc --version)"
    rustup update stable 2>/dev/null || true
else
    info "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    source "$HOME/.cargo/env"
    info "Rust installed: $(rustc --version)"
fi

if [ -f "$HOME/.cargo/env" ]; then
    source "$HOME/.cargo/env"
fi
command -v cargo &>/dev/null || error "cargo not found. Open a new shell and re-run."

# --- Detect GPU ---
HAS_CUDA=false
if command -v nvidia-smi &>/dev/null; then
    if nvidia-smi &>/dev/null; then
        HAS_CUDA=true
        info "NVIDIA GPU detected — will download CUDA libtorch"
    fi
fi

# --- Download libtorch ---
# Download latest stable libtorch; bypass tch version check
LIBTORCH_VERSION="2.7.0"
export LIBTORCH_BYPASS_VERSION_CHECK=1

if [ -d "$LIBTORCH_DIR" ] && [ -f "$LIBTORCH_DIR/lib/libtorch_cpu.so" -o -f "$LIBTORCH_DIR/lib/libtorch_cpu.dylib" ]; then
    info "libtorch already exists at $LIBTORCH_DIR"
else
    info "Downloading libtorch $LIBTORCH_VERSION..."

    if [ "$HAS_CUDA" = true ]; then
        # CUDA 12.1 build
        LIBTORCH_URL="https://download.pytorch.org/libtorch/cu121/libtorch-cxx11-abi-shared-with-deps-${LIBTORCH_VERSION}%2Bcu121.zip"
    else
        # CPU-only build
        LIBTORCH_URL="https://download.pytorch.org/libtorch/cpu/libtorch-cxx11-abi-shared-with-deps-${LIBTORCH_VERSION}%2Bcpu.zip"
    fi

    LIBTORCH_ZIP="$SCRIPT_DIR/libtorch.zip"

    info "URL: $LIBTORCH_URL"
    curl -L -o "$LIBTORCH_ZIP" "$LIBTORCH_URL" || {
        warn "Download failed for libtorch $LIBTORCH_VERSION."
        warn "Trying latest CPU libtorch..."
        LIBTORCH_URL="https://download.pytorch.org/libtorch/cpu/libtorch-cxx11-abi-shared-with-deps-${LIBTORCH_VERSION}%2Bcpu.zip"
        curl -L -o "$LIBTORCH_ZIP" "$LIBTORCH_URL" || error "Failed to download libtorch. Check your internet connection."
    }

    info "Extracting libtorch..."
    cd "$SCRIPT_DIR"
    unzip -q -o "$LIBTORCH_ZIP"
    rm -f "$LIBTORCH_ZIP"
    info "libtorch extracted to $LIBTORCH_DIR"
fi

# --- Set environment variables ---
export LIBTORCH="$LIBTORCH_DIR"
export LD_LIBRARY_PATH="${LIBTORCH_DIR}/lib:${LD_LIBRARY_PATH:-}"

info "LIBTORCH=$LIBTORCH"
info "LD_LIBRARY_PATH=$LD_LIBRARY_PATH"

# --- Save env.sh for future runs ---
ENV_FILE="$SCRIPT_DIR/env.sh"
cat > "$ENV_FILE" <<ENVEOF
#!/usr/bin/env bash
export LIBTORCH="$LIBTORCH_DIR"
export LD_LIBRARY_PATH="${LIBTORCH_DIR}/lib:\${LD_LIBRARY_PATH:-}"
export LIBTORCH_BYPASS_VERSION_CHECK=1
ENVEOF
chmod +x "$ENV_FILE"

# --- Add to shell profile so it persists across sessions ---
SOURCE_LINE="source \"$ENV_FILE\""
SHELL_RC=""
if [ -n "${ZSH_VERSION:-}" ] || [ "$(basename "$SHELL")" = "zsh" ]; then
    SHELL_RC="$HOME/.zshrc"
elif [ -f "$HOME/.bashrc" ]; then
    SHELL_RC="$HOME/.bashrc"
fi

if [ -n "$SHELL_RC" ]; then
    if ! grep -qF "$ENV_FILE" "$SHELL_RC" 2>/dev/null; then
        echo "" >> "$SHELL_RC"
        echo "# libtorch environment for CNN+LSTM IDS training" >> "$SHELL_RC"
        echo "$SOURCE_LINE" >> "$SHELL_RC"
        info "Added libtorch env to $SHELL_RC (persistent across sessions)"
    else
        info "libtorch env already in $SHELL_RC"
    fi
else
    warn "Could not detect shell RC file. Manually add: source $ENV_FILE"
fi

# --- Build ---
info "Building CNN+LSTM training binary (release mode)..."
cd "$SCRIPT_DIR"
cargo build --release
info "Build successful!"
info "Binary at: $SCRIPT_DIR/target/release/train-cnn-lstm"

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
    warn "Some datasets are missing. Place them at the repo root:"
    warn "  NSL-KDD-Dataset/KDDTrain+.txt, KDDTest+.txt"
    warn "  CIC-IDS2017-Dataset/CSVs/MachineLearningCSV/MachineLearningCVE/*.csv"
    warn "  CIC-UNSW-NB15-Dataset/Data.csv, Label.csv"
fi

# --- Summary ---
echo ""
echo "=========================================="
info "Setup complete!"
echo "=========================================="
echo ""
echo "Before running, source the environment:"
echo "  source env.sh"
echo ""
echo "Training commands (run from cps-ids/cnn-lstm-train/):"
echo ""
echo "  # Model A: NSL-KDD (quick test)"
echo "  ./target/release/train-cnn-lstm --dataset nsl-kdd \\"
echo "      --nsl-train ../../NSL-KDD-Dataset/KDDTrain+.txt \\"
echo "      --nsl-test ../../NSL-KDD-Dataset/KDDTest+.txt \\"
echo "      --output-dir data/models/model-a"
echo ""
echo "  # Model B: CIC-IDS2017"
echo "  ./target/release/train-cnn-lstm --dataset cicids2017 \\"
echo "      --cicids-dir ../../CIC-IDS2017-Dataset/CSVs/MachineLearningCSV/MachineLearningCVE/ \\"
echo "      --output-dir data/models/model-b --no-smote"
echo ""
echo "  # Model C: UNSW-NB15"
echo "  ./target/release/train-cnn-lstm --dataset unsw-nb15 \\"
echo "      --unsw-data ../../CIC-UNSW-NB15-Dataset/Data.csv \\"
echo "      --unsw-label ../../CIC-UNSW-NB15-Dataset/Label.csv \\"
echo "      --output-dir data/models/model-c"
echo ""
echo "  # Model D: All three combined"
echo "  ./target/release/train-cnn-lstm --dataset combined \\"
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
