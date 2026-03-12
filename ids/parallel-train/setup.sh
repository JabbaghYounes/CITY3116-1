#!/usr/bin/env bash
# Setup script for parallel IDS model training.
# Installs Rust toolchain, builds the parallel trainer, and verifies datasets.
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

# --- Install system packages (only need a C compiler for Rust) ---
install_packages() {
    case "$DISTRO" in
        ubuntu|debian|pop|linuxmint|elementary)
            info "Installing build tools via apt..."
            sudo apt update
            sudo apt install -y build-essential curl git
            ;;
        fedora)
            info "Installing build tools via dnf..."
            sudo dnf install -y gcc gcc-c++ make curl git
            ;;
        centos|rhel|rocky|almalinux)
            info "Installing build tools via yum..."
            sudo yum groupinstall -y "Development Tools"
            sudo yum install -y curl git
            ;;
        arch|manjaro|endeavouros)
            info "Installing build tools via pacman..."
            sudo pacman -Syu --noconfirm base-devel curl git
            ;;
        *)
            warn "Unknown distro '$DISTRO'. Ensure you have: gcc, make, curl, git"
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

# --- Build parallel training binary ---
info "Building parallel training binary (release mode)..."
cd "$SCRIPT_DIR"
cargo build --release
info "Build successful!"
info "Binary at: $SCRIPT_DIR/target/release/train"

# --- Check CPU topology ---
CORES=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo "?")
info "Available CPU cores: $CORES"

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
echo "Training commands (run from ids/parallel-train/):"
echo ""
echo "  # Model A: NSL-KDD (quick test, ~5 min)"
echo "  ./target/release/train --dataset nsl-kdd \\"
echo "      --nsl-train ../../NSL-KDD-Dataset/KDDTrain+.txt \\"
echo "      --nsl-test ../../NSL-KDD-Dataset/KDDTest+.txt \\"
echo "      --output-dir data/models/model-a"
echo ""
echo "  # Model B: CIC-IDS2017 (~35-45 min on 16 cores)"
echo "  ./target/release/train --dataset cicids2017 \\"
echo "      --cicids-dir ../../CIC-IDS2017-Dataset/CSVs/MachineLearningCSV/MachineLearningCVE/ \\"
echo "      --output-dir data/models/model-b --no-smote"
echo ""
echo "  # Model C: UNSW-NB15"
echo "  ./target/release/train --dataset unsw-nb15 \\"
echo "      --unsw-data ../../CIC-UNSW-NB15-Dataset/Data.csv \\"
echo "      --unsw-label ../../CIC-UNSW-NB15-Dataset/Label.csv \\"
echo "      --output-dir data/models/model-c"
echo ""
echo "  # Model D: All three combined (~1-2 hours on 16 cores)"
echo "  ./target/release/train --dataset combined \\"
echo "      --nsl-train ../../NSL-KDD-Dataset/KDDTrain+.txt \\"
echo "      --nsl-test ../../NSL-KDD-Dataset/KDDTest+.txt \\"
echo "      --cicids-dir ../../CIC-IDS2017-Dataset/CSVs/MachineLearningCSV/MachineLearningCVE/ \\"
echo "      --unsw-data ../../CIC-UNSW-NB15-Dataset/Data.csv \\"
echo "      --unsw-label ../../CIC-UNSW-NB15-Dataset/Label.csv \\"
echo "      --output-dir data/models/model-d --no-smote"
echo ""
echo "CPU cores: $CORES (rayon auto-detects, or use --threads N)"
echo "RAM needed: Model A ~150MB, Model C ~300MB, Model B ~2GB, Model D ~8GB+"
