#!/usr/bin/env bash
# Setup script for CPS-IDS model training environment.
# Installs Rust toolchain and system dependencies on a fresh Linux machine.
#
# Usage:
#   chmod +x setup.sh && ./setup.sh
#
# Supports: Debian/Ubuntu, Fedora/RHEL/CentOS, Arch Linux

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[x]${NC} $*"; exit 1; }

# --- Detect distro ---
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    elif command -v lsb_release &>/dev/null; then
        lsb_release -is | tr '[:upper:]' '[:lower:]'
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
            info "Installing packages via apt..."
            sudo apt update
            sudo apt install -y \
                build-essential \
                pkg-config \
                libpcap-dev \
                curl \
                git
            ;;
        fedora)
            info "Installing packages via dnf..."
            sudo dnf install -y \
                gcc \
                gcc-c++ \
                make \
                pkg-config \
                libpcap-devel \
                curl \
                git
            ;;
        centos|rhel|rocky|almalinux)
            info "Installing packages via yum..."
            sudo yum groupinstall -y "Development Tools"
            sudo yum install -y \
                pkg-config \
                libpcap-devel \
                curl \
                git
            ;;
        arch|manjaro|endeavouros)
            info "Installing packages via pacman..."
            sudo pacman -Syu --noconfirm \
                base-devel \
                pkg-config \
                libpcap \
                curl \
                git
            ;;
        *)
            warn "Unknown distro '$DISTRO'. Install these manually:"
            warn "  - C compiler (gcc/clang), make, pkg-config"
            warn "  - libpcap development headers"
            warn "  - curl, git"
            ;;
    esac
}

install_packages

# --- Install Rust toolchain ---
if command -v rustc &>/dev/null; then
    RUST_VER=$(rustc --version)
    info "Rust already installed: $RUST_VER"
    info "Updating toolchain..."
    rustup update stable
else
    info "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
    info "Rust installed: $(rustc --version)"
fi

# --- Verify cargo is available ---
if ! command -v cargo &>/dev/null; then
    # Try sourcing cargo env in case it wasn't picked up
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    fi
fi
command -v cargo &>/dev/null || error "cargo not found after install. Open a new shell and re-run."

info "cargo: $(cargo --version)"

# --- Build the training binary ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CPS_IDS_DIR="$SCRIPT_DIR/cps-ids"

if [ -d "$CPS_IDS_DIR" ]; then
    info "Building training binary (release mode)..."
    cd "$CPS_IDS_DIR"
    cargo build --release -p ids-engine --bin train_models
    info "Build successful!"
    info "Binary at: $CPS_IDS_DIR/target/release/train_models"
else
    warn "cps-ids/ directory not found at $CPS_IDS_DIR"
    warn "Clone the repo first, then run: cd cps-ids && cargo build --release -p ids-engine --bin train_models"
fi

# --- Summary ---
echo ""
echo "=========================================="
info "Setup complete!"
echo "=========================================="
echo ""
echo "Training commands (run from cps-ids/):"
echo ""
echo "  # Model A: NSL-KDD only"
echo "  cargo run --release -p ids-engine --bin train_models -- \\"
echo "      --dataset nsl-kdd \\"
echo "      --nsl-train ../NSL-KDD-Dataset/KDDTrain+.txt \\"
echo "      --nsl-test ../NSL-KDD-Dataset/KDDTest+.txt \\"
echo "      --output-dir data/models/model-a"
echo ""
echo "  # Model B: CIC-IDS2017 only"
echo "  cargo run --release -p ids-engine --bin train_models -- \\"
echo "      --dataset cicids2017 \\"
echo "      --cicids-dir ../CIC-IDS2017-Dataset/CSVs/MachineLearningCSV/MachineLearningCVE/ \\"
echo "      --output-dir data/models/model-b --no-smote"
echo ""
echo "  # Model C: UNSW-NB15 only"
echo "  cargo run --release -p ids-engine --bin train_models -- \\"
echo "      --dataset unsw-nb15 \\"
echo "      --unsw-data ../CIC-UNSW-NB15-Dataset/Data.csv \\"
echo "      --unsw-label ../CIC-UNSW-NB15-Dataset/Label.csv \\"
echo "      --output-dir data/models/model-c"
echo ""
echo "  # Model D: All three combined"
echo "  cargo run --release -p ids-engine --bin train_models -- \\"
echo "      --dataset combined \\"
echo "      --nsl-train ../NSL-KDD-Dataset/KDDTrain+.txt \\"
echo "      --nsl-test ../NSL-KDD-Dataset/KDDTest+.txt \\"
echo "      --cicids-dir ../CIC-IDS2017-Dataset/CSVs/MachineLearningCSV/MachineLearningCVE/ \\"
echo "      --unsw-data ../CIC-UNSW-NB15-Dataset/Data.csv \\"
echo "      --unsw-label ../CIC-UNSW-NB15-Dataset/Label.csv \\"
echo "      --output-dir data/models/model-d --no-smote"
echo ""
echo "RAM requirements: Model A ~150MB, Model C ~300MB, Model B ~2GB, Model D ~8GB+"
