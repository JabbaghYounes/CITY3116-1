# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CPS-IDS: An AI/ML-driven Intrusion Detection System for Cyber-Physical Systems. Two major components:

1. **`ids/`** — Rust workspace + Python training pipeline. ML models trained on three public datasets (NSL-KDD, CIC-IDS2017, UNSW-NB15) with a unified 5-class label scheme (Normal, DoS, Probe, R2L, U2R).
2. **`plant/`** — CPS/ICS testbed. Arduino-based water treatment plant with Modbus RTU/TCP, Python attack tools, Stuxnet-style rootkit, and MiniCPS/Mininet software simulation. The IDS is designed to protect this environment.

## Build & Test Commands

```bash
# Build the main training binary
cd ids && cargo build --release -p ids-engine --bin train_models

# Run all workspace tests (60 tests across 5 crates)
cd ids && cargo test --workspace

# Run tests for a single crate
cd ids && cargo test -p ids-preprocess

# Run a single test by name
cd ids && cargo test -p ids-engine -- evaluate::tests::perfect_classification

# Build parallel training tool (rayon, 16+ cores)
cd ids/parallel-train && ./setup.sh

# Build CNN+LSTM training (requires NVIDIA GPU + libtorch 2.4.0)
cd ids/cnn-lstm-train && ./setup.sh && source env.sh

# Python PyTorch training (AMD ROCm or NVIDIA CUDA)
cd ids/pytorch-train && ./setup.sh && source env.sh && python train.py

# Run all 4 Python models sequentially (A→B→C→D with logging)
cd ids/pytorch-train && source env.sh && ./train_all.sh

# Full system setup (installs system deps, Rust toolchain, builds)
./setup.sh
```

## Architecture

### Cargo Workspace (`ids/crates/`, 6 members)

- **ids-common** — Shared types (`SecurityEvent`, `PacketRecord`, `Alert`), protocol enums (TCP/UDP/ICMP/Modbus/DNP3/OPC-UA), configuration
- **ids-collector** — Network packet capture + flow reconstruction (`network/`), file integrity + process monitoring (`host/`), log watcher, syscall monitor
- **ids-preprocess** — Dataset loaders (`dataset.rs` NSL-KDD, `cicids.rs` CIC-IDS2017, `unsw.rs` UNSW-NB15), `combined.rs` multi-dataset merger (union with zero-padding to 276 features), MinMaxScaler, SMOTE oversampling, one-hot encoding
- **ids-engine** — Random Forest (smartcore), Isolation Forest, ensemble hard voting, training orchestration (`train.rs`), evaluation metrics (`evaluate.rs`), rule-based detection (`rules.rs`). Binary: `train_models`
- **ids-response** — Async alert generation/prioritization (tokio), SIEM CEF/syslog export, network/host blocking
- **ids-dashboard** — Web UI stub (axum)

### Standalone Training Tools (independent Cargo projects, NOT workspace members)

- **parallel-train/** — Rayon-parallelized RF+IForest for multi-core CPUs (Models C & D). Duplicates preprocessing logic from ids-preprocess.
- **cnn-lstm-train/** — tch-rs (libtorch) deep learning: Conv1d→LSTM→FC, ~297K params, NVIDIA GPU. **tch 0.17 requires exactly libtorch 2.4.0** (C++ ABI match).
- **pytorch-train/** — Pure Python PyTorch equivalent of CNN+LSTM, AMD ROCm support. `setup.sh` generates `env.sh` (venv activation + optional `HSA_OVERRIDE_GFX_VERSION` for AMD RX 7900 XT).

Note: `env.sh` files in cnn-lstm-train/ and pytorch-train/ are **generated** by their setup.sh scripts and gitignored.

### Runtime Configuration

`ids/config.toml` — Full IDS runtime config (network interface, host monitoring paths, detection thresholds, ensemble weights, model paths, dashboard port).

## Four Model Variants

| Model | Dataset | Features | Key Result |
|-------|---------|----------|------------|
| A | NSL-KDD | 122 | RF 0.67 accuracy (binary test labels limit eval) |
| B | CIC-IDS2017 | 78 | RF **0.9973** accuracy, best multiclass |
| C | UNSW-NB15 | 76 | RF 0.9390 accuracy |
| D | Combined (A+B+C) | 276 | RF 0.9780 accuracy, best generalization |

## Data Pipeline Conventions

- Train/Val/Test split: 70% / 12% / 18%
- SMOTE enabled for small datasets (A, C), disabled for large (B, D)
- `clean_numeric()` replaces string "NaN"/"Infinity" with 0.0; `sanitize_f64()` catches IEEE non-finite
- CIC-IDS2017 has corrupted en-dash (U+FFFD) in labels — matched via `starts_with()`
- NSL-KDD uses one-hot encoding for 3 categorical columns; CIC-IDS2017 and UNSW-NB15 are all-numeric
- Model persistence: JSON (smartcore models), .pt (PyTorch), scaler saved separately

### Dataset Paths (relative to repo root, gitignored)

```
NSL-KDD-Dataset/KDDTrain+.txt, KDDTest+.txt
CIC-IDS2017-Dataset/CSVs/MachineLearningCSV/MachineLearningCVE/*.csv
CIC-UNSW-NB15-Dataset/Data.csv, Label.csv
```

### Training CLI Flags (all trainers share this pattern)

```
--dataset {nsl-kdd|cicids2017|unsw-nb15|combined}
--nsl-train/--nsl-test <PATH>        # NSL-KDD or combined
--cicids-dir <PATH>                  # CIC-IDS2017 or combined
--unsw-data/--unsw-label <PATH>      # UNSW-NB15 or combined
--output-dir <PATH>                  # default: data/models
--no-smote                           # disable SMOTE oversampling
```

CNN+LSTM and PyTorch trainers add: `--batch-size`, `--epochs`, `--learning-rate`, `--patience`, `--lstm-hidden`, `--lstm-layers`, `--dropout`. Parallel and CNN+LSTM trainers add `--threads`.

## CPS Testbed (`plant/`)

### Hardware Architecture (Purdue Model)

```
Level 3 — PC (SCADA, IDS/IPS, attacker, Wireshark)
  │ Ethernet (Modbus TCP)
Level 2 — TP-Link LS1005G switch
  │
  ├── PLC 1 (Mega + W5500)  192.168.1.20
  │     │ RS-485 (Modbus RTU)
  └── PLC 2 (Uno + MAX485)
        │
Level 1 — PLC control logic
        │
Level 0 — Physical process (sensors + actuators)
```

- **PLC 1** (`arduino-plc-firmware.cpp`): Arduino Mega 2560, 200ms scan cycle, Modbus TCP server (port 502) via W5500, Modbus RTU master over RS-485 to PLC 2. Controls pump relay, servo valve, buzzer, LCD HMI, RFID auth.
- **PLC 2** (`arduino-uno-sensor-node.cpp`): Arduino Uno, Modbus RTU slave (ID 1). Reads ultrasonic, temperature, sound, motion, water level sensors.

### Network Addressing

| Device | IP |
|--------|-----|
| SCADA PC | 192.168.1.10 |
| PLC 1 (Mega) | 192.168.1.20 |
| PLC 2 (Uno) | RTU slave ID 1 via RS-485 |

### Modbus Register Maps

**PLC 1 — Modbus TCP (SCADA-facing, port 502):** Coil 0 = pump state; Reg 0-5 = tank level, valve position, temperature, sound, ultrasonic distance, alarm state.

**PLC 2 — Modbus RTU (polled by PLC 1):** Reg 0-4 = ultrasonic, temperature, sound, motion, water level.

### Process Control Logic

Pump ON when tank < 30%, OFF when tank > 85%. Valve: 120° (pump on), 40° (pump off). Temperature alarm at ADC > 700. Physics anomaly: tank rising while pump OFF. RFID auth expires after 30s.

### Attack Tools

- `attack-framework.py` / `attack.py` — Modbus TCP attacks: command injection, pump oscillation, valve manipulation, replay, sensor spoofing, flood, multi-stage
- `stux/rootkit-proxy.py` — Stuxnet-style async MitM proxy, intermittent attack cycles (20s interval, 8s duration), actuator manipulation + sensor falsification

### MiniCPS Simulation (`plant/simulation/`)

Software twin using MiniCPS + Mininet + pymodbus. Same register map and control thresholds as Arduino firmware. Attack tools work against it without modification.

```bash
cd plant/simulation
pip install -r requirements.txt   # pymodbus, minicps, mininet
sudo python3 run.py               # full Mininet simulation (needs root)
python3 run.py --no-mininet       # local mode (no network isolation)
```

### Plant File Organization

- `arduino-plc-firmware.cpp` / `arduino-uno-sensor-node.cpp` — Arduino firmware
- `attack-framework.py` / `attack.py` — Attack class library + CLI
- `stux/` — Stuxnet-style rootkit + analysis docs
- `simulation/` — MiniCPS simulation (utils.py config, topo.py network, init.py state DB, physical_process.py physics, plc1.py/plc2.py controllers, run.py orchestrator)
- `*.md` — Design docs (lab architecture, wiring layout, CPS concepts, Modbus, firmware, attack timeline)

## Key Dependencies

- **smartcore 0.3** — Random Forest
- **tch 0.17** — PyTorch/libtorch bindings (cnn-lstm-train only, requires libtorch 2.4.0)
- **rayon 1.10** — Parallelism (parallel-train only)
- **ndarray 0.16** — Array operations
- **clap 4** — CLI arg parsing (derive macros)
- **pymodbus** — Modbus TCP/RTU (plant simulation + attack tools)
- **minicps + mininet** — CPS simulation framework (plant/simulation, optional)
- Release profile: `opt-level = 3`, `lto = "thin"`
