# AI/ML Driven Intrusion Detection System for Cyber-Physical Systems

## What This Is

A complete IDS/IPS prototype targeting industrial control systems, consisting of:

1. **`ids/`** — ML detection engine trained on three public intrusion datasets (NSL-KDD, CIC-IDS2017, UNSW-NB15) with a unified 5-class label scheme (Normal, DoS, Probe, R2L, U2R)
2. **`plant/`** — Physical CPS testbed: Arduino-based water treatment plant with Modbus RTU/TCP, attack tools, and a software simulation

## Architecture

![CPS-IDS Architecture](resources/images/architecture.png)

## Detection Models

Detection uses three complementary models:
- **Random Forest** (smartcore) — supervised, handles known attack patterns
- **CNN+LSTM** (PyTorch/ONNX) — deep learning, Conv1d→LSTM→FC, ~297K params — **integrated into the live monitor** via ONNX Runtime inference on completed flows
- **Isolation Forest** — unsupervised anomaly detection for zero-days

### Training Results

| Model | Dataset | Features | Random Forest | CNN+LSTM | Isolation Forest | RF + IForest | FPR |
|-------|---------|----------|---------------|----------|------------------|--------------|-----|
| A | NSL-KDD (1999) | 122 | 67.26%\* | 65.94%\* | 77.24% | 67.26%\* | 0.0301 |
| B | CIC-IDS2017 (2017) | 78 | 99.73% | **99.83%** | 81.37% | 99.73% | **0.0006** |
| C | UNSW-NB15 (2015) | 76 | 93.90% | 92.95% | 82.50% | 93.84% | 0.0251 |
| D | Combined (A+B+C) | 276 | 97.80% | 97.67% | 80.20% | **97.82%** | 0.0043 |

\*Model A metrics limited by NSL-KDD binary-only test labels (Probe/R2L/U2R collapsed)

Key findings:
- **CNN+LSTM achieves 99.83% on Model B** — highest accuracy across all methods
- **Model D** demonstrates cross-era generalisation at 97.8% across 276 zero-padded features
- **RF + IForest ensemble improves minority class detection** (Model D R2L recall: 0.75 → 0.82)
- **Isolation Forest provides unsupervised baseline** at ~80% across all datasets
- **U2R remains hardest** — extremely rare class across all datasets

## Quick Start

### IDS Training

```bash
# Setup (installs Rust toolchain + system deps)
cd ids/scripts && ./setup.sh

# Python PyTorch training (AMD ROCm or NVIDIA CUDA)
cd ids/pytorch-train && ./setup.sh && source env.sh
python train.py --dataset cicids2017 \
    --cicids-dir ../../CIC-IDS2017-Dataset/CSVs/MachineLearningCSV/MachineLearningCVE/ \
    --output-dir data/models/model-b --no-smote

# Run all 4 models sequentially
./train_all.sh

# Rust parallel training (CPU, 16+ cores)
cd ids/parallel-train && ./setup.sh

# Run workspace tests
cd ids && cargo test --workspace
```

### Plant Dashboard (Recommended)

```bash
cd plant/dashboard
python3 app.py
# Open http://localhost:8888
# Click "Start Simulation" — runs the full plant on localhost
# Use SCADA controls to interact, launch attacks from the terminal panel
```

### Live IDS Monitor

```bash
# Build the monitor
cd ids && cargo build --release -p ids-engine --bin monitor

# Run against the simulation — rule engine only
sudo ./target/release/monitor --interface lo --modbus-port 5502

# Run with CNN+LSTM ML inference (requires onnxruntime: pip install onnxruntime)
# First export the model to ONNX (one-time):
cd ids/pytorch-train && python3 export_onnx.py
# Then run the monitor with --model and --scaler:
cd ids && sudo ./target/release/monitor --interface lo --modbus-port 5502 \
  --model pytorch-train/data/models/model-b/cnn_lstm_model.onnx \
  --scaler pytorch-train/data/models/model-b/scaler.json
```

The monitor runs a multi-layer detection pipeline:
1. **Rule engine** (20 rules) — pattern-based detection on each packet/flow
2. **Modbus analysis** — write rate anomalies, read flood detection
3. **CNN+LSTM inference** (optional) — ML classification on expired flows using Model B (99.83% accuracy on CIC-IDS2017)

When `--model` and `--scaler` are provided, the monitor spawns a Python inference subprocess that loads the ONNX model and classifies completed network flows into 5 categories (Normal, DoS, Probe, R2L, U2R). Flows with fewer than 3 packets are skipped. Alerts are generated for non-Normal predictions above the `--ml-threshold` (default: 50%).

### Plant Simulation (CLI)

```bash
cd plant/simulation
pip install -r requirements.txt

# Full Mininet simulation (needs root)
sudo python3 run.py

# Local mode (no network isolation)
python3 run.py --no-mininet
```

### Forensic Investigation (Automated)

Runs all 8 attacks against the simulation while capturing evidence (pcaps, IDS alerts, timestamps) in a 4-pane tmux session:

```bash
./investigation/run.sh
```

This starts the dashboard, IDS monitor (with CNN+LSTM), tcpdump, and an attack runner that auto-sequences all attacks with gaps for flow expiration. Evidence is saved to `evidence/run-YYYYMMDD-HHMMSS/`:

| Artifact | Location |
|----------|----------|
| Packet capture | `evidence/run-YYYYMMDD-HHMMSS/pcaps/full-session.pcap` |
| IDS alert log | `evidence/run-YYYYMMDD-HHMMSS/logs/alerts.jsonl` |
| Attack timestamps | `evidence/run-YYYYMMDD-HHMMSS/logs/attack-manifest.json` |

After the run, open the pcap in Wireshark for analysis: `wireshark evidence/pcaps/full-session.pcap`

See `plant/ATTACK-EVIDENCE-GUIDE.md` for the full manual walkthrough and expected IDS alerts per attack.

### Attack Tools

```bash
pip install pymodbus

# Interactive attack menu targeting PLC 1
python plant/attack.py

# Stuxnet-style rootkit proxy
python plant/stux/rootkit-proxy.py
```

## Datasets

Download and place at repo root (gitignored):

| Dataset | Source | Local Path |
|---------|--------|------------|
| NSL-KDD | [Zenodo Archive](https://zenodo.org/records/17424143) | `NSL-KDD-Dataset/KDDTrain+.txt, KDDTest+.txt` |
| CIC-IDS2017 | [UNB CIC](https://www.unb.ca/cic/datasets/ids-2017.html) | `CIC-IDS2017-Dataset/CSVs/MachineLearningCSV/MachineLearningCVE/*.csv` |
| UNSW-NB15 | [UNB CIC](https://www.unb.ca/cic/datasets/cic-unsw-nb15.html) | `CIC-UNSW-NB15-Dataset/Data.csv, Label.csv` |

## Hardware

- Arduino Mega 2560 (ELEGOO kit) — PLC 1
- Arduino Uno Rev3 — PLC 2
- W5500 Ethernet module — Modbus TCP
- MAX485 RS-485 converter — Modbus RTU fieldbus
- TP-Link LS1005G switch — plant network
- DHT11 temperature/humidity sensor (digital, D4)
- ELEGOO kit sensors/actuators (ultrasonic, motion, sound, water level, relay, servo, buzzer, LCD, RFID)

Wiring diagrams available in `plant/diagrams/` (SVG, printable).
