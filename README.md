# AI/ML Driven Intrusion Detection System for Cyber Physical Systems

## What This Is

A complete IDS/IPS prototype targeting industrial control systems, consisting of:

1. **`ids/`** — ML detection engine trained on three public intrusion datasets (NSL-KDD, CIC-IDS2017, UNSW-NB15) with a unified 5-class label scheme (Normal, DoS, Probe, R2L, U2R)
2. **`plant/`** — Physical CPS testbed: Arduino-based water treatment plant with Modbus RTU/TCP, attack tools, and a software simulation

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

Wiring diagrams available in `plant/diagrams/`
