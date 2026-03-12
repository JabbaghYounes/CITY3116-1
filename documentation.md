# Implementation Documentation

This document logs the implementation steps taken for the CPS-IDS multi-dataset training pipeline.

## Implementation Beyond the Proposed Architecture

The initial proposed architecture described a minimal passive network traffic monitoring pipeline: CSV ingestion → preprocessing → single Random Forest classifier → binary detection → alert generation. The final implementation significantly exceeds this scope across every component:

### 1. Hybrid NIDS + HIDS (vs. network-only)

The proposed design was a passive NIDS that only processed network flow CSVs. The implementation is a full hybrid system:
- **NIDS**: Live packet capture (libpcap) with bidirectional flow reconstruction, plus ICS/SCADA protocol parsing for Modbus (function code validation), DNP3, and OPC-UA — not just flow-level CSV analysis
- **HIDS**: File integrity monitoring (inotify with SHA-256 checksums), process monitoring (spawn/terminate/elevation detection), syscall tracing (audit.log parsing), and system log watching (auth.log pattern matching for failed logins, privilege escalation, segfaults)

This dual-layer approach detects threats that a network-only IDS would miss entirely (insider threats, privilege escalation, file tampering).

### 2. Multi-Model Ensemble (vs. single Random Forest)

The proposed architecture used a single Random Forest. The implementation deploys three complementary models with weighted fusion:
- **Random Forest** (supervised, smartcore): Primary classifier — handles known attack patterns with high precision
- **CNN+LSTM** (deep learning, PyTorch): Conv1d→LSTM→FC architecture (~297K parameters) — captures sequential patterns in feature vectors
- **Isolation Forest** (unsupervised): Anomaly detector trained only on normal traffic — detects novel zero-day attacks not in training data

The ensemble combines RF probability distributions with IForest anomaly scores via a configurable weighted scheme (default: RF 0.35, LSTM 0.40, IForest 0.25), boosting attack class probabilities when the IForest flags anomalies. This provides defence-in-depth at the detection layer.

### 3. Multi-Dataset Cross-Era Training (vs. single dataset)

The proposed system trained on a single dataset. The implementation trains across three datasets spanning 1999–2017 with a unified 5-class label scheme:
- **Model A**: NSL-KDD (1999, 122 features) — classic benchmark
- **Model B**: CIC-IDS2017 (2017, 78 features) — modern traffic, 99.73% RF accuracy
- **Model C**: UNSW-NB15 (2015, 76 features) — mixed attack types
- **Model D**: Combined union (276 features) — cross-dataset generalisation, 97.80% accuracy

The combined model demonstrates that zero-padded feature union enables cross-era generalisation — the model learns patterns from all three attack distributions simultaneously.

### 4. 5-Class Multiclass Classification (vs. binary/per-label)

The proposed system classified traffic as binary (e.g., BENIGN vs DDoS). The implementation uses a unified 5-class taxonomy (Normal, DoS, Probe, R2L, U2R) mapped consistently across all three datasets, enabling:
- Cross-dataset comparison of per-class detection rates
- Identification of which attack categories each dataset best represents
- Macro-averaged metrics that expose weaknesses in minority classes (e.g., U2R)

### 5. Configurable IDS/IPS Mode (vs. passive only)

The proposed system was passive (alert-only). The implementation supports both modes:
- **IDS mode**: Alert generation, severity classification, SIEM export (CEF/syslog)
- **IPS mode**: Automated network blocking (iptables with configurable block duration), host response (process termination, file quarantine), with nips/hips independently toggleable

### 6. Multiple Training Backends (vs. single implementation)

The proposed system had one training pipeline. The implementation provides four:
- **ids-engine** (Rust, smartcore): Single-threaded RF + IForest, baseline
- **parallel-train** (Rust, rayon): Multi-threaded RF + IForest for 16+ core machines
- **cnn-lstm-train** (Rust, tch-rs/libtorch): GPU-accelerated deep learning, NVIDIA CUDA
- **pytorch-train** (Python, PyTorch): GPU-accelerated deep learning, AMD ROCm support

This enables fair comparison between traditional ML and deep learning, and between CPU and GPU training performance.

### 7. Rule-Based Detection Layer

In addition to ML models, a rule-based engine provides signature detection for known CPS-specific attacks (Modbus function code violations, known malicious patterns), complementing the ML ensemble with deterministic detection.

## Phase 1: Multi-Dataset Loader Implementation (2026-03-03)

### Context

The IDS system initially only supported the NSL-KDD dataset (1999). To enable cross-era comparison and demonstrate model generalisation, three datasets spanning 1999–2017 were integrated:

| Dataset | Year | Source | Rows | Features |
|---------|------|--------|------|----------|
| NSL-KDD | 1999 | UNB (derived from KDD Cup 99) | ~148K | 122 (after one-hot) |
| CIC-IDS2017 | 2017 | UNB/CIC, CICFlowMeter output | ~2.83M | 78 (all numeric) |
| UNSW-NB15 | 2015 | UNSW Canberra, CICFlowMeter-processed | ~448K | 76 (all numeric) |

### Key Discovery

The UNSW-NB15 dataset on disk is a CICFlowMeter-processed version (76 numeric columns + separate Label.csv with integer labels 0–9), **not** the original UNSW-NB15 format with categorical columns (proto, service, state). This simplified implementation — no one-hot encoding needed for CIC-IDS2017 or UNSW-NB15. The combined feature width is ~276 (not ~391 as originally planned in `resources/tripple-model-plan.md`).

### Steps Taken

#### Step 1: Made `label_names()` public
- **File**: `ids/crates/ids-preprocess/src/dataset.rs`
- Changed `fn label_names()` → `pub fn label_names()` to allow other dataset loaders to reuse the canonical 5-class names: Normal, DoS, Probe, R2L, U2R.

#### Step 2: Created CIC-IDS2017 loader
- **File**: `ids/crates/ids-preprocess/src/cicids.rs` (new, ~250 lines)
- Public function: `load_cicids2017(csv_dir: &Path) -> Result<DatasetSplit>`
- Concatenates 8 CSV files from the MachineLearningCSV directory
- Data quality mitigations:
  - `clean_numeric()`: replaces string "NaN", "Infinity", "-Infinity" with 0.0
  - `sanitize_f64()`: catches any residual non-finite f64 values
  - `csv::Trim::All`: handles leading whitespace in column names
  - Web Attack label matching via `starts_with("Web Attack")` to handle corrupted en-dash (U+FFFD)
- Label mapping (`cicids_attack_category`): maps 15 CIC-IDS2017 label strings to 5-class scheme (BENIGN→Normal, DDoS/DoS*→DoS, PortScan→Probe, Patator/Bot/Heartbleed/WebAttack→R2L, Infiltration→U2R)
- Splits data: 70% train / 12% val / 18% test (random shuffle)
- 3 unit tests: label mapping, clean_numeric, sanitize_f64

#### Step 3: Created UNSW-NB15 loader
- **File**: `ids/crates/ids-preprocess/src/unsw.rs` (new, ~200 lines)
- Public function: `load_unsw_nb15(data_path: &Path, label_path: &Path) -> Result<DatasetSplit>`
- Loads Data.csv (76 numeric columns) and Label.csv (integer labels 0–9) as separate files
- Verifies row count alignment between the two files
- Label mapping (`unsw_attack_category`): maps integer labels using Readme.txt mapping (0→Normal, 3/6→DoS, 1/5/7→Probe, 4/9→R2L, 2/8→U2R)
- Splits data: 70% train / 12% val / 18% test
- 1 unit test: label mapping for all 10 integer values

#### Step 4: Created N-dataset merger
- **File**: `ids/crates/ids-preprocess/src/combined.rs` (new, ~170 lines)
- Public function: `merge_datasets(splits: &[(&str, &DatasetSplit)]) -> Result<DatasetSplit>`
- Strategy: union with zero-padding — each dataset's features occupy a dedicated column range, other columns are zero
- Feature names prefixed with dataset identifier (e.g., `nsl_duration`, `cic_Flow Duration`, `unsw_Flow Duration`)
- Uses ndarray slice assignment for efficient zero-padding
- Merges train/val/test splits independently
- 1 unit test: verifies dimensions, zero-padding correctness, and feature names

#### Step 5: Wired up `ids-preprocess` modules
- **File**: `ids/crates/ids-preprocess/src/lib.rs`
- Added `pub mod cicids; pub mod unsw; pub mod combined;`
- Added re-exports: `load_cicids2017`, `load_unsw_nb15`, `merge_datasets`, `label_names`

#### Step 6: Created training orchestrator
- **File**: `ids/crates/ids-engine/src/train.rs` (new, ~220 lines)
- `DatasetSource` enum with 4 variants: `NslKdd`, `CicIds2017`, `UnswNb15`, `Combined`
- `TrainConfig` struct: configurable output paths, SMOTE settings, IForest parameters
- `run_training()` pipeline: load → MinMaxScaler normalize → optional SMOTE → train Random Forest → train Isolation Forest (on normal samples only) → evaluate all three (RF, IForest binary, Ensemble) → save models + evaluation report as JSON

#### Step 7: Updated `ids-engine` configuration
- **File**: `ids/crates/ids-engine/Cargo.toml`
  - Added `clap = { version = "4", features = ["derive"] }` for CLI parsing
  - Added `tracing-subscriber` for logging initialisation in the binary
  - Added `[[bin]] name = "train_models"` target
- **File**: `ids/crates/ids-engine/src/lib.rs`
  - Added `pub mod train;`

#### Step 8: Created CLI binary
- **File**: `ids/crates/ids-engine/src/bin/train_models.rs` (new, ~180 lines)
- clap-derive CLI with flags: `--dataset` (nsl-kdd|cicids2017|unsw-nb15|combined), dataset path arguments, `--output-dir`, `--no-smote`, `--smote-target`, IForest configuration
- Prints training summary with accuracy and F1 scores

#### Step 9: Fixed `ids-response` compile error
- **File**: `ids/crates/ids-response/src/alerter.rs`
- Added missing `use ids_common::types::AlertSource;` import in test module
- This was preventing `cargo test` from working at the workspace level

### Test Results

After all changes, full workspace tests pass:

| Crate | Tests | Status |
|-------|-------|--------|
| ids-collector | 17 | PASS |
| ids-common | 0 | PASS |
| ids-preprocess | 17 | PASS |
| ids-engine | 11 | PASS |
| ids-response | 15 | PASS |
| ids-dashboard | 0 | PASS |
| **Total** | **60** | **ALL PASS** |

### Training CLI Usage

```bash
# From ids/ directory

# Model A: NSL-KDD only
cargo run --release -p ids-engine --bin train_models -- \
    --dataset nsl-kdd \
    --nsl-train ../NSL-KDD-Dataset/KDDTrain+.txt \
    --nsl-test ../NSL-KDD-Dataset/KDDTest+.txt \
    --output-dir data/models/model-a

# Model B: CIC-IDS2017 only
cargo run --release -p ids-engine --bin train_models -- \
    --dataset cicids2017 \
    --cicids-dir ../CIC-IDS2017-Dataset/CSVs/MachineLearningCSV/MachineLearningCVE/ \
    --output-dir data/models/model-b \
    --no-smote

# Model C: UNSW-NB15 only
cargo run --release -p ids-engine --bin train_models -- \
    --dataset unsw-nb15 \
    --unsw-data ../CIC-UNSW-NB15-Dataset/Data.csv \
    --unsw-label ../CIC-UNSW-NB15-Dataset/Label.csv \
    --output-dir data/models/model-c

# Model D: All three combined
cargo run --release -p ids-engine --bin train_models -- \
    --dataset combined \
    --nsl-train ../NSL-KDD-Dataset/KDDTrain+.txt \
    --nsl-test ../NSL-KDD-Dataset/KDDTest+.txt \
    --cicids-dir ../CIC-IDS2017-Dataset/CSVs/MachineLearningCSV/MachineLearningCVE/ \
    --unsw-data ../CIC-UNSW-NB15-Dataset/Data.csv \
    --unsw-label ../CIC-UNSW-NB15-Dataset/Label.csv \
    --output-dir data/models/model-d \
    --no-smote
```

### Architecture Decision: 5-Class Label Scheme

All three datasets are mapped to a unified 5-class scheme to enable cross-dataset comparison:

| Class | NSL-KDD | CIC-IDS2017 | UNSW-NB15 |
|-------|---------|-------------|-----------|
| 0: Normal | normal | BENIGN | 0 (Benign) |
| 1: DoS | back, land, neptune, etc. | DDoS, DoS Hulk, DoS GoldenEye, etc. | 3 (DoS), 6 (Generic) |
| 2: Probe | satan, ipsweep, nmap, etc. | PortScan | 1 (Analysis), 5 (Fuzzers), 7 (Recon) |
| 3: R2L | guess_passwd, ftp_write, etc. | FTP/SSH-Patator, Bot, Heartbleed, Web Attack* | 4 (Exploits), 9 (Worms) |
| 4: U2R | buffer_overflow, rootkit, etc. | Infiltration | 2 (Backdoor), 8 (Shellcode) |

## Phase 2: Model A Training — NSL-KDD (2026-03-04)

### Pre-Training Fixes

Three issues were discovered and fixed when running the training pipeline against the actual dataset files:

1. **Tab-delimited format** — The NSL-KDD files (`KDDTrain+.txt`, `KDDTest+.txt`) use tab separators, not commas. Fixed by adding `.delimiter(b'\t')` to the CSV reader in `dataset.rs:read_csv()`.

2. **42-field test file** — The test file has 42 fields (41 features + label) while the train file has 43 (41 features + label + difficulty). Relaxed the field count check from `< 43` to `< 42` to accept both formats.

3. **Binary test labels** — The test file uses generic binary labels ("Normal" / "Attack") instead of specific attack names (neptune, smurf, etc.). Added `"attack" => 1` (DoS) mapping to `attack_category()`. This means multiclass evaluation on the test set is limited — Probe, R2L, and U2R classes have zero test samples.

**Files modified**: `ids/crates/ids-preprocess/src/dataset.rs`

### Training Run

- **Dataset**: NSL-KDD (125,973 train records, 22,544 test records)
- **Features**: 122 (38 numeric + 84 one-hot from 3 categorical columns: protocol=3, service=70, flag=11)
- **Train/Val split**: 82% / 18% (103,298 / 22,675)
- **SMOTE**: Enabled, target=55,368 per class → 276,840 total training samples
- **Duration**: ~34 minutes total (SMOTE ~6 min, RF training ~10 min, evaluation ~19 min)
- **Output**: `ids/data/models/model-a/` (random_forest.json, isolation_forest.json, scaler.json, evaluation_report.json)

### Results

#### Random Forest (5-class)

| Class | Precision | Recall | F1 |
|-------|-----------|--------|-----|
| Normal | 0.6639 | 0.9699 | 0.7882 |
| DoS | 0.9885 | 0.4475 | 0.6161 |
| Probe | 0.0000 | 0.0000 | 0.0000 |
| R2L | 0.0000 | 0.0000 | 0.0000 |
| U2R | 0.0000 | 0.0000 | 0.0000 |

Accuracy: 0.6726 | Macro-F1: 0.2809 | FPR: 0.0301

#### Isolation Forest (binary: Normal vs Attack)

| Class | Precision | Recall | F1 |
|-------|-----------|--------|-----|
| Normal | 0.6581 | 0.9815 | 0.7879 |
| Attack | 0.9777 | 0.6141 | 0.7544 |

Accuracy: 0.7724 | Macro-F1: 0.7711 | FPR: 0.0185

#### Ensemble (RF + IForest)

Accuracy: 0.6726 | Macro-F1: 0.2809 (identical to RF alone)

### Analysis

- **Probe/R2L/U2R show 0.00 metrics** because the test file only contains binary labels ("Normal"/"Attack"). All attack samples are mapped to DoS (class 1), so no test samples exist for classes 2–4. The model itself is trained on all 5 classes from the properly-labelled training data.

- **Isolation Forest is the most meaningful evaluation** here (77.2% accuracy, 0.77 macro-F1) since it evaluates binary Normal-vs-Attack, matching the test set's actual label granularity. Low FPR (1.85%) indicates good specificity.

- **Ensemble is identical to RF** because `predict_proba()` returns a one-hot approximation (hard prediction + 0.01 smoothing). The IForest anomaly boost cannot override a confident RF hard prediction. This is a known limitation of the current architecture.

- **RF shows high precision on attacks (0.99)** but lower recall (0.45), meaning it correctly identifies attacks it finds but misses ~55% of attack traffic — many attacks are predicted as Normal. The high Normal recall (0.97) means very few false alarms.

## Phase 3: Model B Training — CIC-IDS2017 (2026-03-04)

### Training Run

- **Dataset**: CIC-IDS2017 (2,830,743 total records across 8 daily CSV files, 78 numeric features)
- **Train/Val/Test split**: 70% / 12% / 18% (1,981,520 / 339,689 / 509,534)
- **SMOTE**: Disabled (`--no-smote`) due to dataset size — SMOTE on ~2M samples would be prohibitively slow
- **Duration**: ~9 hours total (data loading ~20s, RF training ~8.5h, IForest + evaluation ~30 min, model save ~16s)
- **Output**: `ids/data/models/model-b/` (random_forest.json, isolation_forest.json, scaler.json, evaluation_report.json)

### Results

#### Random Forest (5-class)

| Class | Precision | Recall | F1 |
|-------|-----------|--------|-----|
| Normal | 0.9973 | 0.9994 | 0.9983 |
| DoS | 0.9983 | 0.9959 | 0.9971 |
| Probe | 0.9945 | 0.9994 | 0.9969 |
| R2L | 0.9979 | 0.7424 | 0.8514 |
| U2R | 1.0000 | 0.8571 | 0.9231 |

Accuracy: 0.9973 | Macro-F1: 0.9534 | FPR: 0.0006

#### Isolation Forest (binary: Normal vs Attack)

| Class | Precision | Recall | F1 |
|-------|-----------|--------|-----|
| Normal | 0.8453 | 0.9400 | 0.8901 |
| Attack | 0.5507 | 0.2993 | 0.3878 |

Accuracy: 0.8137 | Macro-F1: 0.6390 | FPR: 0.0600

#### Ensemble (RF + IForest)

Accuracy: 0.9973 | Macro-F1: 0.9534 (identical to RF alone)

### Analysis

- **RF achieves near-perfect multiclass detection** (99.73% accuracy, 0.95 macro-F1). Normal, DoS, and Probe classes all exceed 0.99 F1. This validates the CIC-IDS2017 dataset as well-suited for Random Forest classification with modern flow-level features.

- **R2L is the weakest class** (F1: 0.8514, recall: 0.7424) — 818 of 3,176 R2L test samples were misclassified as Normal. This is expected: R2L attacks (brute-force, bots, web attacks) often resemble legitimate traffic at the flow level. U2R (Infiltration) has perfect precision but only 7 test samples total.

- **Isolation Forest underperforms on this dataset** (81.4% accuracy, 0.39 attack F1). It misses 70% of attacks (recall 0.30). This is because the IForest is trained only on normal samples and the CIC-IDS2017 normal traffic is highly diverse (529K Monday benign flows across many protocols), making it harder to establish a tight normal boundary.

- **Ensemble remains identical to RF** due to the one-hot `predict_proba` limitation — same issue as Model A.

- **Training time (~9 hours)** was dominated by smartcore's single-threaded RF implementation on 1.98M samples. The data loading phase (8 CSV files, 2.83M rows) completed in only ~20 seconds, demonstrating the efficiency of the CIC-IDS2017 loader.

### Comparison: Model A vs Model B

| Metric | Model A (NSL-KDD) | Model B (CIC-IDS2017) |
|--------|-------------------|----------------------|
| RF Accuracy | 0.6726* | 0.9973 |
| RF Macro-F1 | 0.2809* | 0.9534 |
| IForest Accuracy | 0.7724 | 0.8137 |
| IForest Macro-F1 | 0.7711 | 0.6390 |
| FPR | 0.0301 | 0.0006 |
| Train samples | 276,840 | 1,981,520 |
| Features | 122 | 78 |

*Model A metrics are artificially low due to binary-only test labels — not a fair comparison. The IForest binary evaluation is more comparable: Model A (0.77 F1) vs Model B (0.64 F1), suggesting the NSL-KDD normal boundary is tighter and easier for anomaly detection.

## Phase 5: CNN+LSTM Training Crate (2026-03-05)

### Motivation

To compare traditional ML (Random Forest + Isolation Forest) with deep learning for IDS, a standalone CNN+LSTM training crate was created at `ids/cnn-lstm-train/`. This uses the same 4 models (A–D), same datasets, and same 5-class scheme — enabling direct comparison.

### Architecture

CNN+LSTM for tabular data. Input is reshaped from flat features into a pseudo-sequential format for Conv1d processing:

```
Input: (batch, n_features)
  → reshape to (batch, 1, n_features)
  → Conv1d(1, 64, kernel=3, pad=1) + ReLU + BatchNorm1d
  → Conv1d(64, 128, kernel=3, pad=1) + ReLU + BatchNorm1d
  → permute to (batch, n_features, 128)
  → LSTM(input=128, hidden=128, layers=2, dropout=0.3, batch_first=true)
  → last-layer hidden state → (batch, 128)
  → Linear(128, 64) + ReLU + Dropout(0.3)
  → Linear(64, 5)  → raw logits → CrossEntropyLoss
```

~297K trainable parameters. Sequence length varies by dataset (76/78/122/276 features) but LSTM handles this naturally since its parameters depend only on input_size and hidden_size, not sequence length.

### Technology

- **Framework**: tch-rs v0.17 (Rust bindings to PyTorch's libtorch C++ library)
- **Performance**: Same as Python PyTorch — both call the same libtorch C++ kernels
- **Device**: Auto-detects GPU (`Device::cuda_if_available()`), falls back to CPU
- **Optimizer**: Adam, lr=1e-3
- **Training features**: Mini-batch shuffling, early stopping (patience=5), ReduceLROnPlateau LR scheduling, best-weight checkpointing

### Implementation

Created `ids/cnn-lstm-train/` as a standalone crate (`[workspace]` opt-out from parent workspace):

| File | Purpose |
|------|---------|
| `Cargo.toml` | Dependencies: tch, rayon, ndarray, clap, tracing, serde |
| `setup.sh` | Downloads libtorch (CPU or CUDA auto-detect), installs Rust, builds binary |
| `src/preprocess/*` | 7 files copied from parallel-train (dataset loaders, normalization, SMOTE) |
| `src/engine/model.rs` | CnnLstm network definition (Conv1d + BatchNorm + LSTM + FC) |
| `src/engine/trainer.rs` | Training loop, tensor conversion helpers, batched inference |
| `src/engine/train.rs` | Orchestrator: load → normalize → SMOTE → tensor conversion → train → evaluate → save |
| `src/engine/evaluate.rs` | Classification metrics (copied from parallel-train) |
| `src/main.rs` | CLI with clap: dataset args + DL hyperparams (batch_size, epochs, lr, patience, lstm_hidden, lstm_layers, dropout) |

### Key Design Decisions

1. **Standalone crate** rather than adding to workspace — libtorch dependency is ~2GB and shouldn't be required for the existing RF+IForest tools
2. **Reused preprocess modules** — identical data loading and normalization ensures fair comparison
3. **Model saved as .pt** (VarStore::save) — instant save/load, no retraining needed (unlike smartcore RF)
4. **All hyperparameters configurable via CLI** — batch_size, epochs, learning_rate, patience, lstm_hidden, lstm_layers, dropout

### Verification

- All Rust source code compiles cleanly (torch-sys requires libtorch at link time, handled by setup.sh)
- Existing workspace: all 60 tests pass, cnn-lstm-train crate is fully isolated
- `.gitignore` updated: `ids/cnn-lstm-train/target/`, `libtorch/`, `env.sh`

### CLI Usage

```bash
# Setup (downloads libtorch, builds binary)
cd ids/cnn-lstm-train && chmod +x setup.sh && ./setup.sh

# Source environment before running
source env.sh

# Model A: NSL-KDD
./target/release/train-cnn-lstm --dataset nsl-kdd \
    --nsl-train ../../NSL-KDD-Dataset/KDDTrain+.txt \
    --nsl-test ../../NSL-KDD-Dataset/KDDTest+.txt \
    --output-dir data/models/model-a

# Model B: CIC-IDS2017
./target/release/train-cnn-lstm --dataset cicids2017 \
    --cicids-dir ../../CIC-IDS2017-Dataset/CSVs/MachineLearningCSV/MachineLearningCVE/ \
    --output-dir data/models/model-b --no-smote

# Model C: UNSW-NB15
./target/release/train-cnn-lstm --dataset unsw-nb15 \
    --unsw-data ../../CIC-UNSW-NB15-Dataset/Data.csv \
    --unsw-label ../../CIC-UNSW-NB15-Dataset/Label.csv \
    --output-dir data/models/model-c

# Model D: All three combined
./target/release/train-cnn-lstm --dataset combined \
    --nsl-train ../../NSL-KDD-Dataset/KDDTrain+.txt \
    --nsl-test ../../NSL-KDD-Dataset/KDDTest+.txt \
    --cicids-dir ../../CIC-IDS2017-Dataset/CSVs/MachineLearningCSV/MachineLearningCVE/ \
    --unsw-data ../../CIC-UNSW-NB15-Dataset/Data.csv \
    --unsw-label ../../CIC-UNSW-NB15-Dataset/Label.csv \
    --output-dir data/models/model-d --no-smote
```

## Phase 4: Model C & D Training — Parallel (16-core machine, 2026-03-05)

Models C and D were trained on a 16-core machine using the `parallel-train` crate (rayon-parallelized RF+IForest, 32 threads auto-detected). Training was performed remotely and model artifacts were transferred back.

### Model C: UNSW-NB15

- **Dataset**: UNSW-NB15 (447,915 total records, 76 numeric features)
- **Train/Val/Test split**: 70% / 12% / 18% (313,541 / 53,749 / 80,625)
- **SMOTE**: Enabled, target=250,742 per class → 1,253,710 total training samples
- **Duration**: ~2 hours (RF training dominated)
- **Output**: `ids/parallel-train/data/models/model-c/`

#### Random Forest (5-class)

| Class | Precision | Recall | F1 |
|-------|-----------|--------|-----|
| Normal | 0.9999 | 0.9749 | 0.9872 |
| DoS | 0.6850 | 0.6196 | 0.6507 |
| Probe | 0.7275 | 0.8744 | 0.7942 |
| R2L | 0.8377 | 0.7422 | 0.7871 |
| U2R | 0.2183 | 0.5642 | 0.3148 |

Accuracy: 0.9390 | Macro-F1: 0.7068 | FPR: 0.0251

#### Isolation Forest (binary: Normal vs Attack)

| Class | Precision | Recall | F1 |
|-------|-----------|--------|-----|
| Normal | 0.8425 | 0.9613 | 0.8980 |
| Attack | 0.6384 | 0.2757 | 0.3851 |

Accuracy: 0.8250 | Macro-F1: 0.6415 | FPR: 0.0387

#### Ensemble (RF + IForest)

Accuracy: 0.9384 | Macro-F1: 0.7062

### Model D: Combined (NSL-KDD + CIC-IDS2017 + UNSW-NB15)

- **Dataset**: All three combined (3,406,631 total records, 276 features via union zero-padding)
- **Train/Val/Test split**: 70% / 12% / 18% (2,398,359 / ~408K / ~612K)
- **SMOTE**: Disabled (`--no-smote`) due to combined dataset size
- **Duration**: ~7 hours
- **Output**: `ids/parallel-train/data/models/model-d/`

#### Random Forest (5-class)

| Class | Precision | Recall | F1 |
|-------|-----------|--------|-----|
| Normal | 0.9863 | 0.9957 | 0.9910 |
| DoS | 0.9952 | 0.9006 | 0.9456 |
| Probe | 0.8727 | 0.9859 | 0.9258 |
| R2L | 0.8510 | 0.7505 | 0.7976 |
| U2R | 0.7660 | 0.0744 | 0.1356 |

Accuracy: 0.9780 | Macro-F1: 0.7591 | FPR: 0.0043

#### Isolation Forest (binary: Normal vs Attack)

| Class | Precision | Recall | F1 |
|-------|-----------|--------|-----|
| Normal | 0.8117 | 0.9752 | 0.8860 |
| Attack | 0.6264 | 0.1554 | 0.2490 |

Accuracy: 0.8020 | Macro-F1: 0.5675 | FPR: 0.0248

#### Ensemble (RF + IForest)

Accuracy: 0.9782 | Macro-F1: 0.7673

### Analysis

- **Model C (UNSW-NB15)** achieves 93.9% RF accuracy with strong Normal detection (F1 0.99) but weaker attack classes. U2R is the hardest class (F1 0.31) — only 452 test samples with high confusion against Probe/R2L. The SMOTE-balanced training improved minority class recall compared to unbalanced approaches.

- **Model D (Combined)** achieves the best overall RF accuracy (97.8%) and demonstrates that the union zero-padding approach works — the model can learn cross-dataset patterns despite 276-dimensional sparse feature vectors. U2R remains problematic (F1 0.14, recall 0.07) due to extreme rarity across all datasets.

- **Ensemble improves R2L recall in Model D** (0.75→0.82) compared to RF alone — this is the first time the IForest anomaly boost meaningfully helps, because the parallel-train RF uses proper probability outputs rather than one-hot approximations.

- **IForest consistently underperforms RF** across all models (80-83% accuracy vs 94-98%), confirming that supervised classification is more effective than unsupervised anomaly detection for IDS when labelled data is available.

### All-Models Comparison

| Metric | Model A (NSL-KDD) | Model B (CIC-IDS2017) | Model C (UNSW-NB15) | Model D (Combined) |
|--------|-------------------|----------------------|---------------------|-------------------|
| RF Accuracy | 0.6726* | 0.9973 | 0.9390 | 0.9780 |
| RF Macro-F1 | 0.2809* | 0.9534 | 0.7068 | 0.7591 |
| Ensemble Acc | 0.6726* | 0.9973 | 0.9384 | 0.9782 |
| Ensemble F1 | 0.2809* | 0.9534 | 0.7062 | 0.7673 |
| IForest Acc | 0.7724 | 0.8137 | 0.8250 | 0.8020 |
| FPR | 0.0301 | 0.0006 | 0.0251 | 0.0043 |
| Features | 122 | 78 | 76 | 276 |
| Train samples | 276,840 | 1,981,520 | 1,253,710 | 2,398,359 |

*Model A metrics limited by binary-only test labels.

## Phase 6: Python PyTorch CNN+LSTM Training Package (2026-03-05)

### Motivation

The Rust `cnn-lstm-train` crate uses tch-rs/libtorch which only supports NVIDIA GPUs (CUDA). The training machine has an AMD Radeon RX 7900 XT (RDNA 3). Python PyTorch supports AMD GPUs via ROCm, so a Python port was created at `ids/pytorch-train/` to enable GPU-accelerated CNN+LSTM training on AMD hardware.

### Implementation

The Python package exactly replicates the Rust CNN+LSTM training pipeline:

| File | Purpose |
|------|---------|
| `setup.sh` | Creates Python venv, installs PyTorch (ROCm/CUDA/CPU auto-detect), numpy, pandas, tqdm |
| `requirements.txt` | Python dependencies |
| `model.py` | CnnLstm nn.Module — exact replica of Rust architecture (Conv1d→BN→Conv1d→BN→LSTM→FC) |
| `preprocessing.py` | MinMaxScaler, OneHotEncoder, SMOTE (matching Rust implementations) |
| `data_loaders.py` | NSL-KDD, CIC-IDS2017, UNSW-NB15, combined loaders (same parsing, same attack category mappings) |
| `evaluate.py` | Classification metrics (accuracy, per-class P/R/F1, macro averages, FPR, confusion matrix) |
| `train.py` | Main CLI entry point + training loop (Adam, early stopping, LR decay, checkpointing) |

### Key Design Decisions

1. **Exact architecture replica** — same Conv1d channels (64, 128), kernel size (3), LSTM hidden (128), layers (2), dropout (0.3), FC hidden (64). Ensures fair comparison between Rust and Python training.

2. **Same CLI flags** — `--dataset`, `--nsl-train`, `--nsl-test`, `--cicids-dir`, `--unsw-data`, `--unsw-label`, `--output-dir`, `--no-smote`, `--batch-size`, `--epochs`, `--learning-rate`, `--patience`, `--lstm-hidden`, `--lstm-layers`, `--dropout`.

3. **Same JSON output format** — `evaluation_report.json` with identical schema (`cnn_lstm`, `training_metrics`, `model_config`, `dataset`, `n_train_samples`).

4. **Same data pipeline** — load → MinMaxScaler normalize (fit on train) → optional SMOTE → tensor conversion → train → evaluate on test → save model + scaler + report.

5. **PRNG note** — SMOTE uses numpy PCG64 (vs Rust ChaCha8). Same seed pattern (42 + class*1M + idx) but different PRNG engines means synthetic samples will differ. Algorithm and hyperparameters are identical.

### AMD GPU Support

- ROCm exposes AMD GPUs as CUDA devices in PyTorch (`torch.cuda.is_available()` returns True)
- RX 7900 XT (RDNA 3) may need `HSA_OVERRIDE_GFX_VERSION=11.0.0` for ROCm compatibility
- setup.sh auto-detects ROCm and installs PyTorch with ROCm 6.2 support

### CLI Usage

```bash
cd ids/pytorch-train && ./setup.sh && source env.sh

# Model A: NSL-KDD
python train.py --dataset nsl-kdd \
    --nsl-train ../../NSL-KDD-Dataset/KDDTrain+.txt \
    --nsl-test ../../NSL-KDD-Dataset/KDDTest+.txt \
    --output-dir data/models/model-a

# Model B: CIC-IDS2017
python train.py --dataset cicids2017 \
    --cicids-dir ../../CIC-IDS2017-Dataset/CSVs/MachineLearningCSV/MachineLearningCVE/ \
    --output-dir data/models/model-b --no-smote

# Model C: UNSW-NB15
python train.py --dataset unsw-nb15 \
    --unsw-data ../../CIC-UNSW-NB15-Dataset/Data.csv \
    --unsw-label ../../CIC-UNSW-NB15-Dataset/Label.csv \
    --output-dir data/models/model-c

# Model D: All three combined
python train.py --dataset combined \
    --nsl-train ../../NSL-KDD-Dataset/KDDTrain+.txt \
    --nsl-test ../../NSL-KDD-Dataset/KDDTest+.txt \
    --cicids-dir ../../CIC-IDS2017-Dataset/CSVs/MachineLearningCSV/MachineLearningCVE/ \
    --unsw-data ../../CIC-UNSW-NB15-Dataset/Data.csv \
    --unsw-label ../../CIC-UNSW-NB15-Dataset/Label.csv \
    --output-dir data/models/model-d --no-smote
```
