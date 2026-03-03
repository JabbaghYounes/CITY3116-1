# Implementation Documentation

This document logs the implementation steps taken for the CPS-IDS multi-dataset training pipeline.

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
- **File**: `cps-ids/crates/ids-preprocess/src/dataset.rs`
- Changed `fn label_names()` → `pub fn label_names()` to allow other dataset loaders to reuse the canonical 5-class names: Normal, DoS, Probe, R2L, U2R.

#### Step 2: Created CIC-IDS2017 loader
- **File**: `cps-ids/crates/ids-preprocess/src/cicids.rs` (new, ~250 lines)
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
- **File**: `cps-ids/crates/ids-preprocess/src/unsw.rs` (new, ~200 lines)
- Public function: `load_unsw_nb15(data_path: &Path, label_path: &Path) -> Result<DatasetSplit>`
- Loads Data.csv (76 numeric columns) and Label.csv (integer labels 0–9) as separate files
- Verifies row count alignment between the two files
- Label mapping (`unsw_attack_category`): maps integer labels using Readme.txt mapping (0→Normal, 3/6→DoS, 1/5/7→Probe, 4/9→R2L, 2/8→U2R)
- Splits data: 70% train / 12% val / 18% test
- 1 unit test: label mapping for all 10 integer values

#### Step 4: Created N-dataset merger
- **File**: `cps-ids/crates/ids-preprocess/src/combined.rs` (new, ~170 lines)
- Public function: `merge_datasets(splits: &[(&str, &DatasetSplit)]) -> Result<DatasetSplit>`
- Strategy: union with zero-padding — each dataset's features occupy a dedicated column range, other columns are zero
- Feature names prefixed with dataset identifier (e.g., `nsl_duration`, `cic_Flow Duration`, `unsw_Flow Duration`)
- Uses ndarray slice assignment for efficient zero-padding
- Merges train/val/test splits independently
- 1 unit test: verifies dimensions, zero-padding correctness, and feature names

#### Step 5: Wired up `ids-preprocess` modules
- **File**: `cps-ids/crates/ids-preprocess/src/lib.rs`
- Added `pub mod cicids; pub mod unsw; pub mod combined;`
- Added re-exports: `load_cicids2017`, `load_unsw_nb15`, `merge_datasets`, `label_names`

#### Step 6: Created training orchestrator
- **File**: `cps-ids/crates/ids-engine/src/train.rs` (new, ~220 lines)
- `DatasetSource` enum with 4 variants: `NslKdd`, `CicIds2017`, `UnswNb15`, `Combined`
- `TrainConfig` struct: configurable output paths, SMOTE settings, IForest parameters
- `run_training()` pipeline: load → MinMaxScaler normalize → optional SMOTE → train Random Forest → train Isolation Forest (on normal samples only) → evaluate all three (RF, IForest binary, Ensemble) → save models + evaluation report as JSON

#### Step 7: Updated `ids-engine` configuration
- **File**: `cps-ids/crates/ids-engine/Cargo.toml`
  - Added `clap = { version = "4", features = ["derive"] }` for CLI parsing
  - Added `tracing-subscriber` for logging initialisation in the binary
  - Added `[[bin]] name = "train_models"` target
- **File**: `cps-ids/crates/ids-engine/src/lib.rs`
  - Added `pub mod train;`

#### Step 8: Created CLI binary
- **File**: `cps-ids/crates/ids-engine/src/bin/train_models.rs` (new, ~180 lines)
- clap-derive CLI with flags: `--dataset` (nsl-kdd|cicids2017|unsw-nb15|combined), dataset path arguments, `--output-dir`, `--no-smote`, `--smote-target`, IForest configuration
- Prints training summary with accuracy and F1 scores

#### Step 9: Fixed `ids-response` compile error
- **File**: `cps-ids/crates/ids-response/src/alerter.rs`
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
# From cps-ids/ directory

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
