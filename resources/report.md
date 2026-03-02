# Implementation Report: CPS IDS/IPS in Rust

## Summary

Built a complete AI/ML-driven Intrusion Detection and Prevention System for Cyber-Physical Systems as a Rust Cargo workspace with 6 crates. The system supports both **Network-based (NIDS/NIPS)** and **Host-based (HIDS/HIPS)** detection simultaneously. The entire workspace compiles cleanly with zero errors and zero warnings.

---

## Phase 0: Project Setup

**Action:** Created Cargo workspace at `cps-ids/` with 6 crates and supporting directories.

**Files created:**
- `cps-ids/Cargo.toml` — Workspace root with shared dependencies (serde, tokio, tracing, ndarray, etc.)
- `cps-ids/crates/ids-common/Cargo.toml`
- `cps-ids/crates/ids-collector/Cargo.toml`
- `cps-ids/crates/ids-preprocess/Cargo.toml`
- `cps-ids/crates/ids-engine/Cargo.toml`
- `cps-ids/crates/ids-response/Cargo.toml`
- `cps-ids/crates/ids-dashboard/Cargo.toml`
- `cps-ids/config.toml` — Runtime configuration with sections for network, host, preprocessing, detection, response, dashboard, and model paths
- `cps-ids/scripts/download_dataset.sh` — NSL-KDD dataset download script

**Directory structure:**
```
cps-ids/
  Cargo.toml
  config.toml
  crates/
    ids-common/src/          (3 files)
    ids-collector/src/       (14 files across network/ and host/)
    ids-preprocess/src/      (6 files)
    ids-engine/src/          (6 files)
    ids-response/src/        (5 files)
    ids-dashboard/src/       (4 files + 1 HTML)
  data/nsl-kdd/
  data/models/
  scripts/
  results/
  tests/integration/
```

---

## Phase 1: ids-common — Shared Types and Configuration

**Files:**
- `src/lib.rs` — Module re-exports
- `src/types.rs` — All shared type definitions
- `src/config.rs` — Configuration structs with TOML deserialization
- `src/error.rs` — Error types via thiserror

**Types implemented:**
- `SecurityEvent` — Unified enum: `Network(PacketRecord)` | `Host(HostEvent)`
- **Network types:** `PacketRecord`, `Protocol`, `TcpFlags`, `FlowKey`, `FlowRecord`, `ModbusInfo`
- **Host types:** `HostEvent` (enum: `FileChange`, `ProcessActivity`, `SyscallTrace`, `LogEntry`), `FileChangeEvent`, `ProcessEvent`, `SyscallEvent`, `LogEvent`, plus associated enums (`FileChangeType`, `ProcessEventType`, `LogSeverity`)
- **Alert types:** `Alert` (with both network and host fields), `AlertSource`, `Severity`, `AttackCategory`
- **Detection types:** `DetectionResult`, `DetectionMetadata`
- **Config:** `AppConfig` with nested structs for all subsystems, `Default` impl, TOML `load()` method

---

## Phase 2: ids-collector — Data Collection (NIDS + HIDS)

**Network collection (`src/network/`):**
- `capture.rs` — `NetworkCapture` struct wrapping pnet datalink channel. Parses Ethernet → IP → TCP/UDP headers, detects Modbus by port 502, sends `PacketRecord` events via channel
- `protocols/modbus.rs` — Parses 7-byte MBAP header + PDU function code, extracts register addresses and values
- `protocols/dnp3.rs` — Stub logging "not implemented"
- `protocols/opcua.rs` — Stub logging "not implemented"
- `flow.rs` — `FlowTable` with `HashMap<FlowKey, FlowRecord>`, methods for update, expire (timeout-based), get active flows
- `replay.rs` — PCAP file replay using `pcap-file` crate, feeds packets through same pipeline as live capture

**Host collection (`src/host/`):**
- `file_integrity.rs` — `FileIntegrityMonitor` using `notify` crate for filesystem watching + `sha2` for SHA-256 hashing. Builds baseline on startup, detects create/modify/delete events, tracks hash changes
- `process_monitor.rs` — `ProcessMonitor` using `sysinfo` crate. Polls process table at intervals, detects new/terminated processes, checks against whitelist, reports suspicious spawns
- `syscall_monitor.rs` — `SyscallMonitor` that tails `/var/log/audit/audit.log`, parses audit entries for security-relevant syscalls (execve, connect, chmod, setuid, ptrace)
- `log_watcher.rs` — `LogWatcher` that tails system logs (auth.log, syslog), parses for failed logins, sudo usage, error events

**Key design:** Both NIDS and HIDS collectors send events as `SecurityEvent` variants through `tokio::sync::mpsc` channels into the unified pipeline.

---

## Phase 3: ids-preprocess — Preprocessing Pipeline

**Files:**
- `src/dataset.rs` — NSL-KDD CSV loader with comprehensive attack label mapping (DoS: 11 subtypes, Probe: 6, R2L: 15, U2R: 7). Reads KDDTrain+.txt and KDDTest+.txt, handles categorical columns, applies one-hot encoding, splits data 82/18 for train/val
- `src/encode.rs` — `OneHotEncoder` that learns categories from training data, transforms categorical values to binary vectors
- `src/normalize.rs` — `MinMaxScaler` with fit/transform/fit_transform, serializable via serde_json for inference-time reuse
- `src/smote.rs` — SMOTE oversampling implementation. Finds k nearest neighbors within same class, generates synthetic samples by interpolation
- `src/features.rs` — Feature extraction from live events:
  - Network: duration, packet counts, byte counts, mean/std of packet sizes and inter-arrival times, temporal features
  - Host: file change counts, process spawn counts, suspicious syscall counts, failed login counts, privilege escalation indicators

**Output type:** `DatasetSplit` with x_train, y_train, x_val, y_val, x_test, y_test as ndarray arrays, plus feature_names and label_names.

---

## Phase 4: ids-engine — Detection Engine

**Files:**
- `src/rules.rs` — Rule-based detection engine with `DetectionRule` struct supporting both network and host rules:
  - Network rules: SYN flood rate, port scan detection, Modbus illegal function codes, payload pattern matching
  - Host rules: critical file modification, suspicious process paths, failed login rate, privilege escalation syscalls
  - `default_rules()` returns ~20 preconfigured rules
- `src/random_forest.rs` — `RFModel` wrapper around smartcore `RandomForestClassifier<f64, i32>`. Hyperparameters: 100 trees, max depth 20, min samples split 2. Includes predict_proba approximation with Laplace smoothing. Persistence via training data serialization.
- `src/isolation_forest.rs` — Custom `IsolationForest` implementation (~200 lines). Builds isolation trees by random feature splits, computes anomaly scores based on average path length. Uses `c_factor()` for the expected average path length of a BST.
- `src/ensemble.rs` — `EnsembleDetector` with configurable weights (RF: 0.35, IForest: 0.25). Weighted combination of RF class probabilities with anomaly score escalation.
- `src/evaluate.rs` — `ClassificationReport` with accuracy, precision/recall/F1 per class, macro averages, FPR, 5x5 confusion matrix. Includes `print_report()` for formatted output and `cross_validate()` for k-fold evaluation.

**Fix applied:** smartcore 0.3 requires `TY: Ord` for labels — changed from `f64` to `i32` label type. Also fixed `with_max_depth()` API (takes `u16`, not `Option`).

---

## Phase 5: ids-response — Response Module

**Files:**
- `src/alerter.rs` — `Alerter::create_alert()` maps DetectionResult → Alert. Severity mapping: DoS/U2R → Critical, Probe → High, R2L → Medium. Confidence < 0.7 triggers severity downgrade. Populates network or host fields from DetectionMetadata.
- `src/blocker.rs` — Prevention actions (logging-only for safety):
  - `NetworkBlocker`: simulates iptables block/unblock, tracks blocked IPs with timestamps, auto-expires
  - `HostBlocker`: simulates process kill and file quarantine
- `src/siem.rs` — `format_cef()` (ArcSight Common Event Format) and `format_syslog()` (RFC 5424) output formatters with proper severity mapping and field escaping
- `src/logger.rs` — `AlertLogger` for structured JSON-line logging to file. `init_tracing()` for global tracing_subscriber setup with JSON format and env filter.

**Includes unit tests** for severity mapping, CEF format validation, syslog priority calculation, and async log file writing.

---

## Phase 6: ids-dashboard — Management Interface

**Files:**
- `src/main.rs` — Axum HTTP server entry point. Loads config, creates shared `AppState`, mounts routes and static files, starts server on configured host:port.
- `src/routes.rs` — REST API:
  - `GET /api/alerts` — Paginated alert list with severity/source filters
  - `GET /api/alerts/:id` — Single alert by UUID
  - `GET /api/stats` — Aggregated statistics (total, by severity, by source, by category)
  - `GET /api/models` — Model info with placeholder metrics
  - `GET /api/config` — Current configuration
  - `GET /api/health` — Health check
- `src/ws.rs` — WebSocket handler at `/ws/alerts` broadcasting real-time alerts via `tokio::sync::broadcast`
- `src/static/index.html` — Dark-themed single-page dashboard with:
  - Stats cards (Total, Network, Host, Critical alerts)
  - Real-time alert feed via WebSocket with severity badges
  - Alerts-by-category bar chart (Chart.js)
  - Model performance comparison table

**Shared state:** `AppState` with `Arc<RwLock<Vec<Alert>>>`, `broadcast::Sender<Alert>`, and `Arc<RwLock<AppConfig>>`.

---

## Build Verification

```
$ cargo check
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.56s
    (zero errors, zero warnings)

$ cargo build
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 38.55s
```

**Total crates compiled:** 247 dependencies + 6 workspace crates
**Binary produced:** `target/debug/ids-dashboard`

---

## Issues Encountered and Resolved

| Issue | Resolution |
|-------|-----------|
| smartcore `RandomForestClassifier` requires `TY: Ord`, `f64` doesn't implement `Ord` | Changed label type from `f64` to `i32` |
| smartcore `with_max_depth()` takes `u16`, not `Option<u16>` | Changed `Some(20)` to `20` |
| smartcore types don't implement `Serialize`/`Deserialize` | Store training data in wrapper struct, retrain on load |
| Borrow checker conflict in `FileIntegrityMonitor::build_baseline()` (iterating `&self.config` while calling `&mut self` method) | Clone watch_paths before iteration |
| Unused imports in ids-collector and ids-response | Removed `pnet::packet::Packet` and moved `AlertSource` to test-only |

---

## File Count Summary

| Crate | Source Files | Lines (approx) |
|-------|-------------|----------------|
| ids-common | 4 | ~350 |
| ids-collector | 14 | ~750 |
| ids-preprocess | 6 | ~600 |
| ids-engine | 6 | ~700 |
| ids-response | 5 | ~400 |
| ids-dashboard | 4 (+1 HTML) | ~550 |
| **Total** | **39 (+1 HTML)** | **~3,350** |

---

## Next Steps

1. Download NSL-KDD dataset (`scripts/download_dataset.sh`)
2. Train models: `cargo run -p ids-engine -- train`
3. Run evaluation benchmarks and generate results tables
4. Integration test with VulnShop application
5. Screenshot dashboard for presentation
