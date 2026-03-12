# Implementation Plan: AI/ML-Driven IDS/IPS for CPS in Rust

## Overview

A phased plan for building an AI/ML-driven Intrusion Detection and Prevention System for Cyber-Physical Systems, implemented in Rust. The system supports both **Network-based (NIDS/NIPS)** and **Host-based (HIDS/HIPS)** detection and prevention simultaneously. It uses a Cargo workspace with six crates corresponding to the five architectural modules from the writeup (Data Collection, Preprocessing, Detection Engine, Response, Management Interface) plus a shared types crate.

**NIDS/NIPS** monitors network traffic — packet capture, flow reconstruction, protocol parsing (Modbus, DNP3, OPC UA) — to detect network-layer attacks such as DoS, port scanning, and MITM.

**HIDS/HIPS** monitors host activity — file integrity, process behaviour, system calls, and log analysis — to detect host-layer attacks such as privilege escalation, rootkits, ransomware, and unauthorized file modifications.

Both subsystems feed into a unified detection engine where ML models operate on a combined feature space, and alerts from either source are handled by the same response and dashboard modules.

The project targets the NSL-KDD dataset as the primary benchmark (network features), with optional support for CICIDS2017 and ICS/SCADA datasets. Host-based detection is evaluated using ADFA-LD (Australian Defence Force Academy Linux Dataset) for system call anomaly detection. Three ML models are implemented: Random Forest (via `smartcore`), LSTM (via `burn`), and Isolation Forest (custom implementation). Results are compared against a rule-based detection baseline.

---

## 0. Project Setup and Structure

### Cargo Workspace Layout

```
ids/
  Cargo.toml                    # workspace root
  config.toml                   # runtime configuration
  crates/
    ids-common/                 # shared types, config, errors
      Cargo.toml
      src/
        lib.rs
        types.rs                # PacketRecord, FlowRecord, HostEvent, Alert, etc.
        config.rs               # global config struct (serde)
        error.rs                # thiserror error types
    ids-collector/              # Phase 1: Data Collection (NIDS + HIDS)
      Cargo.toml
      src/
        lib.rs
        network/                # --- NIDS data sources ---
          mod.rs
          capture.rs            # pnet packet capture
          protocols/
            mod.rs
            modbus.rs           # Modbus TCP parser
            dnp3.rs             # DNP3 parser (stub)
            opcua.rs            # OPC UA parser (stub)
          flow.rs               # flow table, flow reconstruction
          replay.rs             # PCAP replay for offline analysis
        host/                   # --- HIDS data sources ---
          mod.rs
          file_integrity.rs     # file system monitoring (notify crate)
          process_monitor.rs    # process creation/termination tracking (sysinfo)
          syscall_monitor.rs    # system call tracing (Linux audit / eBPF)
          log_watcher.rs        # system log ingestion (syslog, auth.log, journald)
    ids-preprocess/             # Phase 2: Preprocessing
      Cargo.toml
      src/
        lib.rs
        features.rs             # feature extraction (network + host)
        normalize.rs            # min-max, z-score normalization
        encode.rs               # one-hot, label encoding
        smote.rs                # SMOTE oversampling
        dataset.rs              # CSV loading, train/val/test split
    ids-engine/                 # Phase 3: Detection Engine
      Cargo.toml
      src/
        lib.rs
        rules.rs                # rule-based detection (Snort-like)
        random_forest.rs        # RF classifier via smartcore
        lstm.rs                 # LSTM model via burn
        isolation_forest.rs     # anomaly detection
        ensemble.rs             # weighted ensemble combiner
        evaluate.rs             # metrics: accuracy, precision, recall, F1, FPR
    ids-response/               # Phase 4: Response Module
      Cargo.toml
      src/
        lib.rs
        alerter.rs              # alert generation, severity levels
        blocker.rs              # IPS mode: iptables/nftables integration
        siem.rs                 # syslog/CEF output for SIEM
        logger.rs               # structured logging
    ids-dashboard/              # Phase 5: Management Interface
      Cargo.toml
      src/
        main.rs                 # axum HTTP server
        routes.rs               # REST endpoints
        ws.rs                   # WebSocket real-time feed
        static/                 # HTML/JS dashboard files
          index.html
          dashboard.js
  data/
    nsl-kdd/
      KDDTrain+.txt
      KDDTest+.txt
      feature_names.txt
    models/                     # serialized trained models
  scripts/
    download_dataset.sh         # curl commands to fetch NSL-KDD
    snort_baseline.sh           # run Snort on test PCAP
  results/                      # evaluation output artifacts
  tests/
    integration/
      end_to_end.rs
```

### Root `Cargo.toml`

```toml
[workspace]
resolver = "2"
members = [
    "crates/ids-common",
    "crates/ids-collector",
    "crates/ids-preprocess",
    "crates/ids-engine",
    "crates/ids-response",
    "crates/ids-dashboard",
]

[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["full"] }
tracing = "0.1"
tracing-subscriber = "0.3"
thiserror = "2"
anyhow = "1"
chrono = { version = "0.4", features = ["serde"] }
ndarray = { version = "0.16", features = ["serde"] }
```

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| `pnet` 0.35 | Raw packet capture, Ethernet/IP/TCP/UDP parsing (NIDS) |
| `smartcore` 0.4 | Random Forest classifier (configurable n_trees, max_depth, min_samples_split) |
| `linfa` + `linfa-preprocessing` 0.7 | Data normalization and scaling utilities |
| `burn` + `burn-ndarray` 0.16 | LSTM deep learning model (CPU backend) |
| `csv` 1.3 | Reading NSL-KDD CSV files |
| `ndarray` 0.16 | Core tensor type, bridges smartcore and linfa |
| `axum` 0.8 | Dashboard web server |
| `tokio` 1.x | Async runtime |
| `serde` / `serde_json` | Serialization throughout |
| `tracing` | Structured logging |
| `pcap-file` 2 | PCAP file reading for replay mode (NIDS) |
| `notify` 7 | File system event watching (HIDS file integrity) |
| `sysinfo` 0.33 | Process listing, CPU/memory stats (HIDS process monitor) |

---

## Phase 1: Data Collection Module (`ids-collector`)

**Goal:** Collect security-relevant data from both network and host sources, providing a unified event stream to the preprocessing pipeline.

### 1a. Network-Based Collection (NIDS)

**`network/capture.rs`** — Wrapper around `pnet::datalink::channel()` that opens a datalink channel on a specified interface. Produces a stream of `PacketRecord` structs containing parsed Ethernet, IP, TCP/UDP headers and payload.

**`network/protocols/modbus.rs`** — Modbus TCP parser for traffic on port 502. Parses the 7-byte MBAP header (transaction ID, protocol ID, length, unit ID) and PDU (function code + data). Extracts function codes (1-6, 15, 16), register addresses, and values.

**`network/protocols/dnp3.rs` and `network/protocols/opcua.rs`** — Stub implementations that log "unsupported protocol". Including them demonstrates architectural extensibility.

**`network/flow.rs`** — `FlowTable` backed by `HashMap<FlowKey, FlowRecord>`. A `FlowKey` is `(src_ip, dst_ip, src_port, dst_port, protocol)`. Each `FlowRecord` accumulates: packet count, byte count, start/last time, packet sizes list, inter-arrival times list. Flows expire after a configurable timeout (default 120s). Thread-safe via `Arc<RwLock<FlowTable>>`.

**`network/replay.rs`** — Read PCAP files using `pcap-file` and feed packets through the same pipeline as live capture. Essential for training and evaluation using dataset files.

### 1b. Host-Based Collection (HIDS)

**`host/file_integrity.rs`** — File Integrity Monitor (FIM) using the `notify` crate. Watches configured directories (e.g., `/etc`, `/usr/bin`, PLC config paths) for create, modify, delete, and rename events. Computes SHA-256 hashes of files on startup to build a baseline, then detects deviations at runtime. Produces `HostEvent::FileChange` events.

```rust
pub struct FileIntegrityMonitor {
    watched_paths: Vec<PathBuf>,
    baseline_hashes: HashMap<PathBuf, String>,  // path -> SHA-256
    watcher: RecommendedWatcher,
}
```

**`host/process_monitor.rs`** — Process monitor using `sysinfo` crate. Polls the process table at configurable intervals (default 2s). Detects:
- New process creation (especially from unexpected parent processes)
- Processes running as root/elevated privileges
- Unusual process names or paths (not in a whitelist)
- High resource consumption anomalies (CPU/memory spikes)

Produces `HostEvent::ProcessActivity` events.

```rust
pub struct ProcessMonitor {
    system: System,
    known_processes: HashMap<Pid, ProcessSnapshot>,
    whitelist: HashSet<PathBuf>,
    poll_interval: Duration,
}
```

**`host/syscall_monitor.rs`** — System call tracing via Linux Audit subsystem (`/var/log/audit/audit.log`). Parses audit log entries for security-relevant syscalls: `execve`, `open`, `connect`, `chmod`, `setuid`, `ptrace`, `mount`. This is a log-parsing approach (no eBPF required) that works on standard Linux with auditd enabled. Produces `HostEvent::SyscallTrace` events.

**`host/log_watcher.rs`** — Tail and parse system logs for security events:
- `/var/log/auth.log` or `journalctl`: failed SSH attempts, sudo usage, user creation
- `/var/log/syslog`: service start/stop, kernel messages
- Application logs: CPS-specific application logs (configurable paths)

Uses `notify` to watch for file changes and reads new lines incrementally. Produces `HostEvent::LogEntry` events.

### Key Types (`ids-common/src/types.rs`)

```rust
/// Unified event enum — everything the collector produces goes through this
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEvent {
    Network(PacketRecord),
    Host(HostEvent),
}

// --- Network types (NIDS) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketRecord {
    pub timestamp: DateTime<Utc>,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub payload_len: usize,
    pub tcp_flags: Option<TcpFlags>,
    pub raw_payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Protocol { Tcp, Udp, Icmp, Modbus, Dnp3, OpcUa, Other(u8) }

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TcpFlags { pub syn: bool, pub ack: bool, pub fin: bool, pub rst: bool, pub psh: bool, pub urg: bool }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowRecord {
    pub key: FlowKey,
    pub start_time: DateTime<Utc>,
    pub last_time: DateTime<Utc>,
    pub packet_count: u64,
    pub byte_count: u64,
    pub fwd_packet_count: u64,
    pub bwd_packet_count: u64,
    pub packet_sizes: Vec<usize>,
    pub inter_arrival_times_us: Vec<i64>,
    pub tcp_flags_seen: Vec<TcpFlags>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModbusInfo {
    pub transaction_id: u16,
    pub unit_id: u8,
    pub function_code: u8,
    pub register_address: Option<u16>,
    pub register_value: Option<u16>,
    pub is_response: bool,
}

// --- Host types (HIDS) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HostEvent {
    FileChange(FileChangeEvent),
    ProcessActivity(ProcessEvent),
    SyscallTrace(SyscallEvent),
    LogEntry(LogEvent),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChangeEvent {
    pub timestamp: DateTime<Utc>,
    pub path: PathBuf,
    pub change_type: FileChangeType,        // Created, Modified, Deleted, Renamed
    pub old_hash: Option<String>,           // SHA-256 before change
    pub new_hash: Option<String>,           // SHA-256 after change
    pub file_permissions: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub timestamp: DateTime<Utc>,
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub exe_path: PathBuf,
    pub uid: u32,
    pub event_type: ProcessEventType,       // Spawned, Terminated, Elevated
    pub cpu_usage: f32,
    pub memory_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEvent {
    pub timestamp: DateTime<Utc>,
    pub pid: u32,
    pub syscall: String,                    // execve, open, connect, chmod, etc.
    pub args: Vec<String>,
    pub return_code: i64,
    pub uid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub timestamp: DateTime<Utc>,
    pub source: String,                     // auth.log, syslog, application name
    pub severity: LogSeverity,              // Debug, Info, Warning, Error, Critical
    pub message: String,
    pub parsed_fields: HashMap<String, String>,  // extracted IPs, usernames, etc.
}
```

### Notes

- `pnet` requires `sudo` or `CAP_NET_RAW` for live network capture. Document in README.
- HIDS file integrity monitoring runs unprivileged for user-owned paths; watching system paths like `/etc` may require elevated permissions.
- `syscall_monitor` reads the audit log passively — auditd must be running and configured with appropriate rules (e.g., `auditctl -a always,exit -F arch=b64 -S execve`).
- For the ML pipeline, NSL-KDD is already CSV (network features) and ADFA-LD is system call sequences (host features) — the collector demonstrates live capability but training reads datasets directly in Phase 2.
- Both NIDS and HIDS collectors send events through the same `tokio::sync::mpsc` channel as `SecurityEvent` variants.

### Dependencies

```toml
[dependencies]
ids-common = { path = "../ids-common" }
pnet = "0.35"
pcap-file = "2"
notify = "7"
sysinfo = "0.33"
sha2 = "0.10"
tokio = { workspace = true }
tracing = { workspace = true }
chrono = { workspace = true }
serde = { workspace = true }
```

---

## Phase 2: Preprocessing Pipeline (`ids-preprocess`)

**Goal:** Load datasets, extract features from both network and host events, normalize, handle class imbalance, and produce train/validation/test splits.

### Components

**`dataset.rs`** — Dataset loaders for both network and host data.

*Network (NIDS):* NSL-KDD CSV loader. Reads `KDDTrain+.txt` and `KDDTest+.txt` (41 features + label + difficulty per row). Maps attack labels to 5 categories:

| Category | Attack Types |
|----------|-------------|
| Normal | `normal` |
| DoS | `back`, `land`, `neptune`, `pod`, `smurf`, `teardrop`, `apache2`, `udpstorm`, `processtable`, `worm`, `mailbomb` |
| Probe | `satan`, `ipsweep`, `nmap`, `portsweep`, `mscan`, `saint` |
| R2L | `guess_passwd`, `ftp_write`, `imap`, `phf`, `multihop`, `warezmaster`, `warezclient`, `spy`, `xlock`, `xsnoop`, `snmpguess`, `snmpgetattack`, `httptunnel`, `sendmail`, `named` |
| U2R | `buffer_overflow`, `loadmodule`, `rootkit`, `perl`, `sqlattack`, `xterm`, `ps` |

Produces `ndarray::Array2<f64>` feature matrices and `Array1<usize>` label vectors.

**`encode.rs`** — One-hot encoding for categorical features:
- `protocol_type`: 3 values (tcp, udp, icmp)
- `service`: ~70 values
- `flag`: 11 values

Total features after encoding: ~122 (38 numeric + 84 one-hot). Label encoding: 0=Normal, 1=DoS, 2=Probe, 3=R2L, 4=U2R.

**`normalize.rs`** — Min-max normalization to [0, 1] range. Store scaling parameters (min/max per column) for reuse at inference time. Serialize alongside the model.

**`smote.rs`** — Synthetic Minority Over-sampling Technique:
- For each minority class sample, find k=5 nearest neighbors within same class
- Generate synthetic samples by interpolating between sample and random neighbor
- Target: balance each class to roughly equal representation
- ~100 lines of implementation

**`features.rs`** — Feature extraction from both network and host events for live/replay mode:

*Network features (from `FlowRecord`):*
- Duration, packet counts (fwd/bwd/total), byte counts
- Mean and std of packet sizes and inter-arrival times
- Protocol-specific: Modbus function code frequency distribution
- Temporal: hour of day, is_weekend

*Host features (from `HostEvent`):*
- File integrity: number of file changes per window, ratio of modifications vs. creations, changes in sensitive directories (`/etc`, `/usr/bin`), permission changes count
- Process activity: new process count per window, root process spawns, processes from non-whitelisted paths, CPU/memory anomaly scores
- System calls: syscall frequency distribution (execve, open, connect, chmod counts), unique syscall count, privilege escalation syscalls (setuid, ptrace), failed syscall ratio
- Log events: failed login count, sudo invocations, error/critical log frequency, unique source IPs in auth failures

*Combined feature vector:* For unified detection, network and host features are concatenated into a single vector. Events that are network-only or host-only have zeros for the missing half. This allows the ensemble models to learn correlations across both domains (e.g., a port scan followed by a brute-force SSH attempt).

*ADFA-LD dataset:* System call trace sequences for host-based anomaly detection. Each trace is a variable-length sequence of syscall numbers. Loaded as integer sequences and padded/truncated to a fixed window (length 200) for the LSTM model.

### Key Types

```rust
pub struct DatasetSplit {
    pub x_train: Array2<f64>,
    pub y_train: Array1<usize>,
    pub x_val: Array2<f64>,
    pub y_val: Array1<usize>,
    pub x_test: Array2<f64>,
    pub y_test: Array1<usize>,
    pub feature_names: Vec<String>,
    pub label_names: Vec<String>,  // ["Normal", "DoS", "Probe", "R2L", "U2R"]
}

/// Source tag so the detection engine knows which subsystem produced the features
#[derive(Debug, Clone, Copy)]
pub enum EventSource {
    Network,
    Host,
    Combined,
}
```

### Splitting Strategy

Use NSL-KDD's provided train/test split. Further split the training set: 70% train, 15% validation. The provided test set is the 15% test. For cross-validation, implement a k-fold splitter partitioning training data into 5 folds.

### Dependencies

```toml
[dependencies]
ids-common = { path = "../ids-common" }
csv = "1.3"
ndarray = { workspace = true }
ndarray-rand = "0.15"
linfa = "0.7"
linfa-preprocessing = "0.7"
serde = { workspace = true }
rand = "0.8"
tracing = { workspace = true }
anyhow = { workspace = true }
```

---

## Phase 3: Detection Engine (`ids-engine`)

**Goal:** Implement three ML models, a rule-based baseline, ensemble combiner, and evaluation metrics.

### 3a. Rule-Based Detection (`rules.rs`)

Simplified Snort-like rule engine with ~20 hardcoded rules:

```rust
pub struct DetectionRule {
    pub id: u32,
    pub name: String,
    pub protocol: Option<Protocol>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub content: Option<Vec<u8>>,       // payload pattern match
    pub threshold: Option<Threshold>,    // rate-based detection
    pub action: RuleAction,              // Alert, Drop, or Log
}
```

*Network rules (~10):* SYN flood detection, port scan detection, Modbus illegal function codes, known malicious payload signatures, abnormal packet sizes for industrial protocols.

*Host rules (~10):* Modification of critical system files (`/etc/passwd`, `/etc/shadow`), process spawned from `/tmp` or `/dev/shm`, use of `ptrace`/`setuid` syscalls by non-root, excessive failed login attempts, unauthorized sudo usage, known ransomware file extensions created, anomalous process tree depth.

Combined, provides the rule-based baseline comparison (~89% accuracy).

### 3b. Random Forest Classifier (`random_forest.rs`)

Using `smartcore::ensemble::random_forest_classifier::RandomForestClassifier`.

```rust
pub struct RFModel {
    model: Option<RandomForestClassifier<f64, u32, DenseMatrix<f64>, Vec<u32>>>,
}
```

Hyperparameters (matching writeup): **100 trees, max depth 20, min samples split 5**.

Convert between `ndarray::Array2` and `smartcore::DenseMatrix` for interop. Support serialization with `bincode` for model persistence.

### 3c. LSTM Model (`lstm.rs`)

Using `burn` with `burn-ndarray` backend (CPU).

Architecture matching writeup: **2 LSTM layers (128, 64 units), dropout 0.3, dense output with softmax (5 classes)**.

```rust
#[derive(Module, Debug)]
pub struct IdsLstmModel<B: Backend> {
    lstm1: Lstm<B>,          // input -> 128 hidden
    lstm2: Lstm<B>,          // 128 -> 64 hidden
    dropout: Dropout,
    fc: Linear<B>,           // 64 -> 5 classes
}
```

Training: Adam optimizer, learning rate 0.001, batch size 64, ~30 epochs, early stopping with patience of 5 epochs on validation loss.

**Sequence handling:** NSL-KDD records are independent connections. Use seq_len=1 (each record is a single-step sequence through the LSTM). Document this design choice.

### 3d. Isolation Forest (`isolation_forest.rs`)

Custom implementation (~200 lines):

```rust
pub struct IsolationForest {
    trees: Vec<IsolationTree>,
    n_samples: usize,
    contamination: f64,   // expected anomaly fraction
    threshold: f64,        // computed after fitting
}
```

Anomaly score based on average path length to isolate a point. Anomalies have shorter paths. Does not use labels during training (unsupervised).

### 3e. Ensemble Combiner (`ensemble.rs`)

Weighted voting combining all three models:

```rust
pub struct EnsembleDetector {
    pub rf_weight: f64,        // 0.35
    pub lstm_weight: f64,      // 0.40
    pub iforest_weight: f64,   // 0.25
}
```

Weighted average of RF and LSTM class probabilities. Isolation Forest anomaly score used to escalate uncertain predictions.

### 3f. Evaluation (`evaluate.rs`)

```rust
pub struct ClassificationReport {
    pub accuracy: f64,
    pub precision_per_class: Vec<f64>,
    pub recall_per_class: Vec<f64>,
    pub f1_per_class: Vec<f64>,
    pub macro_precision: f64,
    pub macro_recall: f64,
    pub macro_f1: f64,
    pub fpr: f64,
    pub confusion_matrix: Array2<usize>,  // 5x5
}
```

Also implements 5-fold cross-validation runner.

### Target Benchmarks

| Model | Accuracy | Precision | Recall | F1-Score |
|-------|----------|-----------|--------|----------|
| Random Forest | 97.8% | 96.5% | 98.2% | 97.3% |
| LSTM | 98.2% | 97.1% | 98.5% | 97.8% |
| Ensemble | 98.6% | 97.8% | 98.7% | 98.2% |
| Rule-based | 89.3% | 95.2% | 82.1% | 88.2% |

### Dependencies

```toml
[dependencies]
ids-common = { path = "../ids-common" }
ids-preprocess = { path = "../ids-preprocess" }
smartcore = "0.4"
burn = "0.16"
burn-ndarray = "0.16"
ndarray = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
bincode = "1"
rand = "0.8"
tracing = { workspace = true }
anyhow = { workspace = true }
```

---

## Phase 4: Response Module (`ids-response`)

**Goal:** Generate alerts, optionally take prevention actions (IPS mode for both network and host), and output to SIEM-compatible formats.

### Components

**`alerter.rs`** — Converts detection results into structured alerts:

```rust
pub struct Alert {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,          // Low, Medium, High, Critical
    pub category: AttackCategory,    // Normal, DoS, Probe, R2L, U2R, Unknown
    pub source: AlertSource,         // Network or Host
    pub description: String,
    pub confidence: f64,
    pub model_source: String,
    // Network-specific (populated for NIDS alerts)
    pub source_ip: Option<IpAddr>,
    pub dest_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub dest_port: Option<u16>,
    // Host-specific (populated for HIDS alerts)
    pub hostname: Option<String>,
    pub pid: Option<u32>,
    pub affected_path: Option<PathBuf>,
    pub username: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AlertSource { Network, Host }
```

Severity mapping: DoS/U2R -> Critical, Probe -> High, R2L -> Medium. File integrity violations on critical paths -> Critical. Privilege escalation -> Critical. Confidence < 0.7 downgrades by one level.

**`blocker.rs`** — IPS prevention actions for both subsystems. Defaults to `enabled: false`.

*Network (NIPS):* Shells out to `iptables` to drop traffic from malicious IPs. Auto-unblocks after configurable duration.

*Host (HIPS):* Process termination via `kill` for detected malicious processes. File quarantine by moving suspicious files to a quarantine directory and revoking permissions. Optional: restore modified files from baseline hashes.

**`siem.rs`** — Output alerts in CEF (Common Event Format) for SIEM integration. Also supports syslog output (UDP).

**`logger.rs`** — Structured JSON logging of all alerts to `logs/alerts.jsonl` using `tracing` with JSON formatter.

### Dependencies

```toml
[dependencies]
ids-common = { path = "../ids-common" }
tokio = { workspace = true }
uuid = { version = "1", features = ["v4"] }
chrono = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true, features = ["json"] }
anyhow = { workspace = true }
```

---

## Phase 5: Management Interface (`ids-dashboard`)

**Goal:** Web-based dashboard for real-time monitoring, configuration, and model management.

### Components

**`main.rs`** — Axum HTTP server on port 8080. Serves static files and API.

**`routes.rs`** — REST API endpoints:
- `GET /api/alerts` — paginated alert list with filters (severity, category, time range)
- `GET /api/alerts/:id` — single alert detail
- `GET /api/stats` — aggregated statistics (alerts/hour, top attack types, top source IPs)
- `GET /api/models` — trained models with evaluation metrics
- `POST /api/models/:name/retrain` — trigger model retraining
- `GET /api/rules` / `POST /api/rules` / `DELETE /api/rules/:id` — rule management
- `GET /api/config` / `PUT /api/config` — system configuration

**`ws.rs`** — WebSocket endpoint at `/ws/alerts` broadcasting new alerts in real time via `tokio::sync::broadcast`.

**`static/index.html`** — Single-page dashboard (vanilla HTML/JS + Chart.js from CDN):
- Real-time alert feed via WebSocket (tagged as Network or Host source)
- Statistics cards (total alerts, by severity, detection rate, split by NIDS/HIDS)
- Alerts-over-time chart (with network vs. host series)
- Model performance table
- System status indicator (showing which collectors are active: network capture, file integrity, process monitor, log watcher)

### Shared Application State

```rust
pub struct AppState {
    pub alerts: Arc<RwLock<Vec<Alert>>>,
    pub alert_tx: broadcast::Sender<Alert>,
    pub rules: Arc<RwLock<Vec<DetectionRule>>>,
    pub config: Arc<RwLock<SystemConfig>>,
    pub model_metrics: Arc<RwLock<HashMap<String, ClassificationReport>>>,
}
```

### Dependencies

```toml
[dependencies]
ids-common = { path = "../ids-common" }
ids-engine = { path = "../ids-engine" }
ids-response = { path = "../ids-response" }
axum = { version = "0.8", features = ["ws"] }
tokio = { workspace = true }
tower-http = { version = "0.6", features = ["fs", "cors"] }
serde = { workspace = true }
serde_json = { workspace = true }
chrono = { workspace = true }
tracing = { workspace = true }
uuid = { version = "1", features = ["v4"] }
```

---

## Phase 6: Integration and Testing

**Goal:** Wire all modules together with an async pipeline and test against the VulnShop application.

### Pipeline Architecture

Both NIDS and HIDS collectors feed into a unified pipeline via `tokio::sync::mpsc` channels:

```
network_capture_tx ─┐
                    ├─> event_rx (SecurityEvent) ─> preprocess ─> engine ─> response
host_monitors_tx  ──┘      (unified stream)       (features)   (detect)   (alerts)
                                                                              |
                                                                         broadcast_tx
                                                                              |
                                                                    dashboard WebSocket
```

### Main Binary Flow

1. Load config from `config.toml`
2. Initialize logging (`tracing_subscriber`)
3. Load trained models from disk
4. Start **network** collector (packet capture or PCAP replay) in background task
5. Start **host** collectors (file integrity, process monitor, syscall monitor, log watcher) in background tasks
6. Start preprocessing pipeline (accepts `SecurityEvent`, outputs feature vectors)
7. Start detection engine (runs ensemble on features)
8. Start response module (alert routing, optional NIPS/HIPS actions)
9. Start dashboard web server
10. Signal handling for graceful shutdown

### Configuration (`config.toml`)

```toml
[network]
enabled = true
interface = "lo"
pcap_file = ""                          # set to replay a PCAP instead of live capture

[host]
enabled = true

[host.file_integrity]
enabled = true
watch_paths = ["/etc", "/usr/bin", "/home"]
baseline_on_startup = true

[host.process_monitor]
enabled = true
poll_interval_secs = 2
whitelist_paths = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]

[host.syscall_monitor]
enabled = false                         # requires auditd; disabled by default
audit_log_path = "/var/log/audit/audit.log"

[host.log_watcher]
enabled = true
log_paths = ["/var/log/auth.log", "/var/log/syslog"]

[preprocessing]
normalization = "min-max"
window_size = 1

[detection]
mode = "ids"                            # "ids" or "ips"
ensemble_weights = { rf = 0.35, lstm = 0.40, iforest = 0.25 }
confidence_threshold = 0.5

[response]
nips_enabled = false                    # network blocking via iptables
hips_enabled = false                    # host actions (process kill, file quarantine)
block_duration_secs = 300
quarantine_dir = "/var/ids/quarantine"
siem_host = ""
siem_port = 514
log_file = "logs/alerts.jsonl"

[dashboard]
port = 8080
host = "127.0.0.1"

[models]
rf_path = "data/models/random_forest.bin"
lstm_path = "data/models/lstm_model"
iforest_path = "data/models/isolation_forest.bin"
scaler_path = "data/models/scaler.json"
```

### Integration Test with VulnShop (NIDS)

The existing VulnShop application (`website/`) provides a network test target:

1. Start VulnShop on port 3000
2. Start IDS monitoring the loopback interface
3. Send normal HTTP requests (browsing products, login)
4. Send malicious requests (SQL injection via `/api/login`, command injection via `/api/ping`, DoS simulation)
5. Verify the NIDS detects and alerts on malicious traffic
6. If NIPS mode enabled, verify blocking of subsequent malicious requests

### Integration Test for HIDS

Simulate host-based attacks in a controlled environment:

1. Start IDS with file integrity and process monitoring enabled
2. Create/modify files in a watched directory — verify `FileChange` alerts
3. Spawn a process from `/tmp` — verify suspicious process alert
4. Simulate brute-force SSH by writing fake auth.log entries — verify log-based alert
5. If HIPS mode enabled, verify malicious process is terminated and file is quarantined

### Unit Tests

- **ids-preprocess:** CSV parsing, normalization (known input -> known output), SMOTE (verify output dimensions)
- **ids-collector:** File integrity hash computation, process snapshot diffing, log line parsing
- **ids-engine:** Rule matching (both network and host rules), model prediction on known data, evaluation metric calculations
- **ids-response:** Alert generation (network + host variants), CEF format correctness, quarantine path handling

---

## Phase 7: Evaluation and Benchmarking

**Goal:** Produce evaluation results, confusion matrices, and model comparison.

### Steps

1. **Train all models** on NSL-KDD training set:
   ```bash
   cargo run --release -p ids-engine -- train --dataset data/nsl-kdd/KDDTrain+.txt --model rf
   cargo run --release -p ids-engine -- train --dataset data/nsl-kdd/KDDTrain+.txt --model lstm --epochs 30
   cargo run --release -p ids-engine -- train --dataset data/nsl-kdd/KDDTrain+.txt --model iforest
   ```

2. **Evaluate each model** on test set and print `ClassificationReport`.

3. **Run 5-fold cross-validation** on training data, report mean/std of metrics.

4. **Rule-based baseline comparison** using the rule engine as proxy for traditional IDS.

5. **Generate output artifacts:**
   - `results/metrics_table.md` — comparison table
   - `results/confusion_matrix_rf.csv` — 5x5 confusion matrix
   - `results/confusion_matrix_lstm.csv`
   - `results/confusion_matrix_ensemble.csv`
   - `results/training_loss_curve.csv` — LSTM loss per epoch
   - `results/feature_importance_rf.csv` — top 20 features by RF importance

---

## Recommended Build Order

Build in this order to get working results as early as possible:

| Step | What | Why |
|------|------|-----|
| 1 | Phase 0 (setup) | Foundation |
| 2 | Phase 2 (preprocessing + CSV/dataset loaders) | Models need data |
| 3 | Phase 3b (Random Forest) + Phase 3f (evaluation) | First working ML pipeline end-to-end |
| 4 | Phase 3c (LSTM) + Phase 3d (Isolation Forest) | Additional models |
| 5 | Phase 3e (ensemble) + Phase 3a (rules — network + host) | Combiner + baseline |
| 6 | Phase 7 (benchmarking) | Results for writeup |
| 7 | Phase 1a (network collector) + Phase 1b (host collectors) | Both data sources |
| 8 | Phase 4 (response — NIPS + HIPS actions) | Prevention capability |
| 9 | Phase 5 (dashboard) + Phase 6 (integration) | UI and full pipeline wiring |

---

## Potential Pitfalls and Mitigations

| Pitfall | Mitigation |
|---------|-----------|
| `smartcore` compilation issues | Fall back to `linfa-ensemble` or `rustlearn` for Random Forest |
| `burn` LSTM slow on CPU | Limit to 20-30 epochs; use smaller data subset during development |
| NSL-KDD categorical encoding expands features to ~122 | Ensure all models handle this dimensionality; document feature count |
| LSTM with seq_len=1 | Acceptable for NSL-KDD (independent records); document the choice |
| `pnet` needs root for live capture | Use PCAP replay for development; only demonstrate live capture if feasible |
| Snort comparison too complex to set up | Use the rule-based engine as proxy; writeup already labels it "Snort (Rule-based)" |
| HIDS syscall monitoring needs auditd | Default to disabled; fall back to log watching which works without special setup |
| Combined feature vector is sparse | Network-only events have zero host features and vice versa; models handle this via the training data containing both types |
| HIPS process kill is destructive | Default to `hips_enabled = false`; require explicit opt-in; always log before acting |
| File integrity baseline takes time on large dirs | Limit watched paths to critical directories; compute baseline async on startup |

---

## Crate Documentation References

- **pnet:** https://docs.rs/pnet/latest/pnet/
- **smartcore:** https://docs.rs/smartcore/latest/smartcore/
- **linfa:** https://rust-ml.github.io/linfa/
- **burn:** https://docs.rs/burn/latest/burn/
- **csv:** https://docs.rs/csv/latest/csv/
- **ndarray:** https://docs.rs/ndarray/latest/ndarray/
- **axum:** https://docs.rs/axum/latest/axum/
- **NSL-KDD dataset:** https://www.unb.ca/cic/datasets/nsl.html
