use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub network: NetworkConfig,
    pub host: HostConfig,
    pub preprocessing: PreprocessingConfig,
    pub detection: DetectionConfig,
    pub response: ResponseConfig,
    pub dashboard: DashboardConfig,
    pub models: ModelPaths,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub enabled: bool,
    pub interface: String,
    pub pcap_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfig {
    pub enabled: bool,
    pub file_integrity: FileIntegrityConfig,
    pub process_monitor: ProcessMonitorConfig,
    pub syscall_monitor: SyscallMonitorConfig,
    pub log_watcher: LogWatcherConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIntegrityConfig {
    pub enabled: bool,
    pub watch_paths: Vec<PathBuf>,
    pub baseline_on_startup: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMonitorConfig {
    pub enabled: bool,
    pub poll_interval_secs: u64,
    pub whitelist_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallMonitorConfig {
    pub enabled: bool,
    pub audit_log_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogWatcherConfig {
    pub enabled: bool,
    pub log_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreprocessingConfig {
    pub normalization: String,
    pub window_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    pub mode: String,
    pub ensemble_weights: EnsembleWeights,
    pub confidence_threshold: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnsembleWeights {
    pub rf: f64,
    pub lstm: f64,
    pub iforest: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseConfig {
    pub nips_enabled: bool,
    pub hips_enabled: bool,
    pub block_duration_secs: u64,
    pub quarantine_dir: PathBuf,
    pub siem_host: Option<String>,
    pub siem_port: u16,
    pub log_file: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    pub port: u16,
    pub host: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPaths {
    pub rf_path: PathBuf,
    pub lstm_path: PathBuf,
    pub iforest_path: PathBuf,
    pub scaler_path: PathBuf,
}

impl AppConfig {
    pub fn load(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: AppConfig = toml::from_str(&content)?;
        Ok(config)
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig {
                enabled: true,
                interface: "lo".into(),
                pcap_file: None,
            },
            host: HostConfig {
                enabled: true,
                file_integrity: FileIntegrityConfig {
                    enabled: true,
                    watch_paths: vec![PathBuf::from("/etc"), PathBuf::from("/usr/bin")],
                    baseline_on_startup: true,
                },
                process_monitor: ProcessMonitorConfig {
                    enabled: true,
                    poll_interval_secs: 2,
                    whitelist_paths: vec![
                        PathBuf::from("/usr/bin"),
                        PathBuf::from("/usr/sbin"),
                        PathBuf::from("/bin"),
                        PathBuf::from("/sbin"),
                    ],
                },
                syscall_monitor: SyscallMonitorConfig {
                    enabled: false,
                    audit_log_path: PathBuf::from("/var/log/audit/audit.log"),
                },
                log_watcher: LogWatcherConfig {
                    enabled: true,
                    log_paths: vec![
                        PathBuf::from("/var/log/auth.log"),
                        PathBuf::from("/var/log/syslog"),
                    ],
                },
            },
            preprocessing: PreprocessingConfig {
                normalization: "min-max".into(),
                window_size: 1,
            },
            detection: DetectionConfig {
                mode: "ids".into(),
                ensemble_weights: EnsembleWeights {
                    rf: 0.35,
                    lstm: 0.40,
                    iforest: 0.25,
                },
                confidence_threshold: 0.5,
            },
            response: ResponseConfig {
                nips_enabled: false,
                hips_enabled: false,
                block_duration_secs: 300,
                quarantine_dir: PathBuf::from("/var/ids/quarantine"),
                siem_host: None,
                siem_port: 514,
                log_file: PathBuf::from("logs/alerts.jsonl"),
            },
            dashboard: DashboardConfig {
                port: 8080,
                host: "127.0.0.1".into(),
            },
            models: ModelPaths {
                rf_path: PathBuf::from("data/models/random_forest.bin"),
                lstm_path: PathBuf::from("data/models/lstm_model"),
                iforest_path: PathBuf::from("data/models/isolation_forest.bin"),
                scaler_path: PathBuf::from("data/models/scaler.json"),
            },
        }
    }
}
