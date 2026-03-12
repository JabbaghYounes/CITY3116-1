use anyhow::{Context, Result};
use ids_common::types::Alert;
use std::path::{Path, PathBuf};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Structured alert logger that appends one JSON line per alert.
pub struct AlertLogger {
    file_path: PathBuf,
}

impl AlertLogger {
    /// Create a new [`AlertLogger`] that will write to `log_file`.
    ///
    /// If the file (or its parent directory) does not yet exist the directory
    /// structure is created on first write, not at construction time, so this
    /// method never fails due to missing paths.
    pub fn new(log_file: &Path) -> Result<Self> {
        // Eagerly create parent directories so the first write succeeds.
        if let Some(parent) = log_file.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create log directory {}", parent.display()))?;
        }

        Ok(Self {
            file_path: log_file.to_path_buf(),
        })
    }

    /// Serialise `alert` as a single JSON line and append it to the log file.
    pub async fn log_alert(&mut self, alert: &Alert) -> Result<()> {
        let mut json = serde_json::to_string(alert)
            .context("Failed to serialise alert to JSON")?;
        json.push('\n');

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path)
            .await
            .with_context(|| {
                format!("Failed to open log file {}", self.file_path.display())
            })?;

        file.write_all(json.as_bytes())
            .await
            .with_context(|| {
                format!("Failed to write to log file {}", self.file_path.display())
            })?;

        file.flush().await?;

        tracing::debug!(
            alert_id = %alert.id,
            "Alert logged to {}",
            self.file_path.display()
        );

        Ok(())
    }
}

/// Initialise the global `tracing_subscriber` with a JSON formatter and an
/// environment-driven filter (respects `RUST_LOG`).
///
/// This should be called once, early in the program lifetime.  Subsequent
/// calls are silently ignored (the subscriber is already installed).
pub fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let json_layer = fmt::layer()
        .json()
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true);

    // `try_init` returns Err if a subscriber is already set — we ignore that.
    let _ = tracing_subscriber::registry()
        .with(env_filter)
        .with(json_layer)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use ids_common::types::{AlertSource, AttackCategory, Severity};
    use std::net::{IpAddr, Ipv4Addr};
    use uuid::Uuid;

    fn sample_alert() -> Alert {
        Alert {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            severity: Severity::High,
            category: AttackCategory::DoS,
            source: AlertSource::Network,
            description: "Test alert".into(),
            confidence: 0.9,
            model_source: "test".into(),
            source_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            dest_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            source_port: Some(12345),
            dest_port: Some(502),
            hostname: None,
            pid: None,
            affected_path: None,
            username: None,
        }
    }

    #[tokio::test]
    async fn log_alert_writes_json_line() {
        let dir = std::env::temp_dir().join("ids-response-test");
        let _ = std::fs::remove_dir_all(&dir);
        let log_file = dir.join("alerts.jsonl");

        let mut logger = AlertLogger::new(&log_file).unwrap();
        let alert = sample_alert();
        logger.log_alert(&alert).await.unwrap();

        let content = tokio::fs::read_to_string(&log_file).await.unwrap();
        assert!(!content.is_empty());

        // The file should contain valid JSON
        let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed["severity"], "High");

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }
}
