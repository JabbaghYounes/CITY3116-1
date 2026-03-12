use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::Utc;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

use ids_common::config::LogWatcherConfig;
use ids_common::types::{HostEvent, LogEvent, LogSeverity, SecurityEvent};

/// Watches system log files (e.g. auth.log, syslog) for security-relevant
/// entries such as failed logins, sudo usage, service starts/stops, and
/// SSH events.
///
/// Each configured log path is tailed concurrently. Parsed lines are sent
/// as `LogEvent` records through the provided channel.
pub struct LogWatcher {
    config: LogWatcherConfig,
}

impl LogWatcher {
    pub fn new(config: LogWatcherConfig) -> Self {
        Self { config }
    }

    /// Start tailing all configured log files concurrently.
    pub async fn start(self, tx: mpsc::Sender<SecurityEvent>) -> Result<()> {
        info!(
            log_count = self.config.log_paths.len(),
            "Log watcher starting"
        );

        let mut handles = Vec::new();
        for path in self.config.log_paths.clone() {
            let tx = tx.clone();
            let handle = tokio::spawn(async move {
                if let Err(e) = tail_log_file(path.clone(), tx).await {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "Log watcher task failed"
                    );
                }
            });
            handles.push(handle);
        }

        // Wait for all tailers to finish (they run indefinitely).
        for handle in handles {
            let _ = handle.await;
        }

        Ok(())
    }
}

/// Tail a single log file, parsing each new line and sending events.
async fn tail_log_file(path: PathBuf, tx: mpsc::Sender<SecurityEvent>) -> Result<()> {
    info!(path = %path.display(), "Tailing log file");

    let file = File::open(&path)
        .await
        .with_context(|| format!("Failed to open log file: {}", path.display()))?;

    let mut reader = BufReader::new(file);
    // Seek to end so we only see new entries.
    reader.seek(std::io::SeekFrom::End(0)).await?;

    let source = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string());

    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                // No new data — brief sleep then retry.
                tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
                continue;
            }
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                if let Some(event) = parse_log_line(trimmed, &source) {
                    trace!(
                        source = %source,
                        severity = ?event.severity,
                        "Log event captured"
                    );
                    if tx
                        .send(SecurityEvent::Host(HostEvent::LogEntry(event)))
                        .await
                        .is_err()
                    {
                        debug!("Receiver dropped — stopping log watcher for {}", source);
                        return Ok(());
                    }
                }
            }
            Err(e) => {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "Error reading log line"
                );
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
    }
}

/// Parse a syslog-style line and return a `LogEvent` if it matches any
/// security-relevant pattern.
///
/// Patterns detected:
/// - Failed authentication (`authentication failure`, `Failed password`)
/// - Successful sudo usage
/// - SSH session open/close
/// - Account/group modifications (useradd, usermod, userdel, groupadd)
/// - Service start/stop/restart
/// - Segfaults and OOM kills
fn parse_log_line(line: &str, source: &str) -> Option<LogEvent> {
    let lower = line.to_lowercase();

    let mut parsed_fields = HashMap::new();

    // Try to extract the process/daemon name from a typical syslog line:
    //   "Feb 10 12:34:56 hostname daemon[1234]: message"
    if let Some(msg_start) = line.find(": ") {
        let prefix = &line[..msg_start];
        // Daemon name is the last whitespace-separated token before the colon.
        if let Some(daemon) = prefix.split_whitespace().last() {
            // Strip the [pid] suffix if present.
            let daemon_name = daemon.split('[').next().unwrap_or(daemon);
            parsed_fields.insert("daemon".to_string(), daemon_name.to_string());
        }
    }

    // --------------- Failed authentication ---------------
    if lower.contains("authentication failure")
        || lower.contains("failed password")
        || lower.contains("auth failure")
        || lower.contains("invalid user")
    {
        // Try to extract the username.
        if let Some(user) = extract_user_from_line(&lower) {
            parsed_fields.insert("username".to_string(), user);
        }
        // Try to extract source IP.
        if let Some(ip) = extract_ip_from_line(line) {
            parsed_fields.insert("source_ip".to_string(), ip);
        }

        return Some(LogEvent {
            timestamp: Utc::now(),
            source: source.to_string(),
            severity: LogSeverity::Warning,
            message: line.to_string(),
            parsed_fields,
        });
    }

    // --------------- Sudo usage ---------------
    if lower.contains("sudo") && (lower.contains("command=") || lower.contains("session opened"))
    {
        if let Some(user) = extract_user_from_line(&lower) {
            parsed_fields.insert("username".to_string(), user);
        }
        // Extract the command if present.
        if let Some(cmd_start) = lower.find("command=") {
            let cmd = &line[cmd_start + 8..];
            let cmd = cmd.split(';').next().unwrap_or(cmd).trim();
            parsed_fields.insert("command".to_string(), cmd.to_string());
        }

        return Some(LogEvent {
            timestamp: Utc::now(),
            source: source.to_string(),
            severity: LogSeverity::Info,
            message: line.to_string(),
            parsed_fields,
        });
    }

    // --------------- SSH sessions ---------------
    if lower.contains("sshd") && (lower.contains("session opened") || lower.contains("accepted")) {
        if let Some(user) = extract_user_from_line(&lower) {
            parsed_fields.insert("username".to_string(), user);
        }
        if let Some(ip) = extract_ip_from_line(line) {
            parsed_fields.insert("source_ip".to_string(), ip);
        }
        parsed_fields.insert("event".to_string(), "ssh_session".to_string());

        return Some(LogEvent {
            timestamp: Utc::now(),
            source: source.to_string(),
            severity: LogSeverity::Info,
            message: line.to_string(),
            parsed_fields,
        });
    }

    if lower.contains("sshd") && lower.contains("session closed") {
        parsed_fields.insert("event".to_string(), "ssh_session_closed".to_string());

        return Some(LogEvent {
            timestamp: Utc::now(),
            source: source.to_string(),
            severity: LogSeverity::Debug,
            message: line.to_string(),
            parsed_fields,
        });
    }

    // --------------- Account modifications ---------------
    if lower.contains("useradd")
        || lower.contains("usermod")
        || lower.contains("userdel")
        || lower.contains("groupadd")
        || lower.contains("passwd")
    {
        return Some(LogEvent {
            timestamp: Utc::now(),
            source: source.to_string(),
            severity: LogSeverity::Warning,
            message: line.to_string(),
            parsed_fields,
        });
    }

    // --------------- Service changes ---------------
    if lower.contains("systemd") && (lower.contains("started") || lower.contains("stopped")) {
        return Some(LogEvent {
            timestamp: Utc::now(),
            source: source.to_string(),
            severity: LogSeverity::Info,
            message: line.to_string(),
            parsed_fields,
        });
    }

    // --------------- Kernel-level events ---------------
    if lower.contains("segfault") || lower.contains("oom-killer") || lower.contains("out of memory")
    {
        return Some(LogEvent {
            timestamp: Utc::now(),
            source: source.to_string(),
            severity: LogSeverity::Error,
            message: line.to_string(),
            parsed_fields,
        });
    }

    // Not a security-relevant line.
    None
}

/// Try to extract a username from common syslog patterns.
fn extract_user_from_line(lower: &str) -> Option<String> {
    // "for user <name>" or "for <name>"
    for prefix in &["for user ", "for invalid user "] {
        if let Some(idx) = lower.find(prefix) {
            let rest = &lower[idx + prefix.len()..];
            let user = rest.split_whitespace().next()?;
            return Some(user.to_string());
        }
    }
    // "user=<name>"
    if let Some(idx) = lower.find("user=") {
        let rest = &lower[idx + 5..];
        let user = rest.split(|c: char| c.is_whitespace() || c == ';' || c == ')').next()?;
        if !user.is_empty() {
            return Some(user.to_string());
        }
    }
    // "for <name> from"
    if let Some(idx) = lower.find("for ") {
        let rest = &lower[idx + 4..];
        let user = rest.split_whitespace().next()?;
        if user != "invalid" {
            return Some(user.to_string());
        }
    }
    None
}

/// Try to extract an IP address from a log line.
fn extract_ip_from_line(line: &str) -> Option<String> {
    // "from <IP>" pattern
    if let Some(idx) = line.find("from ") {
        let rest = &line[idx + 5..];
        let candidate = rest.split_whitespace().next()?;
        if candidate.parse::<std::net::IpAddr>().is_ok() {
            return Some(candidate.to_string());
        }
    }
    // "rhost=<IP>" pattern
    if let Some(idx) = line.find("rhost=") {
        let rest = &line[idx + 6..];
        let candidate = rest.split(|c: char| c.is_whitespace() || c == ';').next()?;
        if candidate.parse::<std::net::IpAddr>().is_ok() {
            return Some(candidate.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_failed_password() {
        let line = "Feb 10 12:00:00 server sshd[1234]: Failed password for user admin from 192.168.1.100 port 22 ssh2";
        let event = parse_log_line(line, "auth.log").expect("should parse");
        assert_eq!(event.severity, LogSeverity::Warning);
        assert_eq!(
            event.parsed_fields.get("username"),
            Some(&"admin".to_string())
        );
        assert_eq!(
            event.parsed_fields.get("source_ip"),
            Some(&"192.168.1.100".to_string())
        );
    }

    #[test]
    fn test_sudo_command() {
        let line = "Feb 10 12:00:00 server sudo[5678]:   admin : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/apt update";
        let event = parse_log_line(line, "auth.log").expect("should parse");
        assert_eq!(event.severity, LogSeverity::Info);
    }

    #[test]
    fn test_uninteresting_line() {
        let line = "Feb 10 12:00:00 server kernel: [12345.678] NET: Registered protocol family 2";
        assert!(parse_log_line(line, "syslog").is_none());
    }

    #[test]
    fn test_useradd() {
        let line = "Feb 10 12:00:00 server useradd[999]: new user: name=testuser, UID=1001, GID=1001";
        let event = parse_log_line(line, "auth.log").expect("should parse");
        assert_eq!(event.severity, LogSeverity::Warning);
    }

    #[test]
    fn test_segfault() {
        let line = "Feb 10 12:00:00 server kernel: myapp[1234]: segfault at 0000000000000000";
        let event = parse_log_line(line, "syslog").expect("should parse");
        assert_eq!(event.severity, LogSeverity::Error);
    }
}
