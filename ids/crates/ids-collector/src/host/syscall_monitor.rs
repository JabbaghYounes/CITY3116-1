use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::Utc;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader, AsyncSeekExt};
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

use ids_common::config::SyscallMonitorConfig;
use ids_common::types::{HostEvent, SecurityEvent, SyscallEvent};

/// Set of syscall names that are security-relevant and worth tracking.
const MONITORED_SYSCALLS: &[&str] = &[
    "execve",
    "open",
    "openat",
    "connect",
    "chmod",
    "fchmod",
    "fchmodat",
    "setuid",
    "setgid",
    "setreuid",
    "setregid",
    "ptrace",
];

/// Monitor for Linux audit log entries.
///
/// Tails the audit log file (typically `/var/log/audit/audit.log`) produced by
/// the Linux audit subsystem, parses SYSCALL records, and emits
/// `SyscallEvent` values for security-relevant system calls.
pub struct SyscallMonitor {
    config: SyscallMonitorConfig,
}

impl SyscallMonitor {
    pub fn new(config: SyscallMonitorConfig) -> Self {
        Self { config }
    }

    /// Start tailing the audit log and sending events.
    pub async fn start(self, tx: mpsc::Sender<SecurityEvent>) -> Result<()> {
        let log_path = &self.config.audit_log_path;
        info!(path = %log_path.display(), "Syscall monitor starting — tailing audit log");

        // Wait for the log file to appear (it may not exist on all systems).
        let file = wait_for_file(log_path).await?;
        let mut reader = BufReader::new(file);

        // Seek to end so we only see new entries.
        reader.seek(std::io::SeekFrom::End(0)).await?;

        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => {
                    // No new data — brief sleep then retry (tail behaviour).
                    tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
                    continue;
                }
                Ok(_) => {
                    if let Some(event) = parse_audit_line(&line) {
                        trace!(
                            pid = event.pid,
                            syscall = %event.syscall,
                            "Audit syscall captured"
                        );
                        if tx
                            .send(SecurityEvent::Host(HostEvent::SyscallTrace(event)))
                            .await
                            .is_err()
                        {
                            debug!("Receiver dropped — stopping syscall monitor");
                            return Ok(());
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Error reading audit log line");
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
        }
    }
}

/// Wait for the audit log file to appear, retrying a few times.
async fn wait_for_file(path: &PathBuf) -> Result<File> {
    for attempt in 0..10 {
        match File::open(path).await {
            Ok(f) => return Ok(f),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if attempt == 0 {
                    info!(path = %path.display(), "Audit log not found — waiting");
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("Failed to open audit log: {}", path.display())
                });
            }
        }
    }
    anyhow::bail!(
        "Audit log {} did not appear after retries",
        path.display()
    );
}

/// Parse a single line from the Linux audit log.
///
/// Example audit SYSCALL line:
/// ```text
/// type=SYSCALL msg=audit(1700000000.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=... a1=... a2=... a3=... items=2 ppid=1234 pid=5678 auid=1000 uid=0 gid=0 ...
/// ```
///
/// We look for lines with `type=SYSCALL`, extract pid, uid, syscall number,
/// and the return code. Syscall numbers are mapped to names for the monitored
/// set on x86_64.
fn parse_audit_line(line: &str) -> Option<SyscallEvent> {
    // Only process SYSCALL records.
    if !line.contains("type=SYSCALL") {
        return None;
    }

    let fields = parse_audit_fields(line);

    // Resolve the syscall name. The audit log contains a numeric syscall
    // field; map it to a name. If SYSCALL lines include a "comm" or we
    // have direct names we can also use those.
    let syscall_str = fields.get("syscall")?;
    let syscall_name = resolve_syscall_name(syscall_str);

    // Filter to only monitored syscalls.
    if !MONITORED_SYSCALLS.contains(&syscall_name.as_str()) {
        return None;
    }

    let pid: u32 = fields.get("pid").and_then(|v| v.parse().ok()).unwrap_or(0);
    let uid: u32 = fields.get("uid").and_then(|v| v.parse().ok()).unwrap_or(0);
    let return_code: i64 = fields
        .get("exit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    // Collect argument fields (a0..a3).
    let args: Vec<String> = (0..4)
        .filter_map(|i| fields.get(&format!("a{}", i)).cloned())
        .collect();

    Some(SyscallEvent {
        timestamp: Utc::now(),
        pid,
        syscall: syscall_name,
        args,
        return_code,
        uid,
    })
}

/// Split an audit log line into key=value pairs.
fn parse_audit_fields(line: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for token in line.split_whitespace() {
        if let Some((key, value)) = token.split_once('=') {
            // Strip surrounding quotes if present.
            let value = value.trim_matches('"');
            map.insert(key.to_string(), value.to_string());
        }
    }
    map
}

/// Map x86_64 syscall numbers to names, with a fallback for already-named
/// values (some audit configurations include the name directly).
fn resolve_syscall_name(raw: &str) -> String {
    // If it's already a name (not a number), return as-is.
    if raw.parse::<u64>().is_err() {
        return raw.to_string();
    }

    // Common x86_64 syscall numbers.
    match raw {
        "2" => "open".to_string(),
        "21" => "access".to_string(),
        "42" => "connect".to_string(),
        "59" => "execve".to_string(),
        "90" => "chmod".to_string(),
        "91" => "fchmod".to_string(),
        "101" => "ptrace".to_string(),
        "105" => "setuid".to_string(),
        "106" => "setgid".to_string(),
        "113" => "setreuid".to_string(),
        "114" => "setregid".to_string(),
        "257" => "openat".to_string(),
        "268" => "fchmodat".to_string(),
        other => format!("syscall_{}", other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_execve_line() {
        let line = r#"type=SYSCALL msg=audit(1700000000.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=7f a1=7f a2=0 a3=0 items=2 ppid=1000 pid=2000 auid=1000 uid=0 gid=0 euid=0"#;
        let event = parse_audit_line(line).expect("should parse execve");
        assert_eq!(event.syscall, "execve");
        assert_eq!(event.pid, 2000);
        assert_eq!(event.uid, 0);
        assert_eq!(event.return_code, 0);
        assert_eq!(event.args.len(), 4);
    }

    #[test]
    fn test_non_syscall_line_ignored() {
        let line = "type=CWD msg=audit(1700000000.123:456): cwd=\"/root\"";
        assert!(parse_audit_line(line).is_none());
    }

    #[test]
    fn test_non_monitored_syscall_ignored() {
        // syscall 0 = read on x86_64, which is not in our monitored set
        let line = "type=SYSCALL msg=audit(1700000000.123:456): arch=c000003e syscall=0 success=yes exit=100 pid=1 uid=0";
        assert!(parse_audit_line(line).is_none());
    }
}
