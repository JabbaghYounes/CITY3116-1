use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Network IPS — block / unblock source IPs
// ---------------------------------------------------------------------------

/// Simulated network blocker that logs iptables commands it *would* run.
///
/// No commands are ever actually executed -- this is a university assignment
/// demo that only records the intent and writes `tracing::warn!` messages.
pub struct NetworkBlocker {
    blocked_ips: HashMap<IpAddr, Instant>,
    enabled: bool,
}

impl NetworkBlocker {
    pub fn new(enabled: bool) -> Self {
        Self {
            blocked_ips: HashMap::new(),
            enabled,
        }
    }

    /// Record a block for `ip`.  Logs the iptables command that *would* be
    /// executed but does **not** actually run it.
    pub async fn block_ip(&mut self, ip: IpAddr) -> Result<()> {
        if !self.enabled {
            tracing::info!("NIPS disabled — skipping block for {ip}");
            return Ok(());
        }

        tracing::warn!(
            "[NIPS-SIMULATED] Would execute: iptables -A INPUT -s {ip} -j DROP"
        );

        self.blocked_ips.insert(ip, Instant::now());

        tracing::info!("Blocked IP {ip} — total active blocks: {}", self.blocked_ips.len());
        Ok(())
    }

    /// Remove the block for `ip`.  Logs the iptables command that *would* be
    /// executed but does **not** actually run it.
    pub async fn unblock_ip(&mut self, ip: IpAddr) -> Result<()> {
        if !self.enabled {
            tracing::info!("NIPS disabled — skipping unblock for {ip}");
            return Ok(());
        }

        tracing::warn!(
            "[NIPS-SIMULATED] Would execute: iptables -D INPUT -s {ip} -j DROP"
        );

        self.blocked_ips.remove(&ip);

        tracing::info!("Unblocked IP {ip} — total active blocks: {}", self.blocked_ips.len());
        Ok(())
    }

    /// Returns `true` when `ip` is currently in the blocked set.
    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        self.blocked_ips.contains_key(ip)
    }

    /// Remove all blocks that are older than `max_age`.
    pub async fn cleanup_expired(&mut self, max_age: Duration) {
        let before = self.blocked_ips.len();
        self.blocked_ips.retain(|ip, blocked_at| {
            let expired = blocked_at.elapsed() > max_age;
            if expired {
                tracing::warn!(
                    "[NIPS-SIMULATED] Would execute: iptables -D INPUT -s {ip} -j DROP  (expired)"
                );
            }
            !expired
        });
        let removed = before - self.blocked_ips.len();
        if removed > 0 {
            tracing::info!("Expired {removed} block(s) — remaining: {}", self.blocked_ips.len());
        }
    }
}

// ---------------------------------------------------------------------------
// Host IPS — kill processes, quarantine files
// ---------------------------------------------------------------------------

/// Simulated host blocker that logs kill / quarantine commands it *would* run.
pub struct HostBlocker {
    enabled: bool,
}

impl HostBlocker {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Logs the kill command that would terminate `pid`.  Never actually
    /// executes the command.
    pub async fn kill_process(&self, pid: u32) -> Result<()> {
        if !self.enabled {
            tracing::info!("HIPS disabled — skipping kill for PID {pid}");
            return Ok(());
        }

        tracing::warn!(
            "[HIPS-SIMULATED] Would execute: kill -9 {pid}"
        );

        tracing::info!("Process {pid} marked for termination (simulated)");
        Ok(())
    }

    /// Logs the file move that would quarantine the file at `path`.  Never
    /// actually moves anything on disk.
    pub async fn quarantine_file(&self, path: &Path, quarantine_dir: &Path) -> Result<()> {
        if !self.enabled {
            tracing::info!(
                "HIPS disabled — skipping quarantine for {}",
                path.display()
            );
            return Ok(());
        }

        let dest = quarantine_dir.join(
            path.file_name()
                .context("Cannot quarantine a path with no file name")?,
        );

        tracing::warn!(
            "[HIPS-SIMULATED] Would execute: mv {} {}",
            path.display(),
            dest.display(),
        );

        tracing::info!(
            "File {} marked for quarantine to {} (simulated)",
            path.display(),
            dest.display(),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn block_and_check() {
        let mut nb = NetworkBlocker::new(true);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        assert!(!nb.is_blocked(&ip));
        nb.block_ip(ip).await.unwrap();
        assert!(nb.is_blocked(&ip));
    }

    #[tokio::test]
    async fn unblock_removes_entry() {
        let mut nb = NetworkBlocker::new(true);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        nb.block_ip(ip).await.unwrap();
        nb.unblock_ip(ip).await.unwrap();
        assert!(!nb.is_blocked(&ip));
    }

    #[tokio::test]
    async fn disabled_blocker_does_not_record() {
        let mut nb = NetworkBlocker::new(false);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        nb.block_ip(ip).await.unwrap();
        assert!(!nb.is_blocked(&ip));
    }

    #[tokio::test]
    async fn cleanup_expired_removes_old_entries() {
        let mut nb = NetworkBlocker::new(true);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));

        nb.block_ip(ip).await.unwrap();
        // With a zero-second max_age everything should be expired immediately
        // (Instant::now() elapsed > Duration::ZERO is true for any non-zero elapsed time).
        // Sleep a tiny bit to guarantee elapsed > 0.
        tokio::time::sleep(Duration::from_millis(5)).await;
        nb.cleanup_expired(Duration::ZERO).await;
        assert!(!nb.is_blocked(&ip));
    }

    #[tokio::test]
    async fn host_kill_process_ok() {
        let hb = HostBlocker::new(true);
        hb.kill_process(1234).await.unwrap();
    }

    #[tokio::test]
    async fn host_quarantine_file_ok() {
        let hb = HostBlocker::new(true);
        hb.quarantine_file(
            Path::new("/tmp/malware.bin"),
            Path::new("/var/ids/quarantine"),
        )
        .await
        .unwrap();
    }
}
