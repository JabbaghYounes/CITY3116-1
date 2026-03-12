use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;
use chrono::Utc;
use sysinfo::{Pid, System};
use tokio::sync::mpsc;
use tokio::time::{self, Duration};
use tracing::{debug, info, trace};

use ids_common::config::ProcessMonitorConfig;
use ids_common::types::{HostEvent, ProcessEvent, ProcessEventType, SecurityEvent};

/// Tracks running processes and detects spawns / terminations.
///
/// Uses the `sysinfo` crate to periodically poll the process table. On each
/// poll it compares the current set of PIDs to the previously known set and
/// emits `ProcessEvent` records for new and terminated processes. If a
/// process's executable path is not covered by the configured whitelist it is
/// flagged accordingly.
pub struct ProcessMonitor {
    config: ProcessMonitorConfig,
    system: System,
    /// Map from PID to the executable path seen on the last poll.
    known_pids: HashMap<Pid, ProcessSnapshot>,
}

/// Lightweight snapshot of a process at the time it was first observed.
#[derive(Debug, Clone)]
struct ProcessSnapshot {
    name: String,
    exe_path: PathBuf,
    pid: u32,
    ppid: u32,
    uid: u32,
}

impl ProcessMonitor {
    /// Create a new process monitor.
    pub fn new(config: ProcessMonitorConfig) -> Self {
        Self {
            config,
            system: System::new_all(),
            known_pids: HashMap::new(),
        }
    }

    /// Run the polling loop, emitting events through `tx`.
    pub async fn start(mut self, tx: mpsc::Sender<SecurityEvent>) -> Result<()> {
        let interval = Duration::from_secs(self.config.poll_interval_secs);
        info!(
            interval_secs = self.config.poll_interval_secs,
            "Process monitor starting"
        );

        // Initial snapshot — record everything currently running without
        // emitting events, so we only fire for *changes*.
        self.system.refresh_all();
        for (pid, proc_info) in self.system.processes() {
            self.known_pids.insert(
                *pid,
                snapshot_process(proc_info),
            );
        }
        info!(
            known_count = self.known_pids.len(),
            "Initial process snapshot captured"
        );

        let mut ticker = time::interval(interval);
        loop {
            ticker.tick().await;
            self.system.refresh_all();

            let current_pids: HashMap<Pid, ProcessSnapshot> = self
                .system
                .processes()
                .iter()
                .map(|(pid, p)| (*pid, snapshot_process(p)))
                .collect();

            // Detect newly spawned processes.
            for (pid, snap) in &current_pids {
                if !self.known_pids.contains_key(pid) {
                    let whitelisted = self.is_whitelisted(&snap.exe_path);
                    let proc_info = self.system.process(*pid);
                    let cpu_usage = proc_info.map_or(0.0, |p| p.cpu_usage());
                    let memory_bytes = proc_info.map_or(0, |p| p.memory());

                    let event = ProcessEvent {
                        timestamp: Utc::now(),
                        pid: snap.pid,
                        ppid: snap.ppid,
                        name: snap.name.clone(),
                        exe_path: snap.exe_path.clone(),
                        uid: snap.uid,
                        event_type: ProcessEventType::Spawned,
                        cpu_usage,
                        memory_bytes,
                    };

                    if !whitelisted {
                        debug!(
                            pid = snap.pid,
                            name = %snap.name,
                            exe = %snap.exe_path.display(),
                            "Non-whitelisted process spawned"
                        );
                    } else {
                        trace!(
                            pid = snap.pid,
                            name = %snap.name,
                            "Process spawned"
                        );
                    }

                    if tx
                        .send(SecurityEvent::Host(HostEvent::ProcessActivity(event)))
                        .await
                        .is_err()
                    {
                        debug!("Receiver dropped — stopping process monitor");
                        return Ok(());
                    }
                }
            }

            // Detect terminated processes.
            for (pid, snap) in &self.known_pids {
                if !current_pids.contains_key(pid) {
                    let event = ProcessEvent {
                        timestamp: Utc::now(),
                        pid: snap.pid,
                        ppid: snap.ppid,
                        name: snap.name.clone(),
                        exe_path: snap.exe_path.clone(),
                        uid: snap.uid,
                        event_type: ProcessEventType::Terminated,
                        cpu_usage: 0.0,
                        memory_bytes: 0,
                    };

                    trace!(
                        pid = snap.pid,
                        name = %snap.name,
                        "Process terminated"
                    );

                    if tx
                        .send(SecurityEvent::Host(HostEvent::ProcessActivity(event)))
                        .await
                        .is_err()
                    {
                        debug!("Receiver dropped — stopping process monitor");
                        return Ok(());
                    }
                }
            }

            self.known_pids = current_pids;
        }
    }

    /// Check whether an executable path falls under one of the whitelisted
    /// directories.
    fn is_whitelisted(&self, exe_path: &PathBuf) -> bool {
        self.config
            .whitelist_paths
            .iter()
            .any(|allowed| exe_path.starts_with(allowed))
    }
}

/// Build a lightweight snapshot from a `sysinfo::Process`.
fn snapshot_process(proc_info: &sysinfo::Process) -> ProcessSnapshot {
    let pid = proc_info.pid().as_u32();

    let ppid = proc_info
        .parent()
        .map(|p| p.as_u32())
        .unwrap_or(0);

    let uid = {
        #[cfg(unix)]
        {
            proc_info
                .user_id()
                .map(|u| **u)
                .unwrap_or(0)
        }
        #[cfg(not(unix))]
        {
            0u32
        }
    };

    ProcessSnapshot {
        name: proc_info.name().to_string_lossy().to_string(),
        exe_path: proc_info.exe().map(|p| p.to_path_buf()).unwrap_or_default(),
        pid,
        ppid,
        uid,
    }
}
