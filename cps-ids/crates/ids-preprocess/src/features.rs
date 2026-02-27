use ids_common::types::{
    FileChangeType, FlowRecord, HostEvent, LogSeverity, ProcessEventType,
};
use serde::{Deserialize, Serialize};

/// Indicates the origin of a feature vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventSource {
    /// Feature vector was extracted from network flow data.
    Network,
    /// Feature vector was extracted from host-level events.
    Host,
    /// Feature vector combines both network and host features.
    Combined,
}

// ---------------------------------------------------------------------------
// Suspicious syscall list (heuristic — covers common exploitation paths)
// ---------------------------------------------------------------------------
const SUSPICIOUS_SYSCALLS: &[&str] = &[
    "execve",
    "ptrace",
    "mprotect",
    "mmap",
    "fork",
    "clone",
    "setuid",
    "setgid",
    "mount",
    "umount",
    "pivot_root",
    "chroot",
    "init_module",
    "finit_module",
    "delete_module",
    "personality",
    "unshare",
    "setns",
];

/// Extract a numeric feature vector from a [`FlowRecord`].
///
/// The returned vector contains (in order):
///
/// | Index | Feature                          |
/// |------:|:---------------------------------|
/// |     0 | duration (seconds)               |
/// |     1 | total packet count               |
/// |     2 | total byte count                 |
/// |     3 | forward packet count             |
/// |     4 | backward packet count            |
/// |     5 | fwd / bwd packet ratio           |
/// |     6 | mean packet size                 |
/// |     7 | std-dev packet size              |
/// |     8 | min packet size                  |
/// |     9 | max packet size                  |
/// |    10 | mean inter-arrival time (us)     |
/// |    11 | std-dev inter-arrival time (us)  |
/// |    12 | min inter-arrival time (us)      |
/// |    13 | max inter-arrival time (us)      |
/// |    14 | bytes per second                 |
/// |    15 | packets per second               |
/// |    16 | SYN flag count                   |
/// |    17 | ACK flag count                   |
/// |    18 | FIN flag count                   |
/// |    19 | RST flag count                   |
/// |    20 | PSH flag count                   |
/// |    21 | URG flag count                   |
pub fn extract_network_features(flow: &FlowRecord) -> Vec<f64> {
    let duration_secs = (flow.last_time - flow.start_time)
        .num_milliseconds()
        .max(0) as f64
        / 1000.0;

    let pkt_count = flow.packet_count as f64;
    let byte_count = flow.byte_count as f64;
    let fwd_pkt = flow.fwd_packet_count as f64;
    let bwd_pkt = flow.bwd_packet_count as f64;
    let fwd_bwd_ratio = if bwd_pkt > 0.0 {
        fwd_pkt / bwd_pkt
    } else {
        fwd_pkt
    };

    // Packet sizes.
    let sizes: Vec<f64> = flow.packet_sizes.iter().map(|&s| s as f64).collect();
    let (mean_pkt, std_pkt, min_pkt, max_pkt) = stats(&sizes);

    // Inter-arrival times.
    let iats: Vec<f64> = flow.inter_arrival_times_us.iter().map(|&t| t as f64).collect();
    let (mean_iat, std_iat, min_iat, max_iat) = stats(&iats);

    // Throughput.
    let bytes_per_sec = if duration_secs > 0.0 {
        byte_count / duration_secs
    } else {
        byte_count
    };
    let pkts_per_sec = if duration_secs > 0.0 {
        pkt_count / duration_secs
    } else {
        pkt_count
    };

    // TCP flag counts.
    let (mut syn, mut ack, mut fin, mut rst, mut psh, mut urg) =
        (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    for f in &flow.tcp_flags_seen {
        if f.syn {
            syn += 1;
        }
        if f.ack {
            ack += 1;
        }
        if f.fin {
            fin += 1;
        }
        if f.rst {
            rst += 1;
        }
        if f.psh {
            psh += 1;
        }
        if f.urg {
            urg += 1;
        }
    }

    vec![
        duration_secs,
        pkt_count,
        byte_count,
        fwd_pkt,
        bwd_pkt,
        fwd_bwd_ratio,
        mean_pkt,
        std_pkt,
        min_pkt,
        max_pkt,
        mean_iat,
        std_iat,
        min_iat,
        max_iat,
        bytes_per_sec,
        pkts_per_sec,
        syn as f64,
        ack as f64,
        fin as f64,
        rst as f64,
        psh as f64,
        urg as f64,
    ]
}

/// Extract a numeric feature vector from a window of [`HostEvent`]s.
///
/// The returned vector contains (in order):
///
/// | Index | Feature                              |
/// |------:|:-------------------------------------|
/// |     0 | total event count                    |
/// |     1 | file-created count                   |
/// |     2 | file-modified count                  |
/// |     3 | file-deleted count                   |
/// |     4 | file-renamed count                   |
/// |     5 | process-spawned count                |
/// |     6 | process-terminated count             |
/// |     7 | process-elevated count               |
/// |     8 | unique PIDs observed                 |
/// |     9 | mean CPU usage (process events)      |
/// |    10 | max memory bytes (process events)    |
/// |    11 | suspicious syscall count             |
/// |    12 | unique suspicious syscalls           |
/// |    13 | failed syscall count (ret < 0)       |
/// |    14 | log-debug count                      |
/// |    15 | log-info count                       |
/// |    16 | log-warning count                    |
/// |    17 | log-error count                      |
/// |    18 | log-critical count                   |
/// |    19 | distinct log sources                 |
pub fn extract_host_features(events: &[HostEvent]) -> Vec<f64> {
    let total = events.len() as f64;

    let mut file_created = 0u64;
    let mut file_modified = 0u64;
    let mut file_deleted = 0u64;
    let mut file_renamed = 0u64;

    let mut proc_spawned = 0u64;
    let mut proc_terminated = 0u64;
    let mut proc_elevated = 0u64;
    let mut pids = std::collections::HashSet::<u32>::new();
    let mut cpu_usages: Vec<f64> = Vec::new();
    let mut max_mem: u64 = 0;

    let mut suspicious_count = 0u64;
    let mut suspicious_unique = std::collections::HashSet::<String>::new();
    let mut failed_syscall = 0u64;

    let mut log_debug = 0u64;
    let mut log_info = 0u64;
    let mut log_warning = 0u64;
    let mut log_error = 0u64;
    let mut log_critical = 0u64;
    let mut log_sources = std::collections::HashSet::<String>::new();

    for ev in events {
        match ev {
            HostEvent::FileChange(fc) => match fc.change_type {
                FileChangeType::Created => file_created += 1,
                FileChangeType::Modified => file_modified += 1,
                FileChangeType::Deleted => file_deleted += 1,
                FileChangeType::Renamed => file_renamed += 1,
            },
            HostEvent::ProcessActivity(p) => {
                match p.event_type {
                    ProcessEventType::Spawned => proc_spawned += 1,
                    ProcessEventType::Terminated => proc_terminated += 1,
                    ProcessEventType::Elevated => proc_elevated += 1,
                }
                pids.insert(p.pid);
                cpu_usages.push(p.cpu_usage as f64);
                if p.memory_bytes > max_mem {
                    max_mem = p.memory_bytes;
                }
            }
            HostEvent::SyscallTrace(sc) => {
                let name = sc.syscall.as_str();
                if SUSPICIOUS_SYSCALLS.contains(&name) {
                    suspicious_count += 1;
                    suspicious_unique.insert(name.to_string());
                }
                if sc.return_code < 0 {
                    failed_syscall += 1;
                }
            }
            HostEvent::LogEntry(le) => {
                match le.severity {
                    LogSeverity::Debug => log_debug += 1,
                    LogSeverity::Info => log_info += 1,
                    LogSeverity::Warning => log_warning += 1,
                    LogSeverity::Error => log_error += 1,
                    LogSeverity::Critical => log_critical += 1,
                }
                log_sources.insert(le.source.clone());
            }
        }
    }

    let mean_cpu = if cpu_usages.is_empty() {
        0.0
    } else {
        cpu_usages.iter().sum::<f64>() / cpu_usages.len() as f64
    };

    vec![
        total,
        file_created as f64,
        file_modified as f64,
        file_deleted as f64,
        file_renamed as f64,
        proc_spawned as f64,
        proc_terminated as f64,
        proc_elevated as f64,
        pids.len() as f64,
        mean_cpu,
        max_mem as f64,
        suspicious_count as f64,
        suspicious_unique.len() as f64,
        failed_syscall as f64,
        log_debug as f64,
        log_info as f64,
        log_warning as f64,
        log_error as f64,
        log_critical as f64,
        log_sources.len() as f64,
    ]
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute (mean, std, min, max) for a slice.  Returns all zeros when the
/// slice is empty.
fn stats(values: &[f64]) -> (f64, f64, f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0, 0.0, 0.0);
    }
    let n = values.len() as f64;
    let sum: f64 = values.iter().sum();
    let mean = sum / n;
    let var = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
    let std = var.sqrt();
    let min = values.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    (mean, std, min, max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_empty() {
        let (m, s, mn, mx) = stats(&[]);
        assert_eq!((m, s, mn, mx), (0.0, 0.0, 0.0, 0.0));
    }

    #[test]
    fn test_stats_single() {
        let (m, s, _mn, _mx) = stats(&[5.0]);
        assert!((m - 5.0).abs() < 1e-12);
        assert!((s - 0.0).abs() < 1e-12);
    }

    #[test]
    fn test_extract_host_features_empty() {
        let v = extract_host_features(&[]);
        assert_eq!(v.len(), 20);
        assert!(v.iter().all(|&x| x == 0.0));
    }
}
