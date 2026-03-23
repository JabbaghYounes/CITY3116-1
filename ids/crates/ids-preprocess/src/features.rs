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

/// Extract a 78-element feature vector matching the CIC-IDS2017 column order.
///
/// Features that cannot be computed from live packet captures (bulk stats,
/// subflow stats, active/idle stats, TCP header/window sizes) are zero-padded.
/// The model still performs well because the most discriminative features
/// (packet counts, byte counts, IATs, flag counts) are all populated.
///
/// Column order matches `FEATURE_NAMES` in `cicids.rs`.
pub fn extract_cicids_features(flow: &FlowRecord) -> Vec<f64> {
    let duration_us = (flow.last_time - flow.start_time)
        .num_microseconds()
        .unwrap_or(0)
        .max(0) as f64;
    let duration_secs = duration_us / 1_000_000.0;

    // Destination port
    let dst_port = flow.key.dst_port as f64;

    // Packet counts
    let total_fwd = flow.fwd_packet_count as f64;
    let total_bwd = flow.bwd_packet_count as f64;
    let total_fwd_bytes = flow.fwd_byte_count as f64;
    let total_bwd_bytes = flow.bwd_byte_count as f64;

    // Per-direction packet length stats
    let fwd_sizes: Vec<f64> = flow.fwd_packet_sizes.iter().map(|&s| s as f64).collect();
    let bwd_sizes: Vec<f64> = flow.bwd_packet_sizes.iter().map(|&s| s as f64).collect();
    let (fwd_mean, fwd_std, fwd_min, fwd_max) = stats(&fwd_sizes);
    let (bwd_mean, bwd_std, bwd_min, bwd_max) = stats(&bwd_sizes);

    // Flow throughput
    let flow_bytes_per_sec = if duration_secs > 0.0 {
        (total_fwd_bytes + total_bwd_bytes) / duration_secs
    } else {
        total_fwd_bytes + total_bwd_bytes
    };
    let flow_pkts_per_sec = if duration_secs > 0.0 {
        (total_fwd + total_bwd) / duration_secs
    } else {
        total_fwd + total_bwd
    };

    // Flow IAT (all packets)
    let iats: Vec<f64> = flow.inter_arrival_times_us.iter().map(|&t| t as f64).collect();
    let (iat_mean, iat_std, iat_min, iat_max) = stats(&iats);

    // Fwd IAT
    let fwd_iats: Vec<f64> = flow.fwd_iats_us.iter().map(|&t| t as f64).collect();
    let fwd_iat_total: f64 = fwd_iats.iter().sum();
    let (fwd_iat_mean, fwd_iat_std, fwd_iat_min, fwd_iat_max) = stats(&fwd_iats);

    // Bwd IAT
    let bwd_iats: Vec<f64> = flow.bwd_iats_us.iter().map(|&t| t as f64).collect();
    let bwd_iat_total: f64 = bwd_iats.iter().sum();
    let (bwd_iat_mean, bwd_iat_std, bwd_iat_min, bwd_iat_max) = stats(&bwd_iats);

    // TCP flag counts (per-direction for PSH/URG, total for the rest)
    let (mut fwd_psh, mut bwd_psh, mut fwd_urg, mut bwd_urg) = (0u64, 0u64, 0u64, 0u64);
    let (mut fin, mut syn, mut rst, mut psh, mut ack, mut urg) =
        (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);

    // We track direction by index: first fwd_packet_count flags are forward
    let fwd_count = flow.fwd_packet_count as usize;
    for (i, f) in flow.tcp_flags_seen.iter().enumerate() {
        let is_fwd = i < fwd_count;
        if f.psh {
            psh += 1;
            if is_fwd { fwd_psh += 1; } else { bwd_psh += 1; }
        }
        if f.urg {
            urg += 1;
            if is_fwd { fwd_urg += 1; } else { bwd_urg += 1; }
        }
        if f.fin { fin += 1; }
        if f.syn { syn += 1; }
        if f.rst { rst += 1; }
        if f.ack { ack += 1; }
    }

    // Fwd/Bwd packets per second
    let fwd_pkts_per_sec = if duration_secs > 0.0 { total_fwd / duration_secs } else { total_fwd };
    let bwd_pkts_per_sec = if duration_secs > 0.0 { total_bwd / duration_secs } else { total_bwd };

    // Overall packet length stats
    let all_sizes: Vec<f64> = flow.packet_sizes.iter().map(|&s| s as f64).collect();
    let (pkt_mean, pkt_std, pkt_min, pkt_max) = stats(&all_sizes);
    let pkt_var = pkt_std * pkt_std;

    // Down/Up Ratio
    let down_up = if total_fwd > 0.0 { total_bwd / total_fwd } else { 0.0 };

    // Average segment sizes (same as mean packet length per direction)
    let avg_pkt_size = if (total_fwd + total_bwd) > 0.0 {
        (total_fwd_bytes + total_bwd_bytes) / (total_fwd + total_bwd)
    } else {
        0.0
    };

    // Subflow = same as totals (single subflow per flow in live capture)
    let subflow_fwd_pkts = total_fwd;
    let subflow_fwd_bytes = total_fwd_bytes;
    let subflow_bwd_pkts = total_bwd;
    let subflow_bwd_bytes = total_bwd_bytes;

    // 78 features in CIC-IDS2017 column order
    vec![
        dst_port,                    // 0: Destination Port
        duration_us,                 // 1: Flow Duration (microseconds)
        total_fwd,                   // 2: Total Fwd Packets
        total_bwd,                   // 3: Total Backward Packets
        total_fwd_bytes,             // 4: Total Length of Fwd Packets
        total_bwd_bytes,             // 5: Total Length of Bwd Packets
        fwd_max,                     // 6: Fwd Packet Length Max
        fwd_min,                     // 7: Fwd Packet Length Min
        fwd_mean,                    // 8: Fwd Packet Length Mean
        fwd_std,                     // 9: Fwd Packet Length Std
        bwd_max,                     // 10: Bwd Packet Length Max
        bwd_min,                     // 11: Bwd Packet Length Min
        bwd_mean,                    // 12: Bwd Packet Length Mean
        bwd_std,                     // 13: Bwd Packet Length Std
        flow_bytes_per_sec,          // 14: Flow Bytes/s
        flow_pkts_per_sec,           // 15: Flow Packets/s
        iat_mean,                    // 16: Flow IAT Mean
        iat_std,                     // 17: Flow IAT Std
        iat_max,                     // 18: Flow IAT Max
        iat_min,                     // 19: Flow IAT Min
        fwd_iat_total,               // 20: Fwd IAT Total
        fwd_iat_mean,                // 21: Fwd IAT Mean
        fwd_iat_std,                 // 22: Fwd IAT Std
        fwd_iat_max,                 // 23: Fwd IAT Max
        fwd_iat_min,                 // 24: Fwd IAT Min
        bwd_iat_total,               // 25: Bwd IAT Total
        bwd_iat_mean,                // 26: Bwd IAT Mean
        bwd_iat_std,                 // 27: Bwd IAT Std
        bwd_iat_max,                 // 28: Bwd IAT Max
        bwd_iat_min,                 // 29: Bwd IAT Min
        fwd_psh as f64,              // 30: Fwd PSH Flags
        bwd_psh as f64,              // 31: Bwd PSH Flags
        fwd_urg as f64,              // 32: Fwd URG Flags
        bwd_urg as f64,              // 33: Bwd URG Flags
        0.0,                         // 34: Fwd Header Length (not available)
        0.0,                         // 35: Bwd Header Length (not available)
        fwd_pkts_per_sec,            // 36: Fwd Packets/s
        bwd_pkts_per_sec,            // 37: Bwd Packets/s
        pkt_min,                     // 38: Min Packet Length
        pkt_max,                     // 39: Max Packet Length
        pkt_mean,                    // 40: Packet Length Mean
        pkt_std,                     // 41: Packet Length Std
        pkt_var,                     // 42: Packet Length Variance
        fin as f64,                  // 43: FIN Flag Count
        syn as f64,                  // 44: SYN Flag Count
        rst as f64,                  // 45: RST Flag Count
        psh as f64,                  // 46: PSH Flag Count
        ack as f64,                  // 47: ACK Flag Count
        urg as f64,                  // 48: URG Flag Count
        0.0,                         // 49: CWE Flag Count (not tracked)
        0.0,                         // 50: ECE Flag Count (not tracked)
        down_up,                     // 51: Down/Up Ratio
        avg_pkt_size,                // 52: Average Packet Size
        fwd_mean,                    // 53: Avg Fwd Segment Size
        bwd_mean,                    // 54: Avg Bwd Segment Size
        0.0,                         // 55: Fwd Header Length.1 (duplicate, not available)
        0.0,                         // 56: Fwd Avg Bytes/Bulk (not computable)
        0.0,                         // 57: Fwd Avg Packets/Bulk
        0.0,                         // 58: Fwd Avg Bulk Rate
        0.0,                         // 59: Bwd Avg Bytes/Bulk
        0.0,                         // 60: Bwd Avg Packets/Bulk
        0.0,                         // 61: Bwd Avg Bulk Rate
        subflow_fwd_pkts,            // 62: Subflow Fwd Packets
        subflow_fwd_bytes,           // 63: Subflow Fwd Bytes
        subflow_bwd_pkts,            // 64: Subflow Bwd Packets
        subflow_bwd_bytes,           // 65: Subflow Bwd Bytes
        0.0,                         // 66: Init_Win_bytes_forward (not tracked)
        0.0,                         // 67: Init_Win_bytes_backward (not tracked)
        0.0,                         // 68: act_data_pkt_fwd (not tracked)
        0.0,                         // 69: min_seg_size_forward (not tracked)
        0.0,                         // 70: Active Mean (not computable)
        0.0,                         // 71: Active Std
        0.0,                         // 72: Active Max
        0.0,                         // 73: Active Min
        0.0,                         // 74: Idle Mean (not computable)
        0.0,                         // 75: Idle Std
        0.0,                         // 76: Idle Max
        0.0,                         // 77: Idle Min
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
