use ids_common::types::{
    FlowRecord, HostEvent, PacketRecord, Protocol, Severity,
};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Rule types
// ---------------------------------------------------------------------------

/// Whether a rule targets network traffic or host-level events.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuleType {
    Network,
    Host,
}

/// Action to take when a rule matches.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuleAction {
    Alert,
    Drop,
    Log,
}

/// A single condition that can trigger a rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleCondition {
    /// SYN packets per second exceed the threshold.
    SynFloodRate { threshold_per_sec: f64 },
    /// Number of distinct destination ports exceeds the minimum.
    PortScanPorts { min_ports: u16 },
    /// Modbus function codes that are considered illegal.
    ModbusIllegalFunction { illegal_codes: Vec<u8> },
    /// Raw payload contains a byte pattern.
    PayloadPattern { pattern: Vec<u8> },
    /// A file on a critical path was modified.
    CriticalFileModified { paths: Vec<String> },
    /// A process was spawned from a suspicious prefix.
    SuspiciousProcess { path_prefixes: Vec<String> },
    /// Failed logins per second exceed the threshold.
    FailedLoginRate { threshold: f64 },
    /// Any privilege escalation event.
    PrivilegeEscalation,
}

/// Complete detection rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub id: u32,
    pub name: String,
    pub description: String,
    pub rule_type: RuleType,
    pub conditions: Vec<RuleCondition>,
    pub action: RuleAction,
    pub severity: Severity,
}

/// Returned when a rule fires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    pub rule_id: u32,
    pub rule_name: String,
    pub severity: Severity,
    pub description: String,
}

// ---------------------------------------------------------------------------
// Rule engine
// ---------------------------------------------------------------------------

/// Stateless rule engine that evaluates packets/flows/host events against a
/// set of detection rules.
pub struct RuleEngine {
    rules: Vec<DetectionRule>,
}

impl RuleEngine {
    pub fn new(rules: Vec<DetectionRule>) -> Self {
        Self { rules }
    }

    /// Create an engine loaded with the default CPS/IDS rule-set.
    pub fn with_defaults() -> Self {
        Self::new(default_rules())
    }

    pub fn rules(&self) -> &[DetectionRule] {
        &self.rules
    }

    // ----- network evaluation -----

    /// Evaluate a single packet + its associated flow against all network
    /// rules.  Returns every rule that matched.
    pub fn evaluate_network(
        &self,
        packet: &PacketRecord,
        flow: &FlowRecord,
    ) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        for rule in &self.rules {
            if rule.rule_type != RuleType::Network {
                continue;
            }
            if self.network_conditions_met(rule, packet, flow) {
                matches.push(RuleMatch {
                    rule_id: rule.id,
                    rule_name: rule.name.clone(),
                    severity: rule.severity,
                    description: rule.description.clone(),
                });
            }
        }
        matches
    }

    fn network_conditions_met(
        &self,
        rule: &DetectionRule,
        packet: &PacketRecord,
        flow: &FlowRecord,
    ) -> bool {
        // All conditions within a rule are ANDed together.
        rule.conditions.iter().all(|cond| match cond {
            RuleCondition::SynFloodRate { threshold_per_sec } => {
                self.check_syn_flood(flow, *threshold_per_sec)
            }
            RuleCondition::PortScanPorts { min_ports } => {
                // Heuristic: if the flow has many packets but few bytes, likely
                // a scan.  We use packet_count as a proxy for distinct ports
                // because the flow key is per (src,dst,port,proto).  A real
                // implementation would aggregate across flows; here we
                // approximate.
                flow.packet_count >= *min_ports as u64
            }
            RuleCondition::ModbusIllegalFunction { illegal_codes } => {
                self.check_modbus_illegal(packet, illegal_codes)
            }
            RuleCondition::PayloadPattern { pattern } => {
                self.check_payload_pattern(packet, pattern)
            }
            // Host-only conditions never match in a network context.
            _ => false,
        })
    }

    fn check_syn_flood(&self, flow: &FlowRecord, threshold: f64) -> bool {
        let duration_secs = (flow.last_time - flow.start_time)
            .num_milliseconds()
            .max(1) as f64
            / 1000.0;
        // Count SYN flags in the flow.
        let syn_count = flow
            .tcp_flags_seen
            .iter()
            .filter(|f| f.syn && !f.ack)
            .count() as f64;
        syn_count / duration_secs > threshold
    }

    fn check_modbus_illegal(
        &self,
        packet: &PacketRecord,
        illegal_codes: &[u8],
    ) -> bool {
        if packet.protocol != Protocol::Modbus {
            return false;
        }
        // Modbus TCP: function code is at byte offset 7 in the payload
        // (after the 7-byte MBAP header).
        if packet.raw_payload.len() > 7 {
            let fc = packet.raw_payload[7];
            return illegal_codes.contains(&fc);
        }
        false
    }

    fn check_payload_pattern(
        &self,
        packet: &PacketRecord,
        pattern: &[u8],
    ) -> bool {
        if pattern.is_empty() {
            return false;
        }
        packet
            .raw_payload
            .windows(pattern.len())
            .any(|window| window == pattern)
    }

    // ----- host evaluation -----

    /// Evaluate a host-level event against all host rules.
    pub fn evaluate_host(&self, event: &HostEvent) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        for rule in &self.rules {
            if rule.rule_type != RuleType::Host {
                continue;
            }
            if self.host_conditions_met(rule, event) {
                matches.push(RuleMatch {
                    rule_id: rule.id,
                    rule_name: rule.name.clone(),
                    severity: rule.severity,
                    description: rule.description.clone(),
                });
            }
        }
        matches
    }

    fn host_conditions_met(&self, rule: &DetectionRule, event: &HostEvent) -> bool {
        rule.conditions.iter().all(|cond| match cond {
            RuleCondition::CriticalFileModified { paths } => {
                self.check_critical_file(event, paths)
            }
            RuleCondition::SuspiciousProcess { path_prefixes } => {
                self.check_suspicious_process(event, path_prefixes)
            }
            RuleCondition::FailedLoginRate { threshold } => {
                self.check_failed_login(event, *threshold)
            }
            RuleCondition::PrivilegeEscalation => self.check_priv_esc(event),
            // Network-only conditions never match in a host context.
            _ => false,
        })
    }

    fn check_critical_file(&self, event: &HostEvent, paths: &[String]) -> bool {
        if let HostEvent::FileChange(fc) = event {
            let p = fc.path.to_string_lossy();
            return paths.iter().any(|critical| p.starts_with(critical));
        }
        false
    }

    fn check_suspicious_process(
        &self,
        event: &HostEvent,
        prefixes: &[String],
    ) -> bool {
        if let HostEvent::ProcessActivity(proc_ev) = event {
            let exe = proc_ev.exe_path.to_string_lossy();
            return prefixes.iter().any(|pfx| exe.starts_with(pfx));
        }
        false
    }

    fn check_failed_login(&self, event: &HostEvent, _threshold: f64) -> bool {
        // In a real implementation we would track failed login rate over time.
        // Here we match any auth-failure log entry as a single-event
        // heuristic.
        if let HostEvent::LogEntry(log) = event {
            let msg = log.message.to_lowercase();
            return msg.contains("authentication failure")
                || msg.contains("failed password")
                || msg.contains("invalid user");
        }
        false
    }

    fn check_priv_esc(&self, event: &HostEvent) -> bool {
        match event {
            HostEvent::ProcessActivity(proc_ev) => {
                proc_ev.event_type
                    == ids_common::types::ProcessEventType::Elevated
            }
            HostEvent::SyscallTrace(sc) => {
                let name = sc.syscall.as_str();
                name == "setuid" || name == "setgid" || name == "setresuid"
            }
            HostEvent::LogEntry(log) => {
                let msg = log.message.to_lowercase();
                msg.contains("sudo") && msg.contains("root")
            }
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Default rule-set (~20 rules)
// ---------------------------------------------------------------------------

/// Returns a default set of roughly 20 detection rules covering common
/// network attacks (SYN flood, port scan, Modbus abuse, etc.) and host
/// intrusions (file integrity, suspicious processes, brute-force, priv-esc).
pub fn default_rules() -> Vec<DetectionRule> {
    vec![
        // ===================== NETWORK RULES (1–10) =====================
        DetectionRule {
            id: 1,
            name: "SYN Flood".into(),
            description: "High rate of SYN packets indicating a SYN flood DoS attack".into(),
            rule_type: RuleType::Network,
            conditions: vec![RuleCondition::SynFloodRate {
                threshold_per_sec: 1000.0,
            }],
            action: RuleAction::Drop,
            severity: Severity::Critical,
        },
        DetectionRule {
            id: 2,
            name: "Port Scan (horizontal)".into(),
            description: "Connection attempts to many distinct ports from a single source".into(),
            rule_type: RuleType::Network,
            conditions: vec![RuleCondition::PortScanPorts { min_ports: 50 }],
            action: RuleAction::Alert,
            severity: Severity::High,
        },
        DetectionRule {
            id: 3,
            name: "Modbus Illegal Function (Restart)".into(),
            description: "Modbus function code 0x08 (Diagnostics/Restart) is unusual in production".into(),
            rule_type: RuleType::Network,
            conditions: vec![RuleCondition::ModbusIllegalFunction {
                illegal_codes: vec![0x08],
            }],
            action: RuleAction::Alert,
            severity: Severity::High,
        },
        DetectionRule {
            id: 4,
            name: "Modbus Write Coils Abuse".into(),
            description: "Unexpected Modbus Write Multiple Coils (0x0F) command".into(),
            rule_type: RuleType::Network,
            conditions: vec![RuleCondition::ModbusIllegalFunction {
                illegal_codes: vec![0x0F, 0x10],
            }],
            action: RuleAction::Alert,
            severity: Severity::Medium,
        },
        DetectionRule {
            id: 5,
            name: "Modbus Illegal Function Codes".into(),
            description: "Modbus function codes outside normal operating range".into(),
            rule_type: RuleType::Network,
            conditions: vec![RuleCondition::ModbusIllegalFunction {
                illegal_codes: vec![0x11, 0x14, 0x15, 0x16, 0x17, 0x2B],
            }],
            action: RuleAction::Drop,
            severity: Severity::Critical,
        },
        DetectionRule {
            id: 6,
            name: "Shell Command in Payload".into(),
            description: "Payload contains /bin/sh suggesting command injection".into(),
            rule_type: RuleType::Network,
            conditions: vec![RuleCondition::PayloadPattern {
                pattern: b"/bin/sh".to_vec(),
            }],
            action: RuleAction::Drop,
            severity: Severity::Critical,
        },
        DetectionRule {
            id: 7,
            name: "Nmap OS Fingerprint".into(),
            description: "Nmap-style OS fingerprint probe detected in payload".into(),
            rule_type: RuleType::Network,
            conditions: vec![RuleCondition::PayloadPattern {
                pattern: b"Nmap".to_vec(),
            }],
            action: RuleAction::Alert,
            severity: Severity::Medium,
        },
        DetectionRule {
            id: 8,
            name: "DNS Exfiltration Indicator".into(),
            description: "Unusually long DNS query suggesting data exfiltration".into(),
            rule_type: RuleType::Network,
            // Heuristic: DNS queries exceeding 100 packets in a single flow
            // are suspicious.
            conditions: vec![RuleCondition::PortScanPorts { min_ports: 100 }],
            action: RuleAction::Alert,
            severity: Severity::High,
        },
        DetectionRule {
            id: 9,
            name: "Low-Rate SYN Scan".into(),
            description: "Slow SYN-based port scanning below flood thresholds".into(),
            rule_type: RuleType::Network,
            conditions: vec![RuleCondition::SynFloodRate {
                threshold_per_sec: 10.0,
            }],
            action: RuleAction::Log,
            severity: Severity::Low,
        },
        DetectionRule {
            id: 10,
            name: "Shellcode NOP Sled".into(),
            description: "Long NOP sled (0x90 bytes) in payload may indicate shellcode".into(),
            rule_type: RuleType::Network,
            conditions: vec![RuleCondition::PayloadPattern {
                pattern: vec![0x90; 16],
            }],
            action: RuleAction::Drop,
            severity: Severity::Critical,
        },
        // ===================== HOST RULES (11–20) =====================
        DetectionRule {
            id: 11,
            name: "Critical Config Modified".into(),
            description: "Modification to /etc/passwd, /etc/shadow, or /etc/sudoers".into(),
            rule_type: RuleType::Host,
            conditions: vec![RuleCondition::CriticalFileModified {
                paths: vec![
                    "/etc/passwd".into(),
                    "/etc/shadow".into(),
                    "/etc/sudoers".into(),
                ],
            }],
            action: RuleAction::Alert,
            severity: Severity::Critical,
        },
        DetectionRule {
            id: 12,
            name: "SSH Config Modified".into(),
            description: "SSH daemon configuration was changed".into(),
            rule_type: RuleType::Host,
            conditions: vec![RuleCondition::CriticalFileModified {
                paths: vec!["/etc/ssh/sshd_config".into()],
            }],
            action: RuleAction::Alert,
            severity: Severity::High,
        },
        DetectionRule {
            id: 13,
            name: "Crontab Modified".into(),
            description: "System crontab files changed — potential persistence mechanism".into(),
            rule_type: RuleType::Host,
            conditions: vec![RuleCondition::CriticalFileModified {
                paths: vec![
                    "/etc/crontab".into(),
                    "/var/spool/cron".into(),
                    "/etc/cron.d".into(),
                ],
            }],
            action: RuleAction::Alert,
            severity: Severity::High,
        },
        DetectionRule {
            id: 14,
            name: "PLC Firmware Directory Modified".into(),
            description: "Files in the PLC firmware directory were changed".into(),
            rule_type: RuleType::Host,
            conditions: vec![RuleCondition::CriticalFileModified {
                paths: vec!["/opt/plc/firmware".into(), "/var/lib/scada".into()],
            }],
            action: RuleAction::Drop,
            severity: Severity::Critical,
        },
        DetectionRule {
            id: 15,
            name: "Process from /tmp".into(),
            description: "A process was spawned from /tmp — common malware behaviour".into(),
            rule_type: RuleType::Host,
            conditions: vec![RuleCondition::SuspiciousProcess {
                path_prefixes: vec!["/tmp/".into(), "/var/tmp/".into()],
            }],
            action: RuleAction::Alert,
            severity: Severity::High,
        },
        DetectionRule {
            id: 16,
            name: "Process from /dev/shm".into(),
            description: "Process executed from shared memory — evasion technique".into(),
            rule_type: RuleType::Host,
            conditions: vec![RuleCondition::SuspiciousProcess {
                path_prefixes: vec!["/dev/shm/".into()],
            }],
            action: RuleAction::Drop,
            severity: Severity::Critical,
        },
        DetectionRule {
            id: 17,
            name: "Hidden Process".into(),
            description: "Process spawned from a hidden directory (dot-prefixed)".into(),
            rule_type: RuleType::Host,
            conditions: vec![RuleCondition::SuspiciousProcess {
                path_prefixes: vec!["/home/.".into(), "/root/.".into()],
            }],
            action: RuleAction::Alert,
            severity: Severity::High,
        },
        DetectionRule {
            id: 18,
            name: "SSH Brute Force".into(),
            description: "Elevated rate of failed SSH login attempts".into(),
            rule_type: RuleType::Host,
            conditions: vec![RuleCondition::FailedLoginRate { threshold: 5.0 }],
            action: RuleAction::Alert,
            severity: Severity::High,
        },
        DetectionRule {
            id: 19,
            name: "Privilege Escalation".into(),
            description: "Detected privilege escalation via setuid/sudo".into(),
            rule_type: RuleType::Host,
            conditions: vec![RuleCondition::PrivilegeEscalation],
            action: RuleAction::Alert,
            severity: Severity::Critical,
        },
        DetectionRule {
            id: 20,
            name: "Systemd Unit Modified".into(),
            description: "Systemd service files changed — possible persistence".into(),
            rule_type: RuleType::Host,
            conditions: vec![RuleCondition::CriticalFileModified {
                paths: vec![
                    "/etc/systemd/system".into(),
                    "/lib/systemd/system".into(),
                ],
            }],
            action: RuleAction::Alert,
            severity: Severity::High,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_rules_count() {
        let rules = default_rules();
        assert_eq!(rules.len(), 20);
        let net = rules.iter().filter(|r| r.rule_type == RuleType::Network).count();
        let host = rules.iter().filter(|r| r.rule_type == RuleType::Host).count();
        assert_eq!(net, 10);
        assert_eq!(host, 10);
    }
}
