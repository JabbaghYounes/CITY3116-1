use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Unified event — everything the collector produces
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEvent {
    Network(PacketRecord),
    Host(HostEvent),
}

// ---------------------------------------------------------------------------
// Network types (NIDS)
// ---------------------------------------------------------------------------

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
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Modbus,
    Dnp3,
    OpcUa,
    Other(u8),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
}

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

// ---------------------------------------------------------------------------
// Host types (HIDS)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HostEvent {
    FileChange(FileChangeEvent),
    ProcessActivity(ProcessEvent),
    SyscallTrace(SyscallEvent),
    LogEntry(LogEvent),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FileChangeType {
    Created,
    Modified,
    Deleted,
    Renamed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChangeEvent {
    pub timestamp: DateTime<Utc>,
    pub path: PathBuf,
    pub change_type: FileChangeType,
    pub old_hash: Option<String>,
    pub new_hash: Option<String>,
    pub file_permissions: Option<u32>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProcessEventType {
    Spawned,
    Terminated,
    Elevated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub timestamp: DateTime<Utc>,
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub exe_path: PathBuf,
    pub uid: u32,
    pub event_type: ProcessEventType,
    pub cpu_usage: f32,
    pub memory_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEvent {
    pub timestamp: DateTime<Utc>,
    pub pid: u32,
    pub syscall: String,
    pub args: Vec<String>,
    pub return_code: i64,
    pub uid: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LogSeverity {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub severity: LogSeverity,
    pub message: String,
    pub parsed_fields: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Alert types (shared by response + dashboard)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttackCategory {
    Normal,
    DoS,
    Probe,
    R2L,
    U2R,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertSource {
    Network,
    Host,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,
    pub category: AttackCategory,
    pub source: AlertSource,
    pub description: String,
    pub confidence: f64,
    pub model_source: String,
    // Network-specific
    pub source_ip: Option<IpAddr>,
    pub dest_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub dest_port: Option<u16>,
    // Host-specific
    pub hostname: Option<String>,
    pub pid: Option<u32>,
    pub affected_path: Option<PathBuf>,
    pub username: Option<String>,
}

// ---------------------------------------------------------------------------
// Detection result (engine -> response)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub event_source: AlertSource,
    pub predicted_category: AttackCategory,
    pub confidence: f64,
    pub model_source: String,
    pub feature_vector: Vec<f64>,
    /// Original event metadata for alert enrichment
    pub metadata: DetectionMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionMetadata {
    Network {
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: Protocol,
    },
    Host {
        hostname: String,
        pid: Option<u32>,
        affected_path: Option<PathBuf>,
        username: Option<String>,
    },
}
