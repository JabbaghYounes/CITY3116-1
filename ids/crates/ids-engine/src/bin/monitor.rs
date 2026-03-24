//! Live IDS Monitor
//!
//! Captures packets on a network interface, tracks flows, runs the rule engine
//! against each packet/flow, and runs CNN+LSTM inference on completed flows.
//!
//! Usage:
//!   sudo cargo run --release -p ids-engine --bin monitor -- --interface lo --modbus-port 5502
//!   sudo cargo run --release -p ids-engine --bin monitor -- --interface lo --modbus-port 5502 \
//!     --model ../pytorch-train/data/models/model-b/cnn_lstm_model.onnx \
//!     --scaler ../pytorch-train/data/models/model-b/scaler.json

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use chrono::Utc;
use clap::Parser;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;

use ids_collector::network::capture::NetworkCapture;
use ids_collector::network::flow::FlowTable;
use ids_common::types::{
    Alert, AlertSource, AttackCategory, FlowRecord, PacketRecord, Protocol, SecurityEvent,
    Severity,
};
use ids_engine::ml_inference::{CnnLstmClassifier, Prediction};
use ids_engine::rules::{RuleEngine, RuleMatch};
use ids_preprocess::extract_cicids_features;
use ids_response::logger::AlertLogger;

#[derive(Parser)]
#[command(name = "ids-monitor", about = "Live IDS/IPS monitor for CPS networks")]
struct Cli {
    /// Network interface to capture on
    #[arg(short, long, default_value = "lo")]
    interface: String,

    /// Modbus TCP port(s) to monitor (can be specified multiple times)
    #[arg(long = "modbus-port", default_value = "502")]
    modbus_ports: Vec<u16>,

    /// Alert log file path
    #[arg(long, default_value = "logs/alerts.jsonl")]
    log_file: PathBuf,

    /// Flow idle timeout in seconds
    #[arg(long, default_value = "30")]
    flow_timeout: u64,

    /// Write frequency threshold (writes per second to trigger alert)
    #[arg(long, default_value = "2.0")]
    write_freq_threshold: f64,

    /// Path to the ONNX model file for CNN+LSTM inference
    #[arg(long)]
    model: Option<PathBuf>,

    /// Path to the scaler JSON file for CNN+LSTM inference
    #[arg(long)]
    scaler: Option<PathBuf>,

    /// Minimum confidence threshold for ML-based alerts (0.0–1.0)
    #[arg(long, default_value = "0.5")]
    ml_threshold: f64,
}

// ---------------------------------------------------------------------------
// CPS Process-Aware Detection
// ---------------------------------------------------------------------------

/// Physical process constraints for the water treatment plant.
/// These mirror the control logic in arduino-plc-firmware.cpp and plant/simulation/plc1.py.
mod cps {
    /// Tank level ADC range (0–1023 for 10-bit ADC).
    #[allow(dead_code)]
    pub const TANK_LEVEL_MIN: u16 = 0;
    pub const TANK_LEVEL_MAX: u16 = 1023;
    /// Valve servo range (degrees).
    #[allow(dead_code)]
    pub const VALVE_MIN: u16 = 0;
    pub const VALVE_MAX: u16 = 180;
    /// Temperature alarm threshold (Celsius, DHT11 range).
    pub const TEMP_MAX_REASONABLE: u16 = 80;
    /// Control logic thresholds (% of 1023).
    pub const PUMP_ON_THRESHOLD: u16 = (1023.0 * 0.30) as u16;  // ~307
    pub const PUMP_OFF_THRESHOLD: u16 = (1023.0 * 0.85) as u16; // ~869
    /// Normal valve positions for pump states.
    pub const VALVE_PUMP_ON: u16 = 120;
    pub const VALVE_PUMP_OFF: u16 = 40;
    /// Maximum plausible tank level change per second (ADC units).
    /// Fill rate is ~5 ADC/cycle at 200ms = ~25/sec. Allow 2x margin.
    pub const MAX_TANK_RATE: f64 = 50.0;
    /// Minimum interval between pump toggles to be considered normal (seconds).
    pub const MIN_PUMP_TOGGLE_INTERVAL: f64 = 5.0;

    /// Modbus register addresses (PLC 1 SCADA-facing).
    pub const REG_TANK_LEVEL: u16 = 0;
    pub const REG_VALVE_POS: u16 = 1;
    pub const REG_TEMPERATURE: u16 = 2;
    // pub const REG_SOUND: u16 = 3;
    // pub const REG_ULTRASONIC: u16 = 4;
    // pub const REG_ALARM: u16 = 5;
    pub const COIL_PUMP: u16 = 0;
}

/// Tracks physical process state from observed Modbus register writes/responses
/// to detect physics-violating anomalies.
struct ProcessStateTracker {
    /// Last known tank level (from register reads/writes).
    tank_level: Option<u16>,
    tank_level_time: Option<chrono::DateTime<Utc>>,
    /// Last known pump state (from coil writes: 0xFF00=ON, 0x0000=OFF).
    pump_state: Option<bool>,
    /// Timestamps of pump toggle commands for oscillation detection.
    pump_toggles: Vec<chrono::DateTime<Utc>>,
    /// Last known valve position.
    valve_pos: Option<u16>,
    /// Last known temperature.
    temperature: Option<u16>,
}

impl ProcessStateTracker {
    fn new() -> Self {
        Self {
            tank_level: None,
            tank_level_time: None,
            pump_state: None,
            pump_toggles: Vec::new(),
            valve_pos: None,
            temperature: None,
        }
    }

    /// Process a Modbus write command and return any physics-based alerts.
    fn process_write(
        &mut self,
        fc: u8,
        register_addr: Option<u16>,
        register_val: Option<u16>,
        packet: &PacketRecord,
    ) -> Vec<Alert> {
        let mut alerts = Vec::new();
        let now = Utc::now();

        match fc {
            // Write Single Coil (FC 0x05) — pump control
            0x05 => {
                if let (Some(addr), Some(val)) = (register_addr, register_val) {
                    if addr == cps::COIL_PUMP {
                        let pump_on = val == 0xFF00;
                        let prev_state = self.pump_state;
                        self.pump_state = Some(pump_on);

                        // Detect pump oscillation (Stuxnet-style rapid toggling)
                        if prev_state.is_some() && prev_state != Some(pump_on) {
                            self.pump_toggles.push(now);
                            // Keep only last 60 seconds of toggles
                            let cutoff = now - chrono::Duration::seconds(60);
                            self.pump_toggles.retain(|t| *t > cutoff);

                            if self.pump_toggles.len() >= 2 {
                                let n = self.pump_toggles.len();
                                let last_interval = (self.pump_toggles[n - 1]
                                    - self.pump_toggles[n - 2])
                                    .num_milliseconds() as f64
                                    / 1000.0;
                                if last_interval < cps::MIN_PUMP_TOGGLE_INTERVAL {
                                    alerts.push(cps_alert(
                                        packet,
                                        format!(
                                            "CPS: Rapid pump oscillation detected — {} toggles in 60s, \
                                             last interval {:.1}s (min safe: {:.0}s)",
                                            self.pump_toggles.len(),
                                            last_interval,
                                            cps::MIN_PUMP_TOGGLE_INTERVAL,
                                        ),
                                        Severity::Critical,
                                        AttackCategory::U2R,
                                    ));
                                }
                            }
                        }

                        // Detect pump command contradicting process state
                        // (e.g., turning pump ON when tank is above 85%)
                        if let Some(level) = self.tank_level {
                            if pump_on && level > cps::PUMP_OFF_THRESHOLD {
                                alerts.push(cps_alert(
                                    packet,
                                    format!(
                                        "CPS: Pump forced ON while tank at {} (>{} overflow threshold) \
                                         — possible command injection",
                                        level, cps::PUMP_OFF_THRESHOLD,
                                    ),
                                    Severity::High,
                                    AttackCategory::R2L,
                                ));
                            }
                            if !pump_on && level < cps::PUMP_ON_THRESHOLD {
                                alerts.push(cps_alert(
                                    packet,
                                    format!(
                                        "CPS: Pump forced OFF while tank at {} (<{} low threshold) \
                                         — possible command injection",
                                        level, cps::PUMP_ON_THRESHOLD,
                                    ),
                                    Severity::High,
                                    AttackCategory::R2L,
                                ));
                            }
                        }
                    }
                }
            }
            // Write Single Register (FC 0x06) — valve, sensor spoofing
            0x06 => {
                if let (Some(addr), Some(val)) = (register_addr, register_val) {
                    match addr {
                        a if a == cps::REG_VALVE_POS => {
                            // Valve out of physical range
                            if val > cps::VALVE_MAX {
                                alerts.push(cps_alert(
                                    packet,
                                    format!(
                                        "CPS: Valve position {} exceeds physical maximum {}° \
                                         — invalid actuator command",
                                        val, cps::VALVE_MAX,
                                    ),
                                    Severity::High,
                                    AttackCategory::R2L,
                                ));
                            }
                            // Valve position inconsistent with pump state
                            if let Some(pump_on) = self.pump_state {
                                let expected = if pump_on {
                                    cps::VALVE_PUMP_ON
                                } else {
                                    cps::VALVE_PUMP_OFF
                                };
                                let diff = (val as i32 - expected as i32).unsigned_abs();
                                if diff > 30 {
                                    alerts.push(cps_alert(
                                        packet,
                                        format!(
                                            "CPS: Valve set to {}° but pump is {} (expected ~{}°) \
                                             — valve/pump state mismatch",
                                            val,
                                            if pump_on { "ON" } else { "OFF" },
                                            expected,
                                        ),
                                        Severity::Medium,
                                        AttackCategory::R2L,
                                    ));
                                }
                            }
                            self.valve_pos = Some(val);
                        }
                        a if a == cps::REG_TANK_LEVEL => {
                            // Direct write to tank level register = sensor spoofing
                            // (SCADA should only read this, not write)
                            alerts.push(cps_alert(
                                packet,
                                format!(
                                    "CPS: Direct write to tank level register (addr {}, val {}) \
                                     — sensor spoofing detected",
                                    addr, val,
                                ),
                                Severity::Critical,
                                AttackCategory::R2L,
                            ));
                            // Also check for impossible values
                            if val > cps::TANK_LEVEL_MAX {
                                alerts.push(cps_alert(
                                    packet,
                                    format!(
                                        "CPS: Spoofed tank level {} exceeds ADC maximum {} \
                                         — physically impossible value",
                                        val, cps::TANK_LEVEL_MAX,
                                    ),
                                    Severity::Critical,
                                    AttackCategory::R2L,
                                ));
                            }
                            // Check rate of change
                            if let (Some(prev_level), Some(prev_time)) =
                                (self.tank_level, self.tank_level_time)
                            {
                                let dt = (now - prev_time).num_milliseconds().max(1) as f64
                                    / 1000.0;
                                let rate =
                                    (val as f64 - prev_level as f64).abs() / dt;
                                if rate > cps::MAX_TANK_RATE {
                                    alerts.push(cps_alert(
                                        packet,
                                        format!(
                                            "CPS: Tank level changed {} → {} ({:.0} units/sec) \
                                             — exceeds physical rate limit ({:.0} units/sec)",
                                            prev_level, val, rate, cps::MAX_TANK_RATE,
                                        ),
                                        Severity::High,
                                        AttackCategory::R2L,
                                    ));
                                }
                            }
                            self.tank_level = Some(val);
                            self.tank_level_time = Some(now);
                        }
                        a if a == cps::REG_TEMPERATURE => {
                            if val > cps::TEMP_MAX_REASONABLE {
                                alerts.push(cps_alert(
                                    packet,
                                    format!(
                                        "CPS: Temperature register set to {}°C — exceeds \
                                         reasonable sensor range (max {}°C)",
                                        val, cps::TEMP_MAX_REASONABLE,
                                    ),
                                    Severity::Medium,
                                    AttackCategory::R2L,
                                ));
                            }
                            self.temperature = Some(val);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        alerts
    }

    /// Update state from observed Modbus read responses (FC 0x03 response).
    /// This lets us track process state even from normal polling traffic.
    fn observe_read_response(&mut self, data: &[u8]) {
        // Modbus FC 0x03 response format: [byte_count, reg0_hi, reg0_lo, reg1_hi, ...]
        // PLC1 returns 6 registers: tank, valve, temp, sound, ultrasonic, alarm
        if data.len() >= 13 {
            // data[0] = byte count (should be 12 for 6 registers)
            let byte_count = data[0] as usize;
            if byte_count >= 12 && data.len() >= 13 {
                let tank = u16::from_be_bytes([data[1], data[2]]);
                let valve = u16::from_be_bytes([data[3], data[4]]);
                let temp = u16::from_be_bytes([data[5], data[6]]);

                if tank <= cps::TANK_LEVEL_MAX {
                    self.tank_level = Some(tank);
                    self.tank_level_time = Some(Utc::now());
                }
                if valve <= cps::VALVE_MAX {
                    self.valve_pos = Some(valve);
                }
                self.temperature = Some(temp);
            }
        }
    }
}

fn cps_alert(
    packet: &PacketRecord,
    description: String,
    severity: Severity,
    category: AttackCategory,
) -> Alert {
    Alert {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        severity,
        category,
        source: AlertSource::Network,
        description,
        confidence: 0.95,
        model_source: "cps-physics-engine".into(),
        source_ip: Some(packet.src_ip),
        dest_ip: Some(packet.dst_ip),
        source_port: Some(packet.src_port),
        dest_port: Some(packet.dst_port),
        hostname: None,
        pid: None,
        affected_path: None,
        username: None,
    }
}

// ---------------------------------------------------------------------------
// Rate Trackers
// ---------------------------------------------------------------------------

/// Tracks Modbus write frequency per source IP for rate-based detection.
struct WriteTracker {
    /// (source_ip, timestamp) pairs for recent writes
    writes: Vec<(std::net::IpAddr, chrono::DateTime<Utc>)>,
    /// Window size for rate calculation
    window: chrono::Duration,
}

impl WriteTracker {
    fn new(window_secs: i64) -> Self {
        Self {
            writes: Vec::new(),
            window: chrono::Duration::seconds(window_secs),
        }
    }

    /// Record a write and return the current rate (writes/sec) for this source.
    fn record_write(&mut self, src: std::net::IpAddr) -> f64 {
        let now = Utc::now();
        self.writes.push((src, now));

        // Prune old entries
        let cutoff = now - self.window;
        self.writes.retain(|(_, t)| *t > cutoff);

        // Count writes from this source in the window
        let count = self.writes.iter().filter(|(ip, _)| *ip == src).count();
        let secs = self.window.num_seconds().max(1) as f64;
        count as f64 / secs
    }
}

/// Tracks Modbus read frequency per source IP for flood detection.
struct ReadTracker {
    reads: Vec<(std::net::IpAddr, chrono::DateTime<Utc>)>,
    window: chrono::Duration,
}

impl ReadTracker {
    fn new(window_secs: i64) -> Self {
        Self {
            reads: Vec::new(),
            window: chrono::Duration::seconds(window_secs),
        }
    }

    fn record_read(&mut self, src: std::net::IpAddr) -> f64 {
        let now = Utc::now();
        self.reads.push((src, now));

        let cutoff = now - self.window;
        self.reads.retain(|(_, t)| *t > cutoff);

        let count = self.reads.iter().filter(|(ip, _)| *ip == src).count();
        let secs = self.window.num_seconds().max(1) as f64;
        count as f64 / secs
    }
}

fn rule_match_to_alert(rm: &RuleMatch, packet: &PacketRecord) -> Alert {
    Alert {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        severity: rm.severity,
        category: match rm.severity {
            Severity::Critical => AttackCategory::DoS,
            Severity::High => AttackCategory::Probe,
            Severity::Medium => AttackCategory::R2L,
            Severity::Low => AttackCategory::Normal,
        },
        source: AlertSource::Network,
        description: rm.description.clone(),
        confidence: 1.0,
        model_source: format!("rule-engine/rule-{}", rm.rule_id),
        source_ip: Some(packet.src_ip),
        dest_ip: Some(packet.dst_ip),
        source_port: Some(packet.src_port),
        dest_port: Some(packet.dst_port),
        hostname: None,
        pid: None,
        affected_path: None,
        username: None,
    }
}

fn write_rate_alert(
    src: std::net::IpAddr,
    dst: std::net::IpAddr,
    port: u16,
    rate: f64,
    fc: u8,
) -> Alert {
    Alert {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        severity: Severity::High,
        category: AttackCategory::DoS,
        source: AlertSource::Network,
        description: format!(
            "High Modbus write rate: {:.1} writes/sec from {} (FC 0x{:02X})",
            rate, src, fc
        ),
        confidence: 0.9,
        model_source: "rule-engine/write-rate".into(),
        source_ip: Some(src),
        dest_ip: Some(dst),
        source_port: None,
        dest_port: Some(port),
        hostname: None,
        pid: None,
        affected_path: None,
        username: None,
    }
}

fn modbus_event_alert(
    packet: &PacketRecord,
    description: String,
    severity: Severity,
    category: AttackCategory,
) -> Alert {
    Alert {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        severity,
        category,
        source: AlertSource::Network,
        description,
        confidence: 0.85,
        model_source: "rule-engine/modbus-analysis".into(),
        source_ip: Some(packet.src_ip),
        dest_ip: Some(packet.dst_ip),
        source_port: Some(packet.src_port),
        dest_port: Some(packet.dst_port),
        hostname: None,
        pid: None,
        affected_path: None,
        username: None,
    }
}

fn ml_prediction_to_alert(pred: &Prediction, flow: &FlowRecord) -> Alert {
    let severity = match pred.category {
        AttackCategory::DoS => Severity::Critical,
        AttackCategory::U2R => Severity::Critical,
        AttackCategory::R2L => Severity::High,
        AttackCategory::Probe => Severity::Medium,
        _ => Severity::Low,
    };

    Alert {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        severity,
        category: pred.category,
        source: AlertSource::Network,
        description: format!(
            "CNN+LSTM: {:?} detected (confidence: {:.1}%, {} packets in flow)",
            pred.category,
            pred.confidence * 100.0,
            flow.packet_count,
        ),
        confidence: pred.confidence,
        model_source: format!("cnn-lstm/{}", pred.model_source),
        source_ip: Some(flow.key.src_ip),
        dest_ip: Some(flow.key.dst_ip),
        source_port: Some(flow.key.src_port),
        dest_port: Some(flow.key.dst_port),
        hostname: None,
        pid: None,
        affected_path: None,
        username: None,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

    info!(
        interface = %cli.interface,
        modbus_ports = ?cli.modbus_ports,
        "Starting IDS monitor"
    );

    // Create log directory
    if let Some(parent) = cli.log_file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut logger = AlertLogger::new(&cli.log_file)?;

    // Rule engine
    let rule_engine = RuleEngine::with_defaults();
    info!(rules = rule_engine.rules().len(), "Rule engine loaded");

    // CNN+LSTM classifier (optional)
    let mut classifier: Option<CnnLstmClassifier> = None;
    if let (Some(model_path), Some(scaler_path)) = (&cli.model, &cli.scaler) {
        match CnnLstmClassifier::load(model_path, scaler_path) {
            Ok(c) => {
                info!(
                    n_features = c.n_features(),
                    "CNN+LSTM classifier loaded — ML inference enabled"
                );
                classifier = Some(c);
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "Failed to load CNN+LSTM model — running with rule engine only"
                );
            }
        }
    } else {
        info!("No --model/--scaler provided — running with rule engine only");
    }

    // Packet channel
    let (tx, mut rx) = mpsc::channel::<SecurityEvent>(4096);

    // Start capture in background thread
    let interface = cli.interface.clone();
    let ports = cli.modbus_ports.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(e) = NetworkCapture::start_with_ports(&interface, ports, tx) {
            error!(error = %e, "Capture failed");
        }
    });

    // Flow tracking
    let mut flow_table = FlowTable::new();
    let flow_timeout = Duration::from_secs(cli.flow_timeout);

    // Write/read rate tracking
    let mut write_tracker = WriteTracker::new(10);
    let mut read_tracker = ReadTracker::new(5);

    // CPS process-aware detection
    let mut process_state = ProcessStateTracker::new();
    let mut cps_alerts_generated: u64 = 0;
    let write_threshold = cli.write_freq_threshold;
    let read_flood_threshold = 50.0; // reads per second
    let ml_threshold = cli.ml_threshold;

    // Graceful shutdown on Ctrl+C / SIGINT
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        r.store(false, Ordering::SeqCst);
    });

    // Track which flows have already been ML-classified (avoid duplicates)
    let mut ml_classified_flows: HashSet<ids_common::types::FlowKey> = HashSet::new();
    let mut last_ml_scan = Utc::now();

    // Stats
    let mut total_packets: u64 = 0;
    let mut modbus_packets: u64 = 0;
    let mut alerts_generated: u64 = 0;
    let mut ml_inferences: u64 = 0;
    let mut ml_detections: u64 = 0;
    let mut last_stats = Utc::now();
    let mut last_expire = Utc::now();

    let ml_status = if classifier.is_some() {
        "CNN+LSTM ENABLED"
    } else {
        "rule engine only"
    };

    println!();
    println!("========================================");
    println!("  CPS-IDS Live Monitor");
    println!("========================================");
    println!("  Interface:      {}", cli.interface);
    println!("  Modbus ports:   {:?}", cli.modbus_ports);
    println!("  Log file:       {}", cli.log_file.display());
    println!("  Write threshold: {:.1} writes/sec", write_threshold);
    println!("  ML detection:   {}", ml_status);
    if classifier.is_some() {
        println!("  ML threshold:   {:.0}%", ml_threshold * 100.0);
    }
    println!("  CPS physics:    ENABLED (process-aware anomaly detection)");
    println!("========================================");
    println!();

    // Main event loop
    while running.load(Ordering::SeqCst) {
        let event = tokio::select! {
            e = rx.recv() => match e {
                Some(ev) => ev,
                None => break,
            },
            _ = tokio::time::sleep(Duration::from_millis(100)) => continue,
        };
        let packet = match event {
            SecurityEvent::Network(p) => p,
            _ => continue,
        };

        total_packets += 1;

        // Update flow table
        flow_table.update(&packet);

        // Get the flow for this packet
        let flow_key = ids_common::types::FlowKey {
            src_ip: packet.src_ip,
            dst_ip: packet.dst_ip,
            src_port: packet.src_port,
            dst_port: packet.dst_port,
            protocol: packet.protocol,
        };
        let flow = flow_table.get_active_flows()
            .into_iter()
            .find(|f| f.key == flow_key || (
                f.key.src_ip == packet.dst_ip
                && f.key.dst_ip == packet.src_ip
                && f.key.src_port == packet.dst_port
                && f.key.dst_port == packet.src_port
            ));

        // Run rule engine against packet + flow
        if let Some(flow) = flow {
            let matches = rule_engine.evaluate_network(&packet, flow);
            for rm in &matches {
                let alert = rule_match_to_alert(rm, &packet);
                print_alert(&alert);
                logger.log_alert(&alert).await?;
                alerts_generated += 1;
            }
        }

        // Modbus-specific analysis
        if packet.protocol == Protocol::Modbus {
            modbus_packets += 1;

            // Parse Modbus function code
            if packet.raw_payload.len() > 7 {
                let fc = packet.raw_payload[7];
                let is_write = matches!(fc, 0x05 | 0x06 | 0x0F | 0x10);

                if is_write {
                    // Track write frequency
                    let rate = write_tracker.record_write(packet.src_ip);
                    if rate > write_threshold {
                        let alert = write_rate_alert(
                            packet.src_ip, packet.dst_ip,
                            packet.dst_port, rate, fc,
                        );
                        print_alert(&alert);
                        logger.log_alert(&alert).await?;
                        alerts_generated += 1;
                    }

                    // Log all Modbus writes for forensic record
                    let data = &packet.raw_payload[8..];
                    let (addr, val) = if data.len() >= 4 {
                        (
                            Some(u16::from_be_bytes([data[0], data[1]])),
                            Some(u16::from_be_bytes([data[2], data[3]])),
                        )
                    } else {
                        (None, None)
                    };
                    info!(
                        src = %packet.src_ip,
                        fc = format!("0x{:02X}", fc),
                        register = ?addr,
                        value = ?val,
                        "Modbus WRITE"
                    );

                    // CPS physics-aware detection on every write
                    let cps_alerts_list = process_state.process_write(
                        fc, addr, val, &packet,
                    );
                    for alert in &cps_alerts_list {
                        print_alert(alert);
                        logger.log_alert(alert).await?;
                        alerts_generated += 1;
                        cps_alerts_generated += 1;
                    }
                }

                // Observe read responses to passively track process state
                // FC >= 0x80 indicates a response; FC 0x03 response contains register data
                if fc == 0x03 && packet.raw_payload.len() > 8 {
                    // This is a read holding registers response — extract register values
                    process_state.observe_read_response(&packet.raw_payload[8..]);
                }

                // Detect reads at unusually high rates (flood)
                if matches!(fc, 0x01 | 0x02 | 0x03 | 0x04) {
                    // Rate-based detection (independent of flow state)
                    let read_rate = read_tracker.record_read(packet.src_ip);
                    if read_rate > read_flood_threshold {
                        let alert = modbus_event_alert(
                            &packet,
                            format!("Modbus read flood: {:.0} reads/sec from {}",
                                read_rate, packet.src_ip),
                            Severity::High,
                            AttackCategory::DoS,
                        );
                        print_alert(&alert);
                        logger.log_alert(&alert).await?;
                        alerts_generated += 1;
                    }

                    // Flow-based detection (full 5-tuple matching)
                    let read_flow_key = ids_common::types::FlowKey {
                        src_ip: packet.src_ip,
                        dst_ip: packet.dst_ip,
                        src_port: packet.src_port,
                        dst_port: packet.dst_port,
                        protocol: packet.protocol,
                    };
                    if let Some(flow) = flow_table.get_active_flows()
                        .into_iter()
                        .find(|f| f.key == read_flow_key || (
                            f.key.src_ip == packet.dst_ip
                            && f.key.dst_ip == packet.src_ip
                            && f.key.src_port == packet.dst_port
                            && f.key.dst_port == packet.src_port
                        ))
                    {
                        let duration_secs = (flow.last_time - flow.start_time)
                            .num_milliseconds().max(1) as f64 / 1000.0;
                        let pps = flow.packet_count as f64 / duration_secs;
                        if pps > 50.0 && flow.packet_count > 20 {
                            let alert = modbus_event_alert(
                                &packet,
                                format!("Modbus read flood: {:.0} packets/sec ({} total in flow)",
                                    pps, flow.packet_count),
                                Severity::High,
                                AttackCategory::DoS,
                            );
                            print_alert(&alert);
                            logger.log_alert(&alert).await?;
                            alerts_generated += 1;
                        }
                    }
                }
            }
        }

        // Periodic flow expiry + ML inference on completed flows
        let now = Utc::now();
        if (now - last_expire).num_seconds() > 5 {
            let expired = flow_table.expire(flow_timeout);
            if !expired.is_empty() {
                println!(
                    "[EXPIRE] {} flows expired, checking for ML inference...",
                    expired.len()
                );
                for flow in &expired {
                    println!(
                        "  flow {}:{} -> {}:{} packets={} bytes={}",
                        flow.key.src_ip, flow.key.src_port,
                        flow.key.dst_ip, flow.key.dst_port,
                        flow.packet_count, flow.byte_count
                    );
                }

                // Run ML inference on expired flows
                if let Some(ref mut clf) = classifier {
                    for flow in &expired {
                        // Skip flows with too few packets (not enough data)
                        if flow.packet_count < 3 {
                            println!("  -> skipped (only {} packets)", flow.packet_count);
                            continue;
                        }

                        let features = extract_cicids_features(flow);
                        ml_inferences += 1;

                        match clf.predict(&features) {
                            Ok(pred) => {
                                println!(
                                    "  -> ML: {:?} confidence={:.1}%",
                                    pred.category,
                                    pred.confidence * 100.0
                                );
                                if pred.category != AttackCategory::Normal
                                    && pred.confidence >= ml_threshold
                                {
                                    ml_detections += 1;
                                    let alert = ml_prediction_to_alert(&pred, flow);
                                    print_alert(&alert);
                                    logger.log_alert(&alert).await?;
                                    alerts_generated += 1;
                                }
                            }
                            Err(e) => {
                                println!("  -> ML ERROR: {}", e);
                                warn!(error = %e, "ML inference failed for flow");
                            }
                        }
                    }
                } else {
                    println!("  -> classifier not loaded, skipping ML");
                }
            }
            // Clean up classified flow tracker for expired flows
            for flow in &expired {
                ml_classified_flows.remove(&flow.key);
            }
            last_expire = now;
        }

        // Time-windowed ML inference on ACTIVE flows (bypasses expiry bottleneck)
        if (now - last_ml_scan).num_seconds() > 10 {
            if let Some(ref mut clf) = classifier {
                let snapshots = flow_table.snapshot_flows_with_min_packets(10);
                for flow in &snapshots {
                    if ml_classified_flows.contains(&flow.key) {
                        continue;
                    }
                    let features = extract_cicids_features(flow);
                    ml_inferences += 1;
                    match clf.predict(&features) {
                        Ok(pred) => {
                            println!(
                                "[ML-SCAN] {}:{} -> {}:{} pkts={} => {:?} ({:.1}%) [{}]",
                                flow.key.src_ip, flow.key.src_port,
                                flow.key.dst_ip, flow.key.dst_port,
                                flow.packet_count,
                                pred.category,
                                pred.confidence * 100.0,
                                pred.model_source,
                            );
                            ml_classified_flows.insert(flow.key.clone());
                            if pred.category != AttackCategory::Normal
                                && pred.confidence >= ml_threshold
                            {
                                ml_detections += 1;
                                let alert = ml_prediction_to_alert(&pred, flow);
                                print_alert(&alert);
                                logger.log_alert(&alert).await?;
                                alerts_generated += 1;
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "ML scan inference failed");
                        }
                    }
                }
            }
            last_ml_scan = now;
        }

        // Periodic stats
        if (now - last_stats).num_seconds() > 15 {
            if classifier.is_some() {
                println!(
                    "[STATS] packets={} modbus={} flows={} alerts={} cps_physics={} ml_inferences={} ml_detections={}",
                    total_packets, modbus_packets, flow_table.len(), alerts_generated,
                    cps_alerts_generated, ml_inferences, ml_detections
                );
            } else {
                println!(
                    "[STATS] packets={} modbus={} flows={} alerts={} cps_physics={}",
                    total_packets, modbus_packets, flow_table.len(), alerts_generated,
                    cps_alerts_generated
                );
            }
            last_stats = now;
        }
    }

    // Graceful shutdown: expire all remaining flows and run final ML inference
    println!("\n[SHUTDOWN] Expiring all remaining flows for final ML inference...");
    let remaining = flow_table.expire(Duration::from_secs(0));
    if !remaining.is_empty() {
        info!(flows = remaining.len(), "Final flow expiry");
        if let Some(ref mut clf) = classifier {
            for flow in &remaining {
                if flow.packet_count < 3 {
                    continue;
                }
                let features = extract_cicids_features(flow);
                ml_inferences += 1;
                match clf.predict(&features) {
                    Ok(pred) => {
                        if pred.category != AttackCategory::Normal
                            && pred.confidence >= ml_threshold
                        {
                            ml_detections += 1;
                            let alert = ml_prediction_to_alert(&pred, flow);
                            print_alert(&alert);
                            logger.log_alert(&alert).await?;
                            alerts_generated += 1;
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "ML inference failed for flow");
                    }
                }
            }
        }
    }

    println!(
        "\n[FINAL] packets={} modbus={} alerts={} cps_physics={} ml_inferences={} ml_detections={}",
        total_packets, modbus_packets, alerts_generated, cps_alerts_generated,
        ml_inferences, ml_detections
    );

    Ok(())
}

fn print_alert(alert: &Alert) {
    let severity_str = match alert.severity {
        Severity::Critical => "\x1b[91mCRITICAL\x1b[0m",
        Severity::High => "\x1b[93mHIGH\x1b[0m",
        Severity::Medium => "\x1b[33mMEDIUM\x1b[0m",
        Severity::Low => "\x1b[32mLOW\x1b[0m",
    };
    println!(
        "[ALERT] [{}] {} | {}:{} -> {}:{} | {}",
        severity_str,
        alert.timestamp.format("%H:%M:%S"),
        alert.source_ip.map(|ip| ip.to_string()).unwrap_or_default(),
        alert.source_port.unwrap_or(0),
        alert.dest_ip.map(|ip| ip.to_string()).unwrap_or_default(),
        alert.dest_port.unwrap_or(0),
        alert.description,
    );
}
