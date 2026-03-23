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

use std::path::PathBuf;
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
        model_source: "cnn-lstm/model-b".into(),
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

    // Write rate tracking
    let mut write_tracker = WriteTracker::new(10);
    let write_threshold = cli.write_freq_threshold;
    let ml_threshold = cli.ml_threshold;

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
    println!("========================================");
    println!();

    // Main event loop
    while let Some(event) = rx.recv().await {
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
                }

                // Detect reads at unusually high rates (flood)
                if matches!(fc, 0x01 | 0x02 | 0x03 | 0x04) {
                    // Check if this flow has high packet count (potential flood)
                    if let Some(flow) = flow_table.get_active_flows()
                        .into_iter()
                        .find(|f| f.key.src_ip == packet.src_ip && f.key.dst_ip == packet.dst_ip)
                    {
                        let duration_secs = (flow.last_time - flow.start_time)
                            .num_milliseconds().max(1) as f64 / 1000.0;
                        let pps = flow.packet_count as f64 / duration_secs;
                        if pps > 50.0 && flow.packet_count > 20 {
                            let alert = modbus_event_alert(
                                &packet,
                                format!("Modbus read flood: {:.0} packets/sec ({} total packets)",
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
        if (now - last_expire).num_seconds() > 10 {
            let expired = flow_table.expire(flow_timeout);
            if !expired.is_empty() {
                info!(expired = expired.len(), "Expired idle flows");

                // Run ML inference on expired flows
                if let Some(ref mut clf) = classifier {
                    for flow in &expired {
                        // Skip flows with too few packets (not enough data)
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
            last_expire = now;
        }

        // Periodic stats
        if (now - last_stats).num_seconds() > 15 {
            if classifier.is_some() {
                println!(
                    "[STATS] packets={} modbus={} flows={} alerts={} ml_inferences={} ml_detections={}",
                    total_packets, modbus_packets, flow_table.len(), alerts_generated,
                    ml_inferences, ml_detections
                );
            } else {
                println!(
                    "[STATS] packets={} modbus={} flows={} alerts={}",
                    total_packets, modbus_packets, flow_table.len(), alerts_generated
                );
            }
            last_stats = now;
        }
    }

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
