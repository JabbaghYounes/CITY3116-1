use std::path::Path;

use anyhow::{Context, Result};
use chrono::Utc;
use pcap_file::pcap::PcapReader;
use pnet::packet::ethernet::EthernetPacket;

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use ids_common::types::SecurityEvent;

use super::capture::NetworkCapture;

/// Replay a PCAP file, parsing each frame and sending the resulting
/// `SecurityEvent::Network` records through the provided channel.
///
/// This enables offline analysis of previously captured traffic using the same
/// pipeline as live capture.
pub async fn replay_pcap(path: &Path, tx: mpsc::Sender<SecurityEvent>) -> Result<()> {
    let display_path = path.display().to_string();
    info!(path = %display_path, "Starting PCAP replay");

    let file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open PCAP file: {}", display_path))?;

    let mut reader = PcapReader::new(file)
        .with_context(|| format!("Failed to parse PCAP header: {}", display_path))?;

    let mut total_packets: u64 = 0;
    let mut parsed_packets: u64 = 0;

    while let Some(pkt_result) = reader.next_packet() {
        let pkt = match pkt_result {
            Ok(pkt) => pkt,
            Err(e) => {
                warn!(error = %e, "Error reading packet from PCAP, skipping");
                continue;
            }
        };

        total_packets += 1;

        // The raw data in the PCAP record is the full Ethernet frame.
        let frame_data = pkt.data.as_ref();

        // Verify we have a valid Ethernet frame before parsing.
        if EthernetPacket::new(frame_data).is_none() {
            debug!(
                packet_num = total_packets,
                len = frame_data.len(),
                "Frame too short for Ethernet header, skipping"
            );
            continue;
        }

        if let Some(mut record) = NetworkCapture::parse_frame(frame_data) {
            // Override the timestamp with the PCAP record's original capture
            // time so that flow analysis preserves temporal relationships.
            // pcap-file provides timestamps as seconds + microseconds from
            // epoch via ts_sec / ts_usec (or ts_nsec for nanosecond resolution).
            let ts_secs = pkt.timestamp.as_secs() as i64;
            let ts_nanos = pkt.timestamp.subsec_nanos();
            if let Some(dt) = chrono::DateTime::from_timestamp(ts_secs, ts_nanos) {
                record.timestamp = dt;
            } else {
                record.timestamp = Utc::now();
            }

            parsed_packets += 1;

            if tx.send(SecurityEvent::Network(record)).await.is_err() {
                debug!("Receiver dropped — stopping PCAP replay");
                break;
            }
        }
    }

    info!(
        path = %display_path,
        total_packets,
        parsed_packets,
        "PCAP replay complete"
    );

    Ok(())
}
