use std::collections::HashMap;
use std::time::Duration;

use chrono::Utc;
use tracing::{debug, trace};

use ids_common::types::{FlowKey, FlowRecord, PacketRecord};

/// Flow tracking table that aggregates individual packets into bidirectional
/// flow records.
///
/// Each unique 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol) maps to
/// a `FlowRecord` that accumulates statistics such as packet counts, byte
/// counts, inter-arrival times, and TCP flags.
pub struct FlowTable {
    flows: HashMap<FlowKey, FlowRecord>,
}

impl FlowTable {
    /// Create an empty flow table.
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
        }
    }

    /// Update the flow table with a new packet.
    ///
    /// If a matching flow already exists the record is updated with new
    /// counters; otherwise a new flow is created. The forward/backward
    /// direction is determined by comparing the packet's source to the flow
    /// key's source.
    pub fn update(&mut self, packet: &PacketRecord) {
        let forward_key = FlowKey {
            src_ip: packet.src_ip,
            dst_ip: packet.dst_ip,
            src_port: packet.src_port,
            dst_port: packet.dst_port,
            protocol: packet.protocol,
        };

        let reverse_key = FlowKey {
            src_ip: packet.dst_ip,
            dst_ip: packet.src_ip,
            src_port: packet.dst_port,
            dst_port: packet.src_port,
            protocol: packet.protocol,
        };

        // Determine which key exists or create a new forward flow.
        let (key, is_forward) = if self.flows.contains_key(&forward_key) {
            (forward_key, true)
        } else if self.flows.contains_key(&reverse_key) {
            (reverse_key, false)
        } else {
            // New flow — always stored under the forward key.
            (forward_key, true)
        };

        let now = packet.timestamp;
        let pkt_size = packet.payload_len;

        let flow = self.flows.entry(key.clone()).or_insert_with(|| {
            trace!(
                src = %key.src_ip,
                dst = %key.dst_ip,
                src_port = key.src_port,
                dst_port = key.dst_port,
                proto = ?key.protocol,
                "New flow created"
            );
            FlowRecord {
                key: key.clone(),
                start_time: now,
                last_time: now,
                packet_count: 0,
                byte_count: 0,
                fwd_packet_count: 0,
                bwd_packet_count: 0,
                packet_sizes: Vec::new(),
                inter_arrival_times_us: Vec::new(),
                tcp_flags_seen: Vec::new(),
            }
        });

        // Compute inter-arrival time relative to the last packet in this flow.
        let iat_us = (now - flow.last_time).num_microseconds().unwrap_or(0);
        flow.inter_arrival_times_us.push(iat_us);

        flow.last_time = now;
        flow.packet_count += 1;
        flow.byte_count += pkt_size as u64;
        flow.packet_sizes.push(pkt_size);

        if is_forward {
            flow.fwd_packet_count += 1;
        } else {
            flow.bwd_packet_count += 1;
        }

        if let Some(flags) = &packet.tcp_flags {
            flow.tcp_flags_seen.push(*flags);
        }
    }

    /// Expire flows that have been idle for longer than `timeout`.
    ///
    /// Returns the expired flow records (useful for feature extraction on
    /// completed flows) and removes them from the table.
    pub fn expire(&mut self, timeout: Duration) -> Vec<FlowRecord> {
        let now = Utc::now();
        let timeout_chrono = chrono::Duration::from_std(timeout)
            .unwrap_or_else(|_| chrono::Duration::seconds(60));

        let mut expired = Vec::new();
        self.flows.retain(|_key, flow| {
            if now - flow.last_time > timeout_chrono {
                debug!(
                    src = %flow.key.src_ip,
                    dst = %flow.key.dst_ip,
                    packets = flow.packet_count,
                    "Expiring idle flow"
                );
                expired.push(flow.clone());
                false
            } else {
                true
            }
        });

        expired
    }

    /// Return references to all currently active (non-expired) flows.
    pub fn get_active_flows(&self) -> Vec<&FlowRecord> {
        self.flows.values().collect()
    }

    /// Return the number of flows currently tracked.
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// Returns true if no flows are tracked.
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
}

impl Default for FlowTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ids_common::types::Protocol;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_packet(src_port: u16, dst_port: u16) -> PacketRecord {
        PacketRecord {
            timestamp: Utc::now(),
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port,
            dst_port,
            protocol: Protocol::Tcp,
            payload_len: 100,
            tcp_flags: None,
            raw_payload: vec![0u8; 100],
        }
    }

    #[test]
    fn test_new_flow_created() {
        let mut table = FlowTable::new();
        assert!(table.is_empty());

        table.update(&make_packet(12345, 80));
        assert_eq!(table.len(), 1);
        let flows = table.get_active_flows();
        assert_eq!(flows[0].packet_count, 1);
        assert_eq!(flows[0].fwd_packet_count, 1);
    }

    #[test]
    fn test_bidirectional_flow() {
        let mut table = FlowTable::new();

        // Forward packet
        let mut pkt = make_packet(12345, 80);
        table.update(&pkt);

        // Reverse packet (reply)
        pkt.src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        pkt.dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        pkt.src_port = 80;
        pkt.dst_port = 12345;
        table.update(&pkt);

        // Should still be one flow
        assert_eq!(table.len(), 1);
        let flows = table.get_active_flows();
        assert_eq!(flows[0].packet_count, 2);
        assert_eq!(flows[0].fwd_packet_count, 1);
        assert_eq!(flows[0].bwd_packet_count, 1);
    }

    #[test]
    fn test_expire_flows() {
        let mut table = FlowTable::new();
        table.update(&make_packet(12345, 80));

        // Expire with zero timeout -> all flows should expire
        let expired = table.expire(Duration::from_secs(0));
        assert_eq!(expired.len(), 1);
        assert!(table.is_empty());
    }
}
