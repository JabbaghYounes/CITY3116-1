use std::net::IpAddr;

use anyhow::{Context, Result};
use chrono::Utc;
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

use ids_common::types::{PacketRecord, Protocol, SecurityEvent, TcpFlags};

use super::protocols::modbus::parse_modbus;

/// Default MODBUS/TCP well-known port.
const DEFAULT_MODBUS_PORT: u16 = 502;

/// Network packet capture engine.
///
/// Wraps a pnet datalink channel and transforms raw Ethernet frames into
/// structured `PacketRecord` values that are sent through a tokio mpsc channel
/// for downstream processing.
pub struct NetworkCapture {
    interface_name: String,
    modbus_ports: Vec<u16>,
}

impl NetworkCapture {
    /// Create a new `NetworkCapture` targeting the given interface name.
    pub fn new(interface: &str) -> Self {
        Self {
            interface_name: interface.to_string(),
            modbus_ports: vec![DEFAULT_MODBUS_PORT],
        }
    }

    /// Create a new `NetworkCapture` with custom Modbus port(s).
    pub fn with_ports(interface: &str, modbus_ports: Vec<u16>) -> Self {
        Self {
            interface_name: interface.to_string(),
            modbus_ports,
        }
    }

    /// Open the datalink channel and begin sending `SecurityEvent::Network`
    /// messages through `tx`.
    ///
    /// This method blocks the calling thread; it is designed to be run inside
    /// `tokio::task::spawn_blocking`.
    pub fn start(interface: &str, tx: mpsc::Sender<SecurityEvent>) -> Result<()> {
        let capture = Self::new(interface);
        capture.run(tx)
    }

    /// Like `start` but with custom Modbus port detection.
    pub fn start_with_ports(interface: &str, modbus_ports: Vec<u16>, tx: mpsc::Sender<SecurityEvent>) -> Result<()> {
        let capture = Self::with_ports(interface, modbus_ports);
        capture.run(tx)
    }

    /// Resolve the named interface.
    fn find_interface(&self) -> Result<NetworkInterface> {
        let interfaces = datalink::interfaces();
        interfaces
            .into_iter()
            .find(|iface| iface.name == self.interface_name)
            .with_context(|| {
                format!(
                    "Network interface '{}' not found. Available: {}",
                    self.interface_name,
                    datalink::interfaces()
                        .iter()
                        .map(|i| i.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
    }

    /// Core capture loop.
    fn run(&self, tx: mpsc::Sender<SecurityEvent>) -> Result<()> {
        let interface = self.find_interface()?;
        info!(
            interface = %interface.name,
            "Opening datalink channel for packet capture"
        );

        let config = datalink::Config {
            read_timeout: Some(std::time::Duration::from_secs(1)),
            ..Default::default()
        };

        let (_tx_chan, mut rx_chan) = match datalink::channel(&interface, config)? {
            Channel::Ethernet(tx_chan, rx_chan) => (tx_chan, rx_chan),
            _ => anyhow::bail!("Unsupported channel type for interface {}", interface.name),
        };

        info!(interface = %interface.name, "Capture started");

        loop {
            match rx_chan.next() {
                Ok(frame) => {
                    if let Some(record) = self.parse_frame_with_ports(frame) {
                        trace!(
                            src = %record.src_ip,
                            dst = %record.dst_ip,
                            proto = ?record.protocol,
                            "Captured packet"
                        );
                        if tx.blocking_send(SecurityEvent::Network(record)).is_err() {
                            debug!("Receiver dropped — stopping capture");
                            break;
                        }
                    }
                }
                Err(e) => {
                    // Read timeouts are expected; only warn on real errors
                    if e.kind() != std::io::ErrorKind::TimedOut {
                        warn!(error = %e, "Error reading from datalink channel");
                    }
                }
            }
        }

        info!("Capture loop terminated");
        Ok(())
    }

    /// Parse a raw Ethernet frame into a `PacketRecord`.
    pub fn parse_frame(frame: &[u8]) -> Option<PacketRecord> {
        Self::parse_frame_for_ports(frame, &[DEFAULT_MODBUS_PORT])
    }

    /// Parse a frame using the instance's configured Modbus ports.
    fn parse_frame_with_ports(&self, frame: &[u8]) -> Option<PacketRecord> {
        Self::parse_frame_for_ports(frame, &self.modbus_ports)
    }

    /// Parse a raw Ethernet frame, detecting Modbus on the given ports.
    fn parse_frame_for_ports(frame: &[u8], modbus_ports: &[u16]) -> Option<PacketRecord> {
        let ethernet = EthernetPacket::new(frame)?;
        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => Self::parse_ipv4_ports(ethernet.payload(), modbus_ports),
            EtherTypes::Ipv6 => Self::parse_ipv6_ports(ethernet.payload(), modbus_ports),
            other => {
                trace!(ethertype = ?other, "Skipping non-IP ethertype");
                None
            }
        }
    }

    /// Parse an IPv4 packet and its transport-layer header.
    #[allow(dead_code)]
    fn parse_ipv4(ip_payload: &[u8]) -> Option<PacketRecord> {
        Self::parse_ipv4_ports(ip_payload, &[DEFAULT_MODBUS_PORT])
    }

    fn parse_ipv4_ports(ip_payload: &[u8], modbus_ports: &[u16]) -> Option<PacketRecord> {
        let ipv4 = Ipv4Packet::new(ip_payload)?;
        let src_ip = IpAddr::V4(ipv4.get_source());
        let dst_ip = IpAddr::V4(ipv4.get_destination());
        let next_proto = ipv4.get_next_level_protocol();
        let transport_payload = ipv4.payload();

        Self::parse_transport_ports(src_ip, dst_ip, next_proto, transport_payload, modbus_ports)
    }

    /// Parse an IPv6 packet and its transport-layer header.
    #[allow(dead_code)]
    fn parse_ipv6(ip_payload: &[u8]) -> Option<PacketRecord> {
        Self::parse_ipv6_ports(ip_payload, &[DEFAULT_MODBUS_PORT])
    }

    fn parse_ipv6_ports(ip_payload: &[u8], modbus_ports: &[u16]) -> Option<PacketRecord> {
        let ipv6 = Ipv6Packet::new(ip_payload)?;
        let src_ip = IpAddr::V6(ipv6.get_source());
        let dst_ip = IpAddr::V6(ipv6.get_destination());
        let next_proto = ipv6.get_next_header();
        let transport_payload = ipv6.payload();

        Self::parse_transport_ports(src_ip, dst_ip, next_proto, transport_payload, modbus_ports)
    }

    /// Parse transport layer (TCP/UDP/ICMP) and build a `PacketRecord`.
    #[allow(dead_code)]
    fn parse_transport(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        next_proto: pnet::packet::ip::IpNextHeaderProtocol,
        transport_payload: &[u8],
    ) -> Option<PacketRecord> {
        Self::parse_transport_ports(src_ip, dst_ip, next_proto, transport_payload, &[DEFAULT_MODBUS_PORT])
    }

    fn parse_transport_ports(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        next_proto: pnet::packet::ip::IpNextHeaderProtocol,
        transport_payload: &[u8],
        modbus_ports: &[u16],
    ) -> Option<PacketRecord> {
        match next_proto {
            IpNextHeaderProtocols::Tcp => {
                let tcp = TcpPacket::new(transport_payload)?;
                let src_port = tcp.get_source();
                let dst_port = tcp.get_destination();
                let payload = tcp.payload().to_vec();
                let flags = TcpFlags {
                    syn: (tcp.get_flags() & pnet::packet::tcp::TcpFlags::SYN) != 0,
                    ack: (tcp.get_flags() & pnet::packet::tcp::TcpFlags::ACK) != 0,
                    fin: (tcp.get_flags() & pnet::packet::tcp::TcpFlags::FIN) != 0,
                    rst: (tcp.get_flags() & pnet::packet::tcp::TcpFlags::RST) != 0,
                    psh: (tcp.get_flags() & pnet::packet::tcp::TcpFlags::PSH) != 0,
                    urg: (tcp.get_flags() & pnet::packet::tcp::TcpFlags::URG) != 0,
                };

                // Detect Modbus/TCP by configured ports
                let is_modbus_port = modbus_ports.iter().any(|p| dst_port == *p || src_port == *p);
                let protocol = if is_modbus_port {
                    if let Some(_modbus_info) = parse_modbus(&payload) {
                        Protocol::Modbus
                    } else {
                        Protocol::Tcp
                    }
                } else {
                    Protocol::Tcp
                };

                Some(PacketRecord {
                    timestamp: Utc::now(),
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    protocol,
                    payload_len: payload.len(),
                    tcp_flags: Some(flags),
                    raw_payload: payload,
                })
            }
            IpNextHeaderProtocols::Udp => {
                let udp = UdpPacket::new(transport_payload)?;
                let payload = udp.payload().to_vec();

                Some(PacketRecord {
                    timestamp: Utc::now(),
                    src_ip,
                    dst_ip,
                    src_port: udp.get_source(),
                    dst_port: udp.get_destination(),
                    protocol: Protocol::Udp,
                    payload_len: payload.len(),
                    tcp_flags: None,
                    raw_payload: payload,
                })
            }
            IpNextHeaderProtocols::Icmp | IpNextHeaderProtocols::Icmpv6 => {
                let payload = transport_payload.to_vec();
                Some(PacketRecord {
                    timestamp: Utc::now(),
                    src_ip,
                    dst_ip,
                    src_port: 0,
                    dst_port: 0,
                    protocol: Protocol::Icmp,
                    payload_len: payload.len(),
                    tcp_flags: None,
                    raw_payload: payload,
                })
            }
            other => {
                error!(protocol = other.0, "Unsupported transport protocol");
                let payload = transport_payload.to_vec();
                Some(PacketRecord {
                    timestamp: Utc::now(),
                    src_ip,
                    dst_ip,
                    src_port: 0,
                    dst_port: 0,
                    protocol: Protocol::Other(other.0),
                    payload_len: payload.len(),
                    tcp_flags: None,
                    raw_payload: payload,
                })
            }
        }
    }
}
