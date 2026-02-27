use tracing::debug;

/// Stub parser for the DNP3 (Distributed Network Protocol 3) protocol.
///
/// DNP3 is widely used in SCADA/ICS systems for communication between control
/// centres and remote terminal units. A full implementation would parse the
/// data-link, transport, and application layers.
///
/// Returns `None` unconditionally while logging that parsing is not yet
/// implemented.
pub fn parse_dnp3(payload: &[u8]) -> Option<()> {
    debug!(
        payload_len = payload.len(),
        "DNP3 parsing not implemented"
    );
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stub_returns_none() {
        assert!(parse_dnp3(&[0x05, 0x64, 0x05]).is_none());
    }
}
