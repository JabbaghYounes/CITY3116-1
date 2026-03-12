use tracing::debug;

/// Stub parser for the OPC UA (Open Platform Communications Unified
/// Architecture) protocol.
///
/// OPC UA is a machine-to-machine communication protocol for industrial
/// automation developed by the OPC Foundation. A full implementation would
/// parse OPC UA binary/XML encoded messages.
///
/// Returns `None` unconditionally while logging that parsing is not yet
/// implemented.
pub fn parse_opcua(payload: &[u8]) -> Option<()> {
    debug!(
        payload_len = payload.len(),
        "OPC UA parsing not implemented"
    );
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stub_returns_none() {
        assert!(parse_opcua(&[0x48, 0x45, 0x4C]).is_none());
    }
}
