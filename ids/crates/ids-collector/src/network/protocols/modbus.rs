use ids_common::types::ModbusInfo;
use tracing::trace;

/// Minimum MBAP header size (7 bytes) plus function code (1 byte).
const MBAP_HEADER_LEN: usize = 7;
const MIN_MODBUS_PDU: usize = MBAP_HEADER_LEN + 1; // 8 bytes

/// Parse a Modbus/TCP frame from the TCP payload.
///
/// Layout of the MBAP (Modbus Application Protocol) header:
///   Bytes 0-1: Transaction ID
///   Bytes 2-3: Protocol ID (must be 0x0000 for Modbus)
///   Bytes 4-5: Length (remaining bytes including unit ID)
///   Byte  6:   Unit ID
///   Byte  7:   Function code
///   Bytes 8+:  Data (varies by function code)
pub fn parse_modbus(payload: &[u8]) -> Option<ModbusInfo> {
    if payload.len() < MIN_MODBUS_PDU {
        trace!(
            payload_len = payload.len(),
            "Modbus payload too short for MBAP header + function code"
        );
        return None;
    }

    let transaction_id = u16::from_be_bytes([payload[0], payload[1]]);
    let protocol_id = u16::from_be_bytes([payload[2], payload[3]]);
    let _length = u16::from_be_bytes([payload[4], payload[5]]);
    let unit_id = payload[6];
    let function_code = payload[7];

    // Protocol ID must be 0 for Modbus/TCP
    if protocol_id != 0 {
        trace!(
            protocol_id,
            "MBAP protocol identifier is not 0x0000 — not a Modbus frame"
        );
        return None;
    }

    // Function codes >= 0x80 indicate exception responses
    let is_response = function_code >= 0x80;
    let base_fc = if is_response {
        function_code & 0x7F
    } else {
        function_code
    };

    // Try to extract register address and value for common function codes.
    // The data portion starts at byte 8.
    let data = &payload[8..];
    let (register_address, register_value) = extract_register_info(base_fc, data, is_response);

    trace!(
        transaction_id,
        unit_id,
        function_code,
        is_response,
        ?register_address,
        ?register_value,
        "Parsed Modbus frame"
    );

    Some(ModbusInfo {
        transaction_id,
        unit_id,
        function_code,
        register_address,
        register_value,
        is_response,
    })
}

/// Extract register address and value from the Modbus data portion based on
/// the function code.
///
/// Request formats for common function codes:
///   FC 01-04 (Read): [addr_hi, addr_lo, qty_hi, qty_lo]
///   FC 05 (Write Single Coil): [addr_hi, addr_lo, val_hi, val_lo]
///   FC 06 (Write Single Register): [addr_hi, addr_lo, val_hi, val_lo]
///   FC 15/16 (Write Multiple): [addr_hi, addr_lo, qty_hi, qty_lo, byte_count, data...]
///
/// Response formats vary but for write-single the echo is the same layout.
fn extract_register_info(
    base_fc: u8,
    data: &[u8],
    is_response: bool,
) -> (Option<u16>, Option<u16>) {
    match base_fc {
        // Read Coils / Discrete Inputs / Holding Registers / Input Registers
        0x01 | 0x02 | 0x03 | 0x04 => {
            if is_response {
                // Response: [byte_count, data...] — no address available
                (None, None)
            } else if data.len() >= 4 {
                let addr = u16::from_be_bytes([data[0], data[1]]);
                // quantity rather than value, but still useful context
                let qty = u16::from_be_bytes([data[2], data[3]]);
                (Some(addr), Some(qty))
            } else {
                (None, None)
            }
        }
        // Write Single Coil / Write Single Register
        0x05 | 0x06 => {
            if data.len() >= 4 {
                let addr = u16::from_be_bytes([data[0], data[1]]);
                let val = u16::from_be_bytes([data[2], data[3]]);
                (Some(addr), Some(val))
            } else {
                (None, None)
            }
        }
        // Write Multiple Coils / Write Multiple Registers
        0x0F | 0x10 => {
            if data.len() >= 4 {
                let addr = u16::from_be_bytes([data[0], data[1]]);
                let qty = u16::from_be_bytes([data[2], data[3]]);
                (Some(addr), Some(qty))
            } else {
                (None, None)
            }
        }
        _ => (None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_read_holding_registers_request() {
        // MBAP: transaction_id=1, protocol_id=0, length=6, unit_id=1
        // FC 0x03, start_addr=0x0000, quantity=0x000A
        let payload: Vec<u8> = vec![
            0x00, 0x01, // transaction id
            0x00, 0x00, // protocol id
            0x00, 0x06, // length
            0x01, // unit id
            0x03, // function code: read holding registers
            0x00, 0x00, // start address
            0x00, 0x0A, // quantity
        ];
        let info = parse_modbus(&payload).expect("should parse");
        assert_eq!(info.transaction_id, 1);
        assert_eq!(info.unit_id, 1);
        assert_eq!(info.function_code, 0x03);
        assert!(!info.is_response);
        assert_eq!(info.register_address, Some(0));
        assert_eq!(info.register_value, Some(10));
    }

    #[test]
    fn test_parse_write_single_register() {
        let payload: Vec<u8> = vec![
            0x00, 0x02, // transaction id
            0x00, 0x00, // protocol id
            0x00, 0x06, // length
            0x01, // unit id
            0x06, // function code: write single register
            0x00, 0x01, // register address
            0x00, 0x03, // register value
        ];
        let info = parse_modbus(&payload).expect("should parse");
        assert_eq!(info.function_code, 0x06);
        assert_eq!(info.register_address, Some(1));
        assert_eq!(info.register_value, Some(3));
    }

    #[test]
    fn test_reject_non_modbus_protocol_id() {
        let payload: Vec<u8> = vec![
            0x00, 0x01, 0x00, 0x01, // protocol id = 1 (not Modbus)
            0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A,
        ];
        assert!(parse_modbus(&payload).is_none());
    }

    #[test]
    fn test_payload_too_short() {
        let payload: Vec<u8> = vec![0x00; 7]; // exactly 7, need 8
        assert!(parse_modbus(&payload).is_none());
    }
}
