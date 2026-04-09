// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::net::UdpSocket;
use std::time::Duration;

/// STUN magic cookie (RFC 5389).
const MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN message types.
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;

/// STUN attribute types.
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// Default STUN port.
const STUN_PORT: u16 = 3478;

/// Timeout in seconds.
const TIMEOUT_SECS: u64 = 5;

pub struct StunResult {
    pub success: bool,
    pub public_ip: String,
    pub public_port: u16,
    pub message: String,
}

/// Validate STUN server hostname.
fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
}

/// Perform a STUN Binding Request to discover the public IP and port.
///
/// Sends a single UDP packet to the STUN server and parses the
/// XOR-MAPPED-ADDRESS (or MAPPED-ADDRESS) from the response.
///
/// Security: validates server hostname, enforces timeouts,
/// validates response transaction ID to prevent spoofing.
pub fn lookup(server: &str) -> StunResult {
    let (host, port) = parse_server(server);

    if !is_valid_host(&host) {
        return StunResult {
            success: false,
            public_ip: String::new(),
            public_port: 0,
            message: "Invalid STUN server hostname".to_string(),
        };
    }

    let r = match lookup_inner(&host, port) {
        Ok(r) => r,
        Err(e) => StunResult {
            success: false,
            public_ip: String::new(),
            public_port: 0,
            message: e,
        },
    };
    crate::audit_log::record(
        "stun",
        "lookup",
        &host,
        r.success,
        r.public_port as i32,
        &r.message,
    );
    r
}

/// Parse server string: host[:port] (default port 3478).
fn parse_server(server: &str) -> (String, u16) {
    // Strip stun:// prefix if present
    let s = server.strip_prefix("stun://").unwrap_or(server);

    if let Some(colon) = s.rfind(':') {
        if let Ok(port) = s[colon + 1..].parse::<u16>() {
            return (s[..colon].to_string(), port);
        }
    }
    (s.to_string(), STUN_PORT)
}

fn lookup_inner(host: &str, port: u16) -> Result<StunResult, String> {
    // Atomic resolve-and-validate (closes UDP DNS-rebinding TOCTOU, CWE-918).
    let addr = crate::security::resolve_and_validate_udp(host, port)?;

    let bind_addr = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket =
        UdpSocket::bind(bind_addr).map_err(|e| format!("Failed to bind UDP socket: {e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(TIMEOUT_SECS)))
        .map_err(|e| format!("Failed to set timeout: {e}"))?;

    // Generate random 12-byte transaction ID
    let transaction_id = random_transaction_id();

    // Build STUN Binding Request
    let mut request = Vec::with_capacity(20);

    // Message Type: Binding Request (0x0001)
    request.extend_from_slice(&BINDING_REQUEST.to_be_bytes());

    // Message Length: 0 (no attributes)
    request.extend_from_slice(&0u16.to_be_bytes());

    // Magic Cookie
    request.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());

    // Transaction ID (12 bytes)
    request.extend_from_slice(&transaction_id);

    socket
        .send_to(&request, addr)
        .map_err(|e| format!("STUN send failed: {e}"))?;

    // Receive response
    let mut buf = [0u8; 548]; // Max STUN message size
    let (size, _) = socket
        .recv_from(&mut buf)
        .map_err(|e| format!("STUN receive failed: {e}"))?;

    if size < 20 {
        return Err(format!("STUN response too short: {size} bytes"));
    }

    // Validate response
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    let msg_length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

    if msg_type != BINDING_RESPONSE {
        return Err(format!("Expected Binding Response, got 0x{msg_type:04x}"));
    }

    if cookie != MAGIC_COOKIE {
        return Err("Invalid magic cookie in STUN response".to_string());
    }

    // Verify transaction ID
    if buf[8..20] != transaction_id {
        return Err("STUN transaction ID mismatch (possible spoofing)".to_string());
    }

    if 20 + msg_length > size {
        return Err("STUN response truncated".to_string());
    }

    // Parse attributes
    let mut offset = 20;
    let end = 20 + msg_length;

    while offset + 4 <= end {
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let attr_length = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        offset += 4;

        if offset + attr_length > end {
            break;
        }

        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => {
                if let Some((ip, port)) =
                    parse_xor_mapped_address(&buf[offset..offset + attr_length], &transaction_id)
                {
                    return Ok(StunResult {
                        success: true,
                        public_ip: ip,
                        public_port: port,
                        message: "OK".to_string(),
                    });
                }
            }
            ATTR_MAPPED_ADDRESS => {
                if let Some((ip, port)) = parse_mapped_address(&buf[offset..offset + attr_length]) {
                    return Ok(StunResult {
                        success: true,
                        public_ip: ip,
                        public_port: port,
                        message: "OK".to_string(),
                    });
                }
            }
            _ => {}
        }

        // Pad to 4-byte boundary
        offset += (attr_length + 3) & !3;
    }

    Err("No MAPPED-ADDRESS found in STUN response".to_string())
}

/// Parse XOR-MAPPED-ADDRESS attribute (RFC 5389 section 15.2).
fn parse_xor_mapped_address(data: &[u8], transaction_id: &[u8; 12]) -> Option<(String, u16)> {
    if data.len() < 8 {
        return None;
    }

    let family = data[1];
    let x_port = u16::from_be_bytes([data[2], data[3]]);
    let port = x_port ^ (MAGIC_COOKIE >> 16) as u16;

    match family {
        0x01 => {
            // IPv4
            let x_addr = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            let addr = x_addr ^ MAGIC_COOKIE;
            let ip = format!(
                "{}.{}.{}.{}",
                (addr >> 24) & 0xFF,
                (addr >> 16) & 0xFF,
                (addr >> 8) & 0xFF,
                addr & 0xFF
            );
            Some((ip, port))
        }
        0x02 => {
            // IPv6
            if data.len() < 20 {
                return None;
            }
            let mut addr_bytes = [0u8; 16];
            addr_bytes.copy_from_slice(&data[4..20]);

            // XOR with magic cookie + transaction ID
            let magic = MAGIC_COOKIE.to_be_bytes();
            for i in 0..4 {
                addr_bytes[i] ^= magic[i];
            }
            for i in 0..12 {
                addr_bytes[4 + i] ^= transaction_id[i];
            }

            let ip = format!(
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                u16::from_be_bytes([addr_bytes[0], addr_bytes[1]]),
                u16::from_be_bytes([addr_bytes[2], addr_bytes[3]]),
                u16::from_be_bytes([addr_bytes[4], addr_bytes[5]]),
                u16::from_be_bytes([addr_bytes[6], addr_bytes[7]]),
                u16::from_be_bytes([addr_bytes[8], addr_bytes[9]]),
                u16::from_be_bytes([addr_bytes[10], addr_bytes[11]]),
                u16::from_be_bytes([addr_bytes[12], addr_bytes[13]]),
                u16::from_be_bytes([addr_bytes[14], addr_bytes[15]]),
            );
            Some((ip, port))
        }
        _ => None,
    }
}

/// Parse MAPPED-ADDRESS attribute (RFC 5389 section 15.1).
fn parse_mapped_address(data: &[u8]) -> Option<(String, u16)> {
    if data.len() < 8 {
        return None;
    }

    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]);

    match family {
        0x01 => {
            let ip = format!("{}.{}.{}.{}", data[4], data[5], data[6], data[7]);
            Some((ip, port))
        }
        0x02 if data.len() >= 20 => {
            let ip = format!(
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                u16::from_be_bytes([data[4], data[5]]),
                u16::from_be_bytes([data[6], data[7]]),
                u16::from_be_bytes([data[8], data[9]]),
                u16::from_be_bytes([data[10], data[11]]),
                u16::from_be_bytes([data[12], data[13]]),
                u16::from_be_bytes([data[14], data[15]]),
                u16::from_be_bytes([data[16], data[17]]),
                u16::from_be_bytes([data[18], data[19]]),
            );
            Some((ip, port))
        }
        _ => None,
    }
}

/// Generate a random 12-byte transaction ID using cryptographically secure OS entropy.
fn random_transaction_id() -> [u8; 12] {
    crate::security::random_bytes::<12>()
}
