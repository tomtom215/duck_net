// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::net::UdpSocket;
use std::time::Duration;

/// RADIUS default port.
const RADIUS_PORT: u16 = 1812;

/// RADIUS timeout in seconds.
const TIMEOUT_SECS: u64 = 10;

/// Maximum RADIUS packet size per RFC 2865.
const MAX_PACKET_SIZE: usize = 4096;

/// RADIUS packet codes.
const ACCESS_REQUEST: u8 = 1;
const ACCESS_ACCEPT: u8 = 2;
const ACCESS_REJECT: u8 = 3;

/// RADIUS attribute types.
const ATTR_USER_NAME: u8 = 1;
const ATTR_USER_PASSWORD: u8 = 2;
const ATTR_NAS_IP_ADDRESS: u8 = 4;

pub struct RadiusResult {
    pub success: bool,
    pub code: i32,
    pub code_name: String,
    pub message: String,
}

/// Validate host for RADIUS connections.
fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
}

/// Perform RADIUS Access-Request authentication.
///
/// Tests authentication credentials against a RADIUS server.
/// Uses the RADIUS protocol (RFC 2865) over UDP.
///
/// Security:
/// - Validates all inputs before sending
/// - Uses random authenticator for each request
/// - Verifies response authenticator to prevent spoofing
/// - Password encrypted per RFC 2865 section 5.2
/// - Enforces timeouts to prevent hanging
pub fn auth(host: &str, port: u16, secret: &str, username: &str, password: &str) -> RadiusResult {
    if !is_valid_host(host) {
        return RadiusResult {
            success: false,
            code: -1,
            code_name: String::new(),
            message: "Invalid host".to_string(),
        };
    }

    if secret.is_empty() {
        return RadiusResult {
            success: false,
            code: -1,
            code_name: String::new(),
            message: "Shared secret cannot be empty".to_string(),
        };
    }

    if username.is_empty() {
        return RadiusResult {
            success: false,
            code: -1,
            code_name: String::new(),
            message: "Username cannot be empty".to_string(),
        };
    }

    if username.len() > 253 {
        return RadiusResult {
            success: false,
            code: -1,
            code_name: String::new(),
            message: "Username too long (max 253)".to_string(),
        };
    }

    // Atomic resolve-and-validate performed inside auth_inner to close UDP
    // DNS-rebinding TOCTOU (CWE-918).
    match auth_inner(host, port, secret, username, password) {
        Ok(r) => r,
        Err(e) => RadiusResult {
            success: false,
            code: -1,
            code_name: String::new(),
            message: e,
        },
    }
}

/// Convenience wrapper using default port.
pub fn auth_default_port(host: &str, secret: &str, username: &str, password: &str) -> RadiusResult {
    auth(host, RADIUS_PORT, secret, username, password)
}

fn auth_inner(
    host: &str,
    port: u16,
    secret: &str,
    username: &str,
    password: &str,
) -> Result<RadiusResult, String> {
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

    // Generate cryptographically secure random authenticator (16 bytes)
    let authenticator = crate::security::random_bytes::<16>();

    // Generate random identifier
    let identifier = crate::security::random_bytes::<1>()[0];

    // Build Access-Request packet
    let mut attributes = Vec::new();

    // User-Name attribute
    add_attribute(&mut attributes, ATTR_USER_NAME, username.as_bytes());

    // User-Password attribute (encrypted per RFC 2865 section 5.2)
    let encrypted_password = encrypt_password(secret, &authenticator, password);
    add_attribute(&mut attributes, ATTR_USER_PASSWORD, &encrypted_password);

    // NAS-IP-Address (0.0.0.0 - let server determine)
    add_attribute(&mut attributes, ATTR_NAS_IP_ADDRESS, &[0, 0, 0, 0]);

    // Build full packet
    let total_length = 20 + attributes.len(); // 1 code + 1 id + 2 len + 16 auth + attrs
    if total_length > MAX_PACKET_SIZE {
        return Err("RADIUS packet too large".to_string());
    }

    let mut packet = Vec::with_capacity(total_length);
    packet.push(ACCESS_REQUEST);
    packet.push(identifier);
    packet.extend_from_slice(&(total_length as u16).to_be_bytes());
    packet.extend_from_slice(&authenticator);
    packet.extend_from_slice(&attributes);

    // Send request
    socket
        .send_to(&packet, addr)
        .map_err(|e| format!("RADIUS send failed: {e}"))?;

    // Receive response
    let mut response = [0u8; MAX_PACKET_SIZE];
    let (size, _) = socket
        .recv_from(&mut response)
        .map_err(|e| format!("RADIUS receive failed: {e}"))?;

    if size < 20 {
        return Err(format!("RADIUS response too short: {size} bytes"));
    }

    // Validate response
    let resp_code = response[0];
    let resp_id = response[1];
    let resp_length = u16::from_be_bytes([response[2], response[3]]) as usize;

    if resp_id != identifier {
        return Err(format!(
            "RADIUS response ID mismatch: expected {identifier}, got {resp_id}"
        ));
    }

    if resp_length > size {
        return Err("RADIUS response length exceeds received data".to_string());
    }

    // Verify response authenticator (RFC 2865 section 3)
    // ResponseAuth = MD5(Code + ID + Length + RequestAuth + Attributes + Secret)
    let mut verify_buf = Vec::new();
    verify_buf.push(resp_code);
    verify_buf.push(resp_id);
    verify_buf.extend_from_slice(&(resp_length as u16).to_be_bytes());
    verify_buf.extend_from_slice(&authenticator); // Request authenticator
    verify_buf.extend_from_slice(&response[20..resp_length]); // Attributes
    verify_buf.extend_from_slice(secret.as_bytes());

    let expected_auth = md5::compute(&verify_buf);
    let actual_auth = &response[4..20];

    if actual_auth != &expected_auth[..] {
        return Err(
            "RADIUS response authenticator verification failed (possible spoofing)".to_string(),
        );
    }

    let (code_name, success) = match resp_code {
        ACCESS_ACCEPT => ("Access-Accept".to_string(), true),
        ACCESS_REJECT => ("Access-Reject".to_string(), false),
        11 => ("Access-Challenge".to_string(), false),
        _ => (format!("Unknown({})", resp_code), false),
    };

    Ok(RadiusResult {
        success,
        code: resp_code as i32,
        code_name,
        message: if success {
            "Authentication successful".to_string()
        } else {
            "Authentication failed".to_string()
        },
    })
}

/// Encrypt password per RFC 2865 section 5.2.
///
/// The password is padded to 16-byte boundary, then XOR'd with
/// MD5(secret + authenticator) blocks.
fn encrypt_password(secret: &str, authenticator: &[u8; 16], password: &str) -> Vec<u8> {
    let pass_bytes = password.as_bytes();

    // Pad to 16-byte boundary (max 128 bytes per RFC 2865)
    let padded_len = pass_bytes.len().max(1).div_ceil(16) * 16;
    let padded_len = padded_len.min(128);
    let mut padded = vec![0u8; padded_len];
    let copy_len = pass_bytes.len().min(padded_len);
    padded[..copy_len].copy_from_slice(&pass_bytes[..copy_len]);

    let mut result = Vec::with_capacity(padded_len);
    let mut prev_block = authenticator.to_vec();

    for chunk in padded.chunks(16) {
        // b_i = MD5(secret + prev_block)
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(secret.as_bytes());
        hash_input.extend_from_slice(&prev_block);
        let hash = md5::compute(&hash_input);

        // c_i = p_i XOR b_i
        let encrypted: Vec<u8> = chunk.iter().zip(hash.iter()).map(|(p, h)| p ^ h).collect();

        prev_block = encrypted.clone();
        result.extend_from_slice(&encrypted);
    }

    result
}

/// Add a RADIUS attribute to the attribute buffer.
fn add_attribute(buf: &mut Vec<u8>, attr_type: u8, value: &[u8]) {
    let length = 2 + value.len();
    buf.push(attr_type);
    buf.push(length as u8);
    buf.extend_from_slice(value);
}
