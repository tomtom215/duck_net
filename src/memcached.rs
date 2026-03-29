// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Connection timeout in seconds.
const CONNECT_TIMEOUT_SECS: u64 = 10;

/// I/O timeout in seconds.
const IO_TIMEOUT_SECS: u64 = 10;

/// Maximum value size: 1 MiB (Memcached default).
const MAX_VALUE_SIZE: usize = 1024 * 1024;

pub struct MemcachedResult {
    pub success: bool,
    pub value: String,
    pub message: String,
}

/// Validate host for Memcached connections.
fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
}

/// Validate Memcached key: no whitespace, no control characters, max 250 bytes.
fn is_valid_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= 250 && key.bytes().all(|b| b > 0x20 && b < 0x7F)
    // Printable ASCII, no space
}

/// Parse host string: host[:port] (default port 11211).
fn parse_host(host_str: &str) -> Result<(String, u16), String> {
    let (host, port) = if let Some(colon) = host_str.rfind(':') {
        let port: u16 = host_str[colon + 1..]
            .parse()
            .map_err(|_| "Invalid port number")?;
        (host_str[..colon].to_string(), port)
    } else {
        (host_str.to_string(), 11211)
    };

    if !is_valid_host(&host) {
        return Err(format!("Invalid host: {host}"));
    }

    Ok((host, port))
}

/// Connect to Memcached with proper timeouts.
fn connect(host_str: &str) -> Result<BufReader<TcpStream>, String> {
    let (host, port) = parse_host(host_str)?;
    let addr = format!("{host}:{port}");

    let stream = TcpStream::connect_timeout(
        &addr.parse().map_err(|e| format!("Invalid address: {e}"))?,
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
    )
    .map_err(|e| format!("Memcached connection failed: {e}"))?;

    stream
        .set_read_timeout(Some(Duration::from_secs(IO_TIMEOUT_SECS)))
        .map_err(|e| format!("Failed to set timeout: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(IO_TIMEOUT_SECS)))
        .map_err(|e| format!("Failed to set timeout: {e}"))?;

    Ok(BufReader::new(stream))
}

/// GET a value from Memcached using the ASCII protocol.
///
/// Returns the value if found, empty string if not found.
/// Security: validates key format, enforces size limits and timeouts.
pub fn get(host: &str, key: &str) -> MemcachedResult {
    if !is_valid_key(key) {
        return MemcachedResult {
            success: false,
            value: String::new(),
            message: "Invalid key: must be 1-250 printable ASCII characters with no spaces"
                .to_string(),
        };
    }

    match get_inner(host, key) {
        Ok((value, msg)) => MemcachedResult {
            success: true,
            value,
            message: msg,
        },
        Err(e) => MemcachedResult {
            success: false,
            value: String::new(),
            message: e,
        },
    }
}

fn get_inner(host: &str, key: &str) -> Result<(String, String), String> {
    let mut reader = connect(host)?;

    // Send: get <key>\r\n
    let cmd = format!("get {key}\r\n");
    reader
        .get_mut()
        .write_all(cmd.as_bytes())
        .map_err(|e| format!("Memcached write failed: {e}"))?;

    // Response format:
    // VALUE <key> <flags> <bytes>\r\n
    // <data>\r\n
    // END\r\n
    //
    // Or just: END\r\n (key not found)

    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("Memcached read failed: {e}"))?;

    let line = line.trim();

    if line == "END" {
        return Ok((String::new(), "Key not found".to_string()));
    }

    if !line.starts_with("VALUE ") {
        return Err(format!("Unexpected response: {line}"));
    }

    // Parse: VALUE <key> <flags> <bytes>
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        return Err(format!("Malformed VALUE response: {line}"));
    }

    let data_len: usize = parts[3]
        .parse()
        .map_err(|_| format!("Invalid data length: {}", parts[3]))?;

    if data_len > MAX_VALUE_SIZE {
        return Err(format!(
            "Value too large: {data_len} bytes (max {MAX_VALUE_SIZE})"
        ));
    }

    // Read the data + \r\n
    let mut data_buf = vec![0u8; data_len + 2];
    std::io::Read::read_exact(&mut reader, &mut data_buf)
        .map_err(|e| format!("Memcached data read failed: {e}"))?;

    let value = String::from_utf8_lossy(&data_buf[..data_len]).to_string();

    // Read the trailing END\r\n
    let mut end_line = String::new();
    reader
        .read_line(&mut end_line)
        .map_err(|e| format!("Memcached END read failed: {e}"))?;

    Ok((value, "OK".to_string()))
}

/// SET a value in Memcached using the ASCII protocol.
///
/// `ttl` is the expiration time in seconds (0 = never expire).
/// Security: validates key/value, enforces size limits and timeouts.
pub fn set(host: &str, key: &str, value: &str, ttl: u32) -> MemcachedResult {
    if !is_valid_key(key) {
        return MemcachedResult {
            success: false,
            value: String::new(),
            message: "Invalid key: must be 1-250 printable ASCII characters with no spaces"
                .to_string(),
        };
    }

    if value.len() > MAX_VALUE_SIZE {
        return MemcachedResult {
            success: false,
            value: String::new(),
            message: format!(
                "Value too large: {} bytes (max {MAX_VALUE_SIZE})",
                value.len()
            ),
        };
    }

    match set_inner(host, key, value, ttl) {
        Ok(msg) => MemcachedResult {
            success: true,
            value: String::new(),
            message: msg,
        },
        Err(e) => MemcachedResult {
            success: false,
            value: String::new(),
            message: e,
        },
    }
}

fn set_inner(host: &str, key: &str, value: &str, ttl: u32) -> Result<String, String> {
    let mut reader = connect(host)?;
    let data = value.as_bytes();

    // Send: set <key> <flags> <exptime> <bytes>\r\n<data>\r\n
    let cmd = format!("set {key} 0 {ttl} {}\r\n", data.len());
    reader
        .get_mut()
        .write_all(cmd.as_bytes())
        .map_err(|e| format!("Memcached write failed: {e}"))?;
    reader
        .get_mut()
        .write_all(data)
        .map_err(|e| format!("Memcached data write failed: {e}"))?;
    reader
        .get_mut()
        .write_all(b"\r\n")
        .map_err(|e| format!("Memcached write failed: {e}"))?;

    // Read response: STORED\r\n or error
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("Memcached read failed: {e}"))?;

    let line = line.trim();
    if line == "STORED" {
        Ok(format!("Stored {} bytes for key '{key}'", data.len()))
    } else {
        Err(format!("Memcached SET failed: {line}"))
    }
}
