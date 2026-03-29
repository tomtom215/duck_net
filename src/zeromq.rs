// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Connection timeout in seconds.
const CONNECT_TIMEOUT_SECS: u64 = 10;

/// I/O timeout in seconds.
const IO_TIMEOUT_SECS: u64 = 10;

/// Maximum response size: 16 MiB.
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// ZMTP/3.0 greeting size in bytes.
const GREETING_SIZE: usize = 64;

/// ZMTP frame flag bits.
const FLAG_MORE: u8 = 0x01;
const FLAG_LONG: u8 = 0x02;
const FLAG_COMMAND: u8 = 0x04;

pub struct ZmqResult {
    pub success: bool,
    pub response: String,
    pub message: String,
}

/// Validate ZeroMQ endpoint host.
fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
}

/// Parse ZeroMQ TCP endpoint: `tcp://host:port`.
/// Returns (host, port).
fn parse_zmq_endpoint(endpoint: &str) -> Result<(String, u16), String> {
    let rest = endpoint
        .strip_prefix("tcp://")
        .ok_or_else(|| format!("Invalid ZMQ endpoint: must start with tcp:// (got '{endpoint}')"))?;

    let colon = rest
        .rfind(':')
        .ok_or_else(|| "Invalid ZMQ endpoint: missing port".to_string())?;

    let host = rest[..colon].to_string();
    let port: u16 = rest[colon + 1..]
        .parse()
        .map_err(|_| "Invalid ZMQ endpoint: bad port number".to_string())?;

    if !is_valid_host(&host) {
        return Err(format!("Invalid ZMQ endpoint host: {host}"));
    }

    Ok((host, port))
}

/// Write the 64-byte ZMTP/3.0 greeting with NULL security mechanism.
fn write_greeting(stream: &mut TcpStream) -> Result<(), String> {
    let mut greeting = [0u8; GREETING_SIZE];

    // Signature: 0xFF + 8 padding bytes + 0x7F (bytes 0..10)
    greeting[0] = 0xFF;
    // bytes 1..9 are already 0x00
    greeting[9] = 0x7F;

    // Version: 3.0 (bytes 10..12)
    greeting[10] = 3;
    greeting[11] = 0;

    // Mechanism: "NULL" padded to 20 bytes (bytes 12..32)
    let mechanism = b"NULL";
    greeting[12..12 + mechanism.len()].copy_from_slice(mechanism);
    // remaining bytes 16..32 are already 0x00

    // As-server: 0 (byte 32) - we are a REQ client
    greeting[32] = 0x00;

    // Filler: 31 zero bytes (bytes 33..64) - already 0x00

    stream
        .write_all(&greeting)
        .map_err(|e| format!("ZMQ greeting send failed: {e}"))
}

/// Read and validate the 64-byte ZMTP/3.0 greeting from peer.
fn read_greeting(stream: &mut TcpStream) -> Result<(), String> {
    let mut greeting = [0u8; GREETING_SIZE];
    stream
        .read_exact(&mut greeting)
        .map_err(|e| format!("ZMQ greeting read failed: {e}"))?;

    // Validate signature
    if greeting[0] != 0xFF {
        return Err(format!(
            "Invalid ZMQ greeting: expected signature byte 0xFF, got 0x{:02x}",
            greeting[0]
        ));
    }
    if greeting[9] != 0x7F {
        return Err(format!(
            "Invalid ZMQ greeting: expected 0x7F at byte 9, got 0x{:02x}",
            greeting[9]
        ));
    }

    // Validate version (must be >= 3.0)
    let major = greeting[10];
    let minor = greeting[11];
    if major < 3 {
        return Err(format!(
            "Unsupported ZMTP version: {major}.{minor} (need >= 3.0)"
        ));
    }

    // Validate mechanism is NULL
    let mechanism = &greeting[12..32];
    let mech_name: Vec<u8> = mechanism.iter().take_while(|&&b| b != 0).copied().collect();
    if mech_name != b"NULL" {
        return Err(format!(
            "Unsupported ZMQ security mechanism: {}",
            String::from_utf8_lossy(&mech_name)
        ));
    }

    Ok(())
}

/// Build ZMTP metadata property: key_len(1) + key + value_len(4 BE) + value.
fn build_metadata(key: &str, value: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(key.len() as u8);
    buf.extend_from_slice(key.as_bytes());
    buf.extend_from_slice(&(value.len() as u32).to_be_bytes());
    buf.extend_from_slice(value.as_bytes());
    buf
}

/// Send the READY command frame with Socket-Type=REQ metadata.
fn send_ready(stream: &mut TcpStream) -> Result<(), String> {
    // Build command body: length-prefixed command name + metadata
    let command_name = b"READY";
    let mut body = Vec::new();
    body.push(command_name.len() as u8);
    body.extend_from_slice(command_name);
    body.extend_from_slice(&build_metadata("Socket-Type", "REQ"));

    // Send as a COMMAND frame
    let flags = FLAG_COMMAND; // 0x04
    if body.len() <= 255 {
        // Short frame
        stream
            .write_all(&[flags, body.len() as u8])
            .map_err(|e| format!("ZMQ READY send failed: {e}"))?;
    } else {
        // Long frame
        let mut header = [0u8; 9];
        header[0] = flags | FLAG_LONG;
        header[1..9].copy_from_slice(&(body.len() as u64).to_be_bytes());
        stream
            .write_all(&header)
            .map_err(|e| format!("ZMQ READY send failed: {e}"))?;
    }

    stream
        .write_all(&body)
        .map_err(|e| format!("ZMQ READY send failed: {e}"))
}

/// Read a single ZMTP frame. Returns (flags, data).
fn read_frame(stream: &mut TcpStream) -> Result<(u8, Vec<u8>), String> {
    let mut flags_buf = [0u8; 1];
    stream
        .read_exact(&mut flags_buf)
        .map_err(|e| format!("ZMQ frame read failed: {e}"))?;
    let flags = flags_buf[0];

    let size: u64 = if flags & FLAG_LONG != 0 {
        // Long frame: 8-byte BE size
        let mut size_buf = [0u8; 8];
        stream
            .read_exact(&mut size_buf)
            .map_err(|e| format!("ZMQ frame size read failed: {e}"))?;
        u64::from_be_bytes(size_buf)
    } else {
        // Short frame: 1-byte size
        let mut size_buf = [0u8; 1];
        stream
            .read_exact(&mut size_buf)
            .map_err(|e| format!("ZMQ frame size read failed: {e}"))?;
        size_buf[0] as u64
    };

    if size > MAX_RESPONSE_BYTES as u64 {
        return Err(format!(
            "ZMQ frame too large: {size} bytes (max {MAX_RESPONSE_BYTES})"
        ));
    }

    let mut data = vec![0u8; size as usize];
    if size > 0 {
        stream
            .read_exact(&mut data)
            .map_err(|e| format!("ZMQ frame data read failed: {e}"))?;
    }

    Ok((flags, data))
}

/// Read the READY command from the peer and validate Socket-Type.
fn read_ready(stream: &mut TcpStream) -> Result<(), String> {
    let (flags, data) = read_frame(stream)?;

    if flags & FLAG_COMMAND == 0 {
        return Err("Expected COMMAND frame for READY, got data frame".to_string());
    }

    if data.is_empty() {
        return Err("Empty READY command frame".to_string());
    }

    // Parse command name (length-prefixed)
    let name_len = data[0] as usize;
    if name_len + 1 > data.len() {
        return Err("Truncated READY command name".to_string());
    }
    let name = &data[1..1 + name_len];
    if name != b"READY" {
        return Err(format!(
            "Expected READY command, got '{}'",
            String::from_utf8_lossy(name)
        ));
    }

    // Parse metadata to find Socket-Type
    let mut pos = 1 + name_len;
    let mut peer_socket_type: Option<String> = None;

    while pos < data.len() {
        if pos >= data.len() {
            break;
        }
        let key_len = data[pos] as usize;
        pos += 1;
        if pos + key_len > data.len() {
            return Err("Truncated metadata key in READY".to_string());
        }
        let key = String::from_utf8_lossy(&data[pos..pos + key_len]).to_string();
        pos += key_len;

        if pos + 4 > data.len() {
            return Err("Truncated metadata value length in READY".to_string());
        }
        let val_len =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if pos + val_len > data.len() {
            return Err("Truncated metadata value in READY".to_string());
        }
        let value = String::from_utf8_lossy(&data[pos..pos + val_len]).to_string();
        pos += val_len;

        // ZMTP metadata keys are case-insensitive
        if key.eq_ignore_ascii_case("Socket-Type") {
            peer_socket_type = Some(value);
        }
    }

    match peer_socket_type {
        Some(ref st) if st == "REP" || st == "ROUTER" => Ok(()),
        Some(ref st) => Err(format!(
            "Incompatible peer socket type: {st} (expected REP or ROUTER)"
        )),
        None => {
            // Some implementations omit Socket-Type; allow it
            Ok(())
        }
    }
}

/// Send multiple ZMTP data frames. The last frame has no MORE flag;
/// all preceding frames have the MORE flag set.
fn send_frames(stream: &mut TcpStream, frames: &[&[u8]]) -> Result<(), String> {
    for (i, frame) in frames.iter().enumerate() {
        let is_last = i == frames.len() - 1;
        let mut flags: u8 = if is_last { 0x00 } else { FLAG_MORE };

        if frame.len() > 255 {
            // Long frame
            flags |= FLAG_LONG;
            let mut header = [0u8; 9];
            header[0] = flags;
            header[1..9].copy_from_slice(&(frame.len() as u64).to_be_bytes());
            stream
                .write_all(&header)
                .map_err(|e| format!("ZMQ frame send failed: {e}"))?;
        } else {
            // Short frame
            stream
                .write_all(&[flags, frame.len() as u8])
                .map_err(|e| format!("ZMQ frame send failed: {e}"))?;
        }

        if !frame.is_empty() {
            stream
                .write_all(frame)
                .map_err(|e| format!("ZMQ frame data send failed: {e}"))?;
        }
    }

    Ok(())
}

/// Read ZMTP data frames until a frame without the MORE flag.
/// Returns all frame payloads (including empty delimiter frames).
fn read_frames(stream: &mut TcpStream) -> Result<Vec<Vec<u8>>, String> {
    let mut frames = Vec::new();
    let mut total_size: usize = 0;

    loop {
        let (flags, data) = read_frame(stream)?;

        // Command frames during data exchange are unexpected; skip them
        if flags & FLAG_COMMAND != 0 {
            if flags & FLAG_MORE != 0 {
                continue;
            }
            break;
        }

        total_size = total_size
            .checked_add(data.len())
            .ok_or("ZMQ response size overflow")?;
        if total_size > MAX_RESPONSE_BYTES {
            return Err(format!(
                "ZMQ response too large: {total_size} bytes (max {MAX_RESPONSE_BYTES})"
            ));
        }

        let has_more = flags & FLAG_MORE != 0;
        frames.push(data);

        if !has_more {
            break;
        }
    }

    Ok(frames)
}

/// Send a ZeroMQ REQ request and receive the REP response using ZMTP/3.0
/// with NULL security mechanism over TCP.
///
/// The endpoint must be in the form `tcp://host:port`. Connects, performs
/// the ZMTP/3.0 handshake, sends the message as a REQ request (with the
/// required empty delimiter frame), reads the response, and returns it.
///
/// Security: validates host and message size. Enforces connection and I/O
/// timeouts.
pub fn request(endpoint: &str, message: &str) -> ZmqResult {
    if message.is_empty() {
        return ZmqResult {
            success: false,
            response: String::new(),
            message: "Message must not be empty".to_string(),
        };
    }

    if message.len() > MAX_RESPONSE_BYTES {
        return ZmqResult {
            success: false,
            response: String::new(),
            message: format!(
                "Message too large: {} bytes (max {})",
                message.len(),
                MAX_RESPONSE_BYTES
            ),
        };
    }

    match request_inner(endpoint, message) {
        Ok((response, msg)) => ZmqResult {
            success: true,
            response,
            message: msg,
        },
        Err(e) => ZmqResult {
            success: false,
            response: String::new(),
            message: e,
        },
    }
}

fn request_inner(endpoint: &str, message: &str) -> Result<(String, String), String> {
    let (host, port) = parse_zmq_endpoint(endpoint)?;

    let addr = format!("{host}:{port}");
    let mut stream = TcpStream::connect_timeout(
        &addr
            .parse()
            .map_err(|e| format!("Invalid ZMQ endpoint address: {e}"))?,
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
    )
    .map_err(|e| format!("ZMQ connection failed: {e}"))?;

    stream
        .set_read_timeout(Some(Duration::from_secs(IO_TIMEOUT_SECS)))
        .map_err(|e| format!("Failed to set timeout: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(IO_TIMEOUT_SECS)))
        .map_err(|e| format!("Failed to set timeout: {e}"))?;

    // 1. ZMTP/3.0 handshake: exchange greetings
    write_greeting(&mut stream)?;
    read_greeting(&mut stream)?;

    // 2. Exchange READY commands
    send_ready(&mut stream)?;
    read_ready(&mut stream)?;

    // 3. Send request: empty delimiter frame + message frame (REQ envelope)
    let empty: &[u8] = b"";
    let msg_bytes = message.as_bytes();
    send_frames(&mut stream, &[empty, msg_bytes])?;

    // 4. Read response frames
    let frames = read_frames(&mut stream)?;

    // Skip empty delimiter frame(s) and concatenate data
    let mut response_parts: Vec<&[u8]> = Vec::new();
    let mut past_delimiter = false;
    for frame in &frames {
        if !past_delimiter && frame.is_empty() {
            past_delimiter = true;
            continue;
        }
        // If there is no delimiter (some REP implementations), take all frames
        if !past_delimiter && !frame.is_empty() {
            past_delimiter = true;
        }
        response_parts.push(frame);
    }

    let response_bytes: Vec<u8> = response_parts.concat();
    let response = String::from_utf8(response_bytes)
        .map_err(|e| format!("ZMQ response is not valid UTF-8: {e}"))?;

    Ok((
        response.clone(),
        format!(
            "ZMQ REQ/REP completed: sent {} bytes, received {} bytes",
            message.len(),
            response.len()
        ),
    ))
}
