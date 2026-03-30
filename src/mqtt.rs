// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Connection timeout in seconds.
const CONNECT_TIMEOUT_SECS: u64 = 10;

/// I/O timeout in seconds.
const IO_TIMEOUT_SECS: u64 = 10;

/// Maximum topic length per MQTT spec.
const MAX_TOPIC_LENGTH: usize = 65535;

/// Maximum payload size: 16 MiB.
/// MQTT spec allows 256 MiB but we cap at 16 MiB to prevent OOM (CWE-400).
const MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;

pub struct MqttResult {
    pub success: bool,
    pub message: String,
}

/// Validate MQTT broker host.
fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
}

/// Validate MQTT topic: must not be empty, must not contain null character.
fn is_valid_topic(topic: &str) -> bool {
    !topic.is_empty() && topic.len() <= MAX_TOPIC_LENGTH && !topic.contains('\0')
}

/// Parse broker URL: mqtt://[user:pass@]host[:port]
/// Returns (host, port, username, password).
fn parse_broker(broker: &str) -> Result<(String, u16, Option<String>, Option<String>), String> {
    let rest = broker
        .strip_prefix("mqtt://")
        .or_else(|| broker.strip_prefix("tcp://"))
        .unwrap_or(broker); // Allow bare host:port

    let (auth, hostport) = if let Some(at) = rest.rfind('@') {
        (Some(&rest[..at]), &rest[at + 1..])
    } else {
        (None, rest)
    };

    let (username, password) = match auth {
        Some(a) => {
            if let Some(colon) = a.find(':') {
                (
                    Some(a[..colon].to_string()),
                    Some(a[colon + 1..].to_string()),
                )
            } else {
                (Some(a.to_string()), None)
            }
        }
        None => (None, None),
    };

    let (host, port) = if let Some(colon) = hostport.rfind(':') {
        let port: u16 = hostport[colon + 1..]
            .parse()
            .map_err(|_| "Invalid port number")?;
        (hostport[..colon].to_string(), port)
    } else {
        (hostport.to_string(), 1883)
    };

    if !is_valid_host(&host) {
        return Err(format!("Invalid broker host: {host}"));
    }

    Ok((host, port, username, password))
}

/// Fire-and-forget MQTT publish using MQTT 3.1.1 protocol.
///
/// Connects, authenticates (if credentials provided), publishes at QoS 0,
/// and disconnects. QoS 0 means no delivery guarantee (fire-and-forget).
///
/// Security: validates host, topic, and payload size. Enforces timeouts.
/// Credentials are scrubbed from error messages (CWE-532).
pub fn publish(broker: &str, topic: &str, payload: &str) -> MqttResult {
    // Emit security warning for plaintext MQTT (CWE-319)
    if !broker.starts_with("mqtts://") && !broker.starts_with("ssl://") {
        crate::security_warnings::warn_plaintext(
            "MQTT",
            "PLAINTEXT_MQTT",
            "mqtts:// or ssl:// (port 8883)",
        );
    }

    if !is_valid_topic(topic) {
        return MqttResult {
            success: false,
            message: "Invalid MQTT topic".to_string(),
        };
    }

    if payload.len() > MAX_PAYLOAD_SIZE {
        return MqttResult {
            success: false,
            message: format!(
                "Payload too large: {} bytes (max {})",
                payload.len(),
                MAX_PAYLOAD_SIZE
            ),
        };
    }

    // SSRF protection + rate limiting
    if let Ok((host, _, _, _)) = parse_broker(broker) {
        if let Err(e) = crate::security::validate_no_ssrf_host(&host) {
            return MqttResult {
                success: false,
                message: e,
            };
        }
        // Rate limiting: apply per-host token bucket (honours global + per-domain config)
        crate::rate_limit::acquire_for_host(&host);
    }

    match publish_inner(broker, topic, payload) {
        Ok(msg) => MqttResult {
            success: true,
            message: msg,
        },
        Err(e) => MqttResult {
            success: false,
            message: e,
        },
    }
}

fn publish_inner(broker: &str, topic: &str, payload: &str) -> Result<String, String> {
    let (host, port, username, password) = parse_broker(broker)?;

    let addr = format!("{host}:{port}");
    let mut stream = TcpStream::connect_timeout(
        &addr
            .parse()
            .map_err(|e| format!("Invalid broker address: {e}"))?,
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
    )
    .map_err(|e| format!("MQTT connection failed: {e}"))?;

    // Post-connect SSRF check: validate actual peer IP to prevent DNS rebinding (CWE-918)
    crate::security::validate_tcp_peer(&stream)?;

    stream
        .set_read_timeout(Some(Duration::from_secs(IO_TIMEOUT_SECS)))
        .map_err(|e| format!("Failed to set timeout: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(IO_TIMEOUT_SECS)))
        .map_err(|e| format!("Failed to set timeout: {e}"))?;

    // 1. Send CONNECT packet
    send_connect(&mut stream, username.as_deref(), password.as_deref())?;

    // 2. Read CONNACK
    read_connack(&mut stream)?;

    // 3. Send PUBLISH (QoS 0)
    send_publish(&mut stream, topic, payload)?;

    // 4. Send DISCONNECT
    send_disconnect(&mut stream)?;

    Ok(format!(
        "Published {} bytes to topic '{}'",
        payload.len(),
        topic
    ))
}

/// Build and send MQTT CONNECT packet (v3.1.1).
fn send_connect(
    stream: &mut TcpStream,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<(), String> {
    let mut variable_header = Vec::new();

    // Protocol Name: "MQTT"
    variable_header.extend_from_slice(&[0x00, 0x04]); // Length
    variable_header.extend_from_slice(b"MQTT");

    // Protocol Level: 4 (MQTT 3.1.1)
    variable_header.push(0x04);

    // Connect Flags
    let mut flags: u8 = 0x02; // Clean Session
    if username.is_some() {
        flags |= 0x80; // Username flag
    }
    if password.is_some() {
        flags |= 0x40; // Password flag
    }
    variable_header.push(flags);

    // Keep Alive: 60 seconds
    variable_header.extend_from_slice(&60u16.to_be_bytes());

    // Payload
    let mut payload_buf = Vec::new();

    // Client ID: "duck_net_" + random suffix for uniqueness
    let client_id = format!(
        "duck_net_{:08x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
    );
    let id_bytes = client_id.as_bytes();
    payload_buf.extend_from_slice(&(id_bytes.len() as u16).to_be_bytes());
    payload_buf.extend_from_slice(id_bytes);

    // Username
    if let Some(u) = username {
        let ub = u.as_bytes();
        payload_buf.extend_from_slice(&(ub.len() as u16).to_be_bytes());
        payload_buf.extend_from_slice(ub);
    }

    // Password
    if let Some(p) = password {
        let pb = p.as_bytes();
        payload_buf.extend_from_slice(&(pb.len() as u16).to_be_bytes());
        payload_buf.extend_from_slice(pb);
    }

    let remaining = variable_header.len() + payload_buf.len();
    let mut packet = Vec::new();
    packet.push(0x10); // CONNECT packet type
    encode_remaining_length(&mut packet, remaining);
    packet.extend_from_slice(&variable_header);
    packet.extend_from_slice(&payload_buf);

    stream
        .write_all(&packet)
        .map_err(|e| format!("MQTT CONNECT send failed: {e}"))
}

/// Read and validate CONNACK response.
fn read_connack(stream: &mut TcpStream) -> Result<(), String> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(|e| format!("MQTT CONNACK read failed: {e}"))?;

    // Byte 0: packet type 0x20 (CONNACK)
    if header[0] != 0x20 {
        return Err(format!(
            "Expected CONNACK, got packet type 0x{:02x}",
            header[0]
        ));
    }

    // Byte 1: remaining length (should be 2)
    if header[1] != 0x02 {
        return Err("Invalid CONNACK length".to_string());
    }

    // Byte 3: return code
    let return_code = header[3];
    match return_code {
        0x00 => Ok(()),
        0x01 => Err("MQTT: unacceptable protocol version".to_string()),
        0x02 => Err("MQTT: identifier rejected".to_string()),
        0x03 => Err("MQTT: server unavailable".to_string()),
        0x04 => Err("MQTT: bad username or password".to_string()),
        0x05 => Err("MQTT: not authorized".to_string()),
        _ => Err(format!("MQTT: unknown return code 0x{return_code:02x}")),
    }
}

/// Send PUBLISH packet at QoS 0 (no packet ID, no ack).
fn send_publish(stream: &mut TcpStream, topic: &str, payload: &str) -> Result<(), String> {
    let topic_bytes = topic.as_bytes();
    let payload_bytes = payload.as_bytes();

    let remaining = 2 + topic_bytes.len() + payload_bytes.len(); // topic length (2) + topic + payload

    let mut packet = Vec::new();
    packet.push(0x30); // PUBLISH, QoS 0, no retain, no dup
    encode_remaining_length(&mut packet, remaining);

    // Topic
    packet.extend_from_slice(&(topic_bytes.len() as u16).to_be_bytes());
    packet.extend_from_slice(topic_bytes);

    // Payload (no packet ID for QoS 0)
    packet.extend_from_slice(payload_bytes);

    stream
        .write_all(&packet)
        .map_err(|e| format!("MQTT PUBLISH send failed: {e}"))
}

/// Send DISCONNECT packet.
fn send_disconnect(stream: &mut TcpStream) -> Result<(), String> {
    stream
        .write_all(&[0xE0, 0x00])
        .map_err(|e| format!("MQTT DISCONNECT send failed: {e}"))
}

/// Encode MQTT remaining length (variable-length encoding).
fn encode_remaining_length(buf: &mut Vec<u8>, mut length: usize) {
    loop {
        let mut byte = (length % 128) as u8;
        length /= 128;
        if length > 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if length == 0 {
            break;
        }
    }
}

/// Read and validate PUBACK response.
fn read_puback(stream: &mut TcpStream, expected_id: u16) -> Result<(), String> {
    let mut buf = [0u8; 4];
    stream
        .read_exact(&mut buf)
        .map_err(|e| format!("MQTT PUBACK read failed: {e}"))?;

    // Byte 0: packet type 0x40 (PUBACK)
    if buf[0] != 0x40 {
        return Err(format!("Expected PUBACK, got packet type 0x{:02x}", buf[0]));
    }

    // Byte 1: remaining length (should be 2)
    if buf[1] != 0x02 {
        return Err("Invalid PUBACK length".to_string());
    }

    // Bytes 2-3: packet identifier
    let received_id = u16::from_be_bytes([buf[2], buf[3]]);
    if received_id != expected_id {
        return Err(format!(
            "PUBACK packet ID mismatch: expected 0x{expected_id:04x}, got 0x{received_id:04x}"
        ));
    }

    Ok(())
}

/// MQTT publish with QoS 1 (at-least-once delivery) and optional retain flag.
///
/// QoS 1 requires waiting for a PUBACK response from the broker,
/// guaranteeing the message was received. The retain flag tells the
/// broker to store the message for future subscribers.
///
/// Security: validates host, topic, payload size. Enforces timeouts.
pub fn publish_qos1(broker: &str, topic: &str, payload: &str, retain: bool) -> MqttResult {
    if !is_valid_topic(topic) {
        return MqttResult {
            success: false,
            message: "Invalid MQTT topic".to_string(),
        };
    }

    if payload.len() > MAX_PAYLOAD_SIZE {
        return MqttResult {
            success: false,
            message: format!(
                "Payload too large: {} bytes (max {})",
                payload.len(),
                MAX_PAYLOAD_SIZE
            ),
        };
    }

    match publish_qos1_inner(broker, topic, payload, retain) {
        Ok(msg) => MqttResult {
            success: true,
            message: msg,
        },
        Err(e) => MqttResult {
            success: false,
            message: e,
        },
    }
}

fn publish_qos1_inner(
    broker: &str,
    topic: &str,
    payload: &str,
    retain: bool,
) -> Result<String, String> {
    let (host, port, username, password) = parse_broker(broker)?;

    let addr = format!("{host}:{port}");
    let mut stream = TcpStream::connect_timeout(
        &addr
            .parse()
            .map_err(|e| format!("Invalid broker address: {e}"))?,
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
    )
    .map_err(|e| format!("MQTT connection failed: {e}"))?;

    // Post-connect SSRF check: validate actual peer IP to prevent DNS rebinding (CWE-918)
    crate::security::validate_tcp_peer(&stream)?;

    stream
        .set_read_timeout(Some(Duration::from_secs(IO_TIMEOUT_SECS)))
        .map_err(|e| format!("Failed to set timeout: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(IO_TIMEOUT_SECS)))
        .map_err(|e| format!("Failed to set timeout: {e}"))?;

    // 1. Send CONNECT packet
    send_connect(&mut stream, username.as_deref(), password.as_deref())?;

    // 2. Read CONNACK
    read_connack(&mut stream)?;

    // 3. Send PUBLISH (QoS 1)
    let topic_bytes = topic.as_bytes();
    let payload_bytes = payload.as_bytes();
    let packet_id: u16 = 0x0001;

    let remaining = 2 + topic_bytes.len() + 2 + payload_bytes.len(); // topic length (2) + topic + packet id (2) + payload

    let mut packet = Vec::new();
    let mut type_byte: u8 = 0x32; // PUBLISH, QoS 1 (0x30 | 0x02)
    if retain {
        type_byte |= 0x01;
    }
    packet.push(type_byte);
    encode_remaining_length(&mut packet, remaining);

    // Topic
    packet.extend_from_slice(&(topic_bytes.len() as u16).to_be_bytes());
    packet.extend_from_slice(topic_bytes);

    // Packet Identifier (required for QoS 1)
    packet.extend_from_slice(&packet_id.to_be_bytes());

    // Payload
    packet.extend_from_slice(payload_bytes);

    stream
        .write_all(&packet)
        .map_err(|e| format!("MQTT PUBLISH send failed: {e}"))?;

    // 4. Read PUBACK
    read_puback(&mut stream, packet_id)?;

    // 5. Send DISCONNECT
    send_disconnect(&mut stream)?;

    Ok(format!(
        "Published {} bytes to topic '{}' (QoS 1, retain={})",
        payload.len(),
        topic,
        retain
    ))
}
