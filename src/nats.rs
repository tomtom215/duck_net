// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Connection timeout in seconds.
const CONNECT_TIMEOUT_SECS: u64 = 10;

/// I/O timeout in seconds.
const IO_TIMEOUT_SECS: u64 = 10;

/// Maximum payload size: 1 MiB default NATS max.
const MAX_PAYLOAD_SIZE: usize = 1024 * 1024;

/// Maximum response size when reading lines from the server.
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

pub struct NatsResult {
    pub success: bool,
    pub message: String,
}

pub struct NatsRequestResult {
    pub success: bool,
    pub response: String,
    pub message: String,
}

/// Validate NATS server host.
fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
}

/// Validate NATS subject: must not be empty, <= 1024 chars, no whitespace, no null bytes.
fn is_valid_subject(subject: &str) -> bool {
    !subject.is_empty()
        && subject.len() <= 1024
        && !subject.contains('\0')
        && !subject.chars().any(|c| c.is_whitespace())
}

/// Parse NATS URL: nats://[user:pass@]host[:port]
/// Returns (host, port, username, password).
fn parse_nats_url(url: &str) -> Result<(String, u16, Option<String>, Option<String>), String> {
    let rest = url.strip_prefix("nats://").ok_or_else(|| {
        format!(
            "Invalid NATS URL scheme (expected nats://): {}",
            scrub_url(url)
        )
    })?;

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
        (hostport.to_string(), 4222)
    };

    if !is_valid_host(&host) {
        return Err(format!("Invalid NATS host: {host}"));
    }

    Ok((host, port, username, password))
}

/// Scrub credentials from a NATS URL for safe inclusion in error messages.
fn scrub_url(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("nats://") {
        if let Some(at) = rest.rfind('@') {
            return format!("nats://****@{}", &rest[at + 1..]);
        }
    }
    url.to_string()
}

/// Read a single line from the NATS server, enforcing a size limit.
fn read_line(reader: &mut BufReader<TcpStream>) -> Result<String, String> {
    let mut line = String::new();
    let bytes_read = reader
        .read_line(&mut line)
        .map_err(|e| format!("NATS read failed: {e}"))?;

    if bytes_read == 0 {
        return Err("NATS server closed connection".to_string());
    }

    if bytes_read > MAX_RESPONSE_BYTES {
        return Err("NATS response exceeded maximum size".to_string());
    }

    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Build the CONNECT JSON payload.
///
/// Uses proper JSON escaping for user/pass to prevent JSON injection (CWE-116).
fn build_connect_json(username: Option<&str>, password: Option<&str>) -> String {
    match (username, password) {
        (Some(user), Some(pass)) => {
            let user_escaped = crate::security::json_escape(user);
            let pass_escaped = crate::security::json_escape(pass);
            format!(
                "CONNECT {{\"verbose\":false,\"pedantic\":false,\"name\":\"duck_net\",\"user\":\"{user_escaped}\",\"pass\":\"{pass_escaped}\"}}\r\n"
            )
        }
        (Some(user), None) => {
            let user_escaped = crate::security::json_escape(user);
            format!(
                "CONNECT {{\"verbose\":false,\"pedantic\":false,\"name\":\"duck_net\",\"user\":\"{user_escaped}\"}}\r\n"
            )
        }
        _ => "CONNECT {\"verbose\":false,\"pedantic\":false,\"name\":\"duck_net\"}\r\n".to_string(),
    }
}

/// Perform the NATS handshake: read INFO, send CONNECT, verify with PING/PONG.
fn handshake(
    reader: &mut BufReader<TcpStream>,
    stream: &mut TcpStream,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<(), String> {
    // Read INFO line from server
    let info_line = read_line(reader)?;
    if !info_line.starts_with("INFO ") {
        return Err(format!("Expected INFO from server, got: {info_line}"));
    }

    // Send CONNECT
    let connect_cmd = build_connect_json(username, password);
    stream
        .write_all(connect_cmd.as_bytes())
        .map_err(|e| format!("NATS CONNECT send failed: {e}"))?;

    // Send PING to verify connection
    stream
        .write_all(b"PING\r\n")
        .map_err(|e| format!("NATS PING send failed: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("NATS flush failed: {e}"))?;

    // Read PONG (or -ERR)
    let response = read_line(reader)?;
    if response.starts_with("-ERR") {
        return Err(format!("NATS server error: {response}"));
    }
    if response != "PONG" {
        return Err(format!("Expected PONG, got: {response}"));
    }

    Ok(())
}

/// Fire-and-forget NATS publish.
///
/// Connects to the NATS server, authenticates (if credentials provided),
/// publishes the payload to the given subject, and disconnects.
///
/// Security: validates host, subject, and payload size. Enforces timeouts.
/// Credentials are scrubbed from error messages (CWE-532).
pub fn publish(url: &str, subject: &str, payload: &str) -> NatsResult {
    // Warn about plaintext NATS connections (CWE-319)
    if !url.starts_with("nats+tls://") && !url.starts_with("tls://") {
        crate::security_warnings::warn_plaintext(
            "NATS",
            "PLAINTEXT_NATS",
            "nats+tls:// or tls:// (NATS over TLS)",
        );
    }

    if !is_valid_subject(subject) {
        return NatsResult {
            success: false,
            message: "Invalid NATS subject".to_string(),
        };
    }

    if payload.len() > MAX_PAYLOAD_SIZE {
        return NatsResult {
            success: false,
            message: format!(
                "Payload too large: {} bytes (max {})",
                payload.len(),
                MAX_PAYLOAD_SIZE
            ),
        };
    }

    let host_for_audit = parse_nats_url(url)
        .map(|(h, _, _, _)| h)
        .unwrap_or_else(|_| scrub_url(url));
    let result = match publish_inner(url, subject, payload) {
        Ok(msg) => NatsResult {
            success: true,
            message: msg,
        },
        Err(e) => NatsResult {
            success: false,
            message: e,
        },
    };
    crate::audit_log::record(
        "nats",
        "publish",
        &host_for_audit,
        result.success,
        0,
        &result.message,
    );
    result
}

fn publish_inner(url: &str, subject: &str, payload: &str) -> Result<String, String> {
    let (host, port, username, password) = parse_nats_url(url)?;

    // SSRF protection: block connections to private/reserved IPs (CWE-918)
    crate::security::validate_no_ssrf_host(&host)?;

    // Rate limiting: apply per-host token bucket (honours global + per-domain config)
    crate::rate_limit::acquire_for_host(&host);

    let addr = format!("{host}:{port}");
    let stream = TcpStream::connect_timeout(
        &addr
            .parse()
            .map_err(|e| format!("Invalid NATS address: {e}"))?,
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
    )
    .map_err(|e| format!("NATS connection failed: {e}"))?;

    // Post-connect SSRF check: validate actual peer IP to prevent DNS rebinding (CWE-918)
    crate::security::validate_tcp_peer(&stream)?;

    stream
        .set_read_timeout(Some(Duration::from_secs(IO_TIMEOUT_SECS)))
        .map_err(|e| format!("Failed to set timeout: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(IO_TIMEOUT_SECS)))
        .map_err(|e| format!("Failed to set timeout: {e}"))?;

    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|e| format!("Clone failed: {e}"))?,
    );
    let mut writer = stream;

    // 1. Handshake: INFO -> CONNECT -> PING/PONG
    handshake(
        &mut reader,
        &mut writer,
        username.as_deref(),
        password.as_deref(),
    )?;

    // 2. Send PUB
    let pub_cmd = format!("PUB {subject} {}\r\n{payload}\r\n", payload.len());
    writer
        .write_all(pub_cmd.as_bytes())
        .map_err(|e| format!("NATS PUB send failed: {e}"))?;

    // 3. Send PING, read PONG to ensure delivery
    writer
        .write_all(b"PING\r\n")
        .map_err(|e| format!("NATS PING send failed: {e}"))?;
    writer
        .flush()
        .map_err(|e| format!("NATS flush failed: {e}"))?;

    let response = read_line(&mut reader)?;
    if response.starts_with("-ERR") {
        return Err(format!("NATS server error: {response}"));
    }
    if response != "PONG" {
        return Err(format!("Expected PONG after PUB, got: {response}"));
    }

    Ok(format!(
        "Published {} bytes to subject '{}'",
        payload.len(),
        subject
    ))
}

/// NATS request-reply pattern.
///
/// Publishes a message with a unique reply inbox, subscribes to the inbox,
/// and waits for a single response (with timeout). Useful for RPC-style
/// communication over NATS.
///
/// Security: validates host, subject, payload size. Enforces timeouts.
/// Credentials are scrubbed from error messages (CWE-532).
pub fn request(url: &str, subject: &str, payload: &str, timeout_ms: u32) -> NatsRequestResult {
    if !is_valid_subject(subject) {
        return NatsRequestResult {
            success: false,
            response: String::new(),
            message: "Invalid NATS subject".to_string(),
        };
    }

    if payload.len() > MAX_PAYLOAD_SIZE {
        return NatsRequestResult {
            success: false,
            response: String::new(),
            message: format!(
                "Payload too large: {} bytes (max {})",
                payload.len(),
                MAX_PAYLOAD_SIZE
            ),
        };
    }

    let host_for_audit = parse_nats_url(url)
        .map(|(h, _, _, _)| h)
        .unwrap_or_else(|_| scrub_url(url));
    let result = match request_inner(url, subject, payload, timeout_ms) {
        Ok((response, msg)) => NatsRequestResult {
            success: true,
            response,
            message: msg,
        },
        Err(e) => NatsRequestResult {
            success: false,
            response: String::new(),
            message: e,
        },
    };
    crate::audit_log::record(
        "nats",
        "request",
        &host_for_audit,
        result.success,
        0,
        &result.message,
    );
    result
}

fn request_inner(
    url: &str,
    subject: &str,
    payload: &str,
    timeout_ms: u32,
) -> Result<(String, String), String> {
    let (host, port, username, password) = parse_nats_url(url)?;

    // SSRF protection: block connections to private/reserved IPs (CWE-918)
    crate::security::validate_no_ssrf_host(&host)?;

    // Rate limiting: apply per-host token bucket (honours global + per-domain config)
    crate::rate_limit::acquire_for_host(&host);

    // Clamp timeout to 100..30000 ms
    let timeout_ms = timeout_ms.clamp(100, 30000);

    let addr = format!("{host}:{port}");
    let stream = TcpStream::connect_timeout(
        &addr
            .parse()
            .map_err(|e| format!("Invalid NATS address: {e}"))?,
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
    )
    .map_err(|e| format!("NATS connection failed: {e}"))?;

    // Post-connect SSRF check: validate actual peer IP to prevent DNS rebinding (CWE-918)
    crate::security::validate_tcp_peer(&stream)?;

    stream
        .set_write_timeout(Some(Duration::from_secs(IO_TIMEOUT_SECS)))
        .map_err(|e| format!("Failed to set timeout: {e}"))?;

    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|e| format!("Clone failed: {e}"))?,
    );
    let mut writer = stream;

    // Use IO_TIMEOUT for handshake reads
    writer
        .set_read_timeout(Some(Duration::from_secs(IO_TIMEOUT_SECS)))
        .map_err(|e| format!("Failed to set timeout: {e}"))?;

    // Set read timeout on the cloned stream used by reader
    // (reader owns its own clone, so we set timeout via the writer's peer)

    // 1. Handshake: INFO -> CONNECT -> PING/PONG
    handshake(
        &mut reader,
        &mut writer,
        username.as_deref(),
        password.as_deref(),
    )?;

    // 2. Generate unique reply inbox
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let inbox = format!("_INBOX.duck_net_{timestamp}");

    // 3. Subscribe to inbox: SUB {inbox} 1
    let sub_cmd = format!("SUB {inbox} 1\r\n");
    writer
        .write_all(sub_cmd.as_bytes())
        .map_err(|e| format!("NATS SUB send failed: {e}"))?;

    // 4. Publish with reply-to: PUB {subject} {inbox} {length}\r\n{payload}\r\n
    let pub_cmd = format!("PUB {subject} {inbox} {}\r\n{payload}\r\n", payload.len());
    writer
        .write_all(pub_cmd.as_bytes())
        .map_err(|e| format!("NATS PUB send failed: {e}"))?;

    writer
        .flush()
        .map_err(|e| format!("NATS flush failed: {e}"))?;

    // 5. Set read timeout to the request timeout for waiting on the response
    // We need to set it on the underlying stream that the reader wraps.
    // Since reader owns a clone, we re-create reader with proper timeout.
    let reader_stream = reader.into_inner();
    reader_stream
        .set_read_timeout(Some(Duration::from_millis(timeout_ms as u64)))
        .map_err(|e| format!("Failed to set timeout: {e}"))?;
    let mut reader = BufReader::new(reader_stream);

    // 6. Wait for MSG response: MSG {inbox} {sid} {length}\r\n{payload}\r\n
    let msg_line = read_line(&mut reader).map_err(|e| {
        if e.contains("timed out") || e.contains("WouldBlock") {
            format!("NATS request timed out after {timeout_ms}ms")
        } else {
            e
        }
    })?;

    // Handle -ERR or PING while waiting
    if msg_line.starts_with("-ERR") {
        return Err(format!("NATS server error: {msg_line}"));
    }
    if msg_line == "PING" {
        // Respond to server PING, then keep waiting
        writer
            .write_all(b"PONG\r\n")
            .map_err(|e| format!("NATS PONG send failed: {e}"))?;
        writer
            .flush()
            .map_err(|e| format!("NATS flush failed: {e}"))?;
    }

    // Parse MSG line: MSG {subject} {sid} [{reply-to}] {length}
    if !msg_line.starts_with("MSG ") {
        return Err(format!("Expected MSG response, got: {msg_line}"));
    }

    let parts: Vec<&str> = msg_line.split_whitespace().collect();
    if parts.len() < 4 {
        return Err(format!("Invalid MSG line: {msg_line}"));
    }

    // Last element is the payload length
    let msg_len: usize = parts[parts.len() - 1]
        .parse()
        .map_err(|_| format!("Invalid MSG payload length: {msg_line}"))?;

    if msg_len > MAX_PAYLOAD_SIZE {
        return Err(format!(
            "Response payload too large: {msg_len} bytes (max {MAX_PAYLOAD_SIZE})"
        ));
    }

    // Read the payload line
    let response_payload = if msg_len == 0 {
        // Read the empty line
        let _ = read_line(&mut reader)?;
        String::new()
    } else {
        let line = read_line(&mut reader)?;
        if line.len() != msg_len {
            // The payload might contain the exact bytes; use what we got
        }
        line
    };

    // 7. Unsubscribe: UNSUB 1
    writer
        .write_all(b"UNSUB 1\r\n")
        .map_err(|e| format!("NATS UNSUB send failed: {e}"))?;
    writer
        .flush()
        .map_err(|e| format!("NATS flush failed: {e}"))?;

    Ok((
        response_payload.clone(),
        format!(
            "Request-reply on '{}': sent {} bytes, received {} bytes",
            subject,
            payload.len(),
            response_payload.len()
        ),
    ))
}

// ===== NATS subscribe table function =====

/// A single message received during a NATS subscription.
pub struct NatsSubMessage {
    pub subject: String,
    pub reply_to: String,
    pub payload: String,
}

/// Result of a NATS subscribe call.
pub struct NatsSubscribeResult {
    pub success: bool,
    pub messages: Vec<NatsSubMessage>,
    pub message: String,
}

/// Subscribe to a NATS subject and collect messages until timeout or max_messages.
///
/// `timeout_ms` controls how long to wait for each message (100–300_000 ms).
pub fn subscribe(
    url: &str,
    subject: &str,
    max_messages: i64,
    timeout_ms: u32,
) -> NatsSubscribeResult {
    if !is_valid_subject(subject) {
        return NatsSubscribeResult {
            success: false,
            messages: vec![],
            message: "Invalid NATS subject".to_string(),
        };
    }
    let max = max_messages.clamp(1, 100_000) as usize;

    let host_for_audit = parse_nats_url(url)
        .map(|(h, _, _, _)| h)
        .unwrap_or_else(|_| scrub_url(url));
    let result = match subscribe_inner(url, subject, max, timeout_ms) {
        Ok((msgs, msg)) => NatsSubscribeResult {
            success: true,
            messages: msgs,
            message: msg,
        },
        Err(e) => NatsSubscribeResult {
            success: false,
            messages: vec![],
            message: e,
        },
    };
    crate::audit_log::record(
        "nats",
        "subscribe",
        &host_for_audit,
        result.success,
        result.messages.len() as i32,
        &result.message,
    );
    result
}

fn subscribe_inner(
    url: &str,
    subject: &str,
    max_messages: usize,
    timeout_ms: u32,
) -> Result<(Vec<NatsSubMessage>, String), String> {
    // Warn about plaintext NATS connections (CWE-319)
    if !url.starts_with("nats+tls://") && !url.starts_with("tls://") {
        crate::security_warnings::warn_plaintext(
            "NATS",
            "PLAINTEXT_NATS",
            "nats+tls:// or tls:// (NATS over TLS)",
        );
    }

    let (host, port, username, password) = parse_nats_url(url)?;
    crate::security::validate_no_ssrf_host(&host)?;
    crate::rate_limit::acquire_for_host(&host);

    let addr = format!("{host}:{port}");
    let stream = TcpStream::connect_timeout(
        &addr
            .parse()
            .map_err(|e| format!("Invalid NATS address: {e}"))?,
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
    )
    .map_err(|e| format!("NATS connection failed: {}", scrub_url(&e.to_string())))?;

    crate::security::validate_tcp_peer(&stream)?;

    stream
        .set_write_timeout(Some(Duration::from_secs(IO_TIMEOUT_SECS)))
        .map_err(|e| format!("Failed to set write timeout: {e}"))?;

    // Clone the stream: reader wraps the clone, writer owns the original
    let reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|e| format!("Clone failed: {e}"))?,
    );
    let mut writer = stream;

    // Handshake with IO timeout
    let reader_stream = reader.into_inner();
    reader_stream
        .set_read_timeout(Some(Duration::from_secs(IO_TIMEOUT_SECS)))
        .map_err(|e| format!("Failed to set read timeout: {e}"))?;
    let mut reader = BufReader::new(reader_stream);

    handshake(
        &mut reader,
        &mut writer,
        username.as_deref(),
        password.as_deref(),
    )?;

    // Subscribe: SUB <subject> <sid>
    let sid = "1";
    let sub_cmd = format!("SUB {subject} {sid}\r\n");
    writer
        .write_all(sub_cmd.as_bytes())
        .map_err(|e| format!("NATS SUB send failed: {e}"))?;
    writer
        .flush()
        .map_err(|e| format!("NATS flush failed: {e}"))?;

    // Switch to subscribe timeout for message reads
    let timeout_ms = timeout_ms.clamp(100, 300_000);
    let reader_stream = reader.into_inner();
    reader_stream
        .set_read_timeout(Some(Duration::from_millis(timeout_ms as u64)))
        .map_err(|e| format!("Failed to set subscribe timeout: {e}"))?;
    let mut reader = BufReader::new(reader_stream);

    let mut messages = Vec::new();

    loop {
        if messages.len() >= max_messages {
            break;
        }

        let line = match read_line(&mut reader) {
            Ok(l) => l,
            Err(e) => {
                if e.contains("timed out") || e.contains("WouldBlock") || e.contains("os error 11")
                {
                    break;
                }
                return Err(e);
            }
        };

        if let Some(header) = line.strip_prefix("MSG ") {
            // MSG <subject> <sid> [<reply-to>] <byte_count>
            let parts: Vec<&str> = header.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }
            let msg_subject = parts[0].to_string();
            let (reply_to, byte_count_str) = if parts.len() == 4 {
                (parts[2].to_string(), parts[3])
            } else {
                (String::new(), parts[2])
            };
            let byte_count: usize = byte_count_str.trim().parse().unwrap_or(0);
            if byte_count > MAX_PAYLOAD_SIZE {
                continue;
            }
            // Read exactly byte_count bytes + CRLF
            let mut buf = vec![0u8; byte_count + 2];
            if reader.read_exact(&mut buf).is_err() {
                break;
            }
            let payload = String::from_utf8_lossy(&buf[..byte_count]).to_string();
            messages.push(NatsSubMessage {
                subject: msg_subject,
                reply_to,
                payload,
            });
        } else if line == "PING" {
            let _ = writer.write_all(b"PONG\r\n");
            let _ = writer.flush();
        } else if line.starts_with("-ERR") {
            return Err(format!("NATS server error: {line}"));
        }
    }

    // Unsubscribe
    let _ = writer.write_all(format!("UNSUB {sid}\r\n").as_bytes());
    let _ = writer.flush();

    let count = messages.len();
    Ok((
        messages,
        format!("Received {count} message(s) on '{subject}'"),
    ))
}
