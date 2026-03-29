// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::time::Duration;

/// Maximum WebSocket response size: 16 MiB.
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Default timeout for WebSocket operations.
const DEFAULT_TIMEOUT_SECS: u64 = 10;

pub struct WsResult {
    pub success: bool,
    pub response: String,
    pub message: String,
}

/// Validate WebSocket URL scheme.
fn validate_url(url: &str) -> Result<(), String> {
    if !url.starts_with("ws://") && !url.starts_with("wss://") {
        return Err("URL must start with ws:// or wss://".to_string());
    }

    // Basic length validation
    if url.len() > 2048 {
        return Err("URL too long (max 2048 characters)".to_string());
    }

    Ok(())
}

/// Send a single message over WebSocket and wait for one response.
///
/// This is a one-shot request-response pattern: connect, send message,
/// receive one response, close. Suitable for health checks and simple
/// RPC-over-WS patterns.
///
/// Security: validates URL scheme, enforces timeouts, limits response size.
pub fn request(url: &str, message: &str, timeout_secs: u32) -> WsResult {
    if let Err(e) = validate_url(url) {
        return WsResult {
            success: false,
            response: String::new(),
            message: e,
        };
    }

    let timeout = Duration::from_secs(timeout_secs.clamp(1, 300) as u64);

    match request_inner(url, message, timeout) {
        Ok(response) => WsResult {
            success: true,
            response,
            message: "OK".to_string(),
        },
        Err(e) => WsResult {
            success: false,
            response: String::new(),
            message: e,
        },
    }
}

/// Default timeout variant.
pub fn request_default_timeout(url: &str, message: &str) -> WsResult {
    request(url, message, DEFAULT_TIMEOUT_SECS as u32)
}

fn request_inner(url: &str, message: &str, timeout: Duration) -> Result<String, String> {
    use tungstenite::{connect, Message};

    // Set a deadline for the entire operation
    let deadline = std::time::Instant::now() + timeout;

    // Connect with timeout
    let (mut socket, _response) = if url.starts_with("wss://") {
        // TLS WebSocket - tungstenite handles TLS via rustls feature
        connect(url).map_err(|e| format!("WebSocket TLS connect failed: {e}"))?
    } else {
        connect(url).map_err(|e| format!("WebSocket connect failed: {e}"))?
    };

    // Set TCP socket timeout for reads/writes
    {
        use tungstenite::stream::MaybeTlsStream;
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .unwrap_or(Duration::from_secs(1));
        match socket.get_ref() {
            MaybeTlsStream::Plain(tcp) => {
                let _ = tcp.set_read_timeout(Some(remaining));
                let _ = tcp.set_write_timeout(Some(remaining));
            }
            MaybeTlsStream::Rustls(tls) => {
                let tcp = tls.get_ref();
                let _ = tcp.set_read_timeout(Some(remaining));
                let _ = tcp.set_write_timeout(Some(remaining));
            }
            _ => {}
        }
    }

    // Send the message
    socket
        .send(Message::Text(message.into()))
        .map_err(|e| format!("WebSocket send failed: {e}"))?;

    // Wait for one response message
    loop {
        if std::time::Instant::now() > deadline {
            let _ = socket.close(None);
            return Err("WebSocket response timed out".to_string());
        }

        match socket.read() {
            Ok(Message::Text(text)) => {
                if text.len() > MAX_RESPONSE_BYTES {
                    let _ = socket.close(None);
                    return Err(format!(
                        "WebSocket response too large: {} bytes",
                        text.len()
                    ));
                }
                let _ = socket.close(None);
                return Ok(text);
            }
            Ok(Message::Binary(data)) => {
                if data.len() > MAX_RESPONSE_BYTES {
                    let _ = socket.close(None);
                    return Err(format!(
                        "WebSocket response too large: {} bytes",
                        data.len()
                    ));
                }
                let _ = socket.close(None);
                return Ok(String::from_utf8_lossy(&data).to_string());
            }
            Ok(Message::Ping(_)) => {
                // Pong is sent automatically by tungstenite
                continue;
            }
            Ok(Message::Pong(_)) => continue,
            Ok(Message::Close(_)) => {
                return Err("WebSocket closed by server before response".to_string());
            }
            Ok(Message::Frame(_)) => continue,
            Err(e) => {
                return Err(format!("WebSocket read failed: {e}"));
            }
        }
    }
}
