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

/// Validate WebSocket URL scheme, with SSRF protection (CWE-918).
fn validate_url(url: &str) -> Result<(), String> {
    if !url.starts_with("ws://") && !url.starts_with("wss://") {
        return Err("URL must start with ws:// or wss://".to_string());
    }

    // Basic length validation
    if url.len() > 2048 {
        return Err("URL too long (max 2048 characters)".to_string());
    }

    // Convert ws:// to http:// for SSRF hostname checking
    let http_url = if url.starts_with("wss://") {
        format!("https://{}", &url[6..])
    } else {
        format!("http://{}", &url[5..])
    };
    crate::security::validate_no_ssrf(&http_url)?;

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

/// Maximum number of messages allowed in a single multi-request call.
const MAX_MULTI_MESSAGES: usize = 100;

pub struct WsMultiResult {
    pub success: bool,
    pub responses: Vec<String>,
    pub message: String,
}

/// Send multiple messages over a single WebSocket connection and collect responses.
///
/// This variant keeps the connection open for conversational protocols,
/// sending each message and collecting one response per message.
/// Useful for WebSocket APIs that require multi-step interactions
/// (authentication handshakes, subscription flows, etc.).
///
/// Security: validates URL scheme, enforces timeout per message and overall,
/// limits response size per message.
pub fn multi_request(url: &str, messages: &[String], timeout_secs: u32) -> WsMultiResult {
    if let Err(e) = validate_url(url) {
        return WsMultiResult {
            success: false,
            responses: Vec::new(),
            message: e,
        };
    }

    if messages.is_empty() {
        return WsMultiResult {
            success: false,
            responses: Vec::new(),
            message: "No messages to send".to_string(),
        };
    }

    if messages.len() > MAX_MULTI_MESSAGES {
        return WsMultiResult {
            success: false,
            responses: Vec::new(),
            message: format!(
                "Too many messages: {} exceeds limit of {MAX_MULTI_MESSAGES}",
                messages.len()
            ),
        };
    }

    let timeout = Duration::from_secs(timeout_secs.clamp(1, 300) as u64);

    match multi_request_inner(url, messages, timeout) {
        Ok(responses) => WsMultiResult {
            success: true,
            responses,
            message: "OK".to_string(),
        },
        Err((responses, e)) => WsMultiResult {
            success: false,
            responses,
            message: e,
        },
    }
}

/// Default timeout variant for multi-message requests.
pub fn multi_request_default_timeout(url: &str, messages: &[String]) -> WsMultiResult {
    multi_request(url, messages, DEFAULT_TIMEOUT_SECS as u32)
}

fn multi_request_inner(
    url: &str,
    messages: &[String],
    timeout: Duration,
) -> Result<Vec<String>, (Vec<String>, String)> {
    use tungstenite::{connect, Message};

    let deadline = std::time::Instant::now() + timeout;

    let (mut socket, _response) = if url.starts_with("wss://") {
        connect(url).map_err(|e| (Vec::new(), format!("WebSocket TLS connect failed: {e}")))?
    } else {
        connect(url).map_err(|e| (Vec::new(), format!("WebSocket connect failed: {e}")))?
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

    let mut responses = Vec::with_capacity(messages.len());

    for (i, msg) in messages.iter().enumerate() {
        // Check deadline before sending
        if std::time::Instant::now() > deadline {
            let _ = socket.close(None);
            return Err((
                responses,
                format!("Timed out before sending message {i}"),
            ));
        }

        // Send the message
        if let Err(e) = socket.send(Message::Text(msg.clone().into())) {
            let _ = socket.close(None);
            return Err((
                responses,
                format!("WebSocket send failed on message {i}: {e}"),
            ));
        }

        // Wait for one response
        let response = loop {
            if std::time::Instant::now() > deadline {
                let _ = socket.close(None);
                return Err((
                    responses,
                    format!("Timed out waiting for response to message {i}"),
                ));
            }

            match socket.read() {
                Ok(Message::Text(text)) => {
                    if text.len() > MAX_RESPONSE_BYTES {
                        let _ = socket.close(None);
                        return Err((
                            responses,
                            format!(
                                "Response to message {i} too large: {} bytes",
                                text.len()
                            ),
                        ));
                    }
                    break text;
                }
                Ok(Message::Binary(data)) => {
                    if data.len() > MAX_RESPONSE_BYTES {
                        let _ = socket.close(None);
                        return Err((
                            responses,
                            format!(
                                "Response to message {i} too large: {} bytes",
                                data.len()
                            ),
                        ));
                    }
                    break String::from_utf8_lossy(&data).to_string();
                }
                Ok(Message::Ping(_)) => continue,
                Ok(Message::Pong(_)) => continue,
                Ok(Message::Close(_)) => {
                    return Err((
                        responses,
                        format!(
                            "Server closed connection after {} of {} messages",
                            i,
                            messages.len()
                        ),
                    ));
                }
                Ok(Message::Frame(_)) => continue,
                Err(e) => {
                    return Err((
                        responses,
                        format!("WebSocket read failed on message {i}: {e}"),
                    ));
                }
            }
        };

        responses.push(response);
    }

    // Close connection gracefully
    let _ = socket.close(None);

    Ok(responses)
}
