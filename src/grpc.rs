// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::sync::Arc;

use crate::runtime;

/// Build a rustls ClientConfig for gRPC TLS, honouring any globally configured
/// CA bundle and/or client certificate (for mTLS).
pub(crate) fn build_grpc_tls_config(
    _host: &str,
    override_ca_pem: Option<&str>,
    override_cert_and_key: Option<(&str, &str)>,
) -> Result<rustls::ClientConfig, String> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Apply global CA bundle (or per-call override)
    let ca_pem = override_ca_pem
        .map(|s| s.to_string())
        .or_else(|| crate::http::ca_bundle_pem());
    if let Some(ref pem) = ca_pem {
        for result in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            let cert = result.map_err(|e| format!("CA cert parse error: {e}"))?;
            root_store.add(cert).map_err(|e| format!("CA cert add error: {e}"))?;
        }
    }

    // Determine client cert / key (per-call override wins over global)
    let (cert_pem_opt, key_pem_opt) = match override_cert_and_key {
        Some((c, k)) => (Some(c.to_string()), Some(k.to_string())),
        None => (crate::http::client_cert_pem(), crate::http::client_key_pem()),
    };

    let config = match (cert_pem_opt, key_pem_opt) {
        (Some(cert_pem), Some(key_pem)) => {
            let cert_chain: Vec<CertificateDer<'static>> =
                CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                    .collect::<Result<_, _>>()
                    .map_err(|e| format!("Client cert parse error: {e}"))?;
            let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
                .map_err(|e| format!("Private key parse error: {e}"))?;
            rustls::ClientConfig::builder_with_protocol_versions(&[
                &rustls::version::TLS12,
                &rustls::version::TLS13,
            ])
            .with_root_certificates(root_store)
            .with_client_auth_cert(cert_chain, key)
            .map_err(|e| format!("mTLS config error: {e}"))?
        }
        _ => rustls::ClientConfig::builder_with_protocol_versions(&[
            &rustls::version::TLS12,
            &rustls::version::TLS13,
        ])
        .with_root_certificates(root_store)
        .with_no_client_auth(),
    };

    Ok(config)
}

/// Maximum gRPC response size: 16 MiB.
pub(crate) const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// gRPC call timeout in seconds.
pub(crate) const DEFAULT_TIMEOUT_SECS: u64 = 30;

pub struct GrpcResult {
    pub success: bool,
    pub status_code: i32,
    pub body: String,
    pub grpc_status: i32,
    pub grpc_message: String,
}

pub struct GrpcReflectionResult {
    pub success: bool,
    pub services: Vec<String>,
    pub message: String,
}

/// Validate host for gRPC connections.
fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
}

/// Validate gRPC service and method names (must be valid identifiers/paths).
fn is_valid_grpc_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 256 {
        return false;
    }
    name.chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Parse a gRPC URL: grpc://host:port or grpcs://host:port
/// Returns (host, port, use_tls).
pub(crate) fn parse_url(url: &str) -> Result<(String, u16, bool), String> {
    let (rest, tls) = if let Some(r) = url.strip_prefix("grpcs://") {
        (r, true)
    } else if let Some(r) = url.strip_prefix("grpc://") {
        (r, false)
    } else if let Some(r) = url.strip_prefix("https://") {
        (r, true)
    } else if let Some(r) = url.strip_prefix("http://") {
        (r, false)
    } else {
        return Err("URL must start with grpc://, grpcs://, http://, or https://".to_string());
    };

    // Remove trailing path
    let hostport = rest.split('/').next().unwrap_or(rest);

    let (host, port) = if let Some(colon) = hostport.rfind(':') {
        let port: u16 = hostport[colon + 1..]
            .parse()
            .map_err(|_| "Invalid port number")?;
        (hostport[..colon].to_string(), port)
    } else {
        let default_port = if tls { 443 } else { 50051 };
        (hostport.to_string(), default_port)
    };

    if !is_valid_host(&host) {
        return Err(format!("Invalid gRPC host: {host}"));
    }

    Ok((host, port, tls))
}

/// Encode a gRPC message with the standard 5-byte frame header.
/// Format: [compressed(1 byte)] [length(4 bytes big-endian)] [message]
pub(crate) fn encode_grpc_message(data: &[u8]) -> Vec<u8> {
    // gRPC length field is a u32 (max ~4 GiB). Use try_from to avoid silent
    // truncation if data.len() somehow exceeds u32::MAX (CWE-190).
    let length: u32 = u32::try_from(data.len()).unwrap_or(u32::MAX);
    let mut frame = Vec::with_capacity(5 + data.len());
    frame.push(0u8); // Not compressed
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(data);
    frame
}

/// Decode a gRPC response body, stripping the 5-byte frame header.
pub(crate) fn decode_grpc_message(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 5 {
        return Err(format!(
            "gRPC response too short: {} bytes (need at least 5)",
            data.len()
        ));
    }

    let _compressed = data[0];
    // Safe: u32 always fits in usize on any 32- or 64-bit platform.
    // The size check below further bounds this to MAX_RESPONSE_BYTES (16 MiB),
    // preventing any overflow in the subsequent `5 + length` arithmetic.
    let length = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;

    if length > MAX_RESPONSE_BYTES {
        return Err(format!(
            "gRPC response too large: {length} bytes (max {MAX_RESPONSE_BYTES})"
        ));
    }

    // Use checked addition to defend against pathological inputs (CWE-190).
    let frame_end = 5usize.checked_add(length).ok_or("gRPC frame length overflow")?;
    if data.len() < frame_end {
        return Err(format!(
            "gRPC response truncated: expected {} bytes, got {}",
            frame_end,
            data.len()
        ));
    }

    Ok(data[5..frame_end].to_vec())
}

/// Make a unary gRPC call over HTTP/2.
///
/// The `json_payload` is sent as the message body. For servers supporting
/// `application/grpc+json`, this works directly. For protobuf servers,
/// the user should provide base64-encoded protobuf bytes.
pub fn call(url: &str, service: &str, method: &str, json_payload: &str) -> GrpcResult {
    if !is_valid_grpc_name(service) {
        return GrpcResult {
            success: false,
            status_code: 0,
            body: String::new(),
            grpc_status: -1,
            grpc_message: "Invalid service name".to_string(),
        };
    }

    if !is_valid_grpc_name(method) {
        return GrpcResult {
            success: false,
            status_code: 0,
            body: String::new(),
            grpc_status: -1,
            grpc_message: "Invalid method name".to_string(),
        };
    }

    runtime::block_on(call_async(url, service, method, json_payload))
}

async fn call_async(url: &str, service: &str, method: &str, json_payload: &str) -> GrpcResult {
    match call_inner(url, service, method, json_payload).await {
        Ok(r) => r,
        Err(e) => GrpcResult {
            success: false,
            status_code: 0,
            body: String::new(),
            grpc_status: -1,
            grpc_message: e,
        },
    }
}

async fn call_inner(
    url: &str,
    service: &str,
    method: &str,
    json_payload: &str,
) -> Result<GrpcResult, String> {
    let (host, port, use_tls) = parse_url(url)?;
    // SSRF protection: block connections to private/reserved IPs (CWE-918)
    crate::security::validate_no_ssrf_host(&host)?;
    let path = format!("/{service}/{method}");

    let addr = format!("{host}:{port}");
    let tcp = tokio::time::timeout(
        tokio::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| "gRPC TCP connect timed out".to_string())?
    .map_err(|e| format!("gRPC TCP connect failed: {e}"))?;

    // Post-connect SSRF check: validate actual peer IP to prevent DNS rebinding (CWE-918)
    if let Ok(peer) = tcp.peer_addr() {
        crate::security::validate_peer_socket_addr(peer)?;
    }

    // Encode the payload with gRPC framing
    let payload = encode_grpc_message(json_payload.as_bytes());

    if use_tls {
        call_tls(tcp, &host, &path, &payload).await
    } else {
        call_plaintext(tcp, &path, &payload).await
    }
}

async fn call_plaintext(
    tcp: tokio::net::TcpStream,
    path: &str,
    payload: &[u8],
) -> Result<GrpcResult, String> {
    let (mut client, h2_conn) = h2::client::handshake(tcp)
        .await
        .map_err(|e| format!("HTTP/2 handshake failed: {e}"))?;

    tokio::spawn(async move {
        let _ = h2_conn.await;
    });

    send_grpc_request(&mut client, path, payload).await
}

async fn call_tls(
    tcp: tokio::net::TcpStream,
    host: &str,
    path: &str,
    payload: &[u8],
) -> Result<GrpcResult, String> {
    let tls_config = build_grpc_tls_config(host, None, None)?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let domain = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| format!("Invalid TLS server name: {e}"))?;

    let tls_stream = tokio::time::timeout(
        tokio::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        connector.connect(domain, tcp),
    )
    .await
    .map_err(|_| "TLS handshake timed out".to_string())?
    .map_err(|e| format!("TLS handshake failed: {e}"))?;

    let (mut client, h2_conn) = h2::client::handshake(tls_stream)
        .await
        .map_err(|e| format!("HTTP/2 handshake failed: {e}"))?;

    tokio::spawn(async move {
        let _ = h2_conn.await;
    });

    send_grpc_request(&mut client, path, payload).await
}

async fn send_grpc_request(
    client: &mut h2::client::SendRequest<bytes::Bytes>,
    path: &str,
    payload: &[u8],
) -> Result<GrpcResult, String> {
    let request = ::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("grpc-timeout", format!("{}S", DEFAULT_TIMEOUT_SECS))
        .body(())
        .map_err(|e| format!("Failed to build gRPC request: {e}"))?;

    let (response, mut send_stream) = client
        .send_request(request, false)
        .map_err(|e| format!("Failed to send gRPC request: {e}"))?;

    send_stream
        .send_data(bytes::Bytes::from(payload.to_vec()), true)
        .map_err(|e| format!("Failed to send gRPC payload: {e}"))?;

    let response = tokio::time::timeout(
        tokio::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        response,
    )
    .await
    .map_err(|_| "gRPC response timed out".to_string())?
    .map_err(|e| format!("gRPC response error: {e}"))?;

    let status = response.status().as_u16() as i32;

    // Read grpc-status and grpc-message from headers (may also be in trailers)
    let grpc_status = response
        .headers()
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(-1);

    let grpc_message = response
        .headers()
        .get("grpc-message")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let mut body = response.into_body();
    let mut body_bytes = Vec::new();

    loop {
        match tokio::time::timeout(
            tokio::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            body.data(),
        )
        .await
        {
            Err(_) => break,
            Ok(None) => break,
            Ok(Some(Ok(chunk))) => {
                if body_bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
                    return Err("gRPC response body too large".to_string());
                }
                body_bytes.extend_from_slice(&chunk);
                let _ = body.flow_control().release_capacity(chunk.len());
            }
            Ok(Some(Err(e))) => {
                return Err(format!("gRPC body read error: {e}"));
            }
        }
    }

    // Check trailers for grpc-status if not in headers
    let (final_grpc_status, final_grpc_message) = if grpc_status == -1 {
        match body.trailers().await {
            Ok(Some(trailers)) => {
                let s = trailers
                    .get("grpc-status")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<i32>().ok())
                    .unwrap_or(-1);
                let m = trailers
                    .get("grpc-message")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                (s, if m.is_empty() { grpc_message } else { m })
            }
            _ => (grpc_status, grpc_message),
        }
    } else {
        (grpc_status, grpc_message)
    };

    let body_str = if body_bytes.len() >= 5 {
        match decode_grpc_message(&body_bytes) {
            Ok(decoded) => String::from_utf8_lossy(&decoded).to_string(),
            Err(_) => String::from_utf8_lossy(&body_bytes).to_string(),
        }
    } else {
        String::from_utf8_lossy(&body_bytes).to_string()
    };

    Ok(GrpcResult {
        success: final_grpc_status == 0,
        status_code: status,
        body: body_str,
        grpc_status: final_grpc_status,
        grpc_message: final_grpc_message,
    })
}

/// Result of a gRPC server-side streaming call.
pub struct GrpcStreamResult {
    pub success: bool,
    pub messages: Vec<String>,
    pub grpc_status: i32,
    pub grpc_message: String,
}

/// Decode all gRPC length-prefixed frames from a concatenated response body.
pub(crate) fn decode_all_grpc_messages(data: &[u8]) -> Vec<String> {
    let mut results = Vec::new();
    let mut pos = 0;
    while pos + 5 <= data.len() {
        let length =
            u32::from_be_bytes([data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4]])
                as usize;
        if length > MAX_RESPONSE_BYTES {
            break;
        }
        let frame_end = match (pos + 5).checked_add(length) {
            Some(end) => end,
            None => break,
        };
        if frame_end > data.len() {
            break;
        }
        results.push(String::from_utf8_lossy(&data[pos + 5..frame_end]).to_string());
        pos = frame_end;
    }
    results
}

/// Make a server-side streaming gRPC call over HTTP/2.
///
/// Collects all response frames until the stream is closed or times out.
pub fn call_stream(url: &str, service: &str, method: &str, json_payload: &str) -> GrpcStreamResult {
    if !is_valid_grpc_name(service) {
        return GrpcStreamResult {
            success: false,
            messages: vec![],
            grpc_status: -1,
            grpc_message: "Invalid service name".to_string(),
        };
    }
    if !is_valid_grpc_name(method) {
        return GrpcStreamResult {
            success: false,
            messages: vec![],
            grpc_status: -1,
            grpc_message: "Invalid method name".to_string(),
        };
    }
    runtime::block_on(call_stream_async(url, service, method, json_payload))
}

async fn call_stream_async(
    url: &str,
    service: &str,
    method: &str,
    json_payload: &str,
) -> GrpcStreamResult {
    match call_stream_inner(url, service, method, json_payload).await {
        Ok(r) => r,
        Err(e) => GrpcStreamResult {
            success: false,
            messages: vec![],
            grpc_status: -1,
            grpc_message: e,
        },
    }
}

async fn call_stream_inner(
    url: &str,
    service: &str,
    method: &str,
    json_payload: &str,
) -> Result<GrpcStreamResult, String> {
    let (host, port, use_tls) = parse_url(url)?;
    crate::security::validate_no_ssrf_host(&host)?;
    let path = format!("/{service}/{method}");
    let addr = format!("{host}:{port}");

    let tcp = tokio::time::timeout(
        tokio::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| "gRPC TCP connect timed out".to_string())?
    .map_err(|e| format!("gRPC TCP connect failed: {e}"))?;

    if let Ok(peer) = tcp.peer_addr() {
        crate::security::validate_peer_socket_addr(peer)?;
    }

    let payload = encode_grpc_message(json_payload.as_bytes());

    if use_tls {
        call_stream_tls(tcp, &host, &path, &payload).await
    } else {
        call_stream_plaintext(tcp, &path, &payload).await
    }
}

async fn call_stream_plaintext(
    tcp: tokio::net::TcpStream,
    path: &str,
    payload: &[u8],
) -> Result<GrpcStreamResult, String> {
    let (mut client, h2_conn) = h2::client::handshake(tcp)
        .await
        .map_err(|e| format!("HTTP/2 handshake failed: {e}"))?;
    tokio::spawn(async move {
        let _ = h2_conn.await;
    });
    send_grpc_stream_request(&mut client, path, payload).await
}

async fn call_stream_tls(
    tcp: tokio::net::TcpStream,
    host: &str,
    path: &str,
    payload: &[u8],
) -> Result<GrpcStreamResult, String> {
    let tls_config = build_grpc_tls_config(host, None, None)?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let domain = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| format!("Invalid TLS server name: {e}"))?;
    let tls_stream = tokio::time::timeout(
        tokio::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        connector.connect(domain, tcp),
    )
    .await
    .map_err(|_| "TLS handshake timed out".to_string())?
    .map_err(|e| format!("TLS handshake failed: {e}"))?;
    let (mut client, h2_conn) = h2::client::handshake(tls_stream)
        .await
        .map_err(|e| format!("HTTP/2 handshake failed: {e}"))?;
    tokio::spawn(async move {
        let _ = h2_conn.await;
    });
    send_grpc_stream_request(&mut client, path, payload).await
}

async fn send_grpc_stream_request(
    client: &mut h2::client::SendRequest<bytes::Bytes>,
    path: &str,
    payload: &[u8],
) -> Result<GrpcStreamResult, String> {
    let request = ::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("grpc-timeout", format!("{}S", DEFAULT_TIMEOUT_SECS))
        .body(())
        .map_err(|e| format!("Failed to build gRPC request: {e}"))?;

    let (response, mut send_stream) = client
        .send_request(request, false)
        .map_err(|e| format!("Failed to send gRPC request: {e}"))?;
    send_stream
        .send_data(bytes::Bytes::from(payload.to_vec()), true)
        .map_err(|e| format!("Failed to send gRPC payload: {e}"))?;

    let response = tokio::time::timeout(
        tokio::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        response,
    )
    .await
    .map_err(|_| "gRPC response timed out".to_string())?
    .map_err(|e| format!("gRPC response error: {e}"))?;

    let grpc_status_hdr = response
        .headers()
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(-1);
    let grpc_msg_hdr = response
        .headers()
        .get("grpc-message")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Limit total stream body to avoid OOM on large streams (100 x MAX_RESPONSE_BYTES)
    let stream_size_limit = MAX_RESPONSE_BYTES.saturating_mul(100);
    let mut body = response.into_body();
    let mut body_bytes = Vec::new();

    loop {
        match tokio::time::timeout(
            tokio::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            body.data(),
        )
        .await
        {
            Err(_) => break,
            Ok(None) => break,
            Ok(Some(Ok(chunk))) => {
                if body_bytes.len() + chunk.len() > stream_size_limit {
                    return Err("gRPC stream body too large".to_string());
                }
                body_bytes.extend_from_slice(&chunk);
                let _ = body.flow_control().release_capacity(chunk.len());
            }
            Ok(Some(Err(e))) => return Err(format!("gRPC body read error: {e}")),
        }
    }

    let (final_grpc_status, final_grpc_message) = if grpc_status_hdr == -1 {
        match body.trailers().await {
            Ok(Some(trailers)) => {
                let s = trailers
                    .get("grpc-status")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<i32>().ok())
                    .unwrap_or(-1);
                let m = trailers
                    .get("grpc-message")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                (s, if m.is_empty() { grpc_msg_hdr } else { m })
            }
            _ => (grpc_status_hdr, grpc_msg_hdr),
        }
    } else {
        (grpc_status_hdr, grpc_msg_hdr)
    };

    let messages = decode_all_grpc_messages(&body_bytes);

    Ok(GrpcStreamResult {
        success: final_grpc_status == 0 || final_grpc_status == -1,
        messages,
        grpc_status: final_grpc_status,
        grpc_message: final_grpc_message,
    })
}

/// Maximum recursion depth for protobuf parsing to prevent stack overflow.
pub(crate) const MAX_PROTO_DEPTH: usize = 16;

/// Extract length-delimited string fields from protobuf-encoded data.
///
/// Scans the byte stream for varint-encoded field tags with wire type 2
/// (length-delimited) and attempts to decode the value as a UTF-8 string.
/// Non-UTF-8 values are silently skipped.
pub(crate) fn extract_proto_strings(data: &[u8]) -> Vec<String> {
    extract_proto_strings_depth(data, 0)
}

/// Depth-limited protobuf string extraction (CWE-674).
fn extract_proto_strings_depth(data: &[u8], depth: usize) -> Vec<String> {
    if depth >= MAX_PROTO_DEPTH {
        return Vec::new();
    }
    let mut strings = Vec::new();
    let mut i = 0;

    while i < data.len() {
        // Read varint field tag
        let (tag, bytes_read) = match read_varint(&data[i..]) {
            Some(v) => v,
            None => break,
        };
        i += bytes_read;

        let wire_type = tag & 0x07;
        match wire_type {
            0 => {
                // Varint: skip
                match read_varint(&data[i..]) {
                    Some((_, n)) => i += n,
                    None => break,
                }
            }
            1 => {
                // 64-bit: skip 8 bytes
                i += 8;
            }
            2 => {
                // Length-delimited
                let (length, bytes_read) = match read_varint(&data[i..]) {
                    Some(v) => v,
                    None => break,
                };
                i += bytes_read;
                let length = length as usize;
                if i + length > data.len() {
                    break;
                }
                let value = &data[i..i + length];
                if let Ok(s) = std::str::from_utf8(value) {
                    if !s.is_empty() {
                        strings.push(s.to_string());
                    }
                }
                // Recurse into the sub-message with depth limit
                let nested = extract_proto_strings_depth(value, depth + 1);
                strings.extend(nested);
                i += length;
            }
            5 => {
                // 32-bit: skip 4 bytes
                i += 4;
            }
            _ => {
                // Unknown wire type, stop parsing
                break;
            }
        }
    }

    strings
}

/// Read a varint from a byte slice. Returns (value, bytes_consumed).
fn read_varint(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() {
        return None;
    }
    let mut value: u64 = 0;
    let mut shift = 0;
    for (i, &byte) in data.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        value |= ((byte & 0x7F) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}
