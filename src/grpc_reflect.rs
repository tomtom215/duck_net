// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::sync::Arc;

use crate::grpc::{
    decode_grpc_message, encode_grpc_message, extract_proto_strings, parse_url,
    GrpcReflectionResult, DEFAULT_TIMEOUT_SECS, MAX_RESPONSE_BYTES,
};
use crate::runtime;

/// Discover available gRPC services via server reflection.
///
/// Uses the gRPC Server Reflection Protocol (grpc.reflection.v1alpha)
/// to list all services registered on the server. This enables
/// automatic proto discovery without needing .proto files.
///
/// Returns a GrpcReflectionResult with the list of discovered services.
pub fn list_services(url: &str) -> GrpcReflectionResult {
    if let Err(e) = parse_url(url) {
        return GrpcReflectionResult {
            success: false,
            services: Vec::new(),
            message: e,
        };
    }

    runtime::block_on(list_services_async(url))
}

async fn list_services_async(url: &str) -> GrpcReflectionResult {
    match list_services_inner(url).await {
        Ok(r) => r,
        Err(e) => GrpcReflectionResult {
            success: false,
            services: Vec::new(),
            message: e,
        },
    }
}

async fn list_services_inner(url: &str) -> Result<GrpcReflectionResult, String> {
    let (host, port, use_tls) = parse_url(url)?;
    // SSRF protection: block connections to private/reserved IPs (CWE-918)
    crate::security::validate_no_ssrf_host(&host)?;
    let path = "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo";

    let addr = format!("{host}:{port}");
    let tcp = tokio::time::timeout(
        tokio::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| "gRPC TCP connect timed out".to_string())?
    .map_err(|e| format!("gRPC TCP connect failed: {e}"))?;

    // Protobuf-encoded ServerReflectionRequest with list_services = ""
    // Field 7, wire type 2 (length-delimited), length 0
    let proto_payload: &[u8] = &[0x3A, 0x00];
    let payload = encode_grpc_message(proto_payload);

    let response = if use_tls {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

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

        send_reflection_request(&mut client, path, &payload).await?
    } else {
        let (mut client, h2_conn) = h2::client::handshake(tcp)
            .await
            .map_err(|e| format!("HTTP/2 handshake failed: {e}"))?;

        tokio::spawn(async move {
            let _ = h2_conn.await;
        });

        send_reflection_request(&mut client, path, &payload).await?
    };

    Ok(response)
}

async fn send_reflection_request(
    client: &mut h2::client::SendRequest<bytes::Bytes>,
    path: &str,
    payload: &[u8],
) -> Result<GrpcReflectionResult, String> {
    let request = ::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("grpc-timeout", format!("{}S", DEFAULT_TIMEOUT_SECS))
        .body(())
        .map_err(|e| format!("Failed to build reflection request: {e}"))?;

    let (response, mut send_stream) = client
        .send_request(request, false)
        .map_err(|e| format!("Failed to send reflection request: {e}"))?;

    send_stream
        .send_data(bytes::Bytes::from(payload.to_vec()), true)
        .map_err(|e| format!("Failed to send reflection payload: {e}"))?;

    let response = tokio::time::timeout(
        tokio::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        response,
    )
    .await
    .map_err(|_| "Reflection response timed out".to_string())?
    .map_err(|e| format!("Reflection response error: {e}"))?;

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
                    return Err("Reflection response body too large".to_string());
                }
                body_bytes.extend_from_slice(&chunk);
                let _ = body.flow_control().release_capacity(chunk.len());
            }
            Ok(Some(Err(e))) => {
                return Err(format!("Reflection body read error: {e}"));
            }
        }
    }

    // Strip gRPC frame header and parse protobuf response
    let decoded = decode_grpc_message(&body_bytes)?;

    // Extract service names from the protobuf response
    // The response is a ServerReflectionResponse with field 6 (list_services_response)
    // containing repeated ServiceResponse messages with field 1 (name)
    let all_strings = extract_proto_strings(&decoded);

    // Filter out common non-service strings (e.g., the host field)
    // Service names typically contain dots (package.ServiceName)
    let services: Vec<String> = all_strings
        .into_iter()
        .filter(|s| s.contains('.') || s.starts_with("grpc."))
        .collect();

    Ok(GrpcReflectionResult {
        success: true,
        services,
        message: "Services discovered via reflection".to_string(),
    })
}
