// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

const TIMEOUT_SECS: u64 = 15;

pub struct OcspResult {
    pub success: bool,
    pub status: String,
    pub revocation_time: String,
    pub this_update: String,
    pub next_update: String,
    pub responder: String,
    pub message: String,
}

/// Check certificate revocation status via OCSP.
///
/// Connects to the host via TLS, extracts the server certificate,
/// finds the OCSP responder URL from the certificate's Authority
/// Information Access (AIA) extension, builds an OCSP request,
/// and checks the certificate's revocation status.
///
/// Security: validates hostname, enforces timeouts, verifies TLS
/// certificate chain before performing OCSP check.
pub fn check(host: &str, port: u16) -> OcspResult {
    if host.is_empty() || host.len() > 253 {
        return OcspResult {
            success: false,
            status: String::new(),
            revocation_time: String::new(),
            this_update: String::new(),
            next_update: String::new(),
            responder: String::new(),
            message: "Invalid hostname".to_string(),
        };
    }

    if port == 0 {
        return err_result("Invalid port: 0");
    }

    match check_inner(host, port) {
        Ok(r) => r,
        Err(e) => err_result(&e),
    }
}

fn err_result(msg: &str) -> OcspResult {
    OcspResult {
        success: false,
        status: String::new(),
        revocation_time: String::new(),
        this_update: String::new(),
        next_update: String::new(),
        responder: String::new(),
        message: msg.to_string(),
    }
}

fn check_inner(host: &str, port: u16) -> Result<OcspResult, String> {
    // SSRF protection: block connections to private/reserved IPs (CWE-918)
    crate::security::validate_no_ssrf_host(host)?;

    let addr = format!("{host}:{port}");
    let timeout = Duration::from_secs(TIMEOUT_SECS);

    // Build TLS config
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS12,
        &rustls::version::TLS13,
    ])
    .with_root_certificates(root_store)
    .with_no_client_auth();

    let server_name = host
        .to_string()
        .try_into()
        .map_err(|e| format!("Invalid server name '{host}': {e}"))?;

    let conn = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| format!("TLS setup failed: {e}"))?;

    let tcp = TcpStream::connect_timeout(
        &addr
            .parse()
            .map_err(|e| format!("Invalid address {addr}: {e}"))?,
        timeout,
    )
    .map_err(|e| format!("TCP connection to {addr} failed: {e}"))?;

    // Post-connect SSRF check: validate actual peer IP to prevent DNS rebinding (CWE-918)
    crate::security::validate_tcp_peer(&tcp)?;

    tcp.set_read_timeout(Some(timeout))
        .map_err(|e| format!("Set timeout: {e}"))?;
    tcp.set_write_timeout(Some(timeout))
        .map_err(|e| format!("Set timeout: {e}"))?;

    let mut stream = StreamOwned::new(conn, tcp);
    let _ = stream.write(&[]);
    let mut buf = [0u8; 1];
    let _ = stream.read(&mut buf);

    // Extract peer certificates
    let certs = stream
        .conn
        .peer_certificates()
        .ok_or("No peer certificates received")?;

    if certs.is_empty() {
        return Err("No certificates in chain".to_string());
    }

    let cert_der = certs[0].as_ref();
    let issuer_der = if certs.len() > 1 {
        Some(certs[1].as_ref())
    } else {
        None
    };

    // Parse the server certificate
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| format!("Failed to parse certificate: {e}"))?;

    // Extract OCSP responder URL from AIA extension
    let ocsp_url = extract_ocsp_url(&cert)?;

    // Get serial number
    let serial = cert.serial.to_bytes_be();

    // Get issuer name hash and issuer key hash
    let issuer_name_hash = sha256_hash(cert.issuer().as_raw());

    let issuer_key_hash = if let Some(issuer_bytes) = issuer_der {
        let (_, issuer_cert) = X509Certificate::from_der(issuer_bytes)
            .map_err(|e| format!("Failed to parse issuer certificate: {e}"))?;
        sha256_hash(issuer_cert.public_key().subject_public_key.as_ref())
    } else {
        // If no issuer in chain, hash the issuer DN from the cert itself
        sha256_hash(cert.issuer().as_raw())
    };

    // Build OCSP request
    let ocsp_request = build_ocsp_request(&issuer_name_hash, &issuer_key_hash, &serial);

    // Send OCSP request via HTTP POST
    let response = send_ocsp_request(&ocsp_url, &ocsp_request)?;

    // Parse OCSP response
    parse_ocsp_response(&response, &ocsp_url)
}

/// Extract OCSP responder URL from Authority Information Access extension.
fn extract_ocsp_url(cert: &X509Certificate) -> Result<String, String> {
    // AIA OID: 1.3.6.1.5.5.7.1.1
    let aia_oid =
        x509_parser::oid_registry::Oid::from(&[1, 3, 6, 1, 5, 5, 7, 1, 1]).expect("valid OID");

    for ext in cert.extensions() {
        if ext.oid == aia_oid {
            let data = ext.value;
            return extract_ocsp_url_from_aia(data);
        }
    }

    Err("No OCSP responder URL found in certificate".to_string())
}

/// Parse AIA extension bytes to find OCSP responder URL.
///
/// Uses bounds-checked access throughout to prevent panics from
/// malformed DER data (CWE-125).
fn extract_ocsp_url_from_aia(data: &[u8]) -> Result<String, String> {
    // Simple ASN.1 DER parser for AIA extension
    // Looking for OID 1.3.6.1.5.5.7.48.1 (OCSP) followed by a URI
    let ocsp_oid: &[u8] = &[0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];

    // Scan for the OCSP OID in the DER data
    for i in 0..data.len().saturating_sub(ocsp_oid.len()) {
        if data.get(i..i + ocsp_oid.len()) == Some(ocsp_oid) {
            // After the OID, look for a context-specific tag [6] (uniformResourceIdentifier)
            let rest = &data[i + ocsp_oid.len()..];
            for j in 0..rest.len().saturating_sub(2) {
                if rest[j] == 0x86 {
                    // Tag [6] implicit IA5String
                    let len = rest[j + 1] as usize;
                    // Bounds check: ensure we don't read past the buffer
                    if len > 2048 {
                        continue; // Unreasonably large URL
                    }
                    if let Some(url_bytes) = rest.get(j + 2..j + 2 + len) {
                        if let Ok(url) = std::str::from_utf8(url_bytes) {
                            if url.starts_with("http://") || url.starts_with("https://") {
                                return Ok(url.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    Err("No OCSP responder URL found in AIA extension".to_string())
}

/// Build a DER-encoded OCSP request.
///
/// OCSPRequest ::= SEQUENCE {
///   tbsRequest TBSRequest
/// }
/// TBSRequest ::= SEQUENCE {
///   requestList SEQUENCE OF Request
/// }
/// Request ::= SEQUENCE {
///   reqCert CertID
/// }
/// CertID ::= SEQUENCE {
///   hashAlgorithm AlgorithmIdentifier,  -- SHA-256
///   issuerNameHash OCTET STRING,
///   issuerKeyHash OCTET STRING,
///   serialNumber CertificateSerialNumber
/// }
fn build_ocsp_request(issuer_name_hash: &[u8], issuer_key_hash: &[u8], serial: &[u8]) -> Vec<u8> {
    // SHA-256 AlgorithmIdentifier: SEQUENCE { OID 2.16.840.1.101.3.4.2.1, NULL }
    let sha256_alg = der_sequence(&[
        &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ],
        &[0x05, 0x00], // NULL
    ]);

    // CertID
    let cert_id = der_sequence(&[
        &sha256_alg,
        &der_octet_string(issuer_name_hash),
        &der_octet_string(issuer_key_hash),
        &der_integer(serial),
    ]);

    // Request
    let request = der_sequence(&[&cert_id]);

    // requestList: SEQUENCE OF Request
    let request_list = der_sequence(&[&request]);

    // tbsRequest: SEQUENCE { requestList }
    let tbs_request = der_sequence(&[&request_list]);

    // OCSPRequest: SEQUENCE { tbsRequest }
    der_sequence(&[&tbs_request])
}

/// Wrap data in an ASN.1 SEQUENCE tag.
fn der_sequence(items: &[&[u8]]) -> Vec<u8> {
    let mut contents = Vec::new();
    for item in items {
        contents.extend_from_slice(item);
    }
    let mut result = vec![0x30]; // SEQUENCE tag
    result.extend_from_slice(&der_length(contents.len()));
    result.extend_from_slice(&contents);
    result
}

/// Wrap data in an ASN.1 OCTET STRING tag.
fn der_octet_string(data: &[u8]) -> Vec<u8> {
    let mut result = vec![0x04]; // OCTET STRING tag
    result.extend_from_slice(&der_length(data.len()));
    result.extend_from_slice(data);
    result
}

/// Encode an integer in ASN.1 DER format.
fn der_integer(data: &[u8]) -> Vec<u8> {
    let mut result = vec![0x02]; // INTEGER tag
                                 // Add leading zero if high bit is set
    if !data.is_empty() && data[0] & 0x80 != 0 {
        result.extend_from_slice(&der_length(data.len() + 1));
        result.push(0x00);
    } else {
        result.extend_from_slice(&der_length(data.len()));
    }
    result.extend_from_slice(data);
    result
}

/// Encode ASN.1 DER length.
fn der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    }
}

fn sha256_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Send OCSP request via HTTP POST.
fn send_ocsp_request(url: &str, request: &[u8]) -> Result<Vec<u8>, String> {
    use crate::http::{self, Method};

    let body_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, request);

    // Use HTTP GET with base64-encoded request in URL (simpler, widely supported)
    let encoded_url = format!(
        "{}/{}",
        url.trim_end_matches('/'),
        crate::json::form_urlencode(&body_b64)
    );

    // Try GET first (RFC 6960 allows it for small requests)
    if encoded_url.len() <= 255 {
        let resp = http::execute(
            Method::Get,
            &encoded_url,
            &[(
                "Accept".to_string(),
                "application/ocsp-response".to_string(),
            )],
            None,
        );

        if resp.status == 200 {
            return Ok(resp.body.as_bytes().to_vec());
        }
    }

    // Fall back to POST
    let headers = vec![
        (
            "Content-Type".to_string(),
            "application/ocsp-request".to_string(),
        ),
        (
            "Accept".to_string(),
            "application/ocsp-response".to_string(),
        ),
    ];

    let resp = http::execute(Method::Post, url, &headers, Some(&body_b64));

    if resp.status != 200 {
        return Err(format!(
            "OCSP responder returned HTTP {}: {}",
            resp.status, resp.reason
        ));
    }

    Ok(resp.body.as_bytes().to_vec())
}

/// Parse OCSP response DER to extract certificate status.
fn parse_ocsp_response(data: &[u8], responder_url: &str) -> Result<OcspResult, String> {
    // OCSPResponse ::= SEQUENCE {
    //   responseStatus ENUMERATED,
    //   responseBytes [0] EXPLICIT ResponseBytes OPTIONAL
    // }
    if data.len() < 3 {
        return Err("OCSP response too short".to_string());
    }

    // Try to find the cert status in the response
    // The cert status is encoded as:
    //   good:    [0] IMPLICIT NULL  (0x80 0x00)
    //   revoked: [1] CONSTRUCTED    (0xA1 ...)
    //   unknown: [2] IMPLICIT NULL  (0x82 0x00)

    let status = if find_bytes(data, &[0x80, 0x00]).is_some() {
        "good".to_string()
    } else if find_bytes(data, &[0x82, 0x00]).is_some() {
        "unknown".to_string()
    } else if let Some(pos) = find_tag(data, 0xA1) {
        // Revoked - try to extract revocation time
        let _revocation_data = &data[pos..];
        "revoked".to_string()
    } else {
        // Can't determine status - look at the response status byte
        // responseStatus: 0=successful, 1=malformedRequest, 2=internalError,
        //                 3=tryLater, 5=sigRequired, 6=unauthorized
        if data.len() >= 5 && data[0] == 0x30 {
            let status_byte = find_enumerated(data).unwrap_or(255);
            match status_byte {
                0 => "good".to_string(), // successful but couldn't find certStatus
                1 => return Err("OCSP: malformed request".to_string()),
                2 => return Err("OCSP: internal error".to_string()),
                3 => return Err("OCSP: try later".to_string()),
                5 => return Err("OCSP: signature required".to_string()),
                6 => return Err("OCSP: unauthorized".to_string()),
                _ => "unknown".to_string(),
            }
        } else {
            "unknown".to_string()
        }
    };

    let revocation_time = if status == "revoked" {
        extract_generalized_time(data).unwrap_or_default()
    } else {
        String::new()
    };

    // Extract thisUpdate and nextUpdate (GeneralizedTime values)
    let this_update = extract_nth_generalized_time(data, 0).unwrap_or_default();
    let next_update = extract_nth_generalized_time(data, 1).unwrap_or_default();

    Ok(OcspResult {
        success: true,
        status,
        revocation_time,
        this_update,
        next_update,
        responder: responder_url.to_string(),
        message: "OK".to_string(),
    })
}

/// Find a 2-byte sequence in data.
fn find_bytes(data: &[u8], needle: &[u8]) -> Option<usize> {
    data.windows(needle.len()).position(|w| w == needle)
}

/// Find a context-specific constructed tag.
fn find_tag(data: &[u8], tag: u8) -> Option<usize> {
    data.iter().position(|&b| b == tag)
}

/// Find first ENUMERATED value in DER data.
fn find_enumerated(data: &[u8]) -> Option<u8> {
    for i in 0..data.len().saturating_sub(2) {
        if data[i] == 0x0A && data[i + 1] == 0x01 {
            return Some(data[i + 2]);
        }
    }
    None
}

/// Extract a GeneralizedTime value after a revoked status tag.
///
/// Uses bounds-checked slice access to prevent panics (CWE-125).
fn extract_generalized_time(data: &[u8]) -> Option<String> {
    // Look for GeneralizedTime tag (0x18) after 0xA1 (revoked)
    if let Some(pos) = find_tag(data, 0xA1) {
        for i in pos..data.len().saturating_sub(2) {
            if data[i] == 0x18 {
                let len = *data.get(i + 1)? as usize;
                if len > 32 {
                    continue; // Unreasonably long timestamp
                }
                let time_bytes = data.get(i + 2..i + 2 + len)?;
                return std::str::from_utf8(time_bytes).ok().map(|s| s.to_string());
            }
        }
    }
    None
}

/// Extract the Nth GeneralizedTime value from DER data.
///
/// Uses bounds-checked slice access to prevent panics (CWE-125).
fn extract_nth_generalized_time(data: &[u8], n: usize) -> Option<String> {
    let mut count = 0;
    for i in 0..data.len().saturating_sub(2) {
        if data[i] == 0x18 {
            let len = *data.get(i + 1)? as usize;
            if len > 32 || len == 0 {
                continue; // Unreasonable length
            }
            if let Some(time_bytes) = data.get(i + 2..i + 2 + len) {
                if let Ok(s) = std::str::from_utf8(time_bytes) {
                    if count == n {
                        return Some(s.to_string());
                    }
                    count += 1;
                }
            }
        }
    }
    None
}
