// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

const TIMEOUT_SECS: u64 = 15;

pub struct TlsCertInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub serial: String,
    pub san_names: Vec<String>,
    pub key_algorithm: String,
    pub signature_algorithm: String,
    pub is_expired: bool,
    pub days_until_expiry: i64,
    pub version: String,
}

/// Inspect the TLS certificate of a host.
pub fn inspect(host: &str, port: u16) -> Result<TlsCertInfo, String> {
    let addr = format!("{host}:{port}");
    let timeout = Duration::from_secs(TIMEOUT_SECS);

    // Build TLS config that captures the certificate
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = host
        .to_string()
        .try_into()
        .map_err(|e| format!("Invalid server name '{host}': {e}"))?;

    let conn = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| format!("TLS connection setup failed: {e}"))?;

    let tcp = TcpStream::connect_timeout(
        &addr
            .parse()
            .map_err(|e| format!("Invalid address {addr}: {e}"))?,
        timeout,
    )
    .map_err(|e| format!("TCP connection to {addr} failed: {e}"))?;

    tcp.set_read_timeout(Some(timeout))
        .map_err(|e| format!("Set read timeout: {e}"))?;
    tcp.set_write_timeout(Some(timeout))
        .map_err(|e| format!("Set write timeout: {e}"))?;

    // Complete TLS handshake
    let mut stream = StreamOwned::new(conn, tcp);
    // Force the handshake by trying to write nothing (just triggers handshake)
    let _ = stream.write(&[]);
    // Read a byte to ensure handshake completes (ignore errors - we just want the cert)
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

    let cert_der = &certs[0].as_ref();
    parse_x509(cert_der)
}

/// Parse a DER-encoded X.509 certificate.
fn parse_x509(der: &[u8]) -> Result<TlsCertInfo, String> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| format!("Failed to parse X.509 certificate: {e}"))?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let not_before = cert
        .validity()
        .not_before
        .to_rfc2822()
        .unwrap_or_else(|_| "unknown".to_string());
    let not_after = cert
        .validity()
        .not_after
        .to_rfc2822()
        .unwrap_or_else(|_| "unknown".to_string());
    let serial = cert.serial.to_str_radix(16);
    let version = format!("v{}", cert.version().0 + 1);

    // Extract SANs
    let mut san_names = Vec::new();
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            match name {
                GeneralName::DNSName(dns) => san_names.push(dns.to_string()),
                GeneralName::IPAddress(ip) => {
                    if ip.len() == 4 {
                        san_names.push(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
                    } else if ip.len() == 16 {
                        san_names.push(format!(
                            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                            u16::from_be_bytes([ip[0], ip[1]]),
                            u16::from_be_bytes([ip[2], ip[3]]),
                            u16::from_be_bytes([ip[4], ip[5]]),
                            u16::from_be_bytes([ip[6], ip[7]]),
                            u16::from_be_bytes([ip[8], ip[9]]),
                            u16::from_be_bytes([ip[10], ip[11]]),
                            u16::from_be_bytes([ip[12], ip[13]]),
                            u16::from_be_bytes([ip[14], ip[15]]),
                        ));
                    }
                }
                _ => {}
            }
        }
    }

    let key_algorithm = cert.public_key().algorithm.algorithm.to_id_string();
    let signature_algorithm = cert.signature_algorithm.algorithm.to_id_string();

    // Check expiry
    let now = cert.validity().not_after.timestamp();
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let is_expired = current_time > now;
    let days_until_expiry = (now - current_time) / 86400;

    Ok(TlsCertInfo {
        subject,
        issuer,
        not_before,
        not_after,
        serial,
        san_names,
        key_algorithm,
        signature_algorithm,
        is_expired,
        days_until_expiry,
        version,
    })
}
