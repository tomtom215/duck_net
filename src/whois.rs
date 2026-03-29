use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const DEFAULT_WHOIS_SERVER: &str = "whois.iana.org";
const WHOIS_PORT: u16 = 43;
const TIMEOUT_SECS: u64 = 15;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Perform a WHOIS lookup for a domain.
///
/// First queries IANA to find the authoritative WHOIS server,
/// then queries that server for full details.
pub fn lookup(domain: &str) -> Result<String, String> {
    // First query IANA to find the authoritative server
    let iana_response = query_server(DEFAULT_WHOIS_SERVER, domain)?;

    // Try to extract the refer: field for authoritative server
    if let Some(refer) = extract_refer(&iana_response) {
        // Query the authoritative server
        match query_server(&refer, domain) {
            Ok(detailed) => Ok(detailed),
            Err(_) => Ok(iana_response), // Fall back to IANA response
        }
    } else {
        Ok(iana_response)
    }
}

/// Query a specific WHOIS server.
pub fn query_server(server: &str, query: &str) -> Result<String, String> {
    let addr = format!("{server}:{WHOIS_PORT}");
    let timeout = Duration::from_secs(TIMEOUT_SECS);

    let mut stream = TcpStream::connect_timeout(
        &addr
            .parse()
            .map_err(|e| format!("Invalid WHOIS server address {addr}: {e}"))?,
        timeout,
    )
    .map_err(|e| format!("Failed to connect to WHOIS server {server}: {e}"))?;

    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| format!("Failed to set read timeout: {e}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| format!("Failed to set write timeout: {e}"))?;

    // Send query
    let query_line = format!("{query}\r\n");
    stream
        .write_all(query_line.as_bytes())
        .map_err(|e| format!("Failed to send WHOIS query: {e}"))?;

    // Read response
    let mut buf = vec![0u8; MAX_RESPONSE_BYTES];
    let mut total = 0;
    loop {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if total >= MAX_RESPONSE_BYTES {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(format!("Failed to read WHOIS response: {e}")),
        }
    }

    buf.truncate(total);
    String::from_utf8(buf).map_err(|e| format!("WHOIS response is not valid UTF-8: {e}"))
}

/// Extract the "refer:" field from an IANA WHOIS response.
fn extract_refer(response: &str) -> Option<String> {
    for line in response.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("refer:") {
            let server = rest.trim();
            if !server.is_empty() {
                return Some(server.to_string());
            }
        }
    }
    None
}

/// Parse structured fields from a WHOIS response.
pub struct WhoisInfo {
    pub registrar: String,
    pub creation_date: String,
    pub expiration_date: String,
    pub updated_date: String,
    pub name_servers: Vec<String>,
    pub status: Vec<String>,
    pub raw: String,
}

pub fn parse_info(response: &str) -> WhoisInfo {
    let mut info = WhoisInfo {
        registrar: String::new(),
        creation_date: String::new(),
        expiration_date: String::new(),
        updated_date: String::new(),
        name_servers: Vec::new(),
        status: Vec::new(),
        raw: response.to_string(),
    };

    for line in response.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('%') || line.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim();
            if value.is_empty() {
                continue;
            }

            match key.as_str() {
                "registrar" | "registrar name" => {
                    if info.registrar.is_empty() {
                        info.registrar = value.to_string();
                    }
                }
                "creation date" | "created" | "registration date" => {
                    if info.creation_date.is_empty() {
                        info.creation_date = value.to_string();
                    }
                }
                "registry expiry date" | "expiration date" | "expiry date" | "paid-till" => {
                    if info.expiration_date.is_empty() {
                        info.expiration_date = value.to_string();
                    }
                }
                "updated date" | "last updated" | "last modified" => {
                    if info.updated_date.is_empty() {
                        info.updated_date = value.to_string();
                    }
                }
                "name server" | "nserver" => {
                    info.name_servers
                        .push(value.to_ascii_lowercase().to_string());
                }
                "domain status" | "status" => {
                    info.status.push(value.to_string());
                }
                _ => {}
            }
        }
    }

    info
}
