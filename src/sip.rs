// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::net::UdpSocket;
use std::time::Duration;

const SIP_DEFAULT_PORT: u16 = 5060;
const TIMEOUT_SECS: u64 = 5;
const MAX_RESPONSE_BYTES: usize = 4096;

pub struct SipResult {
    pub alive: bool,
    pub status_code: i32,
    pub status_text: String,
    pub user_agent: String,
    pub allow_methods: String,
    #[allow(dead_code)]
    pub raw_response: String,
}

/// Send a SIP OPTIONS ping to check if a SIP server is alive.
pub fn options_ping(host: &str, port: u16) -> SipResult {
    let r = match options_ping_inner(host, port) {
        Ok(result) => result,
        Err(e) => SipResult {
            alive: false,
            status_code: 0,
            status_text: e,
            user_agent: String::new(),
            allow_methods: String::new(),
            raw_response: String::new(),
        },
    };
    crate::audit_log::record(
        "sip",
        "options_ping",
        host,
        r.alive,
        r.status_code,
        &r.status_text,
    );
    r
}

fn options_ping_inner(host: &str, port: u16) -> Result<SipResult, String> {
    // Validate host
    crate::security::validate_host(host)?;

    let port = if port == 0 { SIP_DEFAULT_PORT } else { port };
    // Atomic resolve-and-validate (closes UDP DNS-rebinding TOCTOU, CWE-918).
    let addr = crate::security::resolve_and_validate_udp(host, port)?;

    let bind_addr = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket =
        UdpSocket::bind(bind_addr).map_err(|e| format!("Failed to bind UDP socket: {e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(TIMEOUT_SECS)))
        .map_err(|e| format!("Failed to set timeout: {e}"))?;

    let local_addr = socket
        .local_addr()
        .map_err(|e| format!("Local addr: {e}"))?;
    let call_id = format!("{}@{}", rand_hex(8), local_addr.ip());
    let branch = format!("z9hG4bK{}", rand_hex(8));
    let tag = rand_hex(8);

    let request = format!(
        "OPTIONS sip:{host}:{port} SIP/2.0\r\n\
         Via: SIP/2.0/UDP {local_addr};branch={branch}\r\n\
         From: <sip:duck_net@{local_ip}>;tag={tag}\r\n\
         To: <sip:{host}:{port}>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 1 OPTIONS\r\n\
         Max-Forwards: 70\r\n\
         Accept: application/sdp\r\n\
         Content-Length: 0\r\n\
         \r\n",
        local_ip = local_addr.ip()
    );

    socket
        .send_to(request.as_bytes(), addr)
        .map_err(|e| format!("Failed to send SIP OPTIONS: {e}"))?;

    let mut buf = vec![0u8; MAX_RESPONSE_BYTES];
    let (size, _) = socket
        .recv_from(&mut buf)
        .map_err(|e| format!("Failed to receive SIP response: {e}"))?;
    buf.truncate(size);

    let response = String::from_utf8_lossy(&buf).to_string();
    parse_sip_response(&response)
}

fn parse_sip_response(response: &str) -> Result<SipResult, String> {
    let first_line = response.lines().next().ok_or("Empty SIP response")?;

    // Parse "SIP/2.0 200 OK"
    let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(format!("Invalid SIP response line: {first_line}"));
    }

    let status_code = parts[1]
        .parse::<i32>()
        .map_err(|_| format!("Invalid SIP status code: {}", parts[1]))?;
    let status_text = parts.get(2).unwrap_or(&"").to_string();

    let user_agent = extract_sip_header(response, "User-Agent");
    let allow_methods = extract_sip_header(response, "Allow");

    Ok(SipResult {
        alive: (200..300).contains(&status_code),
        status_code,
        status_text,
        user_agent,
        allow_methods,
        raw_response: response.to_string(),
    })
}

fn extract_sip_header(response: &str, header: &str) -> String {
    for line in response.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(&format!("{header}: ")) {
            return rest.to_string();
        }
        // Case-insensitive
        if trimmed.len() > header.len() + 2
            && trimmed[..header.len()].eq_ignore_ascii_case(header)
            && trimmed.as_bytes()[header.len()] == b':'
        {
            return trimmed[header.len() + 1..].trim().to_string();
        }
    }
    String::new()
}

/// Generate a random hex string using cryptographically secure OS entropy.
fn rand_hex(bytes: usize) -> String {
    crate::security::random_hex(bytes)
}
