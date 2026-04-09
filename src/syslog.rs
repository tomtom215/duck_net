// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::net::UdpSocket;

const SYSLOG_DEFAULT_PORT: u16 = 514;

/// Syslog facility codes (RFC 5424).
pub fn facility_from_name(name: &str) -> Option<u8> {
    match name.to_ascii_lowercase().as_str() {
        "kern" => Some(0),
        "user" => Some(1),
        "mail" => Some(2),
        "daemon" => Some(3),
        "auth" => Some(4),
        "syslog" => Some(5),
        "lpr" => Some(6),
        "news" => Some(7),
        "uucp" => Some(8),
        "cron" => Some(9),
        "authpriv" => Some(10),
        "ftp" => Some(11),
        "local0" => Some(16),
        "local1" => Some(17),
        "local2" => Some(18),
        "local3" => Some(19),
        "local4" => Some(20),
        "local5" => Some(21),
        "local6" => Some(22),
        "local7" => Some(23),
        _ => name.parse::<u8>().ok(),
    }
}

/// Syslog severity codes (RFC 5424).
pub fn severity_from_name(name: &str) -> Option<u8> {
    match name.to_ascii_lowercase().as_str() {
        "emerg" | "emergency" => Some(0),
        "alert" => Some(1),
        "crit" | "critical" => Some(2),
        "err" | "error" => Some(3),
        "warn" | "warning" => Some(4),
        "notice" => Some(5),
        "info" | "informational" => Some(6),
        "debug" => Some(7),
        _ => name.parse::<u8>().ok(),
    }
}

pub struct SyslogResult {
    pub success: bool,
    pub message: String,
}

/// Send a syslog message via UDP (RFC 5424 format).
pub fn send(
    host: &str,
    port: u16,
    facility: u8,
    severity: u8,
    hostname: &str,
    app_name: &str,
    message: &str,
) -> SyslogResult {
    // Warn about plaintext UDP syslog (CWE-319)
    crate::security_warnings::warn_plaintext(
        "Syslog",
        "PLAINTEXT_SYSLOG",
        "TLS syslog (RFC 5425) via a syslog relay",
    );

    let port = if port == 0 { SYSLOG_DEFAULT_PORT } else { port };

    // Validate inputs
    if facility > 23 {
        return SyslogResult {
            success: false,
            message: format!("Invalid facility: {facility} (must be 0-23)"),
        };
    }
    if severity > 7 {
        return SyslogResult {
            success: false,
            message: format!("Invalid severity: {severity} (must be 0-7)"),
        };
    }

    // Validate message content (CWE-20)
    if message.len() > 65000 {
        return SyslogResult {
            success: false,
            message: "Syslog message too long (max 65000 bytes)".to_string(),
        };
    }
    if message.contains('\0') {
        return SyslogResult {
            success: false,
            message: "Syslog message must not contain null bytes".to_string(),
        };
    }
    // Validate hostname and app_name don't contain control characters (CWE-93)
    if hostname.bytes().any(|b| b < 0x20 && b != b'\t') {
        return SyslogResult {
            success: false,
            message: "Hostname must not contain control characters".to_string(),
        };
    }
    if app_name.bytes().any(|b| b < 0x20 && b != b'\t') {
        return SyslogResult {
            success: false,
            message: "App name must not contain control characters".to_string(),
        };
    }

    let priority = (facility * 8) + severity;

    // RFC 5424 format:
    // <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    let timestamp = rfc3339_now();
    let hostname = if hostname.is_empty() { "-" } else { hostname };
    let app_name = if app_name.is_empty() {
        "duck_net"
    } else {
        app_name
    };
    let pid = std::process::id();

    let packet = format!("<{priority}>1 {timestamp} {hostname} {app_name} {pid} - - {message}");

    let r = match send_udp(host, port, packet.as_bytes()) {
        Ok(()) => SyslogResult {
            success: true,
            message: format!("Sent {len} bytes to {host}:{port}", len = packet.len()),
        },
        Err(e) => SyslogResult {
            success: false,
            message: e,
        },
    };
    crate::audit_log::record("syslog", "send", host, r.success, port as i32, &r.message);
    r
}

/// Validate syslog host: alphanumeric, dots, hyphens, colons (IPv6), brackets.
fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
}

fn send_udp(host: &str, port: u16, data: &[u8]) -> Result<(), String> {
    // Validate host input
    if !is_valid_host(host) {
        return Err(format!("Invalid syslog host: {host}"));
    }
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
        .send_to(data, addr)
        .map_err(|e| format!("Failed to send to {addr}: {e}"))?;
    Ok(())
}

fn rfc3339_now() -> String {
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();

    // Simple UTC timestamp without external crate
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Approximate date calculation (good enough for syslog)
    let (year, month, day) = days_to_ymd(days);

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
