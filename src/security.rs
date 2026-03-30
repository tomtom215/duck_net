// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

//! Shared security utilities for duck_net.
//!
//! Provides centralized input validation, SSRF protection, credential
//! scrubbing, and path traversal prevention used across all protocols.

use std::net::{IpAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};

/// Global flag: when true, private/reserved IP addresses are blocked (SSRF protection).
/// Enabled by default. Can be disabled for local development via
/// `duck_net_set_ssrf_protection(false)`.
static SSRF_PROTECTION_ENABLED: AtomicBool = AtomicBool::new(true);

/// Enable or disable SSRF private-network blocking.
pub fn set_ssrf_protection(enabled: bool) {
    SSRF_PROTECTION_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Check whether SSRF protection is enabled.
pub fn ssrf_protection_enabled() -> bool {
    SSRF_PROTECTION_ENABLED.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// SSRF Protection (CWE-918)
// ---------------------------------------------------------------------------

/// Check if an IP address is private, loopback, link-local, or otherwise
/// reserved. These should not be reachable from SQL queries to prevent SSRF.
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()              // 127.0.0.0/8
                || v4.is_private()         // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local()      // 169.254.0.0/16
                || v4.is_broadcast()       // 255.255.255.255
                || v4.is_unspecified()     // 0.0.0.0
                || v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64 // 100.64.0.0/10 (CGN)
                || v4.octets()[0] == 198 && (v4.octets()[1] & 0xFE) == 18 // 198.18.0.0/15 (benchmark)
                || v4.is_documentation()   // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
                || v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0
            // 192.0.0.0/24 (IETF)
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            v6.is_loopback()     // ::1
                || v6.is_unspecified() // ::
                // Unique local addresses (fc00::/7)
                || (segs[0] & 0xFE00) == 0xFC00
                // Link-local (fe80::/10)
                || (segs[0] & 0xFFC0) == 0xFE80
                // Multicast (ff00::/8)
                || (segs[0] & 0xFF00) == 0xFF00
                // Teredo tunneling (2001::/32) – RFC 4380
                || (segs[0] == 0x2001 && segs[1] == 0x0000)
                // 6to4 (2002::/16) – RFC 3056: embedded IPv4 may be private
                || (segs[0] == 0x2002 && {
                    let embedded = std::net::Ipv4Addr::new(
                        (segs[1] >> 8) as u8,
                        (segs[1] & 0xFF) as u8,
                        (segs[2] >> 8) as u8,
                        (segs[2] & 0xFF) as u8,
                    );
                    is_private_ip(&IpAddr::V4(embedded))
                })
                // NAT64 well-known prefix (64:ff9b::/96) – RFC 6052
                || (segs[0] == 0x0064
                    && segs[1] == 0xFF9B
                    && segs[2] == 0
                    && segs[3] == 0
                    && segs[4] == 0
                    && segs[5] == 0)
                // IPv6 documentation (2001:db8::/32) – RFC 3849
                || (segs[0] == 0x2001 && segs[1] == 0x0DB8)
                // IPv4-mapped addresses (::ffff:0:0/96): check the embedded IPv4
                || v6.to_ipv4_mapped().is_some_and(|v4| {
                    is_private_ip(&IpAddr::V4(v4))
                })
                // IPv4-translated addresses (::ffff:0:0:0/96) – RFC 6145
                || (segs[0] == 0
                    && segs[1] == 0
                    && segs[2] == 0
                    && segs[3] == 0
                    && segs[4] == 0xFFFF
                    && segs[5] == 0)
        }
    }
}

/// Validate that a URL's hostname does not resolve to a private/reserved IP.
/// This prevents SSRF attacks where an attacker controls the URL to reach
/// internal services (e.g., cloud metadata at 169.254.169.254).
///
/// Returns Ok(()) if the URL is safe, or Err with a message if blocked.
pub fn validate_no_ssrf(url: &str) -> Result<(), String> {
    if !ssrf_protection_enabled() {
        return Ok(());
    }

    // Extract hostname from URL
    let host =
        extract_hostname(url).ok_or_else(|| "Cannot extract hostname from URL".to_string())?;

    validate_no_ssrf_host(&host)
}

/// Validate that a raw hostname does not resolve to a private/reserved IP.
/// Use this for non-URL protocols (Redis, MQTT, LDAP, etc.) that take a
/// hostname directly rather than a full URL.
pub fn validate_no_ssrf_host(host: &str) -> Result<(), String> {
    if !ssrf_protection_enabled() {
        return Ok(());
    }

    // Try to resolve the hostname
    let addr_str = if host.contains(':') {
        host.to_string() // Already has port or is IPv6
    } else {
        format!("{}:443", host) // Add dummy port for resolution
    };

    match addr_str.to_socket_addrs() {
        Ok(addrs) => {
            let addrs: Vec<_> = addrs.collect();
            if addrs.is_empty() {
                return Err(format!(
                    "SSRF protection: hostname '{}' resolved to no addresses. \
                     Use duck_net_set_ssrf_protection(false) to disable for local development.",
                    host
                ));
            }
            for addr in &addrs {
                if is_private_ip(&addr.ip()) {
                    return Err(format!(
                        "SSRF protection: hostname '{}' resolves to private/reserved IP {}. \
                         Use duck_net_set_ssrf_protection(false) to disable for local development.",
                        host,
                        addr.ip()
                    ));
                }
            }
            Ok(())
        }
        Err(_) => {
            // Block on DNS resolution failure to prevent DNS rebinding attacks.
            // If this is a legitimate host, retrying will succeed.
            Err(format!(
                "SSRF protection: cannot resolve hostname '{}'. \
                 Use duck_net_set_ssrf_protection(false) to disable for local development.",
                host
            ))
        }
    }
}

/// Extract the hostname portion from a URL.
fn extract_hostname(url: &str) -> Option<String> {
    // Strip scheme: find "://" separator and take everything after it.
    let scheme_end = url.find("://")?;
    let lower_scheme = url[..scheme_end].to_ascii_lowercase();

    // Validate that the scheme is one we recognize
    const KNOWN_SCHEMES: &[&str] = &[
        "https", "http", "ftp", "ftps", "sftp", "mqtt", "mqtts", "tcp", "ldap", "ldaps", "imap",
        "imaps", "smtp", "smtps", "redis", "grpc", "grpcs", "ws", "wss", "nats", "amqp", "amqps",
    ];
    if !KNOWN_SCHEMES.contains(&lower_scheme.as_str()) {
        return None;
    }

    let rest = &url[scheme_end + 3..];

    // Strip userinfo
    let after_auth = if let Some(at) = rest.find('@') {
        &rest[at + 1..]
    } else {
        rest
    };

    // Take host[:port] before path
    let host_port = after_auth.split('/').next().unwrap_or(after_auth);

    // Strip port (but handle IPv6 brackets)
    if host_port.starts_with('[') {
        // IPv6: [::1]:port
        if let Some(bracket_end) = host_port.find(']') {
            Some(host_port[..=bracket_end].to_string())
        } else {
            Some(host_port.to_string())
        }
    } else if let Some(colon) = host_port.rfind(':') {
        // Only strip port if what follows looks like a number
        let after_colon = &host_port[colon + 1..];
        if after_colon.chars().all(|c| c.is_ascii_digit()) {
            Some(host_port[..colon].to_string())
        } else {
            Some(host_port.to_string())
        }
    } else {
        Some(host_port.to_string())
    }
}

// ---------------------------------------------------------------------------
// Credential Scrubbing (CWE-532)
// ---------------------------------------------------------------------------

/// Scrub credentials from a URL for safe inclusion in error messages.
///
/// Replaces `scheme://user:pass@host` with `scheme://***@host`.
pub fn scrub_url(url: &str) -> String {
    if let Some(at) = url.find('@') {
        if let Some(scheme_end) = url.find("://") {
            return format!("{}://***@{}", &url[..scheme_end], &url[at + 1..]);
        }
    }
    url.to_string()
}

/// Scrub known sensitive parameter values from an error message.
///
/// Replaces patterns like `password=value` or `secret_key=value` with
/// redacted forms. Also scrubs Base64-encoded `Authorization` and
/// `Bearer` header values that may leak through error messages (CWE-532).
pub fn scrub_error(msg: &str) -> String {
    let mut result = msg.to_string();

    // Scrub patterns like key=value in error messages
    let sensitive_keys = [
        "password",
        "secret",
        "token",
        "api_key",
        "secret_key",
        "access_key",
        "bearer_token",
        "private_key",
        "client_secret",
        "community",
        "shared_secret",
    ];

    for &key in &sensitive_keys {
        // Pattern: key=somevalue (until whitespace or end)
        let pattern = format!("{}=", key);
        if let Some(start) = result.to_lowercase().find(&pattern) {
            let after = start + pattern.len();
            let end = result[after..]
                .find(|c: char| c.is_whitespace() || c == '&' || c == '"' || c == '\'')
                .map(|p| after + p)
                .unwrap_or(result.len());
            result = format!("{}{}=********{}", &result[..start], key, &result[end..]);
        }
    }

    // Scrub Authorization header values (Basic/Bearer)
    for prefix in &["Authorization: Bearer ", "Authorization: Basic "] {
        if let Some(start) = result.find(prefix) {
            let after = start + prefix.len();
            let end = result[after..]
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                .map(|p| after + p)
                .unwrap_or(result.len());
            result = format!("{}{}********{}", &result[..start], prefix, &result[end..]);
        }
    }

    // Scrub AUTH PLAIN base64 payloads
    if let Some(start) = result.find("AUTH PLAIN ") {
        let after = start + "AUTH PLAIN ".len();
        let end = result[after..]
            .find(|c: char| c.is_whitespace() || c == '\r' || c == '\n')
            .map(|p| after + p)
            .unwrap_or(result.len());
        result = format!("{}AUTH PLAIN ********{}", &result[..start], &result[end..]);
    }

    result
}

// ---------------------------------------------------------------------------
// Path Traversal Prevention (CWE-22)
// ---------------------------------------------------------------------------

/// Validate that a file path does not contain directory traversal sequences.
///
/// Blocks:
/// - `..` path components (traversal)
/// - Null bytes (C string injection)
/// - Excessively long paths
pub fn validate_path_no_traversal(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("Path cannot be empty".to_string());
    }
    if path.len() > 4096 {
        return Err("Path exceeds maximum length of 4096".to_string());
    }
    if path.contains('\0') {
        return Err("Path must not contain null bytes".to_string());
    }

    // Check for directory traversal via path components
    for component in path.split('/') {
        if component == ".." {
            return Err("Path traversal detected: '..' components are not allowed".to_string());
        }
    }

    // Also check backslash-separated paths (Windows-style)
    for component in path.split('\\') {
        if component == ".." {
            return Err("Path traversal detected: '..' components are not allowed".to_string());
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// SSH Command Validation (CWE-78)
// ---------------------------------------------------------------------------

/// Characters that are dangerous in shell commands.
const SHELL_DANGEROUS_CHARS: &[char] = &[
    ';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\n', '\r', '\0',
];

/// Validate an SSH command for dangerous shell metacharacters.
///
/// This is a defense-in-depth measure. Commands are executed via SSH's exec
/// channel which doesn't invoke a shell, but the remote sshd may pipe through
/// a shell depending on configuration.
///
/// When `strict` is true, rejects commands containing shell metacharacters.
/// When `strict` is false, only rejects null bytes and CRLF (always dangerous).
pub fn validate_ssh_command(command: &str, strict: bool) -> Result<(), String> {
    if command.is_empty() {
        return Err("Command cannot be empty".to_string());
    }
    if command.len() > 8192 {
        return Err("Command exceeds maximum length of 8192".to_string());
    }
    if command.contains('\0') {
        return Err("Command must not contain null bytes".to_string());
    }

    if strict {
        for &c in SHELL_DANGEROUS_CHARS {
            if c != '\0' && command.contains(c) {
                return Err(format!(
                    "Command contains potentially dangerous character: '{}'",
                    if c == '\n' {
                        "\\n".to_string()
                    } else if c == '\r' {
                        "\\r".to_string()
                    } else {
                        c.to_string()
                    }
                ));
            }
        }
    } else {
        // Even in non-strict mode, block CRLF injection
        if command.contains('\n') || command.contains('\r') {
            return Err("Command must not contain newline characters".to_string());
        }
    }

    Ok(())
}

/// Global flag for SSH strict command validation.
/// Defaults to true (security-by-default): rejects shell metacharacters.
/// Set to false only for trusted environments that require complex commands.
static SSH_STRICT_COMMANDS: AtomicBool = AtomicBool::new(true);

pub fn set_ssh_strict_commands(strict: bool) {
    SSH_STRICT_COMMANDS.store(strict, Ordering::Relaxed);
}

pub fn ssh_strict_commands() -> bool {
    SSH_STRICT_COMMANDS.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Input length validation
// ---------------------------------------------------------------------------

/// Validate that a credential string is within acceptable bounds.
/// Prevents buffer-overflow attempts and memory exhaustion.
pub fn validate_credential_length(name: &str, value: &str, max_len: usize) -> Result<(), String> {
    if value.len() > max_len {
        return Err(format!(
            "{} exceeds maximum length of {} characters",
            name, max_len
        ));
    }
    if value.contains('\0') {
        return Err(format!("{} must not contain null bytes", name));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// URL Length Validation (CWE-400)
// ---------------------------------------------------------------------------

/// Maximum URL length accepted by duck_net functions.
pub const MAX_URL_LENGTH: usize = 65_536;

/// Validate that a URL does not exceed the maximum length.
pub fn validate_url_length(url: &str) -> Result<(), String> {
    if url.len() > MAX_URL_LENGTH {
        return Err(format!(
            "URL exceeds maximum length of {} characters",
            MAX_URL_LENGTH
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Port Validation
// ---------------------------------------------------------------------------

/// Validate that a port number is in a valid range (1-65535).
#[allow(dead_code)]
pub fn validate_port(port: u16) -> Result<(), String> {
    if port == 0 {
        return Err("Port must be between 1 and 65535".to_string());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Re-exports from security_validate
// ---------------------------------------------------------------------------

/// Escape special characters in LDAP filter values per RFC 4515 (CWE-90).
/// See [`crate::security_validate::ldap_escape_filter_value`].
#[allow(dead_code)]
pub fn ldap_escape_filter_value(value: &str) -> String {
    crate::security_validate::ldap_escape_filter_value(value)
}

/// Escape a string for safe inclusion in a JSON string value (CWE-116).
/// See [`crate::security_validate::json_escape`].
pub fn json_escape(s: &str) -> String {
    crate::security_validate::json_escape(s)
}

/// Validate an iCalendar timestamp format (CWE-91).
/// See [`crate::security_validate::validate_ical_timestamp`].
pub fn validate_ical_timestamp(value: &str) -> Result<(), String> {
    crate::security_validate::validate_ical_timestamp(value)
}

// ---------------------------------------------------------------------------
// Cryptographic Random Bytes
// ---------------------------------------------------------------------------

/// Generate cryptographically secure random bytes using the OS entropy source.
///
/// Uses `getrandom` which calls the OS CSPRNG (e.g., /dev/urandom, CryptGenRandom).
/// Panics if the OS entropy source is unavailable, which should never happen on
/// any supported platform. Failing open with weak randomness would be a security
/// vulnerability (CWE-338).
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf)
        .expect("OS entropy source unavailable — cannot generate secure random bytes");
    buf
}

/// Generate a random hex string of the specified byte length.
///
/// Uses cryptographically secure random bytes from the OS.
pub fn random_hex(byte_count: usize) -> String {
    let bytes = random_bytes_vec(byte_count);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Generate a Vec of cryptographically secure random bytes.
fn random_bytes_vec(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf)
        .expect("OS entropy source unavailable — cannot generate secure random bytes");
    buf
}

// ---------------------------------------------------------------------------
// HTTP Header Injection Prevention (CWE-113)
// ---------------------------------------------------------------------------

/// Validate an HTTP header name against RFC 7230 §3.2 token rules.
///
/// Header names must be non-empty, at most 256 bytes, and contain only
/// `!#$%&'*+-.^_\`|~` and alphanumeric characters. CRLF and spaces are
/// rejected to prevent header injection.
pub fn validate_http_header_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("HTTP header name must not be empty".to_string());
    }
    if name.len() > 256 {
        return Err("HTTP header name too long (max 256 bytes)".to_string());
    }
    for ch in name.chars() {
        if !is_tchar(ch) {
            return Err(format!(
                "HTTP header name contains invalid character: {:?} (RFC 7230 token required)",
                ch
            ));
        }
    }
    Ok(())
}

/// Validate an HTTP header value for CRLF injection (CWE-113).
///
/// Rejects values containing `\r`, `\n`, or `\0` which could inject
/// additional HTTP headers or responses into a connection.
pub fn validate_http_header_value(value: &str) -> Result<(), String> {
    if value.len() > 8192 {
        return Err("HTTP header value too long (max 8192 bytes)".to_string());
    }
    for (i, ch) in value.chars().enumerate() {
        if ch == '\r' || ch == '\n' || ch == '\0' {
            return Err(format!(
                "HTTP header value contains disallowed control character at byte {}: {:?}. \
                 CRLF injection in headers is blocked (CWE-113).",
                i, ch
            ));
        }
    }
    Ok(())
}

/// Validate all headers in a list for name and value safety.
pub fn validate_headers(headers: &[(String, String)]) -> Result<(), String> {
    for (name, value) in headers {
        validate_http_header_name(name)?;
        validate_http_header_value(value)?;
    }
    Ok(())
}

/// RFC 7230 §3.2.6 token character: any VCHAR except delimiters.
fn is_tchar(c: char) -> bool {
    matches!(c,
        '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '.' |
        '^' | '_' | '`' | '|' | '~' |
        'A'..='Z' | 'a'..='z' | '0'..='9'
    )
}

/// Check if a URL uses plain HTTP (not HTTPS).
pub fn is_plaintext_http(url: &str) -> bool {
    url.trim().to_ascii_lowercase().starts_with("http://")
}

/// Check if a URL uses HTTPS.
#[allow(dead_code)]
pub fn is_secure_https(url: &str) -> bool {
    url.trim().to_ascii_lowercase().starts_with("https://")
}

// ---------------------------------------------------------------------------
// Host Validation (shared across protocols)
// ---------------------------------------------------------------------------

/// Validate a hostname or IP address for safe use in network connections.
///
/// Allows: alphanumeric, dots, hyphens, colons (IPv6), brackets (IPv6),
/// underscores (common in internal DNS names).
/// Rejects: empty, too long (>253), or containing other characters.
pub fn validate_host(host: &str) -> Result<(), String> {
    if host.is_empty() {
        return Err("Hostname must not be empty".to_string());
    }
    if host.len() > 253 {
        return Err("Hostname too long (max 253 characters)".to_string());
    }
    if !host
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']' | '_'))
    {
        return Err(format!("Hostname contains invalid characters: '{}'", host));
    }
    Ok(())
}
