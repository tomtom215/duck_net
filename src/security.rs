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
                || v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0 // 192.0.0.0/24 (IETF)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()     // ::1
                || v6.is_unspecified() // ::
                // Unique local addresses (fc00::/7)
                || (v6.segments()[0] & 0xFE00) == 0xFC00
                // Link-local (fe80::/10)
                || (v6.segments()[0] & 0xFFC0) == 0xFE80
                // IPv4-mapped addresses: check the embedded IPv4
                || v6.to_ipv4_mapped().map_or(false, |v4| {
                    is_private_ip(&IpAddr::V4(v4))
                })
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
    let host = extract_hostname(url).ok_or_else(|| "Cannot extract hostname from URL".to_string())?;

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
    // Strip scheme (case-insensitive via lowercase check)
    let lower = url.to_ascii_lowercase();
    let rest = if lower.starts_with("https://") {
        &url[8..]
    } else if lower.starts_with("http://") {
        &url[7..]
    } else if lower.starts_with("ftps://") {
        &url[7..]
    } else if lower.starts_with("ftp://") {
        &url[6..]
    } else if lower.starts_with("sftp://") {
        &url[7..]
    } else if lower.starts_with("mqtt://") || lower.starts_with("mqtts://") {
        &url[url.find("://").unwrap() + 3..]
    } else if lower.starts_with("tcp://") {
        &url[6..]
    } else if lower.starts_with("ldaps://") {
        &url[8..]
    } else if lower.starts_with("ldap://") {
        &url[7..]
    } else if lower.starts_with("imaps://") {
        &url[8..]
    } else if lower.starts_with("imap://") {
        &url[7..]
    } else if lower.starts_with("smtps://") {
        &url[8..]
    } else if lower.starts_with("smtp://") {
        &url[7..]
    } else if lower.starts_with("redis://") {
        &url[8..]
    } else if lower.starts_with("grpcs://") {
        &url[8..]
    } else if lower.starts_with("grpc://") {
        &url[7..]
    } else if lower.starts_with("wss://") {
        &url[6..]
    } else if lower.starts_with("ws://") {
        &url[5..]
    } else if lower.starts_with("nats://") {
        &url[7..]
    } else if lower.starts_with("amqp://") || lower.starts_with("amqps://") {
        &url[url.find("://").unwrap() + 3..]
    } else {
        return None;
    };

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
/// Replaces patterns like `password=value` or `secret_key=value` with redacted forms.

pub fn scrub_error(msg: &str) -> String {
    let mut result = msg.to_string();

    // Scrub patterns like key=value in error messages
    for &key in &[
        "password",
        "secret",
        "token",
        "api_key",
        "secret_key",
        "access_key",
    ] {
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
            return Err(
                "Path traversal detected: '..' components are not allowed".to_string(),
            );
        }
    }

    // Also check backslash-separated paths (Windows-style)
    for component in path.split('\\') {
        if component == ".." {
            return Err(
                "Path traversal detected: '..' components are not allowed".to_string(),
            );
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
