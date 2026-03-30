// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

//! Protocol-specific input validation for duck_net.
//!
//! This module contains validation functions that are used by individual
//! protocol implementations. The core SSRF, credential scrubbing, and
//! network-level validation live in [`crate::security`]; this module
//! holds protocol-aware checks (LDAP filters, memcached keys, iCal
//! timestamps, query payloads, etc.).

// ---------------------------------------------------------------------------
// Query/Payload Size Validation (CWE-400)
// ---------------------------------------------------------------------------

/// Maximum size for query payloads (GraphQL queries, ES query bodies, etc.).
pub const MAX_QUERY_PAYLOAD: usize = 1_048_576; // 1 MiB

/// Validate that a query payload does not exceed the maximum allowed size.
pub fn validate_query_size(payload: &str, protocol: &str) -> Result<(), String> {
    if payload.len() > MAX_QUERY_PAYLOAD {
        return Err(format!(
            "{} query payload too large: {} bytes (max {} bytes)",
            protocol,
            payload.len(),
            MAX_QUERY_PAYLOAD
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Protocol-Aware TLS Enforcement Warning (CWE-319)
// ---------------------------------------------------------------------------

/// Check whether a URL uses a plaintext scheme and emit a security warning
/// if credentials are provided alongside it.
///
/// This is advisory only — it never blocks execution.
pub fn warn_if_credentials_over_plaintext(
    url: &str,
    has_credentials: bool,
    protocol: &'static str,
    warning_code: &'static str,
    secure_scheme: &str,
) {
    if !has_credentials {
        return;
    }
    let lower = url.to_ascii_lowercase();
    let is_plaintext = lower.starts_with("http://")
        || lower.starts_with("ftp://")
        || lower.starts_with("smtp://")
        || lower.starts_with("imap://")
        || lower.starts_with("ldap://")
        || lower.starts_with("mqtt://")
        || lower.starts_with("redis://")
        || lower.starts_with("amqp://")
        || lower.starts_with("nats://")
        || lower.starts_with("ws://");

    if is_plaintext {
        crate::security_warnings::warn_plaintext(protocol, warning_code, secure_scheme);
    }
}

// ---------------------------------------------------------------------------
// LDAP Filter Validation (CWE-90)
// ---------------------------------------------------------------------------

/// Validate an LDAP filter string for obvious injection patterns.
///
/// This does NOT fully parse the RFC 4515 grammar but rejects strings
/// that are likely to be unescaped user input concatenated into a filter.
/// Specifically, it rejects filters containing unbalanced parentheses,
/// null bytes, or exceeding length limits.
pub fn validate_ldap_filter(filter: &str) -> Result<(), String> {
    if filter.is_empty() {
        return Err("LDAP filter must not be empty".to_string());
    }
    if filter.len() > 8192 {
        return Err("LDAP filter too long (max 8192 characters)".to_string());
    }
    if filter.contains('\0') {
        return Err("LDAP filter must not contain null bytes".to_string());
    }

    // Check balanced parentheses
    let mut depth: i32 = 0;
    for ch in filter.chars() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth < 0 {
                    return Err(
                        "LDAP filter has unbalanced parentheses (extra closing)".to_string()
                    );
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err("LDAP filter has unbalanced parentheses (unclosed)".to_string());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// CalDAV/XML Timestamp Validation (CWE-91)
// ---------------------------------------------------------------------------

/// Validate an iCalendar timestamp format (ISO 8601 / RFC 3339 subset).
///
/// Accepts formats like: `20230101T000000Z` or `2023-01-01T00:00:00Z`.
/// Rejects values containing XML-unsafe characters to prevent XML injection.
pub fn validate_ical_timestamp(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 32 {
        return Err("Timestamp must be 1-32 characters".to_string());
    }
    // Only allow digits, T, Z, :, -, + (ISO 8601 characters)
    if !value
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, 'T' | 'Z' | ':' | '-' | '+' | '.'))
    {
        return Err(format!(
            "Invalid timestamp format: only ISO 8601 characters allowed, got '{}'",
            value
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Memcached Key Validation (CWE-400)
// ---------------------------------------------------------------------------

/// Validate a memcached key per protocol specification.
///
/// Keys must be non-empty, at most 250 bytes, and contain only printable
/// ASCII (0x21–0x7E). Space (0x20) and control characters are rejected.
#[allow(dead_code)]
pub fn validate_memcached_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("Memcached key must not be empty".to_string());
    }
    if key.len() > 250 {
        return Err("Memcached key too long (max 250 bytes)".to_string());
    }
    if !key.bytes().all(|b| (0x21..0x7F).contains(&b)) {
        return Err(
            "Memcached key contains invalid characters (only printable ASCII 0x21-0x7E allowed)"
                .to_string(),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// MQTT Topic Validation
// ---------------------------------------------------------------------------

/// Validate an MQTT topic string for safety.
///
/// Rejects null bytes and excessively long topics. MQTT wildcards
/// (`+` and `#`) are allowed as they are valid in subscriptions.
#[allow(dead_code)]
pub fn validate_mqtt_topic(topic: &str) -> Result<(), String> {
    if topic.is_empty() {
        return Err("MQTT topic must not be empty".to_string());
    }
    if topic.len() > 65535 {
        return Err("MQTT topic too long (max 65535 bytes per spec)".to_string());
    }
    if topic.contains('\0') {
        return Err("MQTT topic must not contain null bytes".to_string());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Redis Command Validation
// ---------------------------------------------------------------------------

/// Validate a Redis command for injection safety.
///
/// Blocks null bytes and excessively long commands. Does NOT prevent
/// dangerous commands (FLUSHALL, CONFIG SET, etc.) — that is the
/// responsibility of Redis ACLs and network policy.
#[allow(dead_code)]
pub fn validate_redis_command(cmd: &str) -> Result<(), String> {
    if cmd.is_empty() {
        return Err("Redis command must not be empty".to_string());
    }
    if cmd.len() > 1_048_576 {
        return Err("Redis command too long (max 1 MiB)".to_string());
    }
    if cmd.contains('\0') {
        return Err("Redis command must not contain null bytes".to_string());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SNMP Community String Validation
// ---------------------------------------------------------------------------

/// Validate an SNMP community string.
///
/// Rejects null bytes and excessively long strings. Community strings
/// are effectively plaintext passwords, so their length is a reasonable
/// proxy for complexity.
#[allow(dead_code)]
pub fn validate_snmp_community(community: &str) -> Result<(), String> {
    if community.is_empty() {
        return Err("SNMP community string must not be empty".to_string());
    }
    if community.len() > 255 {
        return Err("SNMP community string too long (max 255 bytes)".to_string());
    }
    if community.contains('\0') {
        return Err("SNMP community string must not contain null bytes".to_string());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// LDAP Filter Escaping (CWE-90, RFC 4515)
// ---------------------------------------------------------------------------

/// Escape special characters in LDAP filter values per RFC 4515.
///
/// Characters that MUST be escaped: `*`, `(`, `)`, `\`, NUL.
/// This prevents LDAP injection attacks (CWE-90).
pub fn ldap_escape_filter_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 16);
    for byte in value.bytes() {
        match byte {
            b'*' => escaped.push_str("\\2a"),
            b'(' => escaped.push_str("\\28"),
            b')' => escaped.push_str("\\29"),
            b'\\' => escaped.push_str("\\5c"),
            0x00 => escaped.push_str("\\00"),
            _ => escaped.push(byte as char),
        }
    }
    escaped
}

// ---------------------------------------------------------------------------
// JSON String Escaping (CWE-116)
// ---------------------------------------------------------------------------

/// Escape a string for safe inclusion in a JSON string value.
/// Handles all control characters per RFC 8259.
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0C' => out.push_str("\\f"),
            c if c < '\x20' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}
