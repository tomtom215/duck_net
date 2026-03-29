// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use crate::http::{self, Method};

pub struct VaultResult {
    pub success: bool,
    pub data: String,
    pub lease_duration: i64,
    pub renewable: bool,
    pub message: String,
}

pub struct VaultHealthResult {
    pub success: bool,
    pub initialized: bool,
    pub sealed: bool,
    pub standby: bool,
    pub version: String,
    pub message: String,
}

/// Maximum data payload size for write operations: 1 MiB.
const MAX_WRITE_BODY_BYTES: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate a Vault base URL: must be HTTP or HTTPS, at most 2048 characters.
/// Also checks SSRF protection (CWE-918).
fn validate_url(url: &str) -> Result<(), String> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err("Vault URL must start with http:// or https://".to_string());
    }
    if url.len() > 2048 {
        return Err("URL too long (max 2048 characters)".to_string());
    }
    crate::security::validate_no_ssrf(url)?;
    Ok(())
}

/// Validate a Vault secret path: not empty, at most 512 characters, no null
/// bytes, and must not start with `/`.
fn validate_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("Vault path cannot be empty".to_string());
    }
    if path.len() > 512 {
        return Err("Vault path too long (max 512 characters)".to_string());
    }
    if path.contains('\0') {
        return Err("Vault path must not contain null bytes".to_string());
    }
    if path.starts_with('/') {
        return Err("Vault path must not start with /".to_string());
    }
    Ok(())
}

/// Return a failed `VaultResult` with the given message.
fn vault_err(msg: String) -> VaultResult {
    VaultResult {
        success: false,
        data: String::new(),
        lease_duration: 0,
        renewable: false,
        message: msg,
    }
}

/// Return a failed `VaultHealthResult` with the given message.
fn health_err(msg: String) -> VaultHealthResult {
    VaultHealthResult {
        success: false,
        initialized: false,
        sealed: false,
        standby: false,
        version: String::new(),
        message: msg,
    }
}

// ---------------------------------------------------------------------------
// Minimal JSON helpers (booleans and integers are not covered by crate::json)
// ---------------------------------------------------------------------------

/// Extract a top-level boolean value for the given key.
/// Recognises `"key": true` and `"key": false`.
fn extract_bool(json: &str, key: &str) -> Option<bool> {
    let needle = format!("\"{key}\"");
    let mut search_from = 0;

    while let Some(pos) = json[search_from..].find(&needle) {
        let after_key = search_from + pos + needle.len();
        let rest = json[after_key..].trim_start();

        if !rest.starts_with(':') {
            search_from = after_key;
            continue;
        }

        let after_colon = rest[1..].trim_start();
        if after_colon.starts_with("true") {
            return Some(true);
        }
        if after_colon.starts_with("false") {
            return Some(false);
        }
        search_from = after_key;
    }
    None
}

/// Extract a top-level integer value for the given key.
/// Recognises `"key": 12345` (including negative values).
fn extract_i64(json: &str, key: &str) -> Option<i64> {
    let needle = format!("\"{key}\"");
    let mut search_from = 0;

    while let Some(pos) = json[search_from..].find(&needle) {
        let after_key = search_from + pos + needle.len();
        let rest = json[after_key..].trim_start();

        if !rest.starts_with(':') {
            search_from = after_key;
            continue;
        }

        let after_colon = rest[1..].trim_start();
        // Collect digits (and optional leading minus)
        let end = after_colon
            .find(|c: char| c != '-' && !c.is_ascii_digit())
            .unwrap_or(after_colon.len());
        if end == 0 {
            search_from = after_key;
            continue;
        }
        if let Ok(v) = after_colon[..end].parse::<i64>() {
            return Some(v);
        }
        search_from = after_key;
    }
    None
}

/// Extract the raw JSON value (object, array, string, number, bool, null) for
/// a top-level key.  Returns the slice of `json` that represents the value
/// (including surrounding braces/brackets/quotes for compound types).
fn extract_raw_value<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\"");
    let mut search_from = 0;

    while let Some(pos) = json[search_from..].find(&needle) {
        let after_key = search_from + pos + needle.len();
        let rest = json[after_key..].trim_start();

        if !rest.starts_with(':') {
            search_from = after_key;
            continue;
        }

        let after_colon = rest[1..].trim_start();
        let value_start = json.len() - after_colon.len();

        // Maximum nesting depth to prevent stack-exhaustion from
        // deeply nested JSON (CWE-674).
        const MAX_JSON_DEPTH: i32 = 128;

        return match after_colon.as_bytes().first()? {
            b'{' | b'[' => {
                // Find matching close bracket / brace
                let open = after_colon.as_bytes()[0];
                let close = if open == b'{' { b'}' } else { b']' };
                let mut depth = 0i32;
                let mut in_string = false;
                let bytes = after_colon.as_bytes();
                let mut i = 0;
                while i < bytes.len() {
                    if in_string {
                        if bytes[i] == b'\\' {
                            i += 2;
                            continue;
                        }
                        if bytes[i] == b'"' {
                            in_string = false;
                        }
                    } else if bytes[i] == b'"' {
                        in_string = true;
                    } else if bytes[i] == open {
                        depth += 1;
                        if depth > MAX_JSON_DEPTH {
                            return None;
                        }
                    } else if bytes[i] == close {
                        depth -= 1;
                        if depth == 0 {
                            return Some(&json[value_start..value_start + i + 1]);
                        }
                    }
                    i += 1;
                }
                None
            }
            b'"' => {
                // String value – find closing unescaped quote
                let bytes = after_colon.as_bytes();
                let mut i = 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == b'"' {
                        return Some(&json[value_start..value_start + i + 1]);
                    }
                    i += 1;
                }
                None
            }
            _ => {
                // Number, bool, null – ends at comma, whitespace, }, ]
                let end = after_colon
                    .find(|c: char| c == ',' || c == '}' || c == ']' || c.is_whitespace())
                    .unwrap_or(after_colon.len());
                Some(&json[value_start..value_start + end])
            }
        };
    }
    None
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Read a secret from Vault at the given path.
///
/// Sends `GET {url}/v1/{path}` with the `X-Vault-Token` header and parses
/// the JSON response.  Handles both KV v1 and KV v2 response shapes: for v2
/// the actual secret data lives under `data.data`, which is detected
/// automatically.
pub fn read(url: &str, token: &str, path: &str) -> VaultResult {
    if let Err(e) = validate_url(url) {
        return vault_err(e);
    }
    if token.is_empty() {
        return vault_err("Vault token cannot be empty".to_string());
    }
    if let Err(e) = validate_path(path) {
        return vault_err(e);
    }

    let api_url = format!("{}/v1/{}", url.trim_end_matches('/'), path);

    let headers = vec![("X-Vault-Token".to_string(), token.to_string())];

    let resp = http::execute(Method::Get, &api_url, &headers, None);

    if resp.status != 200 {
        return vault_err(format!(
            "Vault returned status {}: {}",
            resp.status, resp.reason
        ));
    }

    let lease_duration = extract_i64(&resp.body, "lease_duration").unwrap_or(0);
    let renewable = extract_bool(&resp.body, "renewable").unwrap_or(false);

    // Determine whether this is a KV v2 response.  KV v2 wraps the real data
    // inside `data.data`.  We detect this by checking whether the top-level
    // `data` object itself contains a `data` key that is an object.
    let data_str = if let Some(outer_data) = extract_raw_value(&resp.body, "data") {
        // Check for nested "data" key inside the outer data object (KV v2).
        if let Some(inner_data) = extract_raw_value(outer_data, "data") {
            // Only treat as v2 if the inner value is an object.
            if inner_data.starts_with('{') {
                inner_data.to_string()
            } else {
                outer_data.to_string()
            }
        } else {
            outer_data.to_string()
        }
    } else {
        String::new()
    };

    VaultResult {
        success: true,
        data: data_str,
        lease_duration,
        renewable,
        message: "OK".to_string(),
    }
}

/// Write (create or update) a secret at the given path.
///
/// Sends `POST {url}/v1/{path}` with the supplied JSON body and the
/// `X-Vault-Token` header.
pub fn write(url: &str, token: &str, path: &str, data_json: &str) -> VaultResult {
    if let Err(e) = validate_url(url) {
        return vault_err(e);
    }
    if token.is_empty() {
        return vault_err("Vault token cannot be empty".to_string());
    }
    if let Err(e) = validate_path(path) {
        return vault_err(e);
    }
    if data_json.is_empty() {
        return vault_err("Data JSON cannot be empty".to_string());
    }
    if data_json.len() > MAX_WRITE_BODY_BYTES {
        return vault_err(format!(
            "Data JSON too large ({} bytes, max {} bytes)",
            data_json.len(),
            MAX_WRITE_BODY_BYTES
        ));
    }

    let api_url = format!("{}/v1/{}", url.trim_end_matches('/'), path);

    let headers = vec![
        ("X-Vault-Token".to_string(), token.to_string()),
        ("Content-Type".to_string(), "application/json".to_string()),
    ];

    let resp = http::execute(Method::Post, &api_url, &headers, Some(data_json));

    if resp.status != 200 && resp.status != 204 {
        return vault_err(format!(
            "Vault returned status {}: {}",
            resp.status, resp.reason
        ));
    }

    let lease_duration = extract_i64(&resp.body, "lease_duration").unwrap_or(0);
    let renewable = extract_bool(&resp.body, "renewable").unwrap_or(false);

    let data_str = extract_raw_value(&resp.body, "data")
        .unwrap_or("")
        .to_string();

    VaultResult {
        success: true,
        data: data_str,
        lease_duration,
        renewable,
        message: "OK".to_string(),
    }
}

/// List secrets at the given path.
///
/// Uses the HTTP `LIST` method via `http::execute_raw_method`.  The Vault
/// HTTP API defines LIST as a distinct verb; the standard `Method` enum does
/// not include it.
pub fn list(url: &str, token: &str, path: &str) -> VaultResult {
    if let Err(e) = validate_url(url) {
        return vault_err(e);
    }
    if token.is_empty() {
        return vault_err("Vault token cannot be empty".to_string());
    }
    if let Err(e) = validate_path(path) {
        return vault_err(e);
    }

    let api_url = format!("{}/v1/{}", url.trim_end_matches('/'), path);

    let headers = vec![("X-Vault-Token".to_string(), token.to_string())];

    // Vault's LIST method is not in the standard Method enum.  Use the raw
    // method helper which accepts an arbitrary method string.
    let resp = http::execute_raw_method("LIST", &api_url, &headers, None);

    if resp.status != 200 {
        return vault_err(format!(
            "Vault returned status {}: {}",
            resp.status, resp.reason
        ));
    }

    let lease_duration = extract_i64(&resp.body, "lease_duration").unwrap_or(0);
    let renewable = extract_bool(&resp.body, "renewable").unwrap_or(false);

    // The keys list lives at data.keys in the response.
    let data_str = if let Some(data_obj) = extract_raw_value(&resp.body, "data") {
        extract_raw_value(data_obj, "keys")
            .unwrap_or(data_obj)
            .to_string()
    } else {
        String::new()
    };

    VaultResult {
        success: true,
        data: data_str,
        lease_duration,
        renewable,
        message: "OK".to_string(),
    }
}

/// Query the Vault health endpoint.
///
/// Sends `GET {url}/v1/sys/health`.  No authentication is required.  Vault
/// returns different HTTP status codes to convey health information:
///
/// - 200 – initialised, unsealed, active
/// - 429 – unsealed, standby node
/// - 472 – data-recovery mode
/// - 501 – not initialised
/// - 503 – sealed
///
/// All of the above still carry a JSON body, so we parse regardless of the
/// status code.
pub fn health(url: &str) -> VaultHealthResult {
    if let Err(e) = validate_url(url) {
        return health_err(e);
    }

    let api_url = format!("{}/v1/sys/health", url.trim_end_matches('/'));

    let resp = http::execute(Method::Get, &api_url, &[], None);

    // Vault health endpoint returns JSON even for non-200 codes.  A status of
    // 0 usually means the server was unreachable.
    if resp.status == 0 {
        return health_err(format!("Failed to reach Vault: {}", resp.reason));
    }

    let initialized = extract_bool(&resp.body, "initialized").unwrap_or(false);
    let sealed = extract_bool(&resp.body, "sealed").unwrap_or(false);
    let standby = extract_bool(&resp.body, "standby").unwrap_or(false);
    let version = crate::json::extract_string(&resp.body, "version")
        .unwrap_or("")
        .to_string();

    let message = match resp.status {
        200 => "OK".to_string(),
        429 => "Vault is in standby mode".to_string(),
        472 => "Vault is in data-recovery mode".to_string(),
        501 => "Vault is not initialized".to_string(),
        503 => "Vault is sealed".to_string(),
        _ => format!("Vault health returned status {}", resp.status),
    };

    VaultHealthResult {
        success: resp.status == 200,
        initialized,
        sealed,
        standby,
        version,
        message,
    }
}
