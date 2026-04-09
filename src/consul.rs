// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use base64::Engine as _;

use crate::http::{self, Method};

pub struct KvResult {
    pub success: bool,
    pub value: String,
    pub message: String,
}

// ===== Validation helpers =====

/// Validate that a URL starts with http:// or https://, is not too long,
/// and does not target private/reserved IPs (SSRF protection, CWE-918).
fn validate_url(url: &str) -> Result<(), String> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err("URL must start with http:// or https://".to_string());
    }
    if url.len() > 2048 {
        return Err("URL too long (max 2048 characters)".to_string());
    }
    crate::security::validate_no_ssrf(url)?;
    Ok(())
}

/// Validate that a key is non-empty, within size limits, and has no null bytes.
fn validate_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("Key cannot be empty".to_string());
    }
    if key.len() > 512 {
        return Err("Key too long (max 512 characters)".to_string());
    }
    if key.contains('\0') {
        return Err("Key must not contain null bytes".to_string());
    }
    Ok(())
}

/// Build a failing `KvResult` from an error message.
fn fail(msg: String) -> KvResult {
    KvResult {
        success: false,
        value: String::new(),
        message: msg,
    }
}

// ===== Consul KV (HTTP API v1) =====

/// Get a value from the Consul KV store.
///
/// Sends GET `{url}/v1/kv/{key}?raw` and returns the raw value body.
/// If `token` is non-empty it is passed as the `X-Consul-Token` header.
pub fn consul_get(url: &str, key: &str, token: &str) -> KvResult {
    if let Err(e) = validate_url(url) {
        return fail(e);
    }
    if let Err(e) = validate_key(key) {
        return fail(e);
    }

    // Warn if token is sent over plaintext HTTP (CWE-523)
    if !token.is_empty() && url.starts_with("http://") {
        crate::security_warnings::warn_token_over_plaintext("Consul", "TOKEN_OVER_HTTP_CONSUL");
    }

    let api_url = format!("{}/v1/kv/{}?raw", url.trim_end_matches('/'), key);

    let mut headers: Vec<(String, String)> = Vec::new();
    if !token.is_empty() {
        headers.push(("X-Consul-Token".into(), token.into()));
    }

    let resp = http::execute(Method::Get, &api_url, &headers, None);
    let host = crate::audit_log::host_from_url(url);

    if resp.status != 200 {
        let msg = format!(
            "Consul GET returned status {}: {}",
            resp.status, resp.reason
        );
        crate::audit_log::record("consul", "get", &host, false, resp.status as i32, &msg);
        return fail(msg);
    }

    crate::audit_log::record("consul", "get", &host, true, resp.status as i32, "");
    KvResult {
        success: true,
        value: resp.body,
        message: "OK".to_string(),
    }
}

/// Set a value in the Consul KV store.
///
/// Sends PUT `{url}/v1/kv/{key}` with the value as the request body.
/// Consul responds with `"true"` or `"false"` indicating success.
pub fn consul_set(url: &str, key: &str, value: &str, token: &str) -> KvResult {
    if let Err(e) = validate_url(url) {
        return fail(e);
    }
    if let Err(e) = validate_key(key) {
        return fail(e);
    }

    let api_url = format!("{}/v1/kv/{}", url.trim_end_matches('/'), key);

    let mut headers: Vec<(String, String)> = Vec::new();
    if !token.is_empty() {
        headers.push(("X-Consul-Token".into(), token.into()));
    }

    let resp = http::execute(Method::Put, &api_url, &headers, Some(value));
    let host = crate::audit_log::host_from_url(url);

    if resp.status != 200 {
        let msg = format!(
            "Consul PUT returned status {}: {}",
            resp.status, resp.reason
        );
        crate::audit_log::record("consul", "set", &host, false, resp.status as i32, &msg);
        return fail(msg);
    }

    let wrote = resp.body.trim() == "true";
    let msg = if wrote {
        "OK".to_string()
    } else {
        "Consul returned false — write was rejected".to_string()
    };
    crate::audit_log::record("consul", "set", &host, wrote, resp.status as i32, &msg);
    KvResult {
        success: wrote,
        value: String::new(),
        message: msg,
    }
}

/// Delete a key from the Consul KV store.
///
/// Sends DELETE `{url}/v1/kv/{key}`.
pub fn consul_delete(url: &str, key: &str, token: &str) -> KvResult {
    if let Err(e) = validate_url(url) {
        return fail(e);
    }
    if let Err(e) = validate_key(key) {
        return fail(e);
    }

    let api_url = format!("{}/v1/kv/{}", url.trim_end_matches('/'), key);

    let mut headers: Vec<(String, String)> = Vec::new();
    if !token.is_empty() {
        headers.push(("X-Consul-Token".into(), token.into()));
    }

    let resp = http::execute(Method::Delete, &api_url, &headers, None);
    let host = crate::audit_log::host_from_url(url);

    if resp.status != 200 {
        let msg = format!(
            "Consul DELETE returned status {}: {}",
            resp.status, resp.reason
        );
        crate::audit_log::record("consul", "delete", &host, false, resp.status as i32, &msg);
        return fail(msg);
    }

    crate::audit_log::record("consul", "delete", &host, true, resp.status as i32, "");
    KvResult {
        success: true,
        value: String::new(),
        message: "OK".to_string(),
    }
}

// ===== etcd v3 HTTP/JSON gateway =====

/// Base64 engine used for etcd key/value encoding.
fn b64_engine() -> &'static base64::engine::general_purpose::GeneralPurpose {
    &base64::engine::general_purpose::STANDARD
}

/// Get a value from etcd via the v3 HTTP/JSON gateway.
///
/// Sends POST `{url}/v3/kv/range` with the key base64-encoded in the
/// JSON body.  The returned value (also base64-encoded) is decoded
/// before being placed in `KvResult.value`.
pub fn etcd_get(url: &str, key: &str) -> KvResult {
    if let Err(e) = validate_url(url) {
        return fail(e);
    }
    if let Err(e) = validate_key(key) {
        return fail(e);
    }

    let api_url = format!("{}/v3/kv/range", url.trim_end_matches('/'));

    let encoded_key = b64_engine().encode(key.as_bytes());
    let body = format!("{{\"key\":\"{encoded_key}\"}}");

    let headers: Vec<(String, String)> = vec![("Content-Type".into(), "application/json".into())];

    let resp = http::execute(Method::Post, &api_url, &headers, Some(&body));
    let host = crate::audit_log::host_from_url(url);

    if resp.status != 200 {
        let msg = format!(
            "etcd range returned status {}: {}",
            resp.status, resp.reason
        );
        crate::audit_log::record("etcd", "get", &host, false, resp.status as i32, &msg);
        return fail(msg);
    }

    // Extract the first value from the kvs array.
    // Response shape: {"kvs":[{"key":"...","value":"<base64>", ...}], ...}
    let value_b64 = match extract_first_kv_value(&resp.body) {
        Some(v) => v,
        None => {
            return fail("Key not found in etcd (no kvs in response)".to_string());
        }
    };

    let decoded = match b64_engine().decode(value_b64.as_bytes()) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => {
                return fail("etcd value is not valid UTF-8".to_string());
            }
        },
        Err(e) => {
            return fail(format!("Failed to base64-decode etcd value: {e}"));
        }
    };

    crate::audit_log::record("etcd", "get", &host, true, resp.status as i32, "");
    KvResult {
        success: true,
        value: decoded,
        message: "OK".to_string(),
    }
}

/// Put a key-value pair into etcd via the v3 HTTP/JSON gateway.
///
/// Sends POST `{url}/v3/kv/put` with both key and value base64-encoded
/// in the JSON body.
pub fn etcd_put(url: &str, key: &str, value: &str) -> KvResult {
    if let Err(e) = validate_url(url) {
        return fail(e);
    }
    if let Err(e) = validate_key(key) {
        return fail(e);
    }

    let api_url = format!("{}/v3/kv/put", url.trim_end_matches('/'));

    let encoded_key = b64_engine().encode(key.as_bytes());
    let encoded_value = b64_engine().encode(value.as_bytes());
    let body = format!("{{\"key\":\"{encoded_key}\",\"value\":\"{encoded_value}\"}}");

    let headers: Vec<(String, String)> = vec![("Content-Type".into(), "application/json".into())];

    let resp = http::execute(Method::Post, &api_url, &headers, Some(&body));
    let host = crate::audit_log::host_from_url(url);

    if resp.status != 200 {
        let msg = format!("etcd put returned status {}: {}", resp.status, resp.reason);
        crate::audit_log::record("etcd", "put", &host, false, resp.status as i32, &msg);
        return fail(msg);
    }

    crate::audit_log::record("etcd", "put", &host, true, resp.status as i32, "");
    KvResult {
        success: true,
        value: String::new(),
        message: "OK".to_string(),
    }
}

/// Extract the `value` field from the first entry in `kvs` inside an etcd
/// range-response JSON body.
///
/// Looks for `"kvs":[{..."value":"<base64>"...}]` and returns the raw
/// base64 string.  Uses simple string scanning (no full JSON parser).
fn extract_first_kv_value(body: &str) -> Option<String> {
    // Locate the "kvs" array.
    let kvs_pos = body.find("\"kvs\"")?;
    let after_kvs = &body[kvs_pos + 5..].trim_start();
    if !after_kvs.starts_with(':') {
        return None;
    }
    let after_colon = after_kvs[1..].trim_start();
    if !after_colon.starts_with('[') {
        return None;
    }

    // Now find "value" inside the first object of the kvs array.
    let first_obj = &after_colon[1..]; // skip '['
    let value_needle = "\"value\"";
    let vpos = first_obj.find(value_needle)?;
    let after_value_key = first_obj[vpos + value_needle.len()..].trim_start();
    if !after_value_key.starts_with(':') {
        return None;
    }
    let after_v_colon = after_value_key[1..].trim_start();
    if !after_v_colon.starts_with('"') {
        return None;
    }
    // Extract the quoted string value.
    let content = &after_v_colon[1..]; // skip opening quote
    let end_quote = content.find('"')?;
    Some(content[..end_quote].to_string())
}
