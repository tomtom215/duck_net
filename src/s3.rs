// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use crate::aws_sigv4;
use crate::http::{self, Method};

const MAX_BODY_SIZE: usize = 256 * 1024 * 1024; // 256 MiB

pub struct S3Result {
    pub success: bool,
    pub body: String,
    pub status: i32,
    pub message: String,
}

pub struct S3ListResult {
    pub success: bool,
    pub keys: Vec<String>,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate that the endpoint starts with http:// or https://.
fn validate_endpoint(endpoint: &str) -> Result<(), String> {
    if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
        return Err("S3 endpoint must start with http:// or https://".to_string());
    }
    Ok(())
}

/// Validate S3 bucket naming rules:
/// - Length between 3 and 63 characters
/// - Only lowercase alphanumeric characters, hyphens, and dots
/// - Must start and end with a letter or digit
fn validate_bucket(bucket: &str) -> Result<(), String> {
    if bucket.is_empty() {
        return Err("Bucket name cannot be empty".to_string());
    }
    if bucket.len() < 3 || bucket.len() > 63 {
        return Err(format!(
            "Bucket name must be between 3 and 63 characters, got {}",
            bucket.len()
        ));
    }
    for ch in bucket.chars() {
        if !ch.is_ascii_lowercase() && !ch.is_ascii_digit() && ch != '-' && ch != '.' {
            return Err(format!(
                "Bucket name contains invalid character: '{}' (allowed: a-z, 0-9, '-', '.')",
                ch
            ));
        }
    }
    let first = bucket.as_bytes()[0];
    let last = bucket.as_bytes()[bucket.len() - 1];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err("Bucket name must start with a letter or digit".to_string());
    }
    if !(last.is_ascii_lowercase() || last.is_ascii_digit()) {
        return Err("Bucket name must end with a letter or digit".to_string());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// URL / header helpers
// ---------------------------------------------------------------------------

/// URL-encode a string for use in path segments.
/// Encodes everything except unreserved characters (A-Z a-z 0-9 - . _ ~) and '/'.
fn url_encode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'.'
            | b'_'
            | b'~'
            | b'/' => out.push(byte as char),
            _ => {
                out.push('%');
                out.push_str(&format!("{byte:02X}"));
            }
        }
    }
    out
}

/// URL-encode a string for use in query parameter values.
/// Encodes everything except unreserved characters (no '/' exception).
fn url_encode_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'.'
            | b'_'
            | b'~' => out.push(byte as char),
            _ => {
                out.push('%');
                out.push_str(&format!("{byte:02X}"));
            }
        }
    }
    out
}

/// Extract the host portion from a URL (strip scheme, take up to the first '/').
fn extract_host(endpoint: &str) -> String {
    let rest = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))
        .unwrap_or(endpoint);
    match rest.find('/') {
        Some(pos) => rest[..pos].to_string(),
        None => rest.to_string(),
    }
}

/// Build the HTTP header vector from a signed request plus the host.
fn build_s3_headers(signed: &aws_sigv4::SignedRequest, host: &str) -> Vec<(String, String)> {
    vec![
        ("Authorization".to_string(), signed.authorization.clone()),
        ("x-amz-date".to_string(), signed.x_amz_date.clone()),
        (
            "x-amz-content-sha256".to_string(),
            signed.x_amz_content_sha256.clone(),
        ),
        ("Host".to_string(), host.to_string()),
    ]
}

/// Parse `<Key>...</Key>` elements from an S3 ListBucketResult XML response.
fn parse_list_keys(xml: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let tag_open = "<Key>";
    let tag_close = "</Key>";
    let mut search_from = 0;
    while let Some(start) = xml[search_from..].find(tag_open) {
        let abs_start = search_from + start + tag_open.len();
        if let Some(end) = xml[abs_start..].find(tag_close) {
            keys.push(xml[abs_start..abs_start + end].to_string());
            search_from = abs_start + end + tag_close.len();
        } else {
            break;
        }
    }
    keys
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Download an object from S3 (or any S3-compatible store).
pub fn s3_get(
    endpoint: &str,
    bucket: &str,
    key: &str,
    access_key: &str,
    secret_key: &str,
    region: &str,
) -> S3Result {
    if let Err(e) = validate_endpoint(endpoint) {
        return S3Result {
            success: false,
            body: String::new(),
            status: 0,
            message: e,
        };
    }
    // SSRF protection for S3 endpoint
    if let Err(e) = crate::security::validate_no_ssrf(endpoint) {
        return S3Result {
            success: false,
            body: String::new(),
            status: 0,
            message: e,
        };
    }
    if let Err(e) = validate_bucket(bucket) {
        return S3Result {
            success: false,
            body: String::new(),
            status: 0,
            message: e,
        };
    }
    if key.is_empty() {
        return S3Result {
            success: false,
            body: String::new(),
            status: 0,
            message: "Object key cannot be empty".to_string(),
        };
    }
    // Validate credential lengths (CWE-400)
    if let Err(e) = crate::security::validate_credential_length("access_key", access_key, 256) {
        return S3Result { success: false, body: String::new(), status: 0, message: e };
    }
    if let Err(e) = crate::security::validate_credential_length("secret_key", secret_key, 256) {
        return S3Result { success: false, body: String::new(), status: 0, message: e };
    }

    let base = endpoint.trim_end_matches('/');
    let encoded_key = url_encode_path(key);
    let url = format!("{base}/{bucket}/{encoded_key}");
    let host = extract_host(endpoint);

    let signed = match aws_sigv4::sign("GET", &url, &[], "", access_key, secret_key, region, "s3")
    {
        Ok(s) => s,
        Err(e) => {
            return S3Result {
                success: false,
                body: String::new(),
                status: 0,
                message: format!("SigV4 signing failed: {e}"),
            };
        }
    };

    let headers = build_s3_headers(&signed, &host);
    let resp = http::execute(Method::Get, &url, &headers, None);

    let status = resp.status as i32;
    if resp.status == 200 {
        S3Result {
            success: true,
            body: resp.body,
            status,
            message: "OK".to_string(),
        }
    } else {
        S3Result {
            success: false,
            body: resp.body.clone(),
            status,
            message: format!("S3 GET failed with status {}: {}", resp.status, resp.reason),
        }
    }
}

/// Upload an object to S3 (or any S3-compatible store).
pub fn s3_put(
    endpoint: &str,
    bucket: &str,
    key: &str,
    body: &str,
    access_key: &str,
    secret_key: &str,
    region: &str,
) -> S3Result {
    if let Err(e) = validate_endpoint(endpoint) {
        return S3Result {
            success: false,
            body: String::new(),
            status: 0,
            message: e,
        };
    }
    // SSRF protection for S3 endpoint
    if let Err(e) = crate::security::validate_no_ssrf(endpoint) {
        return S3Result {
            success: false,
            body: String::new(),
            status: 0,
            message: e,
        };
    }
    // Validate credential lengths (CWE-400)
    if let Err(e) = crate::security::validate_credential_length("access_key", access_key, 256) {
        return S3Result { success: false, body: String::new(), status: 0, message: e };
    }
    if let Err(e) = crate::security::validate_credential_length("secret_key", secret_key, 256) {
        return S3Result { success: false, body: String::new(), status: 0, message: e };
    }
    if let Err(e) = validate_bucket(bucket) {
        return S3Result {
            success: false,
            body: String::new(),
            status: 0,
            message: e,
        };
    }
    if key.is_empty() {
        return S3Result {
            success: false,
            body: String::new(),
            status: 0,
            message: "Object key cannot be empty".to_string(),
        };
    }
    if body.len() > MAX_BODY_SIZE {
        return S3Result {
            success: false,
            body: String::new(),
            status: 0,
            message: format!(
                "Body size {} exceeds maximum allowed {} bytes",
                body.len(),
                MAX_BODY_SIZE
            ),
        };
    }

    let base = endpoint.trim_end_matches('/');
    let encoded_key = url_encode_path(key);
    let url = format!("{base}/{bucket}/{encoded_key}");
    let host = extract_host(endpoint);

    let signed =
        match aws_sigv4::sign("PUT", &url, &[], body, access_key, secret_key, region, "s3") {
            Ok(s) => s,
            Err(e) => {
                return S3Result {
                    success: false,
                    body: String::new(),
                    status: 0,
                    message: format!("SigV4 signing failed: {e}"),
                };
            }
        };

    let headers = build_s3_headers(&signed, &host);
    let resp = http::execute(Method::Put, &url, &headers, Some(body));

    let status = resp.status as i32;
    if resp.status == 200 || resp.status == 201 || resp.status == 204 {
        S3Result {
            success: true,
            body: resp.body,
            status,
            message: "OK".to_string(),
        }
    } else {
        S3Result {
            success: false,
            body: resp.body.clone(),
            status,
            message: format!("S3 PUT failed with status {}: {}", resp.status, resp.reason),
        }
    }
}

/// List objects in an S3 bucket with an optional prefix (ListObjectsV2).
pub fn s3_list(
    endpoint: &str,
    bucket: &str,
    prefix: &str,
    access_key: &str,
    secret_key: &str,
    region: &str,
) -> S3ListResult {
    if let Err(e) = validate_endpoint(endpoint) {
        return S3ListResult {
            success: false,
            keys: Vec::new(),
            message: e,
        };
    }
    // SSRF protection for S3 endpoint
    if let Err(e) = crate::security::validate_no_ssrf(endpoint) {
        return S3ListResult {
            success: false,
            keys: Vec::new(),
            message: e,
        };
    }
    // Validate credential lengths (CWE-400)
    if let Err(e) = crate::security::validate_credential_length("access_key", access_key, 256) {
        return S3ListResult { success: false, keys: Vec::new(), message: e };
    }
    if let Err(e) = crate::security::validate_credential_length("secret_key", secret_key, 256) {
        return S3ListResult { success: false, keys: Vec::new(), message: e };
    }
    if let Err(e) = validate_bucket(bucket) {
        return S3ListResult {
            success: false,
            keys: Vec::new(),
            message: e,
        };
    }

    let base = endpoint.trim_end_matches('/');
    let encoded_prefix = url_encode_value(prefix);
    let url = format!("{base}/{bucket}?list-type=2&prefix={encoded_prefix}");
    let host = extract_host(endpoint);

    let signed = match aws_sigv4::sign("GET", &url, &[], "", access_key, secret_key, region, "s3")
    {
        Ok(s) => s,
        Err(e) => {
            return S3ListResult {
                success: false,
                keys: Vec::new(),
                message: format!("SigV4 signing failed: {e}"),
            };
        }
    };

    let headers = build_s3_headers(&signed, &host);
    let resp = http::execute(Method::Get, &url, &headers, None);

    if resp.status == 200 {
        let keys = parse_list_keys(&resp.body);
        S3ListResult {
            success: true,
            keys,
            message: "OK".to_string(),
        }
    } else {
        S3ListResult {
            success: false,
            keys: Vec::new(),
            message: format!(
                "S3 LIST failed with status {}: {}",
                resp.status, resp.reason
            ),
        }
    }
}
