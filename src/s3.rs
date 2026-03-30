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
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                out.push(byte as char)
            }
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
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
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
/// Includes `x-amz-security-token` when the request used temporary credentials.
fn build_s3_headers(signed: &aws_sigv4::SignedRequest, host: &str) -> Vec<(String, String)> {
    let mut headers = vec![
        ("Authorization".to_string(), signed.authorization.clone()),
        ("x-amz-date".to_string(), signed.x_amz_date.clone()),
        (
            "x-amz-content-sha256".to_string(),
            signed.x_amz_content_sha256.clone(),
        ),
        ("Host".to_string(), host.to_string()),
    ];
    if let Some(ref token) = signed.x_amz_security_token {
        headers.push(("x-amz-security-token".to_string(), token.clone()));
    }
    headers
}

/// Parse `<Key>...</Key>` elements from an S3 ListBucketResult XML response.
///
/// Returns `(keys, is_truncated)`. When `is_truncated` is true the bucket
/// has more objects than were returned; the caller should use continuation
/// tokens to fetch subsequent pages.
fn parse_list_keys(xml: &str) -> (Vec<String>, bool) {
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
    // Check IsTruncated flag (case-insensitive tag match)
    let is_truncated = xml.contains("<IsTruncated>true</IsTruncated>")
        || xml.contains("<IsTruncated>True</IsTruncated>");
    (keys, is_truncated)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Emit a warning if the S3 endpoint uses plain HTTP.
fn warn_if_s3_plaintext(endpoint: &str) {
    if crate::security::is_plaintext_http(endpoint) {
        crate::security_warnings::warn_s3_over_http(endpoint);
    }
}

/// Macro-like helper: early-return S3Result on validation error.
macro_rules! s3_try {
    ($expr:expr, $result_ctor:expr) => {
        match $expr {
            Ok(v) => v,
            Err(e) => return $result_ctor(e),
        }
    };
}

/// Download an object from S3 (or any S3-compatible store).
///
/// `session_token` is required when using temporary AWS credentials (STS).
/// Pass `None` for permanent IAM credentials.
#[allow(clippy::too_many_arguments)]
pub fn s3_get(
    endpoint: &str,
    bucket: &str,
    key: &str,
    access_key: &str,
    secret_key: &str,
    region: &str,
    session_token: Option<&str>,
) -> S3Result {
    let err = |msg: String| S3Result {
        success: false,
        body: String::new(),
        status: 0,
        message: msg,
    };

    s3_try!(validate_endpoint(endpoint), err);
    warn_if_s3_plaintext(endpoint);
    s3_try!(crate::security::validate_no_ssrf(endpoint), err);
    s3_try!(validate_bucket(bucket), err);

    if key.is_empty() {
        return err("Object key cannot be empty".to_string());
    }
    s3_try!(
        crate::security::validate_credential_length("access_key", access_key, 256),
        err
    );
    s3_try!(
        crate::security::validate_credential_length("secret_key", secret_key, 256),
        err
    );

    let base = endpoint.trim_end_matches('/');
    let encoded_key = url_encode_path(key);
    let url = format!("{base}/{bucket}/{encoded_key}");
    let host = extract_host(endpoint);

    let signed = match aws_sigv4::sign_with_token(
        "GET",
        &url,
        &[],
        "",
        access_key,
        secret_key,
        region,
        "s3",
        session_token,
    ) {
        Ok(s) => s,
        Err(e) => return err(format!("SigV4 signing failed: {e}")),
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
///
/// `session_token` is required when using temporary AWS credentials (STS).
/// Pass `None` for permanent IAM credentials.
#[allow(clippy::too_many_arguments)]
pub fn s3_put(
    endpoint: &str,
    bucket: &str,
    key: &str,
    body: &str,
    access_key: &str,
    secret_key: &str,
    region: &str,
    session_token: Option<&str>,
) -> S3Result {
    let err = |msg: String| S3Result {
        success: false,
        body: String::new(),
        status: 0,
        message: msg,
    };

    s3_try!(validate_endpoint(endpoint), err);
    warn_if_s3_plaintext(endpoint);
    s3_try!(crate::security::validate_no_ssrf(endpoint), err);
    s3_try!(
        crate::security::validate_credential_length("access_key", access_key, 256),
        err
    );
    s3_try!(
        crate::security::validate_credential_length("secret_key", secret_key, 256),
        err
    );
    s3_try!(validate_bucket(bucket), err);

    if key.is_empty() {
        return err("Object key cannot be empty".to_string());
    }
    if body.len() > MAX_BODY_SIZE {
        return err(format!(
            "Body size {} exceeds maximum allowed {} bytes",
            body.len(),
            MAX_BODY_SIZE
        ));
    }

    let base = endpoint.trim_end_matches('/');
    let encoded_key = url_encode_path(key);
    let url = format!("{base}/{bucket}/{encoded_key}");
    let host = extract_host(endpoint);

    let signed = match aws_sigv4::sign_with_token(
        "PUT",
        &url,
        &[],
        body,
        access_key,
        secret_key,
        region,
        "s3",
        session_token,
    ) {
        Ok(s) => s,
        Err(e) => return err(format!("SigV4 signing failed: {e}")),
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
///
/// `session_token` is required when using temporary AWS credentials (STS).
/// Pass `None` for permanent IAM credentials.
///
/// Note: results are limited to one page (1,000 objects). Use continuation
/// tokens via raw S3 API calls for paginated listing.
#[allow(clippy::too_many_arguments)]
pub fn s3_list(
    endpoint: &str,
    bucket: &str,
    prefix: &str,
    access_key: &str,
    secret_key: &str,
    region: &str,
    session_token: Option<&str>,
) -> S3ListResult {
    let err = |msg: String| S3ListResult {
        success: false,
        keys: Vec::new(),
        message: msg,
    };

    s3_try!(validate_endpoint(endpoint), err);
    warn_if_s3_plaintext(endpoint);
    s3_try!(crate::security::validate_no_ssrf(endpoint), err);
    s3_try!(
        crate::security::validate_credential_length("access_key", access_key, 256),
        err
    );
    s3_try!(
        crate::security::validate_credential_length("secret_key", secret_key, 256),
        err
    );
    s3_try!(validate_bucket(bucket), err);

    let base = endpoint.trim_end_matches('/');
    let encoded_prefix = url_encode_value(prefix);
    let url = format!("{base}/{bucket}?list-type=2&prefix={encoded_prefix}");
    let host = extract_host(endpoint);

    let signed = match aws_sigv4::sign_with_token(
        "GET",
        &url,
        &[],
        "",
        access_key,
        secret_key,
        region,
        "s3",
        session_token,
    ) {
        Ok(s) => s,
        Err(e) => return err(format!("SigV4 signing failed: {e}")),
    };

    let headers = build_s3_headers(&signed, &host);
    let resp = http::execute(Method::Get, &url, &headers, None);

    if resp.status == 200 {
        let (keys, truncated) = parse_list_keys(&resp.body);
        let message = if truncated {
            "OK (results truncated; use continuation tokens for full listing)".to_string()
        } else {
            "OK".to_string()
        };
        S3ListResult {
            success: true,
            keys,
            message,
        }
    } else {
        err(format!(
            "S3 LIST failed with status {}: {}",
            resp.status, resp.reason
        ))
    }
}
