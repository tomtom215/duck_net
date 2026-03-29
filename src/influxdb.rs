// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use crate::http::{self, Method};

pub struct InfluxResult {
    pub success: bool,
    pub body: String,
    pub message: String,
}

/// Maximum body size for write requests: 256 MiB.
const MAX_WRITE_BODY_SIZE: usize = 256 * 1024 * 1024;

/// Validate InfluxDB URL: must be HTTP/HTTPS and within length limit.
fn validate_url(url: &str) -> Result<(), String> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err("InfluxDB URL must start with http:// or https://".to_string());
    }
    if url.len() > 2048 {
        return Err("URL too long (max 2048 characters)".to_string());
    }
    Ok(())
}

/// Query InfluxDB v2 using the Flux query language.
///
/// Sends a Flux query to the InfluxDB v2 HTTP API and returns the CSV
/// response body.
///
/// Security: validates URL scheme, uses existing HTTP client with
/// SSRF protection, timeouts, and size limits.
pub fn query(url: &str, org: &str, token: &str, flux_query: &str) -> InfluxResult {
    if let Err(e) = validate_url(url) {
        return InfluxResult {
            success: false,
            body: String::new(),
            message: e,
        };
    }

    if org.is_empty() {
        return InfluxResult {
            success: false,
            body: String::new(),
            message: "Organization cannot be empty".to_string(),
        };
    }

    if token.is_empty() {
        return InfluxResult {
            success: false,
            body: String::new(),
            message: "Token cannot be empty".to_string(),
        };
    }

    if flux_query.is_empty() {
        return InfluxResult {
            success: false,
            body: String::new(),
            message: "Flux query cannot be empty".to_string(),
        };
    }

    let encoded_org = crate::json::form_urlencode(org);
    let api_url = format!(
        "{}/api/v2/query?org={}",
        url.trim_end_matches('/'),
        encoded_org
    );

    let headers = [
        ("Authorization".to_string(), format!("Token {token}")),
        ("Content-Type".to_string(), "application/vnd.flux".to_string()),
        ("Accept".to_string(), "application/csv".to_string()),
    ];

    let resp = http::execute(Method::Post, &api_url, &headers, Some(flux_query));

    if resp.status != 200 {
        return InfluxResult {
            success: false,
            body: resp.body.clone(),
            message: format!(
                "InfluxDB query API returned status {}: {}",
                resp.status, resp.reason
            ),
        };
    }

    InfluxResult {
        success: true,
        body: resp.body,
        message: "OK".to_string(),
    }
}

/// Write data to InfluxDB v2 using line protocol.
///
/// Sends line protocol data to the InfluxDB v2 write endpoint with
/// nanosecond precision.
///
/// Security: validates URL scheme, enforces max body size of 256 MiB,
/// uses existing HTTP client with SSRF protection, timeouts, and size limits.
pub fn write(
    url: &str,
    org: &str,
    bucket: &str,
    token: &str,
    line_protocol: &str,
) -> InfluxResult {
    if let Err(e) = validate_url(url) {
        return InfluxResult {
            success: false,
            body: String::new(),
            message: e,
        };
    }

    if org.is_empty() {
        return InfluxResult {
            success: false,
            body: String::new(),
            message: "Organization cannot be empty".to_string(),
        };
    }

    if bucket.is_empty() {
        return InfluxResult {
            success: false,
            body: String::new(),
            message: "Bucket cannot be empty".to_string(),
        };
    }

    if token.is_empty() {
        return InfluxResult {
            success: false,
            body: String::new(),
            message: "Token cannot be empty".to_string(),
        };
    }

    if line_protocol.is_empty() {
        return InfluxResult {
            success: false,
            body: String::new(),
            message: "Line protocol data cannot be empty".to_string(),
        };
    }

    if line_protocol.len() > MAX_WRITE_BODY_SIZE {
        return InfluxResult {
            success: false,
            body: String::new(),
            message: format!(
                "Line protocol data too large ({} bytes, max {} bytes)",
                line_protocol.len(),
                MAX_WRITE_BODY_SIZE
            ),
        };
    }

    let encoded_org = crate::json::form_urlencode(org);
    let encoded_bucket = crate::json::form_urlencode(bucket);
    let api_url = format!(
        "{}/api/v2/write?org={}&bucket={}&precision=ns",
        url.trim_end_matches('/'),
        encoded_org,
        encoded_bucket
    );

    let headers = [
        ("Authorization".to_string(), format!("Token {token}")),
        (
            "Content-Type".to_string(),
            "text/plain; charset=utf-8".to_string(),
        ),
    ];

    let resp = http::execute(Method::Post, &api_url, &headers, Some(line_protocol));

    if resp.status != 204 {
        return InfluxResult {
            success: false,
            body: resp.body.clone(),
            message: format!(
                "InfluxDB write API returned status {}: {}",
                resp.status, resp.reason
            ),
        };
    }

    InfluxResult {
        success: true,
        body: resp.body,
        message: "OK".to_string(),
    }
}

/// Check the health of an InfluxDB instance.
///
/// Sends a GET request to the /health endpoint. No authentication is required.
pub fn health(url: &str) -> InfluxResult {
    if let Err(e) = validate_url(url) {
        return InfluxResult {
            success: false,
            body: String::new(),
            message: e,
        };
    }

    let api_url = format!("{}/health", url.trim_end_matches('/'));

    let resp = http::execute(Method::Get, &api_url, &[], None);

    if resp.status != 200 {
        return InfluxResult {
            success: false,
            body: resp.body.clone(),
            message: format!(
                "InfluxDB health check returned status {}: {}",
                resp.status, resp.reason
            ),
        };
    }

    InfluxResult {
        success: true,
        body: resp.body,
        message: "OK".to_string(),
    }
}
