// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use crate::http::{self, Method};

pub struct PrometheusResult {
    pub success: bool,
    pub result_type: String,
    pub body: String,
    pub message: String,
}

/// Validate Prometheus URL: must be HTTP/HTTPS.
fn validate_url(url: &str) -> Result<(), String> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err("Prometheus URL must start with http:// or https://".to_string());
    }
    if url.len() > 2048 {
        return Err("URL too long (max 2048 characters)".to_string());
    }
    Ok(())
}

/// Query Prometheus using the instant query API (/api/v1/query).
///
/// Sends the PromQL expression to the Prometheus HTTP API and returns
/// the result. Supports both instant and range queries.
///
/// Security: validates URL scheme, uses existing HTTP client with
/// SSRF protection, timeouts, and size limits.
pub fn query(url: &str, promql: &str) -> PrometheusResult {
    if let Err(e) = validate_url(url) {
        return PrometheusResult {
            success: false,
            result_type: String::new(),
            body: String::new(),
            message: e,
        };
    }

    if promql.is_empty() {
        return PrometheusResult {
            success: false,
            result_type: String::new(),
            body: String::new(),
            message: "PromQL expression cannot be empty".to_string(),
        };
    }

    // URL-encode the query parameter
    let encoded_query = crate::json::form_urlencode(promql);
    let api_url = format!(
        "{}/api/v1/query?query={}",
        url.trim_end_matches('/'),
        encoded_query
    );

    let resp = http::execute(Method::Get, &api_url, &[], None);

    if resp.status != 200 {
        return PrometheusResult {
            success: false,
            result_type: String::new(),
            body: resp.body.clone(),
            message: format!(
                "Prometheus API returned status {}: {}",
                resp.status, resp.reason
            ),
        };
    }

    // Parse result_type from JSON response
    let result_type = crate::json::extract_string(&resp.body, "resultType")
        .unwrap_or_default()
        .to_string();

    // Check for Prometheus API-level errors
    let status = crate::json::extract_string(&resp.body, "status")
        .unwrap_or_default()
        .to_string();
    if status == "error" {
        let error_msg = crate::json::extract_string(&resp.body, "error")
            .unwrap_or("Unknown error")
            .to_string();
        return PrometheusResult {
            success: false,
            result_type,
            body: resp.body,
            message: format!("Prometheus error: {error_msg}"),
        };
    }

    PrometheusResult {
        success: true,
        result_type,
        body: resp.body,
        message: "OK".to_string(),
    }
}

/// Query Prometheus using the range query API (/api/v1/query_range).
///
/// `start` and `end` are RFC3339 timestamps or Unix timestamps.
/// `step` is the query resolution step (e.g., "15s", "1m", "5m").
pub fn query_range(
    url: &str,
    promql: &str,
    start: &str,
    end: &str,
    step: &str,
) -> PrometheusResult {
    if let Err(e) = validate_url(url) {
        return PrometheusResult {
            success: false,
            result_type: String::new(),
            body: String::new(),
            message: e,
        };
    }

    if promql.is_empty() {
        return PrometheusResult {
            success: false,
            result_type: String::new(),
            body: String::new(),
            message: "PromQL expression cannot be empty".to_string(),
        };
    }

    let api_url = format!(
        "{}/api/v1/query_range?query={}&start={}&end={}&step={}",
        url.trim_end_matches('/'),
        crate::json::form_urlencode(promql),
        crate::json::form_urlencode(start),
        crate::json::form_urlencode(end),
        crate::json::form_urlencode(step),
    );

    let resp = http::execute(Method::Get, &api_url, &[], None);

    if resp.status != 200 {
        return PrometheusResult {
            success: false,
            result_type: String::new(),
            body: resp.body.clone(),
            message: format!(
                "Prometheus API returned status {}: {}",
                resp.status, resp.reason
            ),
        };
    }

    let result_type = crate::json::extract_string(&resp.body, "resultType")
        .unwrap_or_default()
        .to_string();

    let status = crate::json::extract_string(&resp.body, "status")
        .unwrap_or_default()
        .to_string();
    if status == "error" {
        let error_msg = crate::json::extract_string(&resp.body, "error")
            .unwrap_or("Unknown error")
            .to_string();
        return PrometheusResult {
            success: false,
            result_type,
            body: resp.body,
            message: format!("Prometheus error: {error_msg}"),
        };
    }

    PrometheusResult {
        success: true,
        result_type,
        body: resp.body,
        message: "OK".to_string(),
    }
}
