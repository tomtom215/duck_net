// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use crate::http::{self, Method};

pub struct EsResult {
    pub success: bool,
    pub body: String,
    pub message: String,
}

/// Validate Elasticsearch URL: must be HTTP/HTTPS.
fn validate_url(url: &str) -> Result<(), String> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err("Elasticsearch URL must start with http:// or https://".to_string());
    }
    if url.len() > 2048 {
        return Err("URL too long (max 2048 characters)".to_string());
    }
    Ok(())
}

/// Validate index name: no special characters that could cause path traversal.
fn is_valid_index(index: &str) -> bool {
    if index.is_empty() || index.len() > 255 {
        return false;
    }
    // Elasticsearch index names can contain lowercase letters, digits, hyphens, underscores
    // Must not start with -, _, +
    // Must not be . or ..
    if index == "." || index == ".." {
        return false;
    }
    if index.starts_with('-') || index.starts_with('_') || index.starts_with('+') {
        return false;
    }
    // Prevent path traversal
    if index.contains('/') || index.contains('\\') || index.contains("..") {
        return false;
    }
    index
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '*'))
}

/// Search an Elasticsearch index using the _search endpoint.
///
/// `query_json` is the raw Elasticsearch query DSL JSON body.
/// Returns the full response body as JSON.
///
/// Security: validates URL and index name, uses existing HTTP client
/// with SSRF protection, timeouts, and size limits.
pub fn search(url: &str, index: &str, query_json: &str) -> EsResult {
    if let Err(e) = validate_url(url) {
        return EsResult {
            success: false,
            body: String::new(),
            message: e,
        };
    }

    if !is_valid_index(index) {
        return EsResult {
            success: false,
            body: String::new(),
            message: "Invalid index name".to_string(),
        };
    }

    let api_url = format!("{}/{}/_search", url.trim_end_matches('/'), index);

    let headers = vec![("Content-Type".to_string(), "application/json".to_string())];
    let body = if query_json.is_empty() {
        None
    } else {
        Some(query_json)
    };

    let resp = http::execute(Method::Post, &api_url, &headers, body);

    if resp.status >= 200 && resp.status < 300 {
        EsResult {
            success: true,
            body: resp.body,
            message: "OK".to_string(),
        }
    } else {
        EsResult {
            success: false,
            body: resp.body.clone(),
            message: format!(
                "Elasticsearch returned status {}: {}",
                resp.status, resp.reason
            ),
        }
    }
}

/// Count documents in an Elasticsearch index using the _count endpoint.
pub fn count(url: &str, index: &str, query_json: &str) -> EsResult {
    if let Err(e) = validate_url(url) {
        return EsResult {
            success: false,
            body: String::new(),
            message: e,
        };
    }

    if !is_valid_index(index) {
        return EsResult {
            success: false,
            body: String::new(),
            message: "Invalid index name".to_string(),
        };
    }

    let api_url = format!("{}/{}/_count", url.trim_end_matches('/'), index);

    let headers = vec![("Content-Type".to_string(), "application/json".to_string())];
    let body = if query_json.is_empty() {
        None
    } else {
        Some(query_json)
    };

    let resp = http::execute(Method::Post, &api_url, &headers, body);

    if resp.status >= 200 && resp.status < 300 {
        EsResult {
            success: true,
            body: resp.body,
            message: "OK".to_string(),
        }
    } else {
        EsResult {
            success: false,
            body: resp.body.clone(),
            message: format!(
                "Elasticsearch returned status {}: {}",
                resp.status, resp.reason
            ),
        }
    }
}

/// Get cluster/index info using the _cat endpoint.
///
/// `endpoint` is the _cat sub-endpoint (e.g., "indices", "health", "nodes").
pub fn cat(url: &str, endpoint: &str) -> EsResult {
    if let Err(e) = validate_url(url) {
        return EsResult {
            success: false,
            body: String::new(),
            message: e,
        };
    }

    // Validate endpoint: alphanumeric + hyphens + underscores only
    if endpoint.is_empty()
        || !endpoint
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '/'))
    {
        return EsResult {
            success: false,
            body: String::new(),
            message: "Invalid _cat endpoint name".to_string(),
        };
    }

    // Prevent path traversal
    if endpoint.contains("..") {
        return EsResult {
            success: false,
            body: String::new(),
            message: "Invalid _cat endpoint: path traversal detected".to_string(),
        };
    }

    let api_url = format!(
        "{}/{}?format=json",
        url.trim_end_matches('/'),
        if endpoint.starts_with("_cat/") {
            endpoint.to_string()
        } else {
            format!("_cat/{endpoint}")
        }
    );

    let resp = http::execute(Method::Get, &api_url, &[], None);

    if resp.status >= 200 && resp.status < 300 {
        EsResult {
            success: true,
            body: resp.body,
            message: "OK".to_string(),
        }
    } else {
        EsResult {
            success: false,
            body: resp.body.clone(),
            message: format!(
                "Elasticsearch returned status {}: {}",
                resp.status, resp.reason
            ),
        }
    }
}
