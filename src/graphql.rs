// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use crate::http::{self, HttpResponse, Method};
use crate::json;

/// Execute a GraphQL query/mutation.
///
/// Builds a JSON body `{"query": ..., "variables": ...}` and POSTs it.
///
/// Security:
/// - Validates query payload size (CWE-400) before sending.
/// - Validates the variables payload size independently — the query text alone
///   was previously capped but an attacker could still pass megabytes of
///   variables and exhaust server memory.
/// - Validates that `variables`, if present, parses as JSON so a malformed
///   blob cannot be smuggled into the outgoing POST body.
pub fn query(
    url: &str,
    query_str: &str,
    variables: Option<&str>,
    headers: &[(String, String)],
) -> HttpResponse {
    // Validate query size (CWE-400)
    if let Err(e) = crate::security_validate::validate_query_size(query_str, "GraphQL") {
        return HttpResponse {
            status: 0,
            reason: e.clone(),
            headers: vec![],
            body: e,
        };
    }

    // Validate variables size + shape (CWE-400 + CWE-20).
    if let Some(vars) = variables {
        if !vars.trim().is_empty() {
            if let Err(e) = crate::security_validate::validate_query_size(vars, "GraphQL variables")
            {
                return HttpResponse {
                    status: 0,
                    reason: e.clone(),
                    headers: vec![],
                    body: e,
                };
            }
            if let Err(e) = serde_json::from_str::<serde_json::Value>(vars) {
                let msg = format!("GraphQL variables must be valid JSON: {e}");
                return HttpResponse {
                    status: 0,
                    reason: msg.clone(),
                    headers: vec![],
                    body: msg,
                };
            }
        }
    }

    let body = build_body(query_str, variables);

    let mut all_headers: Vec<(String, String)> = headers.to_vec();
    // Ensure Content-Type is set
    if !all_headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
    {
        all_headers.push(("Content-Type".into(), "application/json".into()));
    }

    let resp = http::execute(Method::Post, url, &all_headers, Some(&body));
    crate::audit_log::record_http(
        "graphql",
        "query",
        &crate::audit_log::host_from_url(url),
        resp.status,
        &resp.reason,
    );
    resp
}

fn build_body(query_str: &str, variables: Option<&str>) -> String {
    let escaped_query = json_escape(query_str);
    match variables {
        Some(vars) if !vars.trim().is_empty() => {
            format!("{{\"query\":\"{escaped_query}\",\"variables\":{vars}}}")
        }
        _ => format!("{{\"query\":\"{escaped_query}\"}}"),
    }
}

/// Check if a GraphQL response contains errors.
pub fn has_errors(body: &str) -> bool {
    // Look for "errors" key containing an array
    body.contains("\"errors\"") && body.contains('[')
}

/// Extract the `errors` array as raw JSON substring.
pub fn extract_errors(body: &str) -> Option<&str> {
    let needle = "\"errors\"";
    let pos = body.find(needle)?;
    let after = &body[pos + needle.len()..].trim_start();
    if !after.starts_with(':') {
        return None;
    }
    let after_colon = after[1..].trim_start();
    if !after_colon.starts_with('[') {
        return None;
    }
    // Find matching ]
    let start = body.len() - after_colon.len();
    let mut depth = 0;
    for (i, ch) in after_colon.char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&body[start..start + i + 1]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Extract the `data` field value as raw JSON.
#[allow(dead_code)]
pub fn extract_data(body: &str) -> Option<&str> {
    json::extract_string(body, "data")
}

/// Escape a string for embedding in a JSON string value.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < '\x20' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}
