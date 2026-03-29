// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use crate::http::{self, HttpResponse, Method};
use crate::json;

/// Execute a GraphQL query/mutation.
///
/// Builds a JSON body `{"query": ..., "variables": ...}` and POSTs it.
pub fn query(
    url: &str,
    query_str: &str,
    variables: Option<&str>,
    headers: &[(String, String)],
) -> HttpResponse {
    let body = build_body(query_str, variables);

    let mut all_headers: Vec<(String, String)> = headers.to_vec();
    // Ensure Content-Type is set
    if !all_headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
    {
        all_headers.push(("Content-Type".into(), "application/json".into()));
    }

    http::execute(Method::Post, url, &all_headers, Some(&body))
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
