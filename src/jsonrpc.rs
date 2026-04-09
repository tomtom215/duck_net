// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use crate::http::{self, HttpResponse, Method};

use std::sync::atomic::{AtomicU64, Ordering};

static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Execute a JSON-RPC 2.0 call.
///
/// Returns the full HTTP response. The body contains the JSON-RPC response.
pub fn call(
    url: &str,
    method: &str,
    params: Option<&str>,
    headers: &[(String, String)],
) -> HttpResponse {
    let id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    let body = build_jsonrpc_body(method, params, id);

    let mut all_headers: Vec<(String, String)> = headers.to_vec();
    if !all_headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
    {
        all_headers.push(("Content-Type".into(), "application/json".into()));
    }

    let resp = http::execute(Method::Post, url, &all_headers, Some(&body));
    crate::audit_log::record_http(
        "jsonrpc",
        method,
        &crate::audit_log::host_from_url(url),
        resp.status,
        &resp.reason,
    );
    resp
}

fn build_jsonrpc_body(method: &str, params: Option<&str>, id: u64) -> String {
    let escaped_method = json_escape(method);
    match params {
        Some(p) if !p.trim().is_empty() => {
            format!("{{\"jsonrpc\":\"2.0\",\"method\":\"{escaped_method}\",\"params\":{p},\"id\":{id}}}")
        }
        _ => {
            format!("{{\"jsonrpc\":\"2.0\",\"method\":\"{escaped_method}\",\"id\":{id}}}")
        }
    }
}

/// Execute an XML-RPC call.
pub fn xmlrpc_call(
    url: &str,
    method: &str,
    params: &[&str],
    headers: &[(String, String)],
) -> HttpResponse {
    let body = build_xmlrpc_body(method, params);

    let mut all_headers: Vec<(String, String)> = headers.to_vec();
    if !all_headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
    {
        all_headers.push(("Content-Type".into(), "text/xml".into()));
    }

    let resp = http::execute(Method::Post, url, &all_headers, Some(&body));
    crate::audit_log::record_http(
        "xmlrpc",
        method,
        &crate::audit_log::host_from_url(url),
        resp.status,
        &resp.reason,
    );
    resp
}

fn build_xmlrpc_body(method: &str, params: &[&str]) -> String {
    let mut xml =
        format!("<?xml version=\"1.0\"?>\n<methodCall>\n  <methodName>{method}</methodName>\n");
    if !params.is_empty() {
        xml.push_str("  <params>\n");
        for p in params {
            xml.push_str("    <param><value>");
            // Detect type: if it looks like a number, use <int> or <double>
            // Otherwise use <string>
            if p.parse::<i64>().is_ok() {
                xml.push_str(&format!("<int>{p}</int>"));
            } else if p.parse::<f64>().is_ok() {
                xml.push_str(&format!("<double>{p}</double>"));
            } else if *p == "true" || *p == "false" {
                let val = if *p == "true" { "1" } else { "0" };
                xml.push_str(&format!("<boolean>{val}</boolean>"));
            } else {
                xml.push_str(&format!("<string>{}</string>", xml_escape(p)));
            }
            xml.push_str("</value></param>\n");
        }
        xml.push_str("  </params>\n");
    }
    xml.push_str("</methodCall>");
    xml
}

/// Extract the JSON-RPC "result" field from a response body.
#[allow(dead_code)]
pub fn extract_result(body: &str) -> Option<&str> {
    crate::json::extract_string(body, "result")
}

/// Check if the JSON-RPC response contains an error.
#[allow(dead_code)]
pub fn has_error(body: &str) -> bool {
    body.contains("\"error\"")
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < '\x20' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
