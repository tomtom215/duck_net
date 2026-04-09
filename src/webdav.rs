// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use crate::http::{self, HttpResponse, Method};

/// A file/directory entry returned by WebDAV PROPFIND.
pub struct WebDavEntry {
    pub href: String,
    pub name: String,
    pub content_type: String,
    pub size: i64,
    pub last_modified: String,
    pub is_collection: bool,
}

/// List directory contents via WebDAV PROPFIND.
pub fn list(
    url: &str,
    headers: &[(String, String)],
    depth: &str,
) -> Result<Vec<WebDavEntry>, String> {
    let propfind_body = r#"<?xml version="1.0" encoding="UTF-8"?>
<d:propfind xmlns:d="DAV:">
  <d:prop>
    <d:displayname/>
    <d:getcontentlength/>
    <d:getcontenttype/>
    <d:getlastmodified/>
    <d:resourcetype/>
  </d:prop>
</d:propfind>"#;

    let mut all_headers: Vec<(String, String)> = headers.to_vec();
    all_headers.push(("Content-Type".into(), "application/xml".into()));
    all_headers.push(("Depth".into(), depth.to_string()));

    let resp = execute_propfind(url, &all_headers, propfind_body);
    let host = crate::audit_log::host_from_url(url);

    if resp.status != 207 && resp.status != 200 {
        let msg = format!("PROPFIND failed: {} {}", resp.status, resp.reason);
        crate::audit_log::record("webdav", "propfind", &host, false, resp.status as i32, &msg);
        return Err(msg);
    }

    crate::audit_log::record("webdav", "propfind", &host, true, resp.status as i32, "");
    Ok(parse_multistatus(&resp.body))
}

/// Read a file via WebDAV GET.
pub fn read(url: &str, headers: &[(String, String)]) -> HttpResponse {
    let resp = http::execute(Method::Get, url, headers, None);
    crate::audit_log::record_http(
        "webdav",
        "get",
        &crate::audit_log::host_from_url(url),
        resp.status,
        &resp.reason,
    );
    resp
}

/// Write/upload a file via WebDAV PUT.
pub fn write(url: &str, content: &str, headers: &[(String, String)]) -> HttpResponse {
    let resp = http::execute(Method::Put, url, headers, Some(content));
    crate::audit_log::record_http(
        "webdav",
        "put",
        &crate::audit_log::host_from_url(url),
        resp.status,
        &resp.reason,
    );
    resp
}

/// Delete a resource via WebDAV DELETE.
pub fn delete(url: &str, headers: &[(String, String)]) -> HttpResponse {
    let resp = http::execute(Method::Delete, url, headers, None);
    crate::audit_log::record_http(
        "webdav",
        "delete",
        &crate::audit_log::host_from_url(url),
        resp.status,
        &resp.reason,
    );
    resp
}

/// Create a collection (directory) via WebDAV MKCOL.
pub fn mkcol(url: &str, headers: &[(String, String)]) -> HttpResponse {
    // MKCOL is not a standard HTTP method in our enum, use http_request directly
    let mut all_headers: Vec<(String, String)> = headers.to_vec();
    all_headers.push(("Content-Length".into(), "0".into()));

    // Use POST with X-HTTP-Method-Override for MKCOL, or direct approach
    // Actually, we need to make a raw MKCOL request. We'll use ureq directly.
    let resp = execute_mkcol(url, &all_headers);
    crate::audit_log::record_http(
        "webdav",
        "mkcol",
        &crate::audit_log::host_from_url(url),
        resp.status,
        &resp.reason,
    );
    resp
}

fn execute_propfind(url: &str, headers: &[(String, String)], body: &str) -> HttpResponse {
    http::execute_raw_method("PROPFIND", url, headers, Some(body))
}

fn execute_mkcol(url: &str, headers: &[(String, String)]) -> HttpResponse {
    http::execute_raw_method("MKCOL", url, headers, Some(""))
}

/// Parse a WebDAV multistatus XML response into entries.
/// Uses simple string parsing to avoid XML dependency.
fn parse_multistatus(xml: &str) -> Vec<WebDavEntry> {
    let mut entries = Vec::new();

    // Split by <d:response> or <D:response> or <response>
    let response_chunks = split_xml_elements(xml, "response");

    for chunk in response_chunks {
        let href = extract_xml_text(&chunk, "href").unwrap_or_default();
        let name = extract_xml_text(&chunk, "displayname").unwrap_or_else(|| href_to_name(&href));
        let content_type = extract_xml_text(&chunk, "getcontenttype").unwrap_or_default();
        let size_str = extract_xml_text(&chunk, "getcontentlength").unwrap_or_default();
        let size = size_str.parse::<i64>().unwrap_or(0);
        let last_modified = extract_xml_text(&chunk, "getlastmodified").unwrap_or_default();
        let is_collection = chunk.contains("<d:collection")
            || chunk.contains("<D:collection")
            || chunk.contains("<collection");

        entries.push(WebDavEntry {
            href,
            name,
            content_type,
            size,
            last_modified,
            is_collection,
        });
    }

    entries
}

/// Split XML by a tag name, handling various namespace prefixes.
fn split_xml_elements(xml: &str, tag: &str) -> Vec<String> {
    let mut results = Vec::new();
    let patterns = [
        (format!("<d:{tag}"), format!("</d:{tag}>")),
        (format!("<D:{tag}"), format!("</D:{tag}>")),
        (format!("<{tag}"), format!("</{tag}>")),
    ];

    for (open, close) in &patterns {
        let mut search_from = 0;
        while let Some(start) = xml[search_from..].find(open.as_str()) {
            let abs_start = search_from + start;
            if let Some(end) = xml[abs_start..].find(close.as_str()) {
                let abs_end = abs_start + end + close.len();
                results.push(xml[abs_start..abs_end].to_string());
                search_from = abs_end;
            } else {
                break;
            }
        }
        if !results.is_empty() {
            break;
        }
    }

    results
}

/// Extract text content from an XML element with various namespace prefixes.
fn extract_xml_text(xml: &str, tag: &str) -> Option<String> {
    let patterns = [
        (format!("<d:{tag}>"), format!("</d:{tag}>")),
        (format!("<d:{tag}"), format!("</d:{tag}>")),
        (format!("<D:{tag}>"), format!("</D:{tag}>")),
        (format!("<D:{tag}"), format!("</D:{tag}>")),
        (format!("<{tag}>"), format!("</{tag}>")),
        (format!("<{tag}"), format!("</{tag}>")),
    ];

    for (open, close) in &patterns {
        if let Some(start) = xml.find(open.as_str()) {
            let after_open = start + open.len();
            // If the open pattern didn't end with >, find the >
            let content_start = if xml[after_open..].starts_with('>') || open.ends_with('>') {
                if open.ends_with('>') {
                    after_open
                } else {
                    after_open + 1
                }
            } else {
                // Find closing > of the opening tag
                match xml[after_open..].find('>') {
                    Some(pos) => after_open + pos + 1,
                    None => continue,
                }
            };
            if let Some(end) = xml[content_start..].find(close.as_str()) {
                let text = xml[content_start..content_start + end].trim();
                return Some(text.to_string());
            }
        }
    }
    None
}

/// Extract a filename from an href path.
fn href_to_name(href: &str) -> String {
    let trimmed = href.trim_end_matches('/');
    trimmed.rsplit('/').next().unwrap_or(trimmed).to_string()
}
