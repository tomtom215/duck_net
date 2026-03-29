// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use crate::http::{self, Method};

/// Default DNS-over-HTTPS resolvers.
const DEFAULT_DOH_URL: &str = "https://cloudflare-dns.com/dns-query";

pub struct DohResult {
    pub success: bool,
    pub records: Vec<String>,
    pub message: String,
}

/// Validate DoH resolver URL.
fn validate_url(url: &str) -> Result<(), String> {
    if !url.starts_with("https://") && !url.starts_with("http://") {
        return Err("DoH resolver URL must start with https:// or http://".to_string());
    }
    if url.len() > 2048 {
        return Err("URL too long (max 2048 characters)".to_string());
    }
    Ok(())
}

/// Validate DNS record type.
fn validate_record_type(rtype: &str) -> Result<(), String> {
    let valid_types = [
        "A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT", "CAA", "DNSKEY", "DS",
        "NAPTR", "SSHFP", "TLSA", "ANY",
    ];
    let upper = rtype.to_uppercase();
    if !valid_types.contains(&upper.as_str()) {
        return Err(format!(
            "Unsupported DNS record type: {}. Supported: {}",
            rtype,
            valid_types.join(", ")
        ));
    }
    Ok(())
}

/// Validate domain name: prevent injection and ensure well-formedness.
fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    // Allow alphanumeric, dots, hyphens, underscores (for SRV records)
    domain
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// Perform DNS lookup using DNS-over-HTTPS (DoH).
///
/// Uses the JSON API format (RFC 8484 / Google/Cloudflare JSON API).
/// This provides privacy-aware DNS resolution over encrypted HTTPS.
///
/// Security: validates all inputs, uses existing HTTP client with
/// SSRF protection and timeouts. Only HTTPS resolvers are recommended.
pub fn lookup(resolver_url: &str, domain: &str, record_type: &str) -> DohResult {
    let url = if resolver_url.is_empty() {
        DEFAULT_DOH_URL
    } else {
        resolver_url
    };

    if let Err(e) = validate_url(url) {
        return DohResult {
            success: false,
            records: vec![],
            message: e,
        };
    }

    if !is_valid_domain(domain) {
        return DohResult {
            success: false,
            records: vec![],
            message: "Invalid domain name".to_string(),
        };
    }

    if let Err(e) = validate_record_type(record_type) {
        return DohResult {
            success: false,
            records: vec![],
            message: e,
        };
    }

    let rtype = record_type.to_uppercase();

    // Use JSON API format (supported by Cloudflare, Google, etc.)
    let api_url = format!(
        "{}?name={}&type={}",
        url.trim_end_matches('/'),
        crate::json::form_urlencode(domain),
        crate::json::form_urlencode(&rtype),
    );

    let headers = vec![("Accept".to_string(), "application/dns-json".to_string())];
    let resp = http::execute(Method::Get, &api_url, &headers, None);

    if resp.status != 200 {
        return DohResult {
            success: false,
            records: vec![],
            message: format!("DoH query failed: HTTP {} {}", resp.status, resp.reason),
        };
    }

    // Parse the JSON response to extract answer records
    let records = extract_answer_records(&resp.body);

    if records.is_empty() {
        // Check if the response has a Status field indicating NXDOMAIN etc.
        let status = extract_dns_status(&resp.body);
        let msg = match status {
            0 => "No records found (NOERROR)".to_string(),
            3 => "Domain not found (NXDOMAIN)".to_string(),
            2 => "Server failure (SERVFAIL)".to_string(),
            _ => format!("DNS status code: {status}"),
        };
        return DohResult {
            success: true,
            records: vec![],
            message: msg,
        };
    }

    DohResult {
        success: true,
        records,
        message: "OK".to_string(),
    }
}

/// Default resolver variant.
pub fn lookup_default(domain: &str, record_type: &str) -> DohResult {
    lookup(DEFAULT_DOH_URL, domain, record_type)
}

/// Extract "data" fields from the "Answer" array in DoH JSON response.
///
/// Response format (simplified):
/// { "Answer": [ { "name": "...", "type": N, "data": "..." }, ... ] }
fn extract_answer_records(body: &str) -> Vec<String> {
    let mut records = Vec::new();

    // Find "Answer" array
    let answer_start = match body.find("\"Answer\"") {
        Some(pos) => pos,
        None => return records,
    };

    let rest = &body[answer_start..];
    let arr_start = match rest.find('[') {
        Some(pos) => pos,
        None => return records,
    };

    // Extract data values from the Answer array
    let arr = &rest[arr_start..];
    let mut depth = 0;
    let mut in_answer = false;
    let mut i = 0;

    while i < arr.len() {
        match arr.as_bytes()[i] {
            b'[' => {
                depth += 1;
                if depth == 1 {
                    in_answer = true;
                }
            }
            b']' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }

        if in_answer && arr[i..].starts_with("\"data\"") {
            // Find the value after "data": "..."
            if let Some(colon) = arr[i..].find(':') {
                let after_colon = &arr[i + colon + 1..];
                let trimmed = after_colon.trim_start();
                if let Some(stripped) = trimmed.strip_prefix('"') {
                    // String value
                    if let Some(end) = find_closing_quote(stripped) {
                        let value = &stripped[..end];
                        records.push(value.replace("\\\"", "\""));
                    }
                }
            }
        }

        i += 1;
    }

    records
}

/// Find the closing quote, handling escaped quotes.
fn find_closing_quote(s: &str) -> Option<usize> {
    let mut i = 0;
    let bytes = s.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'"' && (i == 0 || bytes[i - 1] != b'\\') {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Extract the DNS "Status" field from DoH JSON response.
fn extract_dns_status(body: &str) -> i32 {
    // Look for "Status": N
    if let Some(pos) = body.find("\"Status\"") {
        let rest = &body[pos + 8..];
        if let Some(colon) = rest.find(':') {
            let after_colon = rest[colon + 1..].trim_start();
            let num_end = after_colon
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(after_colon.len());
            if let Ok(n) = after_colon[..num_end].parse::<i32>() {
                return n;
            }
        }
    }
    -1
}
