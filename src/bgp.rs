// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use crate::http::{self, Method};

pub struct BgpResult {
    pub success: bool,
    pub body: String,
    pub message: String,
}

/// Validate IP prefix format: must be a valid CIDR notation.
/// Accepts: 1.2.3.0/24, 2001:db8::/32, or bare IP addresses.
fn is_valid_prefix(prefix: &str) -> bool {
    if prefix.is_empty() || prefix.len() > 64 {
        return false;
    }

    // Must contain only valid characters for IP/CIDR
    prefix
        .chars()
        .all(|c| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '/'))
}

/// Validate AS number format.
fn is_valid_asn(asn: &str) -> bool {
    if asn.is_empty() || asn.len() > 12 {
        return false;
    }
    let stripped = asn
        .strip_prefix("AS")
        .or_else(|| asn.strip_prefix("as"))
        .unwrap_or(asn);
    stripped.chars().all(|c| c.is_ascii_digit())
}

/// Query BGP routing information for a prefix using RIPE RIS Looking Glass API.
///
/// Uses the RIPE NCC RIS (Routing Information Service) public API to retrieve
/// BGP routing data. This includes:
/// - Origin AS for a prefix
/// - BGP path information
/// - Peer visibility
///
/// Security: uses only public HTTP APIs, validates prefix format,
/// no authentication needed. SSRF protection via existing HTTP client.
pub fn route(prefix: &str) -> BgpResult {
    if !is_valid_prefix(prefix) {
        return BgpResult {
            success: false,
            body: String::new(),
            message: "Invalid IP prefix format".to_string(),
        };
    }

    let encoded = crate::json::form_urlencode(prefix);
    let url = format!(
        "https://stat.ripe.net/data/looking-glass/data.json?resource={}",
        encoded
    );

    let resp = http::execute(Method::Get, &url, &[], None);
    let status = resp.status as i32;
    if resp.status != 200 {
        let msg = format!(
            "RIPE RIS API returned status {}: {}",
            resp.status, resp.reason
        );
        crate::audit_log::record("bgp", "route", "stat.ripe.net", false, status, &msg);
        return BgpResult {
            success: false,
            body: resp.body.clone(),
            message: msg,
        };
    }

    crate::audit_log::record("bgp", "route", "stat.ripe.net", true, status, "");
    BgpResult {
        success: true,
        body: resp.body,
        message: "OK".to_string(),
    }
}

/// Query BGP prefix overview (origin ASN, announcement status).
pub fn prefix_overview(prefix: &str) -> BgpResult {
    if !is_valid_prefix(prefix) {
        return BgpResult {
            success: false,
            body: String::new(),
            message: "Invalid IP prefix format".to_string(),
        };
    }

    let encoded = crate::json::form_urlencode(prefix);
    let url = format!(
        "https://stat.ripe.net/data/prefix-overview/data.json?resource={}",
        encoded
    );

    let resp = http::execute(Method::Get, &url, &[], None);
    let status = resp.status as i32;
    if resp.status != 200 {
        let msg = format!(
            "RIPE RIS API returned status {}: {}",
            resp.status, resp.reason
        );
        crate::audit_log::record(
            "bgp",
            "prefix_overview",
            "stat.ripe.net",
            false,
            status,
            &msg,
        );
        return BgpResult {
            success: false,
            body: resp.body.clone(),
            message: msg,
        };
    }

    crate::audit_log::record("bgp", "prefix_overview", "stat.ripe.net", true, status, "");
    BgpResult {
        success: true,
        body: resp.body,
        message: "OK".to_string(),
    }
}

/// Query AS information (name, country, announced prefixes).
pub fn asn_info(asn: &str) -> BgpResult {
    if !is_valid_asn(asn) {
        return BgpResult {
            success: false,
            body: String::new(),
            message: "Invalid AS number format".to_string(),
        };
    }

    let encoded = crate::json::form_urlencode(asn);
    let url = format!(
        "https://stat.ripe.net/data/as-overview/data.json?resource={}",
        encoded
    );

    let resp = http::execute(Method::Get, &url, &[], None);
    let status = resp.status as i32;
    if resp.status != 200 {
        let msg = format!(
            "RIPE RIS API returned status {}: {}",
            resp.status, resp.reason
        );
        crate::audit_log::record("bgp", "asn_info", "stat.ripe.net", false, status, &msg);
        return BgpResult {
            success: false,
            body: resp.body.clone(),
            message: msg,
        };
    }

    crate::audit_log::record("bgp", "asn_info", "stat.ripe.net", true, status, "");
    BgpResult {
        success: true,
        body: resp.body,
        message: "OK".to_string(),
    }
}
