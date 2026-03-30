// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::net::IpAddr;
use std::sync::LazyLock;

use hickory_resolver::TokioResolver;

use crate::runtime;

static RESOLVER: LazyLock<TokioResolver> = LazyLock::new(|| {
    runtime::block_on(async {
        TokioResolver::builder_tokio()
            .unwrap_or_else(|e| panic!("duck_net: failed to create DNS resolver: {e}"))
            .build()
    })
});

/// Maximum hostname length for DNS queries.
const MAX_HOSTNAME_LENGTH: usize = 253;

/// Validate a hostname for DNS queries.
fn validate_hostname(hostname: &str) -> Result<(), String> {
    if hostname.is_empty() {
        return Err("Hostname must not be empty".to_string());
    }
    if hostname.len() > MAX_HOSTNAME_LENGTH {
        return Err(format!(
            "Hostname too long: {} chars (max {MAX_HOSTNAME_LENGTH})",
            hostname.len()
        ));
    }
    if hostname.contains('\0') {
        return Err("Hostname must not contain null bytes".to_string());
    }
    Ok(())
}

/// Resolve a hostname to all IP addresses (IPv4 + IPv6).
pub fn lookup(hostname: &str) -> Result<Vec<String>, String> {
    validate_hostname(hostname)?;
    runtime::block_on(async {
        let response = RESOLVER
            .lookup_ip(hostname)
            .await
            .map_err(|e| format!("DNS lookup failed for {hostname}: {e}"))?;
        let ips: Vec<String> = response.iter().map(|ip: IpAddr| ip.to_string()).collect();
        // Warn if any result is a private/reserved IP (CWE-918)
        let private: Vec<String> = ips
            .iter()
            .filter(|s| crate::security::is_private_ip_str(s))
            .cloned()
            .collect();
        if !private.is_empty() {
            crate::security_warnings::warn_dns_private_result(hostname, &private);
        }
        Ok(ips)
    })
}

/// Resolve a hostname to IPv4 addresses only.
pub fn lookup_a(hostname: &str) -> Result<Vec<String>, String> {
    validate_hostname(hostname)?;
    runtime::block_on(async {
        let response = RESOLVER
            .lookup_ip(hostname)
            .await
            .map_err(|e| format!("DNS lookup failed for {hostname}: {e}"))?;
        Ok(response
            .iter()
            .filter(|ip: &IpAddr| ip.is_ipv4())
            .map(|ip: IpAddr| ip.to_string())
            .collect())
    })
}

/// Resolve a hostname to IPv6 addresses only.
pub fn lookup_aaaa(hostname: &str) -> Result<Vec<String>, String> {
    validate_hostname(hostname)?;
    runtime::block_on(async {
        let response = RESOLVER
            .lookup_ip(hostname)
            .await
            .map_err(|e| format!("DNS lookup failed for {hostname}: {e}"))?;
        Ok(response
            .iter()
            .filter(|ip: &IpAddr| ip.is_ipv6())
            .map(|ip: IpAddr| ip.to_string())
            .collect())
    })
}

/// Reverse DNS lookup: IP address to hostname.
pub fn reverse(ip_str: &str) -> Result<Option<String>, String> {
    let addr: IpAddr = ip_str
        .parse()
        .map_err(|e| format!("Invalid IP address {ip_str}: {e}"))?;
    runtime::block_on(async {
        match RESOLVER.reverse_lookup(addr).await {
            Ok(response) => Ok(response
                .iter()
                .next()
                .map(|name| name.to_string().trim_end_matches('.').to_string())),
            Err(_) => Ok(None),
        }
    })
}

/// Lookup TXT records for a hostname.
pub fn lookup_txt(hostname: &str) -> Result<Vec<String>, String> {
    validate_hostname(hostname)?;
    runtime::block_on(async {
        let response = RESOLVER
            .txt_lookup(hostname)
            .await
            .map_err(|e| format!("DNS TXT lookup failed for {hostname}: {e}"))?;
        Ok(response.iter().map(|txt| txt.to_string()).collect())
    })
}

/// MX record with priority.
pub struct MxRecord {
    pub priority: u16,
    pub host: String,
}

/// Lookup MX records for a hostname.
pub fn lookup_mx(hostname: &str) -> Result<Vec<MxRecord>, String> {
    validate_hostname(hostname)?;
    runtime::block_on(async {
        let response = RESOLVER
            .mx_lookup(hostname)
            .await
            .map_err(|e| format!("DNS MX lookup failed for {hostname}: {e}"))?;
        let mut records: Vec<MxRecord> = response
            .iter()
            .map(|mx| MxRecord {
                priority: mx.preference(),
                host: mx.exchange().to_string().trim_end_matches('.').to_string(),
            })
            .collect();
        records.sort_by_key(|r| r.priority);
        Ok(records)
    })
}
