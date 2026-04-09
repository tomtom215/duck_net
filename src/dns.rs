// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::net::IpAddr;
use std::sync::OnceLock;

use hickory_resolver::TokioResolver;

use crate::runtime;

/// Shared DNS resolver.  Initialised explicitly by [`init`] during extension
/// load so that any failure is surfaced as a DuckDB error, not an abort.
static RESOLVER: OnceLock<TokioResolver> = OnceLock::new();

/// Initialise the shared DNS resolver.
///
/// Must be called during `register_all` before any DNS lookup.  Subsequent
/// calls are no-ops.  Returns an error if the system resolver configuration
/// cannot be read (e.g., malformed `/etc/resolv.conf`).
pub fn init() -> Result<(), String> {
    if RESOLVER.get().is_some() {
        return Ok(());
    }
    let resolver = runtime::block_on(async {
        let builder = TokioResolver::builder_tokio().map_err(|e| {
            format!(
                "duck_net: failed to read system DNS configuration: {e}. \
                 Ensure /etc/resolv.conf (or the platform equivalent) is readable."
            )
        })?;
        Ok::<TokioResolver, String>(builder.build())
    })?;
    let _ = RESOLVER.set(resolver);
    Ok(())
}

/// Return a reference to the shared resolver, or an error if not initialised.
fn resolver() -> Result<&'static TokioResolver, String> {
    RESOLVER.get().ok_or_else(|| {
        "duck_net: DNS resolver not initialised. \
         This is a bug — please file an issue at https://github.com/tomtom215/duck_net"
            .to_string()
    })
}

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

/// Partition a result list into (public, private) based on duck_net's SSRF
/// private-IP definition. The private list is returned only for the warning.
fn partition_private(ips: Vec<String>) -> (Vec<String>, Vec<String>) {
    let (private, public): (Vec<String>, Vec<String>) = ips
        .into_iter()
        .partition(|s| crate::security::is_private_ip_str(s));
    (public, private)
}

/// Apply the DNS block-private policy. When enabled (the default), private
/// results are removed from the returned list AND a warning is emitted so the
/// caller can see what was filtered. When disabled, private results are
/// returned verbatim with only a warning (legacy behaviour).
fn apply_dns_policy(hostname: &str, ips: Vec<String>) -> Vec<String> {
    let (public, private) = partition_private(ips);
    if !private.is_empty() {
        crate::security_warnings::warn_dns_private_result(hostname, &private);
    }
    let out = if crate::security::dns_block_private() {
        public
    } else {
        let mut all = public;
        all.extend(private);
        all
    };
    crate::audit_log::record("dns", "lookup", hostname, true, out.len() as i32, "");
    out
}

/// Resolve a hostname to all IP addresses (IPv4 + IPv6).
///
/// Private/reserved IPs are filtered out by default (CWE-918). Disable with
/// `SELECT duck_net_set_dns_block_private(false);` for development.
pub fn lookup(hostname: &str) -> Result<Vec<String>, String> {
    validate_hostname(hostname)?;
    runtime::block_on(async {
        let response = resolver()?
            .lookup_ip(hostname)
            .await
            .map_err(|e| format!("DNS lookup failed for {hostname}: {e}"))?;
        let ips: Vec<String> = response.iter().map(|ip: IpAddr| ip.to_string()).collect();
        Ok(apply_dns_policy(hostname, ips))
    })
}

/// Resolve a hostname to IPv4 addresses only.
///
/// Private/reserved IPs are filtered out by default (CWE-918).
pub fn lookup_a(hostname: &str) -> Result<Vec<String>, String> {
    validate_hostname(hostname)?;
    runtime::block_on(async {
        let response = resolver()?
            .lookup_ip(hostname)
            .await
            .map_err(|e| format!("DNS lookup failed for {hostname}: {e}"))?;
        let ips: Vec<String> = response
            .iter()
            .filter(|ip: &IpAddr| ip.is_ipv4())
            .map(|ip: IpAddr| ip.to_string())
            .collect();
        Ok(apply_dns_policy(hostname, ips))
    })
}

/// Resolve a hostname to IPv6 addresses only.
///
/// Private/reserved IPs are filtered out by default (CWE-918).
pub fn lookup_aaaa(hostname: &str) -> Result<Vec<String>, String> {
    validate_hostname(hostname)?;
    runtime::block_on(async {
        let response = resolver()?
            .lookup_ip(hostname)
            .await
            .map_err(|e| format!("DNS lookup failed for {hostname}: {e}"))?;
        let ips: Vec<String> = response
            .iter()
            .filter(|ip: &IpAddr| ip.is_ipv6())
            .map(|ip: IpAddr| ip.to_string())
            .collect();
        Ok(apply_dns_policy(hostname, ips))
    })
}

/// Reverse DNS lookup: IP address to hostname.
pub fn reverse(ip_str: &str) -> Result<Option<String>, String> {
    let addr: IpAddr = ip_str
        .parse()
        .map_err(|e| format!("Invalid IP address {ip_str}: {e}"))?;
    runtime::block_on(async {
        match resolver()?.reverse_lookup(addr).await {
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
        let response = resolver()?
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
        let response = resolver()?
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
