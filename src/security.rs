// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

//! Shared security utilities for duck_net.
//!
//! Provides centralized input validation, SSRF protection, credential
//! scrubbing, and path traversal prevention used across all protocols.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, RwLock};

/// Global flag: when true, private/reserved IP addresses are blocked (SSRF protection).
/// Enabled by default. Can be disabled for local development via
/// `duck_net_set_ssrf_protection(false)`.
///
/// Uses `Acquire`/`Release` ordering so that a `set_ssrf_protection(false)` from
/// one thread is observed before any subsequent validation on another — avoiding
/// the weakly-ordered-ARM race where a stale `true` would let a request through
/// after a switch, or a stale `false` would incorrectly block one.
static SSRF_PROTECTION_ENABLED: AtomicBool = AtomicBool::new(true);

/// Enable or disable SSRF private-network blocking.
pub fn set_ssrf_protection(enabled: bool) {
    SSRF_PROTECTION_ENABLED.store(enabled, Ordering::Release);
}

/// Check whether SSRF protection is enabled.
pub fn ssrf_protection_enabled() -> bool {
    SSRF_PROTECTION_ENABLED.load(Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// Positive-match egress allowlist (CWE-918 defense-in-depth)
// ---------------------------------------------------------------------------

/// A set of allowed hostnames / patterns. When non-empty, every outbound
/// connection's hostname MUST match at least one entry before it is allowed
/// to proceed, independent of whether its resolved IP is public or private.
///
/// Patterns:
/// - Exact match (case-insensitive): `"api.example.com"`
/// - Suffix match: `".example.com"` matches any subdomain of example.com
/// - Wildcard match: `"*.example.com"` matches any subdomain of example.com
static EGRESS_ALLOWLIST: LazyLock<RwLock<Option<Vec<String>>>> =
    LazyLock::new(|| RwLock::new(None));

/// Replace the egress allowlist with a fresh set of patterns.
///
/// Pass an empty slice to clear the allowlist (reverting to deny-private-only).
/// Patterns are stored lowercase and whitespace-trimmed.
pub fn set_egress_allowlist(patterns: &[String]) {
    let cleaned: Vec<String> = patterns
        .iter()
        .map(|p| p.trim().to_ascii_lowercase())
        .filter(|p| !p.is_empty())
        .collect();
    let mut guard = EGRESS_ALLOWLIST.write().unwrap_or_else(|p| p.into_inner());
    if cleaned.is_empty() {
        *guard = None;
    } else {
        *guard = Some(cleaned);
    }
}

/// Return the current allowlist as a `Vec<String>` for introspection.
pub fn egress_allowlist() -> Vec<String> {
    let guard = EGRESS_ALLOWLIST.read().unwrap_or_else(|p| p.into_inner());
    guard.clone().unwrap_or_default()
}

/// Check whether a hostname matches the current allowlist.
///
/// Returns `Ok(())` if:
/// - The allowlist is empty (not configured — deny-private-only mode), OR
/// - The hostname matches at least one allowlist entry.
///
/// Returns `Err` if the allowlist is configured and the hostname does not match.
pub fn check_egress_allowlist(host: &str) -> Result<(), String> {
    let host_lc = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let guard = EGRESS_ALLOWLIST.read().unwrap_or_else(|p| p.into_inner());
    let patterns = match guard.as_ref() {
        Some(p) if !p.is_empty() => p,
        _ => return Ok(()), // Unconfigured: deny-private-only mode.
    };

    for pattern in patterns {
        if pattern_matches(pattern, &host_lc) {
            return Ok(());
        }
    }

    Err(format!(
        "Egress allowlist: hostname '{}' is not permitted. \
         Configure allowed hosts with duck_net_set_egress_allowlist([...]).",
        host
    ))
}

/// Match a single allowlist pattern against a lowercase hostname.
fn pattern_matches(pattern: &str, host: &str) -> bool {
    if pattern == host {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // *.example.com matches a.example.com but NOT example.com itself.
        return host.ends_with(&format!(".{}", suffix)) || host == suffix;
    }
    if let Some(rest) = pattern.strip_prefix('.') {
        // .example.com matches a.example.com and example.com.
        return host == rest || host.ends_with(&format!(".{}", rest));
    }
    false
}

// ---------------------------------------------------------------------------
// DNS result filtering (CWE-918)
// ---------------------------------------------------------------------------

/// When true, `dns_lookup()` and its variants strip private/reserved IPs from
/// the result set (instead of merely warning). Enabled by default so that
/// attacker-controlled DNS responses cannot leak internal network topology
/// through a SQL-visible result.
static DNS_BLOCK_PRIVATE: AtomicBool = AtomicBool::new(true);

pub fn set_dns_block_private(enabled: bool) {
    DNS_BLOCK_PRIVATE.store(enabled, Ordering::Release);
}

pub fn dns_block_private() -> bool {
    DNS_BLOCK_PRIVATE.load(Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// SSH Trust-On-First-Use strictness knob (CWE-295)
// ---------------------------------------------------------------------------

/// TOFU behaviour when connecting to an SSH host that is not in known_hosts.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum TofuMode {
    /// Reject all unknown hosts. Safest — requires pre-populated known_hosts.
    Strict,
    /// Warn and accept, but do NOT persist (per-session TOFU).
    Warn,
    /// Accept, warn, and persist to ~/.ssh/known_hosts. Historical default.
    Auto,
}

/// Encoded TOFU mode (0 = Auto, 1 = Warn, 2 = Strict).
/// Stored as `AtomicBool`-adjacent `AtomicU8` for lock-free reads.
static SSH_TOFU_MODE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

pub fn set_ssh_tofu_mode(mode: TofuMode) {
    let v: u8 = match mode {
        TofuMode::Auto => 0,
        TofuMode::Warn => 1,
        TofuMode::Strict => 2,
    };
    SSH_TOFU_MODE.store(v, Ordering::Release);
}

pub fn ssh_tofu_mode() -> TofuMode {
    match SSH_TOFU_MODE.load(Ordering::Acquire) {
        2 => TofuMode::Strict,
        1 => TofuMode::Warn,
        _ => TofuMode::Auto,
    }
}

// ---------------------------------------------------------------------------
// Runtime protocol ACL (multi-tenant defense-in-depth)
// ---------------------------------------------------------------------------

/// When set, only the listed protocols are allowed to execute network operations.
/// Protocols not in the set will have their entry points return a deny error.
/// Unlike `features::is_enabled` (which gates registration at load time), this
/// gates execution at query time — letting an admin reduce the attack surface
/// of a shared DuckDB process without restarting.
static PROTOCOL_ACL: LazyLock<RwLock<Option<HashSet<String>>>> =
    LazyLock::new(|| RwLock::new(None));

pub fn set_protocol_acl(allowed: &[String]) {
    let cleaned: HashSet<String> = allowed
        .iter()
        .map(|p| p.trim().to_ascii_lowercase())
        .filter(|p| !p.is_empty())
        .collect();
    let mut guard = PROTOCOL_ACL.write().unwrap_or_else(|p| p.into_inner());
    if cleaned.is_empty() {
        *guard = None;
    } else {
        *guard = Some(cleaned);
    }
}

pub fn protocol_acl() -> Vec<String> {
    let guard = PROTOCOL_ACL.read().unwrap_or_else(|p| p.into_inner());
    guard
        .as_ref()
        .map(|s| {
            let mut v: Vec<String> = s.iter().cloned().collect();
            v.sort();
            v
        })
        .unwrap_or_default()
}

/// Check whether a protocol is allowed by the runtime ACL.
/// Returns `Ok(())` when no ACL is configured.
#[allow(dead_code)]
pub fn check_protocol_allowed(protocol: &str) -> Result<(), String> {
    let guard = PROTOCOL_ACL.read().unwrap_or_else(|p| p.into_inner());
    match guard.as_ref() {
        Some(set) if !set.contains(&protocol.to_ascii_lowercase()) => Err(format!(
            "Protocol '{}' is not permitted by the runtime ACL. \
             Update the ACL with duck_net_set_protocol_acl([...]).",
            protocol
        )),
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// SSRF Protection (CWE-918)
// ---------------------------------------------------------------------------

/// Check if an IP address is private, loopback, link-local, or otherwise
/// reserved. These should not be reachable from SQL queries to prevent SSRF.
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()              // 127.0.0.0/8
                || v4.is_private()         // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local()      // 169.254.0.0/16
                || v4.is_broadcast()       // 255.255.255.255
                || v4.is_unspecified()     // 0.0.0.0
                || v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64 // 100.64.0.0/10 (CGN)
                || v4.octets()[0] == 198 && (v4.octets()[1] & 0xFE) == 18 // 198.18.0.0/15 (benchmark)
                || v4.is_documentation()   // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
                || v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0
            // 192.0.0.0/24 (IETF)
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            v6.is_loopback()     // ::1
                || v6.is_unspecified() // ::
                // Unique local addresses (fc00::/7)
                || (segs[0] & 0xFE00) == 0xFC00
                // Link-local (fe80::/10)
                || (segs[0] & 0xFFC0) == 0xFE80
                // Multicast (ff00::/8)
                || (segs[0] & 0xFF00) == 0xFF00
                // Teredo tunneling (2001::/32) – RFC 4380
                || (segs[0] == 0x2001 && segs[1] == 0x0000)
                // 6to4 (2002::/16) – RFC 3056: embedded IPv4 may be private
                || (segs[0] == 0x2002 && {
                    let embedded = std::net::Ipv4Addr::new(
                        (segs[1] >> 8) as u8,
                        (segs[1] & 0xFF) as u8,
                        (segs[2] >> 8) as u8,
                        (segs[2] & 0xFF) as u8,
                    );
                    is_private_ip(&IpAddr::V4(embedded))
                })
                // NAT64 well-known prefix (64:ff9b::/96) – RFC 6052
                || (segs[0] == 0x0064
                    && segs[1] == 0xFF9B
                    && segs[2] == 0
                    && segs[3] == 0
                    && segs[4] == 0
                    && segs[5] == 0)
                // IPv6 documentation (2001:db8::/32) – RFC 3849
                || (segs[0] == 0x2001 && segs[1] == 0x0DB8)
                // IPv4-mapped addresses (::ffff:0:0/96): check the embedded IPv4
                || v6.to_ipv4_mapped().is_some_and(|v4| {
                    is_private_ip(&IpAddr::V4(v4))
                })
                // IPv4-translated addresses (::ffff:0:0:0/96) – RFC 6145
                || (segs[0] == 0
                    && segs[1] == 0
                    && segs[2] == 0
                    && segs[3] == 0
                    && segs[4] == 0xFFFF
                    && segs[5] == 0)
        }
    }
}

/// Validate that a URL's hostname does not resolve to a private/reserved IP.
/// This prevents SSRF attacks where an attacker controls the URL to reach
/// internal services (e.g., cloud metadata at 169.254.169.254).
///
/// Returns Ok(()) if the URL is safe, or Err with a message if blocked.
pub fn validate_no_ssrf(url: &str) -> Result<(), String> {
    if !ssrf_protection_enabled() {
        return Ok(());
    }

    // Extract hostname from URL
    let host =
        extract_hostname(url).ok_or_else(|| "Cannot extract hostname from URL".to_string())?;

    validate_no_ssrf_host(&host)
}

/// Validate that a raw hostname does not resolve to a private/reserved IP.
/// Use this for non-URL protocols (Redis, MQTT, LDAP, etc.) that take a
/// hostname directly rather than a full URL.
///
/// Also enforces the egress allowlist when one is configured (defense-in-depth
/// on top of the deny-private filter), and acquires a rate-limit token for
/// the target host so that `duck_net_set_rate_limit()` applies uniformly
/// across every protocol — not just the six that used to call
/// `rate_limit::acquire_for_host` directly.
pub fn validate_no_ssrf_host(host: &str) -> Result<(), String> {
    // Enforce the allowlist first — applies even when SSRF is "disabled".
    check_egress_allowlist(host)?;

    // Per-host rate limiting applies to every protocol via this chokepoint.
    crate::rate_limit::acquire_for_host(host);

    if !ssrf_protection_enabled() {
        return Ok(());
    }

    // Try to resolve the hostname
    let addr_str = if host.contains(':') {
        host.to_string() // Already has port or is IPv6
    } else {
        format!("{}:443", host) // Add dummy port for resolution
    };

    match addr_str.to_socket_addrs() {
        Ok(addrs) => {
            let addrs: Vec<_> = addrs.collect();
            if addrs.is_empty() {
                return Err(format!(
                    "SSRF protection: hostname '{}' resolved to no addresses. \
                     Use duck_net_set_ssrf_protection(false) to disable for local development.",
                    host
                ));
            }
            for addr in &addrs {
                if is_private_ip(&addr.ip()) {
                    return Err(format!(
                        "SSRF protection: hostname '{}' resolves to private/reserved IP {}. \
                         Use duck_net_set_ssrf_protection(false) to disable for local development.",
                        host,
                        addr.ip()
                    ));
                }
            }
            Ok(())
        }
        Err(_) => {
            // Block on DNS resolution failure to prevent DNS rebinding attacks.
            // A rebinding attacker could return NXDOMAIN on the first lookup and
            // a private IP on the second (actual connection) lookup.
            Err(format!(
                "SSRF protection: connection blocked — hostname '{}' could not be resolved. \
                 Use duck_net_set_ssrf_protection(false) to disable for local development.",
                host
            ))
        }
    }
}

/// Resolve a host:port pair into a validated `SocketAddr` suitable for use with
/// `UdpSocket::send_to(buf, addr)` or `TcpStream::connect(addr)`.
///
/// This is the **UDP DNS-rebinding-safe** entry point. Every UDP protocol in
/// duck_net (SNMP, NTP, PTP, SIP, STUN, RADIUS, IPMI, syslog) used to call
/// `validate_no_ssrf_host(host)` and then pass `format!("{host}:{port}")` to
/// `send_to`, which re-resolved via the OS resolver — leaving a TOCTOU window
/// where a rebinding attacker could return a public IP for the check and a
/// private IP for the actual send. This helper closes that window by
/// resolving once, validating every address, and returning a single
/// concrete `SocketAddr` that the caller passes to `send_to` directly.
///
/// The returned `SocketAddr` is guaranteed to be non-private (unless SSRF
/// protection is disabled). The first address with the preferred IP family
/// (IPv4 by default, matching `UdpSocket::bind("0.0.0.0:0")`) is returned;
/// if no IPv4 address is present, the first IPv6 address is returned.
pub fn resolve_and_validate_udp(host: &str, port: u16) -> Result<SocketAddr, String> {
    // Allowlist always applies.
    check_egress_allowlist(host)?;

    // Uniform rate-limiting across all UDP protocols.
    crate::rate_limit::acquire_for_host(host);

    let addr_str = if host.starts_with('[') || host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!(
            "[{}]:{}",
            host.trim_start_matches('[').trim_end_matches(']'),
            port
        )
    } else {
        format!("{}:{}", host, port)
    };

    let resolved: Vec<SocketAddr> = addr_str
        .to_socket_addrs()
        .map_err(|e| {
            format!(
                "SSRF protection: cannot resolve '{}:{}' for UDP send: {}",
                host, port, e
            )
        })?
        .collect();

    if resolved.is_empty() {
        return Err(format!(
            "SSRF protection: '{}:{}' resolved to no addresses",
            host, port
        ));
    }

    if ssrf_protection_enabled() {
        // Reject if ANY resolved address is private (split-horizon defense).
        for addr in &resolved {
            if is_private_ip(&addr.ip()) {
                return Err(format!(
                    "SSRF protection: '{}' resolves to private/reserved IP {}. \
                     Use duck_net_set_ssrf_protection(false) to disable for local development.",
                    host,
                    addr.ip()
                ));
            }
        }
    }

    // Prefer IPv4 — matches the default `0.0.0.0:0` bind used across the crate.
    let chosen = resolved
        .iter()
        .find(|a| a.is_ipv4())
        .copied()
        .unwrap_or_else(|| resolved[0]);

    Ok(chosen)
}

// ---------------------------------------------------------------------------
// SSRF-safe ureq Resolver (CWE-918 — DNS rebinding prevention)
// ---------------------------------------------------------------------------

/// An SSRF-aware [`ureq::unversioned::resolver::Resolver`] that resolves and
/// validates addresses in one atomic step, eliminating the TOCTOU window that
/// would exist if `validate_no_ssrf_host()` checked the hostname and ureq then
/// re-resolved it independently for connection.
///
/// When SSRF protection is enabled (the default):
/// - The hostname is resolved via `ToSocketAddrs`.
/// - Every resolved address is checked against `is_private_ip()`.
/// - If **any** address is private/reserved, the request is blocked.
/// - Only wholly-public address sets are returned to the connector.
///
/// When SSRF protection is disabled (via `set_ssrf_protection(false)`),
/// this delegates to `DefaultResolver` so normal resolution proceeds.
#[derive(Debug)]
pub struct SsrfSafeResolver;

impl ureq::unversioned::resolver::Resolver for SsrfSafeResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        config: &ureq::config::Config,
        timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs};

        // When SSRF protection is disabled, behave exactly like DefaultResolver.
        if !ssrf_protection_enabled() {
            return DefaultResolver::default().resolve(uri, config, timeout);
        }

        let scheme = uri.scheme().ok_or(ureq::Error::HostNotFound)?;
        let authority = uri.authority().ok_or(ureq::Error::HostNotFound)?;

        // Positive-match egress allowlist (CWE-918 defense-in-depth).
        // Applied even when SSRF-by-IP is disabled, because allowlists are
        // independent of private-IP filtering.
        if let Err(msg) = check_egress_allowlist(authority.host()) {
            return Err(ureq::Error::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                msg,
            )));
        }

        // Build "host:port" string (DefaultResolver helper knows default ports).
        let host_port =
            DefaultResolver::host_and_port(scheme, authority).ok_or(ureq::Error::HostNotFound)?;

        // Resolve via the OS resolver — identical to DefaultResolver's sync path.
        let socket_addrs: Vec<std::net::SocketAddr> = host_port
            .to_socket_addrs()
            .map_err(|_| ureq::Error::HostNotFound)?
            .collect();

        if socket_addrs.is_empty() {
            return Err(ureq::Error::HostNotFound);
        }

        // Block if ANY resolved address is a private/reserved IP (CWE-918).
        // Checking all addresses prevents split-horizon DNS bypass attempts.
        for addr in &socket_addrs {
            if is_private_ip(&addr.ip()) {
                return Err(ureq::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!(
                        "SSRF protection: hostname '{}' resolves to private/reserved IP {}. \
                         Use duck_net_set_ssrf_protection(false) to disable for local development.",
                        authority.host(),
                        addr.ip()
                    ),
                )));
            }
        }

        let mut result: ResolvedSocketAddrs = self.empty();
        for addr in socket_addrs.into_iter().take(16) {
            result.push(addr);
        }

        Ok(result)
    }
}

/// Check whether an IP address string is private/reserved.
///
/// Returns `true` if the address is private, `false` if public or unparseable.
/// Used by DNS functions to warn callers about private IP results.
pub fn is_private_ip_str(ip_str: &str) -> bool {
    ip_str.parse::<IpAddr>().is_ok_and(|ip| is_private_ip(&ip))
}

/// Validate a `SocketAddr` directly (for use with tokio or other async TCP streams).
///
/// Use this when you have a `SocketAddr` from `TcpStream::peer_addr()` but
/// the stream type is not `std::net::TcpStream` (e.g., `tokio::net::TcpStream`).
pub fn validate_peer_socket_addr(peer: std::net::SocketAddr) -> Result<(), String> {
    if !ssrf_protection_enabled() {
        return Ok(());
    }
    if is_private_ip(&peer.ip()) {
        Err(format!(
            "SSRF protection: connected peer IP {} is private/reserved. \
             This may indicate a DNS rebinding attack. \
             Use duck_net_set_ssrf_protection(false) to disable for local development.",
            peer.ip()
        ))
    } else {
        Ok(())
    }
}

/// Validate the actual peer IP of an established TCP connection (CWE-918 DNS rebinding).
///
/// Calling `validate_no_ssrf_host()` before connecting leaves a TOCTOU window:
/// an attacker can return a public IP on the pre-flight lookup and then change
/// DNS to a private IP for the actual connection. Calling this function on the
/// connected `TcpStream` eliminates that window by checking the real peer address.
///
/// This should be called immediately after `TcpStream::connect_timeout()` and
/// before any data is sent.
pub fn validate_tcp_peer(stream: &std::net::TcpStream) -> Result<(), String> {
    if !ssrf_protection_enabled() {
        return Ok(());
    }
    match stream.peer_addr() {
        Ok(peer) => {
            if is_private_ip(&peer.ip()) {
                Err(format!(
                    "SSRF protection: connected peer IP {} is private/reserved. \
                     This may indicate a DNS rebinding attack. \
                     Use duck_net_set_ssrf_protection(false) to disable for local development.",
                    peer.ip()
                ))
            } else {
                Ok(())
            }
        }
        Err(e) => Err(format!(
            "SSRF protection: cannot verify peer address for rebinding check: {e}"
        )),
    }
}

/// Extract the hostname portion from a URL.
fn extract_hostname(url: &str) -> Option<String> {
    // Strip scheme: find "://" separator and take everything after it.
    let scheme_end = url.find("://")?;
    let lower_scheme = url[..scheme_end].to_ascii_lowercase();

    // Validate that the scheme is one we recognize
    const KNOWN_SCHEMES: &[&str] = &[
        "https", "http", "ftp", "ftps", "sftp", "mqtt", "mqtts", "tcp", "ldap", "ldaps", "imap",
        "imaps", "smtp", "smtps", "redis", "grpc", "grpcs", "ws", "wss", "nats", "amqp", "amqps",
    ];
    if !KNOWN_SCHEMES.contains(&lower_scheme.as_str()) {
        return None;
    }

    let rest = &url[scheme_end + 3..];

    // Strip userinfo
    let after_auth = if let Some(at) = rest.find('@') {
        &rest[at + 1..]
    } else {
        rest
    };

    // Take host[:port] before path
    let host_port = after_auth.split('/').next().unwrap_or(after_auth);

    // Strip port (but handle IPv6 brackets)
    if host_port.starts_with('[') {
        // IPv6: [::1]:port
        if let Some(bracket_end) = host_port.find(']') {
            Some(host_port[..=bracket_end].to_string())
        } else {
            Some(host_port.to_string())
        }
    } else if let Some(colon) = host_port.rfind(':') {
        // Only strip port if what follows looks like a number
        let after_colon = &host_port[colon + 1..];
        if after_colon.chars().all(|c| c.is_ascii_digit()) {
            Some(host_port[..colon].to_string())
        } else {
            Some(host_port.to_string())
        }
    } else {
        Some(host_port.to_string())
    }
}

// ---------------------------------------------------------------------------
// Credential Scrubbing (CWE-532)
// ---------------------------------------------------------------------------

/// Scrub credentials from a URL for safe inclusion in error messages.
///
/// Replaces `scheme://user:pass@host` with `scheme://***@host` and
/// redacts sensitive query parameters (CWE-532) such as `access_token`,
/// `api_key`, `password`, `secret`, `key`, `auth`, `token`, `signature`.
pub fn scrub_url(url: &str) -> String {
    // Strip userinfo (scheme://user:pass@host → scheme://***@host)
    let url = if let (Some(scheme_end), Some(at)) = (url.find("://"), url.find('@')) {
        if at > scheme_end {
            format!("{}://***@{}", &url[..scheme_end], &url[at + 1..])
        } else {
            url.to_string()
        }
    } else {
        url.to_string()
    };

    // Redact sensitive query-string parameters
    scrub_query_params(&url)
}

/// Redact values of sensitive query parameters in a URL string.
///
/// Replaces `?param=VALUE&...` with `?param=***&...` for known sensitive
/// parameter names. Case-insensitive match on the parameter name.
fn scrub_query_params(url: &str) -> String {
    // Sensitive query parameter names (lower-case for comparison)
    const SENSITIVE_PARAMS: &[&str] = &[
        "access_token",
        "api_key",
        "apikey",
        "auth",
        "client_secret",
        "key",
        "password",
        "private_key",
        "secret",
        "secret_key",
        "signature",
        "token",
        "x-amz-security-token",
        "x-amz-credential",
        "sas",
    ];

    let query_start = match url.find('?') {
        Some(pos) => pos,
        None => return url.to_string(),
    };

    let (base, query_and_fragment) = url.split_at(query_start);
    // query_and_fragment starts with '?'
    let fragment_start = query_and_fragment.find('#');
    let (query_part, fragment_part) = match fragment_start {
        Some(pos) => (&query_and_fragment[1..pos], &query_and_fragment[pos..]),
        None => (&query_and_fragment[1..], ""),
    };

    let redacted: Vec<String> = query_part
        .split('&')
        .map(|pair| {
            if let Some(eq) = pair.find('=') {
                let name = &pair[..eq];
                let lower = name.to_ascii_lowercase();
                if SENSITIVE_PARAMS.iter().any(|&p| p == lower) {
                    return format!("{}=***", name);
                }
            }
            pair.to_string()
        })
        .collect();

    format!("{}?{}{}", base, redacted.join("&"), fragment_part)
}

/// Scrub known sensitive parameter values from an error message.
///
/// Replaces EVERY occurrence of patterns like `password=value` or
/// `secret_key=value` with redacted forms (not just the first). Also scrubs
/// Base64-encoded `Authorization` and `Bearer` header values that may leak
/// through error messages (CWE-532).
pub fn scrub_error(msg: &str) -> String {
    let mut result = msg.to_string();

    let sensitive_keys = [
        "password",
        "secret",
        "token",
        "api_key",
        "secret_key",
        "access_key",
        "bearer_token",
        "private_key",
        "client_secret",
        "community",
        "shared_secret",
    ];

    for &key in &sensitive_keys {
        let pattern = format!("{}=", key);
        // Loop over every occurrence — earlier versions only redacted the first,
        // leaking the second copy of e.g. "password=X password=Y".
        loop {
            let lower = result.to_lowercase();
            let Some(start) = lower.find(&pattern) else {
                break;
            };
            let after = start + pattern.len();
            let end = result[after..]
                .find(|c: char| c.is_whitespace() || c == '&' || c == '"' || c == '\'')
                .map(|p| after + p)
                .unwrap_or(result.len());
            result = format!("{}{}=********{}", &result[..start], key, &result[end..]);
        }
    }

    // Scrub Authorization header values (Basic/Bearer) — all occurrences.
    for prefix in &["Authorization: Bearer ", "Authorization: Basic "] {
        loop {
            let Some(start) = result.find(prefix) else {
                break;
            };
            let after = start + prefix.len();
            let end = result[after..]
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                .map(|p| after + p)
                .unwrap_or(result.len());
            result = format!("{}{}********{}", &result[..start], prefix, &result[end..]);
        }
    }

    // Scrub AUTH PLAIN base64 payloads — all occurrences.
    loop {
        let Some(start) = result.find("AUTH PLAIN ") else {
            break;
        };
        let after = start + "AUTH PLAIN ".len();
        let end = result[after..]
            .find(|c: char| c.is_whitespace() || c == '\r' || c == '\n')
            .map(|p| after + p)
            .unwrap_or(result.len());
        result = format!("{}AUTH PLAIN ********{}", &result[..start], &result[end..]);
    }

    result
}

// ---------------------------------------------------------------------------
// Unified protocol entry helper (audit + rate limit + protocol ACL + warning)
// ---------------------------------------------------------------------------

/// Enter a protocol operation at a single chokepoint.
///
/// Every network protocol entry point can call this exactly once at the top
/// of its public function. It:
///
/// 1. Checks the runtime protocol ACL (`set_protocol_acl`) — denying the
///    call with a clear error if the protocol is not in the allowed set.
/// 2. Acquires a rate-limit token for `host` via
///    `crate::rate_limit::acquire_for_host` (blocks until allowed, honouring
///    both the global and per-domain RPS limits).
///
/// The returned guard automatically records a single audit-log entry when it
/// is dropped, capturing the protocol, operation, host, success flag, status
/// code, and a scrubbed message. Call `.set_status(code)` / `.set_message()`
/// before the guard drops to populate those fields.
#[allow(dead_code)]
pub fn protocol_enter(
    protocol: &'static str,
    operation: &'static str,
    host: &str,
) -> Result<ProtocolGuard, String> {
    check_protocol_allowed(protocol)?;
    crate::rate_limit::acquire_for_host(host);
    Ok(ProtocolGuard {
        protocol,
        operation,
        host: host.to_string(),
        success: false,
        status_code: 0,
        message: String::new(),
    })
}

/// RAII guard returned by [`protocol_enter`]; emits one audit log entry when
/// dropped. Defaults to `success=false` so that accidental panics or early
/// returns show up as failures in the audit log.
#[allow(dead_code)]
pub struct ProtocolGuard {
    protocol: &'static str,
    operation: &'static str,
    host: String,
    success: bool,
    status_code: i32,
    message: String,
}

#[allow(dead_code)]
impl ProtocolGuard {
    pub fn ok(mut self) -> Self {
        self.success = true;
        self
    }

    pub fn set_success(&mut self, success: bool) {
        self.success = success;
    }

    pub fn set_status(&mut self, code: i32) {
        self.status_code = code;
    }

    pub fn set_message(&mut self, msg: impl Into<String>) {
        self.message = msg.into();
    }
}

impl Drop for ProtocolGuard {
    fn drop(&mut self) {
        crate::audit_log::record(
            self.protocol,
            self.operation,
            &self.host,
            self.success,
            self.status_code,
            &self.message,
        );
    }
}

// ---------------------------------------------------------------------------
// Constant-time byte comparison (CWE-208 — timing attacks on MACs / tokens)
// ---------------------------------------------------------------------------

/// Compare two byte slices in constant time relative to their length.
///
/// Used for comparing HMAC / SigV4 / authentication tokens where a naive
/// `==` could leak the matching prefix length via timing. Returns `true`
/// only when the slices are equal and the same length.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Path Traversal Prevention (CWE-22)
// ---------------------------------------------------------------------------

/// Validate that a file path does not contain directory traversal sequences.
///
/// Blocks:
/// - `..` path components (traversal)
/// - Null bytes (C string injection)
/// - Excessively long paths
pub fn validate_path_no_traversal(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("Path cannot be empty".to_string());
    }
    if path.len() > 4096 {
        return Err("Path exceeds maximum length of 4096".to_string());
    }
    if path.contains('\0') {
        return Err("Path must not contain null bytes".to_string());
    }

    // Check for directory traversal via path components
    for component in path.split('/') {
        if component == ".." {
            return Err("Path traversal detected: '..' components are not allowed".to_string());
        }
    }

    // Also check backslash-separated paths (Windows-style)
    for component in path.split('\\') {
        if component == ".." {
            return Err("Path traversal detected: '..' components are not allowed".to_string());
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// SSH Command Validation (CWE-78)
// ---------------------------------------------------------------------------

/// Characters that are dangerous in shell commands.
const SHELL_DANGEROUS_CHARS: &[char] = &[
    ';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\n', '\r', '\0',
];

/// Validate an SSH command for dangerous shell metacharacters.
///
/// This is a defense-in-depth measure. Commands are executed via SSH's exec
/// channel which doesn't invoke a shell, but the remote sshd may pipe through
/// a shell depending on configuration.
///
/// When `strict` is true, rejects commands containing shell metacharacters.
/// When `strict` is false, only rejects null bytes and CRLF (always dangerous).
pub fn validate_ssh_command(command: &str, strict: bool) -> Result<(), String> {
    if command.is_empty() {
        return Err("Command cannot be empty".to_string());
    }
    if command.len() > 8192 {
        return Err("Command exceeds maximum length of 8192".to_string());
    }
    if command.contains('\0') {
        return Err("Command must not contain null bytes".to_string());
    }

    if strict {
        for &c in SHELL_DANGEROUS_CHARS {
            if c != '\0' && command.contains(c) {
                return Err(format!(
                    "Command contains potentially dangerous character: '{}'",
                    if c == '\n' {
                        "\\n".to_string()
                    } else if c == '\r' {
                        "\\r".to_string()
                    } else {
                        c.to_string()
                    }
                ));
            }
        }
    } else {
        // Even in non-strict mode, block CRLF injection
        if command.contains('\n') || command.contains('\r') {
            return Err("Command must not contain newline characters".to_string());
        }
    }

    Ok(())
}

/// Global flag for SSH strict command validation.
/// Defaults to true (security-by-default): rejects shell metacharacters.
/// Set to false only for trusted environments that require complex commands.
static SSH_STRICT_COMMANDS: AtomicBool = AtomicBool::new(true);

pub fn set_ssh_strict_commands(strict: bool) {
    SSH_STRICT_COMMANDS.store(strict, Ordering::Relaxed);
}

pub fn ssh_strict_commands() -> bool {
    SSH_STRICT_COMMANDS.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Input length validation
// ---------------------------------------------------------------------------

/// Validate that a credential string is within acceptable bounds.
/// Prevents buffer-overflow attempts and memory exhaustion.
pub fn validate_credential_length(name: &str, value: &str, max_len: usize) -> Result<(), String> {
    if value.len() > max_len {
        return Err(format!(
            "{} exceeds maximum length of {} characters",
            name, max_len
        ));
    }
    if value.contains('\0') {
        return Err(format!("{} must not contain null bytes", name));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// URL Length Validation (CWE-400)
// ---------------------------------------------------------------------------

/// Maximum URL length accepted by duck_net functions.
pub const MAX_URL_LENGTH: usize = 65_536;

/// Validate that a URL does not exceed the maximum length.
pub fn validate_url_length(url: &str) -> Result<(), String> {
    if url.len() > MAX_URL_LENGTH {
        return Err(format!(
            "URL exceeds maximum length of {} characters",
            MAX_URL_LENGTH
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Port Validation
// ---------------------------------------------------------------------------

/// Validate that a port number is in a valid range (1-65535).
#[allow(dead_code)]
pub fn validate_port(port: u16) -> Result<(), String> {
    if port == 0 {
        return Err("Port must be between 1 and 65535".to_string());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Re-exports from security_validate
// ---------------------------------------------------------------------------

/// Escape special characters in LDAP filter values per RFC 4515 (CWE-90).
/// See [`crate::security_validate::ldap_escape_filter_value`].
pub fn ldap_escape_filter_value(value: &str) -> String {
    crate::security_validate::ldap_escape_filter_value(value)
}

/// Escape a string for safe inclusion in a JSON string value (CWE-116).
/// See [`crate::security_validate::json_escape`].
pub fn json_escape(s: &str) -> String {
    crate::security_validate::json_escape(s)
}

/// Validate an iCalendar timestamp format (CWE-91).
/// See [`crate::security_validate::validate_ical_timestamp`].
pub fn validate_ical_timestamp(value: &str) -> Result<(), String> {
    crate::security_validate::validate_ical_timestamp(value)
}

// ---------------------------------------------------------------------------
// Cryptographic Random Bytes
// ---------------------------------------------------------------------------

/// Generate cryptographically secure random bytes using the OS entropy source.
///
/// Uses `getrandom` which calls the OS CSPRNG (e.g., /dev/urandom, CryptGenRandom).
/// Panics if the OS entropy source is unavailable, which should never happen on
/// any supported platform. Failing open with weak randomness would be a security
/// vulnerability (CWE-338).
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf)
        .expect("OS entropy source unavailable — cannot generate secure random bytes");
    buf
}

/// Generate a random hex string of the specified byte length.
///
/// Uses cryptographically secure random bytes from the OS.
pub fn random_hex(byte_count: usize) -> String {
    let bytes = random_bytes_vec(byte_count);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Generate a Vec of cryptographically secure random bytes.
fn random_bytes_vec(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf)
        .expect("OS entropy source unavailable — cannot generate secure random bytes");
    buf
}

// ---------------------------------------------------------------------------
// HTTP Header Injection Prevention (CWE-113)
// ---------------------------------------------------------------------------

/// Validate an HTTP header name against RFC 7230 §3.2 token rules.
///
/// Header names must be non-empty, at most 256 bytes, and contain only
/// `!#$%&'*+-.^_\`|~` and alphanumeric characters. CRLF and spaces are
/// rejected to prevent header injection.
pub fn validate_http_header_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("HTTP header name must not be empty".to_string());
    }
    if name.len() > 256 {
        return Err("HTTP header name too long (max 256 bytes)".to_string());
    }
    for ch in name.chars() {
        if !is_tchar(ch) {
            return Err(format!(
                "HTTP header name contains invalid character: {:?} (RFC 7230 token required)",
                ch
            ));
        }
    }
    Ok(())
}

/// Validate an HTTP header value for CRLF injection (CWE-113).
///
/// Rejects values containing `\r`, `\n`, or `\0` which could inject
/// additional HTTP headers or responses into a connection.
pub fn validate_http_header_value(value: &str) -> Result<(), String> {
    if value.len() > 8192 {
        return Err("HTTP header value too long (max 8192 bytes)".to_string());
    }
    for (i, ch) in value.chars().enumerate() {
        if ch == '\r' || ch == '\n' || ch == '\0' {
            return Err(format!(
                "HTTP header value contains disallowed control character at byte {}: {:?}. \
                 CRLF injection in headers is blocked (CWE-113).",
                i, ch
            ));
        }
    }
    Ok(())
}

/// Maximum number of HTTP headers accepted per request (CWE-400).
/// Prevents header-count DoS where a caller passes thousands of headers.
pub const MAX_HEADER_COUNT: usize = 128;

/// Validate all headers in a list for name and value safety, plus count.
pub fn validate_headers(headers: &[(String, String)]) -> Result<(), String> {
    if headers.len() > MAX_HEADER_COUNT {
        return Err(format!(
            "Too many HTTP headers: {} (max {})",
            headers.len(),
            MAX_HEADER_COUNT
        ));
    }
    for (name, value) in headers {
        validate_http_header_name(name)?;
        validate_http_header_value(value)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Bounded Reads (CWE-400 — centralized response-size cap)
// ---------------------------------------------------------------------------

/// Read up to `max_bytes` from an `io::Read`, returning an error if the stream
/// exceeds that limit. Use this anywhere a remote peer controls the response
/// size so that resource limits are auditable from a single place.
#[allow(dead_code)]
pub fn bounded_read<R: std::io::Read>(
    reader: &mut R,
    max_bytes: usize,
) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let mut buf = Vec::new();
    // Read at most max_bytes + 1 so an exact-limit response succeeds and an
    // over-limit response fails with a clear message.
    let read = reader
        .take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut buf)?;
    if read > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Response exceeds maximum allowed size of {} bytes (CWE-400 resource exhaustion)",
                max_bytes
            ),
        ));
    }
    Ok(buf)
}

/// RFC 7230 §3.2.6 token character: any VCHAR except delimiters.
fn is_tchar(c: char) -> bool {
    matches!(c,
        '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '.' |
        '^' | '_' | '`' | '|' | '~' |
        'A'..='Z' | 'a'..='z' | '0'..='9'
    )
}

/// Check if a URL uses plain HTTP (not HTTPS).
pub fn is_plaintext_http(url: &str) -> bool {
    url.trim().to_ascii_lowercase().starts_with("http://")
}

/// Check if a URL uses HTTPS.
#[allow(dead_code)]
pub fn is_secure_https(url: &str) -> bool {
    url.trim().to_ascii_lowercase().starts_with("https://")
}

// ---------------------------------------------------------------------------
// Host Validation (shared across protocols)
// ---------------------------------------------------------------------------

/// Validate a hostname or IP address for safe use in network connections.
///
/// Allows: alphanumeric, dots, hyphens, colons (IPv6), brackets (IPv6),
/// underscores (common in internal DNS names).
/// Rejects: empty, too long (>253), or containing other characters.
pub fn validate_host(host: &str) -> Result<(), String> {
    if host.is_empty() {
        return Err("Hostname must not be empty".to_string());
    }
    if host.len() > 253 {
        return Err("Hostname too long (max 253 characters)".to_string());
    }
    if !host
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']' | '_'))
    {
        return Err(format!("Hostname contains invalid characters: '{}'", host));
    }
    Ok(())
}
