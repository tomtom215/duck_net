// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

//! Security warnings subsystem for duck_net.
//!
//! Tracks and surfaces security warnings when users invoke protocols in
//! potentially insecure configurations. Warnings are informational — they
//! never block operations — so that CI pipelines, airgapped systems, and
//! development environments continue to work. Users can suppress warnings
//! globally with [`set_warnings_enabled`].
//!
//! # Design Principles
//!
//! - **Never block**: Warnings inform, they do not prevent execution.
//! - **Dedup**: The same warning is emitted only once per session.
//! - **Auditable**: All warnings can be queried via `duck_net_security_warnings()`.
//! - **Suppressible**: `duck_net_set_security_warnings(false)` silences them.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/// Global flag: when true, security warnings are emitted.
static WARNINGS_ENABLED: AtomicBool = AtomicBool::new(true);

/// Accumulated security warnings for this session.
static WARNINGS: Mutex<Option<WarningStore>> = Mutex::new(None);

struct WarningStore {
    /// Set of already-emitted warning codes (for dedup).
    seen: HashSet<&'static str>,
    /// Ordered list of warnings.
    entries: Vec<SecurityWarning>,
}

/// A single security warning entry.
#[derive(Clone)]
pub struct SecurityWarning {
    /// Short machine-readable code, e.g. "PLAINTEXT_MQTT".
    pub code: &'static str,
    /// CWE identifier, if applicable.
    pub cwe: &'static str,
    /// Human-readable severity level.
    pub severity: Severity,
    /// Protocol or subsystem that triggered the warning.
    pub protocol: &'static str,
    /// Detailed description of the risk and mitigation.
    pub message: String,
}

/// Warning severity levels.
#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
            Self::Info => "INFO",
        }
    }
}

/// Enable or disable security warnings.
pub fn set_warnings_enabled(enabled: bool) {
    WARNINGS_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Check whether security warnings are enabled.
pub fn warnings_enabled() -> bool {
    WARNINGS_ENABLED.load(Ordering::Relaxed)
}

/// Initialize the warnings store. Called once at extension load.
pub fn init() {
    let mut store = WARNINGS.lock().unwrap_or_else(|p| p.into_inner());
    if store.is_none() {
        *store = Some(WarningStore {
            seen: HashSet::new(),
            entries: Vec::new(),
        });
    }
}

/// Emit a security warning (deduped by code).
///
/// Each unique warning (identified by `code`) is:
/// 1. Stored in the in-session log (queryable via `duck_net_security_warnings()`).
/// 2. Printed immediately to stderr so users see it in DuckDB CLI output and
///    application logs without having to query the warnings table (Fix 19 / CWE-532).
///
/// Returns the message string if this code was new, `None` if already emitted
/// or warnings are disabled.
pub fn warn(warning: SecurityWarning) -> Option<String> {
    if !warnings_enabled() {
        return None;
    }

    let mut store = WARNINGS.lock().unwrap_or_else(|p| p.into_inner());
    let ws = store.as_mut()?;

    if ws.seen.contains(warning.code) {
        return None;
    }

    ws.seen.insert(warning.code);
    let msg = warning.message.clone();

    // Surface the warning immediately on stderr so it appears in DuckDB CLI output
    // and application logs (DuckDB itself uses stderr for its own notice messages).
    eprintln!(
        "[duck_net] {} ({}): {}",
        warning.severity.as_str(),
        warning.code,
        msg
    );

    ws.entries.push(warning);
    Some(msg)
}

/// Retrieve all warnings emitted this session.
pub fn list_warnings() -> Vec<SecurityWarning> {
    let store = WARNINGS.lock().unwrap_or_else(|p| p.into_inner());
    match store.as_ref() {
        Some(ws) => ws.entries.clone(),
        None => Vec::new(),
    }
}

/// Clear all accumulated warnings.
pub fn clear_warnings() -> usize {
    let mut store = WARNINGS.lock().unwrap_or_else(|p| p.into_inner());
    match store.as_mut() {
        Some(ws) => {
            let count = ws.entries.len();
            ws.seen.clear();
            ws.entries.clear();
            count
        }
        None => 0,
    }
}

// ---------------------------------------------------------------------------
// Pre-defined warning constructors for common security issues
// ---------------------------------------------------------------------------

/// Warn about plaintext protocol usage when an encrypted alternative exists.
pub fn warn_plaintext(protocol: &'static str, code: &'static str, secure_scheme: &str) {
    warn(SecurityWarning {
        code,
        cwe: "CWE-319",
        severity: Severity::High,
        protocol,
        message: format!(
            "Security warning: {protocol} connection uses plaintext. \
             Credentials and data are sent unencrypted. \
             Use {secure_scheme} for encrypted connections. \
             Suppress with: SELECT duck_net_set_security_warnings(false);"
        ),
    });
}

/// Warn about a protocol that has no authentication mechanism.
pub fn warn_no_auth(protocol: &'static str, code: &'static str) {
    warn(SecurityWarning {
        code,
        cwe: "CWE-306",
        severity: Severity::High,
        protocol,
        message: format!(
            "Security warning: {protocol} has no built-in authentication. \
             Data is accessible to any network client. Only use on trusted \
             networks or behind a firewall. \
             Suppress with: SELECT duck_net_set_security_warnings(false);"
        ),
    });
}

/// Warn when a bearer/API token is sent over plaintext HTTP.
pub fn warn_token_over_plaintext(protocol: &'static str, code: &'static str) {
    warn(SecurityWarning {
        code,
        cwe: "CWE-523",
        severity: Severity::Critical,
        protocol,
        message: format!(
            "Security warning: {protocol} authentication token sent over \
             plaintext HTTP. Tokens can be intercepted by network attackers. \
             Always use HTTPS when providing authentication tokens. \
             Suppress with: SELECT duck_net_set_security_warnings(false);"
        ),
    });
}

/// Warn about weak or legacy authentication mechanisms.
pub fn warn_weak_auth(protocol: &'static str, code: &'static str, detail: &str) {
    warn(SecurityWarning {
        code,
        cwe: "CWE-327",
        severity: Severity::Medium,
        protocol,
        message: format!(
            "Security warning: {protocol} uses {detail}. \
             Consider upgrading to a stronger authentication mechanism. \
             Suppress with: SELECT duck_net_set_security_warnings(false);"
        ),
    });
}

/// Warn about TOFU (Trust-On-First-Use) host key verification.
pub fn warn_tofu(protocol: &'static str, code: &'static str) {
    warn(SecurityWarning {
        code,
        cwe: "CWE-295",
        severity: Severity::Medium,
        protocol,
        message: format!(
            "Security warning: {protocol} uses Trust-On-First-Use (TOFU) for \
             host key verification. The first connection to an unknown host is \
             accepted without verification, which is vulnerable to MITM attacks. \
             Pre-populate ~/.ssh/known_hosts for production deployments. \
             Suppress with: SELECT duck_net_set_security_warnings(false);"
        ),
    });
}

/// Warn about DuckDB persistent secrets being stored unencrypted on disk.
#[allow(dead_code)]
pub fn warn_persistent_secret_unencrypted() {
    warn(SecurityWarning {
        code: "PERSISTENT_SECRET_UNENCRYPTED",
        cwe: "CWE-312",
        severity: Severity::Medium,
        protocol: "secrets",
        message: "Security warning: DuckDB persistent secrets (CREATE PERSISTENT SECRET) \
                  are stored in unencrypted binary format on disk at \
                  ~/.duckdb/stored_secrets/. Use duck_net's in-memory secrets \
                  (duck_net_add_secret) for sensitive credentials that should \
                  not persist to disk. \
                  Suppress with: SELECT duck_net_set_security_warnings(false);"
            .to_string(),
    });
}

/// Warn when an S3 endpoint uses plain HTTP instead of HTTPS.
///
/// S3 credentials (SigV4 signature) and data travel in cleartext over HTTP.
/// An attacker with network access can intercept requests and replay signatures
/// within the 15-minute SigV4 validity window (CWE-319).
pub fn warn_s3_over_http(endpoint: &str) {
    warn(SecurityWarning {
        code: "S3_OVER_HTTP",
        cwe: "CWE-319",
        severity: Severity::High,
        protocol: "s3",
        message: format!(
            "Security warning: S3 endpoint '{}' uses plain HTTP. \
             AWS SigV4 signatures and data travel unencrypted. \
             Use an https:// endpoint for all production S3 workloads. \
             Suppress with: SELECT duck_net_set_security_warnings(false);",
            endpoint
        ),
    });
}

/// Warn when an HTTP redirect downgrades from HTTPS to HTTP.
///
/// Credentials sent with the original HTTPS request (e.g., Authorization
/// headers) are NOT automatically stripped on redirect in many HTTP clients.
/// Even if stripped, the user is now communicating over an unencrypted
/// channel (CWE-319 / CWE-601).
pub fn warn_http_redirect_downgrade() {
    warn(SecurityWarning {
        code: "HTTP_REDIRECT_HTTPS_TO_HTTP",
        cwe: "CWE-319",
        severity: Severity::High,
        protocol: "http",
        message: "Security warning: HTTP redirect from HTTPS to HTTP detected. \
                  Subsequent requests and any credentials sent with them will \
                  travel over an unencrypted connection. Follow the redirect \
                  only if the destination is trusted. \
                  Suppress with: SELECT duck_net_set_security_warnings(false);"
            .to_string(),
    });
}

/// Warn when `duck_net_secret()` is called to retrieve a raw credential value.
///
/// Returning a raw credential as a SQL value means it can appear in query
/// results, logs, or DuckDB's query history (CWE-312 / CWE-532).
pub fn warn_secret_value_exposed(secret_name: &str) {
    warn(SecurityWarning {
        code: "SECRET_VALUE_EXPOSED",
        cwe: "CWE-312",
        severity: Severity::High,
        protocol: "secrets",
        message: format!(
            "Security warning: duck_net_secret('{secret_name}', ...) returned a raw \
             credential value as a SQL result. This value may appear in query logs, \
             DuckDB's query history, or query result exports. Prefer passing the \
             secret name directly to protocol functions (e.g., http_get_secret) \
             rather than extracting raw values. \
             Suppress with: SELECT duck_net_set_security_warnings(false);"
        ),
    });
}

/// Warn when a DNS lookup returns private/reserved IP addresses.
///
/// `dns_lookup()` returns whatever the DNS server answers — it does not apply
/// SSRF filtering. If the result contains a private IP, the caller may
/// inadvertently connect to an internal service (CWE-918).
pub fn warn_dns_private_result(hostname: &str, private_ips: &[String]) {
    warn(SecurityWarning {
        code: "DNS_PRIVATE_IP_RESULT",
        cwe: "CWE-918",
        severity: Severity::Medium,
        protocol: "dns",
        message: format!(
            "Security warning: DNS lookup for '{}' returned private/reserved IP address(es): {}. \
             Connecting to these addresses may reach internal network services. \
             duck_net's HTTP/SSRF protection applies to http_get/http_post etc., \
             but NOT to dns_lookup results used in application logic. \
             Suppress with: SELECT duck_net_set_security_warnings(false);",
            hostname,
            private_ips.join(", ")
        ),
    });
}

/// Warn when TLS certificate verification is disabled.
///
/// Disabling certificate verification makes all TLS connections vulnerable
/// to man-in-the-middle attacks (CWE-295).
#[allow(dead_code)]
pub fn warn_tls_verification_disabled(protocol: &'static str) {
    warn(SecurityWarning {
        code: "TLS_CERT_VERIFICATION_DISABLED",
        cwe: "CWE-295",
        severity: Severity::Critical,
        protocol,
        message: format!(
            "Security warning: TLS certificate verification is disabled for {protocol}. \
             All connections are vulnerable to man-in-the-middle attacks. \
             Only disable certificate verification for local development or testing. \
             Suppress with: SELECT duck_net_set_security_warnings(false);"
        ),
    });
}

/// Warn when a protocol uses self-signed TLS certificates.
#[allow(dead_code)]
pub fn warn_self_signed_certificate(protocol: &'static str, host: &str) {
    warn(SecurityWarning {
        code: "SELF_SIGNED_CERTIFICATE",
        cwe: "CWE-295",
        severity: Severity::Medium,
        protocol,
        message: format!(
            "Security warning: {protocol} connection to '{host}' uses a self-signed \
             TLS certificate. Verify the certificate fingerprint matches the expected \
             server. For production, use a CA-signed certificate. \
             Suppress with: SELECT duck_net_set_security_warnings(false);"
        ),
    });
}
