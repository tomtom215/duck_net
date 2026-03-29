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
    let mut store = WARNINGS.lock().unwrap();
    if store.is_none() {
        *store = Some(WarningStore {
            seen: HashSet::new(),
            entries: Vec::new(),
        });
    }
}

/// Emit a security warning (deduped by code). Returns the message if new.
pub fn warn(warning: SecurityWarning) -> Option<String> {
    if !warnings_enabled() {
        return None;
    }

    let mut store = WARNINGS.lock().unwrap();
    let ws = store.as_mut()?;

    if ws.seen.contains(warning.code) {
        return None;
    }

    ws.seen.insert(warning.code);
    let msg = warning.message.clone();
    ws.entries.push(warning);
    Some(msg)
}

/// Retrieve all warnings emitted this session.
pub fn list_warnings() -> Vec<SecurityWarning> {
    let store = WARNINGS.lock().unwrap();
    match store.as_ref() {
        Some(ws) => ws.entries.clone(),
        None => Vec::new(),
    }
}

/// Clear all accumulated warnings.
pub fn clear_warnings() -> usize {
    let mut store = WARNINGS.lock().unwrap();
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
