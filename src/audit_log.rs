// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

//! Audit logging subsystem for duck_net.
//!
//! Records every outbound network operation with enough context for a security
//! review to answer: *who made what call, to which host, when, and did it
//! succeed?*  Credentials are never logged — only the protocol, host, operation
//! name, outcome, and a sanitised message.
//!
//! # Design
//! - **Disabled by default** — zero overhead when not needed.
//! - **Bounded ring buffer** — at most `MAX_ENTRIES` entries; oldest entry
//!   dropped when the buffer is full, preventing unbounded memory growth.
//! - **No credential logging** — the `message` field passes through
//!   `security::scrub_error` before storage.
//! - **Queryable** — `duck_net_audit_log()` table function returns all entries.
//! - **Clearable** — `duck_net_clear_audit_log()` empties the ring buffer.
//!
//! # Usage
//! ```sql
//! SELECT duck_net_set_audit_logging(true);
//! SELECT * FROM duck_net_audit_log();
//! SELECT duck_net_clear_audit_log();
//! ```

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Global flag: when true, network operations are logged to the audit buffer.
static AUDIT_ENABLED: AtomicBool = AtomicBool::new(false);

/// Maximum number of entries retained in the ring buffer.
/// Old entries are evicted when the limit is reached (CWE-400).
const MAX_ENTRIES: usize = 10_000;

/// A single audit log entry.
#[derive(Clone)]
pub struct AuditEntry {
    /// Unix timestamp (seconds since epoch) when the operation was initiated.
    pub timestamp_secs: i64,
    /// ISO 8601 wall-clock timestamp for display.
    pub timestamp_iso: String,
    /// Protocol name, e.g. "http", "ssh", "smtp".
    pub protocol: String,
    /// Operation name, e.g. "GET", "exec", "send".
    pub operation: String,
    /// Target host (hostname or IP).  Port appended as `:port` when non-default.
    pub host: String,
    /// `true` = operation completed without error.
    pub success: bool,
    /// HTTP status code or exit code where applicable; 0 otherwise.
    pub status_code: i32,
    /// Scrubbed error message (credentials removed).  Empty on success.
    pub message: String,
}

static AUDIT_LOG: Mutex<Option<VecDeque<AuditEntry>>> = Mutex::new(None);

/// Enable or disable audit logging.
pub fn set_enabled(enabled: bool) {
    AUDIT_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Check whether audit logging is currently enabled.
pub fn is_enabled() -> bool {
    AUDIT_ENABLED.load(Ordering::Relaxed)
}

/// Initialise the audit log ring buffer.  Called once from `register_all`.
pub fn init() {
    let mut guard = AUDIT_LOG.lock().unwrap_or_else(|p| p.into_inner());
    if guard.is_none() {
        *guard = Some(VecDeque::with_capacity(256));
    }
}

/// Record one audit entry.
///
/// No-ops when audit logging is disabled, keeping the hot path zero-cost.
/// The `message` is scrubbed of credentials before storage.
pub fn record(
    protocol: &str,
    operation: &str,
    host: &str,
    success: bool,
    status_code: i32,
    message: &str,
) {
    if !is_enabled() {
        return;
    }

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let timestamp_iso = format_iso8601(now_secs);

    // Scrub credentials from error messages before persisting (CWE-532).
    let safe_message = crate::security::scrub_error(message);

    let entry = AuditEntry {
        timestamp_secs: now_secs,
        timestamp_iso,
        protocol: protocol.to_string(),
        operation: operation.to_string(),
        host: host.to_string(),
        success,
        status_code,
        message: safe_message,
    };

    let mut guard = AUDIT_LOG.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(ref mut deque) = *guard {
        if deque.len() >= MAX_ENTRIES {
            deque.pop_front(); // evict oldest
        }
        deque.push_back(entry);
    }
}

/// Return a snapshot of all audit entries in chronological order.
pub fn entries() -> Vec<AuditEntry> {
    let guard = AUDIT_LOG.lock().unwrap_or_else(|p| p.into_inner());
    match *guard {
        Some(ref deque) => deque.iter().cloned().collect(),
        None => Vec::new(),
    }
}

/// Clear all audit entries.  Returns the number of entries cleared.
pub fn clear() -> usize {
    let mut guard = AUDIT_LOG.lock().unwrap_or_else(|p| p.into_inner());
    match *guard {
        Some(ref mut deque) => {
            let count = deque.len();
            deque.clear();
            count
        }
        None => 0,
    }
}

/// Return the total number of entries currently stored.
pub fn len() -> usize {
    let guard = AUDIT_LOG.lock().unwrap_or_else(|p| p.into_inner());
    match *guard {
        Some(ref deque) => deque.len(),
        None => 0,
    }
}

/// Format a Unix timestamp as a minimal ISO 8601 UTC string.
/// Example: "2026-03-31T14:05:22Z"
fn format_iso8601(secs: i64) -> String {
    // Manual implementation — avoids pulling in chrono for a simple conversion.
    const SECS_PER_MIN: i64 = 60;
    const SECS_PER_HOUR: i64 = 3600;
    const SECS_PER_DAY: i64 = 86_400;

    let days_since_epoch = secs / SECS_PER_DAY;
    let time_of_day = secs % SECS_PER_DAY;

    let hour = time_of_day / SECS_PER_HOUR;
    let minute = (time_of_day % SECS_PER_HOUR) / SECS_PER_MIN;
    let second = time_of_day % SECS_PER_MIN;

    // Gregorian calendar calculation from days since 1970-01-01.
    let (year, month, day) = days_to_ymd(days_since_epoch);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

fn days_to_ymd(mut days: i64) -> (i64, u32, u32) {
    // Algorithm: civil_from_days (Howard Hinnant, public domain).
    days += 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let doe = (days - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
