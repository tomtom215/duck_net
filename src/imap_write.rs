// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use crate::imap::{imap_escape, parse_imap_url, ImapSession};

fn host_for_audit(url: &str) -> String {
    parse_imap_url(url)
        .map(|(h, _, _)| h)
        .unwrap_or_else(|_| crate::security::scrub_url(url))
}

pub struct ImapWriteResult {
    pub success: bool,
    pub message: String,
}

/// Validate flags string for IMAP STORE commands.
/// Rejects null bytes, CRLF injection, and overly long values.
fn validate_flags(flags: &str) -> Result<(), String> {
    if flags.is_empty() {
        return Err("Flags must not be empty".to_string());
    }
    if flags.len() > 1024 {
        return Err("Flags string too long (max 1024 characters)".to_string());
    }
    if flags.contains('\0') {
        return Err("Flags must not contain null bytes".to_string());
    }
    if flags.contains('\r') || flags.contains('\n') {
        return Err("Flags must not contain CR or LF characters".to_string());
    }
    Ok(())
}

/// Move a message from one mailbox to another.
/// Tries the MOVE command first, falls back to COPY + STORE + EXPUNGE.
pub fn move_message(
    url: &str,
    username: &str,
    password: &str,
    mailbox: &str,
    uid: i64,
    dest_mailbox: &str,
) -> ImapWriteResult {
    let host = host_for_audit(url);
    let r = match move_message_inner(url, username, password, mailbox, uid, dest_mailbox) {
        Ok(msg) => ImapWriteResult {
            success: true,
            message: msg,
        },
        Err(e) => ImapWriteResult {
            success: false,
            message: e,
        },
    };
    crate::audit_log::record("imap", "move", &host, r.success, 0, &r.message);
    r
}

fn move_message_inner(
    url: &str,
    username: &str,
    password: &str,
    mailbox: &str,
    uid: i64,
    dest_mailbox: &str,
) -> Result<String, String> {
    if uid <= 0 {
        return Err("UID must be greater than 0".to_string());
    }
    if mailbox.is_empty() {
        return Err("Mailbox must not be empty".to_string());
    }
    if dest_mailbox.is_empty() {
        return Err("Destination mailbox must not be empty".to_string());
    }

    let (host, port, use_tls) = parse_imap_url(url)?;
    let mut session = ImapSession::connect(&host, port, use_tls)?;
    session.read_response("*")?;
    session.command(&format!(
        "LOGIN \"{}\" \"{}\"",
        imap_escape(username),
        imap_escape(password)
    ))?;
    session.command(&format!("SELECT \"{}\"", imap_escape(mailbox)))?;

    // Try MOVE first
    let move_result = session.command(&format!("MOVE {uid} \"{}\"", imap_escape(dest_mailbox)));

    if move_result.is_err() {
        // Fall back to COPY + STORE \Deleted + EXPUNGE
        session.command(&format!("COPY {uid} \"{}\"", imap_escape(dest_mailbox)))?;
        session.command(&format!("STORE {uid} +FLAGS (\\Deleted)"))?;
        session.command("EXPUNGE")?;
    }

    session.command("LOGOUT").ok();
    Ok(format!("Message {uid} moved to {dest_mailbox}"))
}

/// Delete a message by marking it as \Deleted and expunging.
pub fn delete_message(
    url: &str,
    username: &str,
    password: &str,
    mailbox: &str,
    uid: i64,
) -> ImapWriteResult {
    let host = host_for_audit(url);
    let r = match delete_message_inner(url, username, password, mailbox, uid) {
        Ok(msg) => ImapWriteResult {
            success: true,
            message: msg,
        },
        Err(e) => ImapWriteResult {
            success: false,
            message: e,
        },
    };
    crate::audit_log::record("imap", "delete", &host, r.success, 0, &r.message);
    r
}

fn delete_message_inner(
    url: &str,
    username: &str,
    password: &str,
    mailbox: &str,
    uid: i64,
) -> Result<String, String> {
    if uid <= 0 {
        return Err("UID must be greater than 0".to_string());
    }
    if mailbox.is_empty() {
        return Err("Mailbox must not be empty".to_string());
    }

    let (host, port, use_tls) = parse_imap_url(url)?;
    let mut session = ImapSession::connect(&host, port, use_tls)?;
    session.read_response("*")?;
    session.command(&format!(
        "LOGIN \"{}\" \"{}\"",
        imap_escape(username),
        imap_escape(password)
    ))?;
    session.command(&format!("SELECT \"{}\"", imap_escape(mailbox)))?;

    session.command(&format!("STORE {uid} +FLAGS (\\Deleted)"))?;
    session.command("EXPUNGE")?;

    session.command("LOGOUT").ok();
    Ok(format!("Message {uid} deleted"))
}

/// Set flags on a message.
/// The `flags` parameter is a space-separated list of IMAP flags,
/// e.g. `\Seen \Flagged` or custom flags.
pub fn flag_message(
    url: &str,
    username: &str,
    password: &str,
    mailbox: &str,
    uid: i64,
    flags: &str,
) -> ImapWriteResult {
    let host = host_for_audit(url);
    let r = match flag_message_inner(url, username, password, mailbox, uid, flags) {
        Ok(msg) => ImapWriteResult {
            success: true,
            message: msg,
        },
        Err(e) => ImapWriteResult {
            success: false,
            message: e,
        },
    };
    crate::audit_log::record("imap", "flag", &host, r.success, 0, &r.message);
    r
}

fn flag_message_inner(
    url: &str,
    username: &str,
    password: &str,
    mailbox: &str,
    uid: i64,
    flags: &str,
) -> Result<String, String> {
    if uid <= 0 {
        return Err("UID must be greater than 0".to_string());
    }
    if mailbox.is_empty() {
        return Err("Mailbox must not be empty".to_string());
    }
    validate_flags(flags)?;

    let (host, port, use_tls) = parse_imap_url(url)?;
    let mut session = ImapSession::connect(&host, port, use_tls)?;
    session.read_response("*")?;
    session.command(&format!(
        "LOGIN \"{}\" \"{}\"",
        imap_escape(username),
        imap_escape(password)
    ))?;
    session.command(&format!("SELECT \"{}\"", imap_escape(mailbox)))?;

    session.command(&format!("STORE {uid} +FLAGS ({flags})"))?;

    session.command("LOGOUT").ok();
    Ok(format!("Flags ({flags}) set on message {uid}"))
}
