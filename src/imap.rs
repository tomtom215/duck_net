// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

const TIMEOUT_SECS: u64 = 30;
const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024; // 10 MiB

pub struct ImapMessage {
    pub uid: i64,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub date: String,
    pub size: i64,
}

pub struct ImapListResult {
    pub success: bool,
    pub messages: Vec<ImapMessage>,
    pub message: String,
}

pub struct ImapFetchResult {
    pub success: bool,
    pub body: String,
    pub message: String,
}

/// Parse an IMAP URL into (host, port, use_tls).
pub(crate) fn parse_imap_url(url: &str) -> Result<(String, u16, bool), String> {
    let lower = url.to_ascii_lowercase();
    let (use_tls, rest) = if lower.strip_prefix("imaps://").is_some() {
        (true, &url[8..])
    } else if lower.strip_prefix("imap://").is_some() {
        (false, &url[7..])
    } else {
        return Err("Invalid IMAP URL scheme: expected imap:// or imaps://".to_string());
    };

    let host_port = rest.split('/').next().unwrap_or(rest);
    // Strip userinfo@ if present
    let host_port = host_port
        .rsplit_once('@')
        .map(|(_, hp)| hp)
        .unwrap_or(host_port);

    let (host, port) = if let Some((h, p)) = host_port.rsplit_once(':') {
        let port = p.parse::<u16>().map_err(|e| format!("Invalid port: {e}"))?;
        (h.to_string(), port)
    } else {
        let default_port = if use_tls { 993 } else { 143 };
        (host_port.to_string(), default_port)
    };

    Ok((host, port, use_tls))
}

/// List emails from an IMAP mailbox.
pub fn list_messages(
    url: &str,
    username: &str,
    password: &str,
    mailbox: &str,
    search_criteria: &str,
    limit: i64,
) -> ImapListResult {
    match list_messages_inner(url, username, password, mailbox, search_criteria, limit) {
        Ok(messages) => {
            let count = messages.len();
            ImapListResult {
                success: true,
                messages,
                message: format!("Found {count} messages"),
            }
        }
        Err(e) => ImapListResult {
            success: false,
            messages: vec![],
            message: e,
        },
    }
}

fn list_messages_inner(
    url: &str,
    username: &str,
    password: &str,
    mailbox: &str,
    search_criteria: &str,
    limit: i64,
) -> Result<Vec<ImapMessage>, String> {
    let (host, port, use_tls) = parse_imap_url(url)?;

    // SSRF protection: block connections to private/reserved IPs (CWE-918)
    crate::security::validate_no_ssrf_host(&host)?;

    // Warn about plaintext IMAP with credentials (CWE-319)
    if !use_tls {
        crate::security_warnings::warn_plaintext("IMAP", "PLAINTEXT_IMAP", "imaps://");
    }

    let mut session = ImapSession::connect(&host, port, use_tls)?;

    // Read greeting
    session.read_response("*")?;

    // Login
    session.command(&format!(
        "LOGIN \"{}\" \"{}\"",
        imap_escape(username),
        imap_escape(password)
    ))?;

    // Select mailbox
    session.command(&format!("SELECT \"{}\"", imap_escape(mailbox)))?;

    // Search
    let criteria = if search_criteria.is_empty() {
        "ALL"
    } else {
        search_criteria
    };
    let search_resp = session.command(&format!("SEARCH {criteria}"))?;
    let uids = parse_search_response(&search_resp);

    // Limit results
    let uids: Vec<i64> = if limit > 0 {
        uids.into_iter().rev().take(limit as usize).collect()
    } else {
        uids
    };

    if uids.is_empty() {
        session.command("LOGOUT").ok();
        return Ok(vec![]);
    }

    // Fetch headers for each UID
    let uid_list: String = uids
        .iter()
        .map(|u| u.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let fetch_resp = session.command(&format!(
        "FETCH {uid_list} (RFC822.SIZE BODY[HEADER.FIELDS (FROM TO SUBJECT DATE)])"
    ))?;

    let messages = parse_fetch_response(&fetch_resp, &uids);

    session.command("LOGOUT").ok();
    Ok(messages)
}

/// Fetch a single email body by sequence number.
pub fn fetch_message(
    url: &str,
    username: &str,
    password: &str,
    mailbox: &str,
    uid: i64,
) -> ImapFetchResult {
    match fetch_message_inner(url, username, password, mailbox, uid) {
        Ok(body) => ImapFetchResult {
            success: true,
            body,
            message: "OK".to_string(),
        },
        Err(e) => ImapFetchResult {
            success: false,
            body: String::new(),
            message: e,
        },
    }
}

fn fetch_message_inner(
    url: &str,
    username: &str,
    password: &str,
    mailbox: &str,
    uid: i64,
) -> Result<String, String> {
    let (host, port, use_tls) = parse_imap_url(url)?;

    // SSRF protection: block connections to private/reserved IPs (CWE-918)
    crate::security::validate_no_ssrf_host(&host)?;

    // Warn about plaintext IMAP with credentials (CWE-319)
    if !use_tls {
        crate::security_warnings::warn_plaintext("IMAP", "PLAINTEXT_IMAP", "imaps://");
    }

    let mut session = ImapSession::connect(&host, port, use_tls)?;

    session.read_response("*")?;
    session.command(&format!(
        "LOGIN \"{}\" \"{}\"",
        imap_escape(username),
        imap_escape(password)
    ))?;
    session.command(&format!("SELECT \"{}\"", imap_escape(mailbox)))?;

    let resp = session.command(&format!("FETCH {uid} BODY[]"))?;

    session.command("LOGOUT").ok();

    // Extract body from FETCH response
    Ok(extract_fetch_body(&resp))
}

// ===== IMAP Session =====

pub(crate) enum ImapStream {
    Plain(BufReader<TcpStream>),
    Tls(Box<BufReader<StreamOwned<ClientConnection, TcpStream>>>),
}

pub(crate) struct ImapSession {
    pub(crate) stream: ImapStream,
    pub(crate) tag_counter: u32,
}

impl ImapSession {
    pub(crate) fn connect(host: &str, port: u16, use_tls: bool) -> Result<Self, String> {
        // SSRF protection: block connections to private/reserved IPs (CWE-918)
        crate::security::validate_no_ssrf_host(host)?;

        let addr = format!("{host}:{port}");
        let timeout = Duration::from_secs(TIMEOUT_SECS);

        let tcp = TcpStream::connect_timeout(
            &addr.parse().map_err(|e| format!("Invalid address: {e}"))?,
            timeout,
        )
        .map_err(|e| format!("Connection failed: {e}"))?;

        tcp.set_read_timeout(Some(timeout)).ok();
        tcp.set_write_timeout(Some(timeout)).ok();

        let stream = if use_tls {
            let mut root_store = RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            let server_name = host
                .to_string()
                .try_into()
                .map_err(|e| format!("Invalid server name: {e}"))?;
            let conn = ClientConnection::new(Arc::new(config), server_name)
                .map_err(|e| format!("TLS setup failed: {e}"))?;
            let tls_stream = StreamOwned::new(conn, tcp);
            ImapStream::Tls(Box::new(BufReader::new(tls_stream)))
        } else {
            ImapStream::Plain(BufReader::new(tcp))
        };

        Ok(ImapSession {
            stream,
            tag_counter: 0,
        })
    }

    pub(crate) fn read_response(&mut self, expected_tag: &str) -> Result<String, String> {
        let mut response = String::new();
        let mut total_bytes = 0;

        loop {
            let mut line = String::new();
            let bytes = match &mut self.stream {
                ImapStream::Plain(r) => r.read_line(&mut line),
                ImapStream::Tls(r) => r.read_line(&mut line),
            }
            .map_err(|e| format!("Read error: {e}"))?;

            if bytes == 0 {
                break;
            }
            total_bytes += bytes;
            if total_bytes > MAX_RESPONSE_BYTES {
                return Err("Response too large".to_string());
            }

            response.push_str(&line);

            // Check if this line is a tagged response or continuation
            let trimmed = line.trim();
            if expected_tag == "*" && trimmed.starts_with("* OK") {
                break;
            }
            if expected_tag != "*"
                && (trimmed.starts_with(&format!("{expected_tag} OK"))
                    || trimmed.starts_with(&format!("{expected_tag} NO"))
                    || trimmed.starts_with(&format!("{expected_tag} BAD")))
            {
                break;
            }
        }

        Ok(response)
    }

    pub(crate) fn command(&mut self, cmd: &str) -> Result<String, String> {
        self.tag_counter += 1;
        let tag = format!("A{:04}", self.tag_counter);
        let full_cmd = format!("{tag} {cmd}\r\n");

        match &mut self.stream {
            ImapStream::Plain(r) => r
                .get_mut()
                .write_all(full_cmd.as_bytes())
                .map_err(|e| format!("Write error: {e}"))?,
            ImapStream::Tls(r) => r
                .get_mut()
                .write_all(full_cmd.as_bytes())
                .map_err(|e| format!("Write error: {e}"))?,
        }

        let resp = self.read_response(&tag)?;

        // Check for error
        if resp.contains(&format!("{tag} NO")) || resp.contains(&format!("{tag} BAD")) {
            return Err(format!("IMAP command failed: {}", resp.trim()));
        }

        Ok(resp)
    }
}

pub(crate) fn imap_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn parse_search_response(resp: &str) -> Vec<i64> {
    let mut uids = Vec::new();
    for line in resp.lines() {
        if line.starts_with("* SEARCH") {
            for part in line.split_whitespace().skip(2) {
                if let Ok(uid) = part.parse::<i64>() {
                    uids.push(uid);
                }
            }
        }
    }
    uids
}

fn parse_fetch_response(resp: &str, uids: &[i64]) -> Vec<ImapMessage> {
    let mut messages = Vec::new();

    // Simple parser: split by "* N FETCH"
    let chunks: Vec<&str> = resp.split("* ").filter(|s| !s.is_empty()).collect();

    for (i, chunk) in chunks.iter().enumerate() {
        if !chunk.contains("FETCH") {
            continue;
        }

        let uid = uids.get(i).copied().unwrap_or(0);
        let size = extract_rfc822_size(chunk);
        let from = extract_header_value(chunk, "From");
        let to = extract_header_value(chunk, "To");
        let subject = extract_header_value(chunk, "Subject");
        let date = extract_header_value(chunk, "Date");

        messages.push(ImapMessage {
            uid,
            from,
            to,
            subject,
            date,
            size,
        });
    }

    messages
}

fn extract_rfc822_size(chunk: &str) -> i64 {
    if let Some(pos) = chunk.find("RFC822.SIZE") {
        let rest = &chunk[pos + 11..];
        let rest = rest.trim_start();
        let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        num_str.parse().unwrap_or(0)
    } else {
        0
    }
}

fn extract_header_value(chunk: &str, header: &str) -> String {
    let needle = format!("{header}: ");
    for line in chunk.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(&needle) {
            return rest.to_string();
        }
        // Case-insensitive
        if trimmed.len() >= needle.len() && trimmed[..needle.len()].eq_ignore_ascii_case(&needle) {
            return trimmed[needle.len()..].to_string();
        }
    }
    String::new()
}

fn extract_fetch_body(resp: &str) -> String {
    // Look for the literal marker {NNN} then grab NNN bytes
    if let Some(pos) = resp.find('{') {
        let rest = &resp[pos + 1..];
        if let Some(end) = rest.find('}') {
            let size_str = &rest[..end];
            if let Ok(size) = size_str.parse::<usize>() {
                // After }\r\n comes the body
                let after_marker = &rest[end + 1..];
                let body_start = if after_marker.starts_with("\r\n") {
                    2
                } else if after_marker.starts_with('\n') {
                    1
                } else {
                    0
                };
                let body = &after_marker[body_start..];
                return body[..body.len().min(size)].to_string();
            }
        }
    }
    resp.to_string()
}
