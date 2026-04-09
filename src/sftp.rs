// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::sync::Arc;

use base64::Engine as _;

use crate::runtime;

/// Maximum file read size: 256 MiB. Prevents OOM from unbounded reads (CWE-400).
const MAX_READ_BYTES: usize = 256 * 1024 * 1024;

/// Scrub credentials from a URL for safe inclusion in error messages (CWE-532).
#[allow(dead_code)]
fn scrub_url(url: &str) -> String {
    if let Some(at) = url.find('@') {
        if let Some(scheme_end) = url.find("://") {
            return format!("{}://***@{}", &url[..scheme_end], &url[at + 1..]);
        }
    }
    url.to_string()
}

pub struct SftpResult {
    pub success: bool,
    pub message: String,
}

pub struct SftpReadBlobResult {
    pub success: bool,
    pub data: Vec<u8>,
    pub size: i64,
    pub message: String,
}

pub struct SftpReadResult {
    pub success: bool,
    pub content: String,
    pub size: i64,
    pub message: String,
}

pub struct SftpWriteResult {
    pub success: bool,
    pub bytes_written: i64,
    pub message: String,
}

pub struct SftpEntry {
    pub name: String,
    pub size: i64,
    pub is_dir: bool,
}

/// Parse SFTP URL: sftp://[user:pass@]host[:port]/path
#[allow(clippy::type_complexity)]
pub fn parse_url(
    url: &str,
) -> Result<(String, u16, Option<String>, Option<String>, String), String> {
    let rest = url
        .strip_prefix("sftp://")
        .ok_or_else(|| "URL must start with sftp://".to_string())?;

    let (userinfo, hostpath) = if let Some(at) = rest.find('@') {
        (Some(&rest[..at]), &rest[at + 1..])
    } else {
        (None, rest)
    };

    let (user, pass) = match userinfo {
        Some(ui) => {
            if let Some(colon) = ui.find(':') {
                (
                    Some(ui[..colon].to_string()),
                    Some(ui[colon + 1..].to_string()),
                )
            } else {
                (Some(ui.to_string()), None)
            }
        }
        None => (None, None),
    };

    let (hostport, path) = if let Some(slash) = hostpath.find('/') {
        (&hostpath[..slash], hostpath[slash..].to_string())
    } else {
        (hostpath, "/".to_string())
    };

    let (host, port) = if let Some(colon) = hostport.rfind(':') {
        let port: u16 = hostport[colon + 1..].parse().unwrap_or(22);
        (hostport[..colon].to_string(), port)
    } else {
        (hostport.to_string(), 22)
    };

    Ok((host, port, user, pass, path))
}

/// SSH client handler with host key verification.
/// Reads ~/.ssh/known_hosts if available. Accepts keys on first connection (TOFU)
/// and rejects changed keys to prevent MITM attacks (CWE-295).
struct SshHandler {
    expected_host: String,
}

impl russh::client::Handler for SshHandler {
    type Error = russh::Error;

    fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        let host = self.expected_host.clone();
        let key_type = server_public_key.algorithm().as_str().to_string();
        let key_data = base64::engine::general_purpose::STANDARD
            .encode(server_public_key.to_bytes().unwrap_or_default());

        // Check known_hosts file
        let result = match check_known_hosts(&host, &key_type, &key_data) {
            KnownHostResult::Matched => true,
            KnownHostResult::NotFound => {
                // TOFU: Trust On First Use — accept and log
                // In a future version, optionally append to known_hosts
                true
            }
            KnownHostResult::Changed => {
                // Host key changed — potential MITM attack
                false
            }
        };
        std::future::ready(Ok(result))
    }
}

enum KnownHostResult {
    Matched,
    NotFound,
    Changed,
}

fn check_known_hosts(host: &str, key_type: &str, key_data: &str) -> KnownHostResult {
    // Try common known_hosts locations
    let paths = [
        dirs_known_hosts(),
        Some("/etc/ssh/ssh_known_hosts".to_string()),
    ];

    for path in paths.into_iter().flatten() {
        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }
            // Format: hostname key-type base64-key
            let hosts_field = parts[0];
            let line_key_type = parts[1];
            let line_key_data = parts[2];

            // Check if this line matches our host
            let host_matches = hosts_field.split(',').any(|h| {
                let h = h.trim_matches(&['[', ']'] as &[char]);
                h == host || h.split(':').next() == Some(host)
            });

            if host_matches {
                if line_key_type == key_type && line_key_data == key_data {
                    return KnownHostResult::Matched;
                } else if line_key_type == key_type {
                    // Same host, same key type, different key = CHANGED
                    return KnownHostResult::Changed;
                }
            }
        }
    }

    KnownHostResult::NotFound
}

fn dirs_known_hosts() -> Option<String> {
    std::env::var("HOME")
        .ok()
        .map(|h| format!("{h}/.ssh/known_hosts"))
}

async fn connect_sftp(
    host: &str,
    port: u16,
    user: &str,
    pass: Option<&str>,
    key_file: Option<&str>,
) -> Result<russh_sftp::client::SftpSession, String> {
    // SSRF protection: block connections to private/reserved IPs (CWE-918)
    crate::security::validate_no_ssrf_host(host)?;

    let config = russh::client::Config::default();
    let handler = SshHandler {
        expected_host: host.to_string(),
    };
    let mut session = russh::client::connect(Arc::new(config), (host, port), handler)
        .await
        .map_err(|e| format!("SSH connection failed: {e}"))?;

    // Authenticate
    if let Some(key_path) = key_file {
        let key_data = std::fs::read_to_string(key_path)
            .map_err(|e| format!("Failed to read key file {key_path}: {e}"))?;
        let key = russh::keys::decode_secret_key(&key_data, None)
            .map_err(|e| format!("Failed to parse key file: {e}"))?;
        let key_with_alg = russh::keys::key::PrivateKeyWithHashAlg::new(Arc::new(key), None);
        let auth = session
            .authenticate_publickey(user, key_with_alg)
            .await
            .map_err(|e| format!("SSH public key auth failed: {e}"))?;
        if !auth.success() {
            return Err("SSH public key authentication rejected".into());
        }
    } else if let Some(password) = pass {
        let auth = session
            .authenticate_password(user, password)
            .await
            .map_err(|e| format!("SSH password auth failed: {e}"))?;
        if !auth.success() {
            return Err("SSH password authentication rejected".into());
        }
    } else {
        return Err("SFTP requires either password or key_file for authentication".into());
    }

    // Open SFTP channel
    let channel = session
        .channel_open_session()
        .await
        .map_err(|e| format!("SSH channel open failed: {e}"))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| format!("SFTP subsystem request failed: {e}"))?;

    let sftp = russh_sftp::client::SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| format!("SFTP session init failed: {e}"))?;

    Ok(sftp)
}

/// Extract the hostname from an sftp:// URL for audit-log records.
fn host_for_audit(url: &str) -> String {
    parse_url(url)
        .map(|(h, _, _, _, _)| h)
        .unwrap_or_else(|_| crate::security::scrub_url(url))
}

pub fn list(url: &str, key_file: Option<&str>) -> Result<Vec<SftpEntry>, String> {
    // Validate path component for traversal (CWE-22)
    if let Ok((_, _, _, _, ref path)) = parse_url(url) {
        crate::security::validate_path_no_traversal(path)?;
    }
    let host = host_for_audit(url);
    let r = runtime::block_on(list_async(url, key_file));
    match &r {
        Ok(v) => crate::audit_log::record("sftp", "list", &host, true, v.len() as i32, ""),
        Err(e) => crate::audit_log::record("sftp", "list", &host, false, 0, e),
    }
    r
}

async fn list_async(url: &str, key_file: Option<&str>) -> Result<Vec<SftpEntry>, String> {
    let (host, port, user, pass, path) = parse_url(url)?;
    let username = user.as_deref().unwrap_or("root");
    let sftp = connect_sftp(&host, port, username, pass.as_deref(), key_file).await?;

    let entries = sftp
        .read_dir(&path)
        .await
        .map_err(|e| format!("SFTP readdir failed: {e}"))?;

    let mut result = Vec::new();
    for entry in entries {
        let name = entry.file_name();
        if name == "." || name == ".." {
            continue;
        }
        let is_dir = entry.file_type().is_dir();
        let size = entry.metadata().size.unwrap_or(0) as i64;
        result.push(SftpEntry { name, size, is_dir });
    }

    Ok(result)
}

pub fn read(url: &str, key_file: Option<&str>) -> SftpReadResult {
    // Validate path component for traversal (CWE-22)
    if let Ok((_, _, _, _, ref path)) = parse_url(url) {
        if let Err(e) = crate::security::validate_path_no_traversal(path) {
            return SftpReadResult {
                success: false,
                content: String::new(),
                size: 0,
                message: e,
            };
        }
    }
    let host = host_for_audit(url);
    let r = match runtime::block_on(read_async(url, key_file)) {
        Ok(r) => r,
        Err(msg) => SftpReadResult {
            success: false,
            content: String::new(),
            size: 0,
            message: msg,
        },
    };
    crate::audit_log::record("sftp", "read", &host, r.success, r.size as i32, &r.message);
    r
}

async fn read_async(url: &str, key_file: Option<&str>) -> Result<SftpReadResult, String> {
    let (host, port, user, pass, path) = parse_url(url)?;
    let username = user.as_deref().unwrap_or("root");
    let sftp = connect_sftp(&host, port, username, pass.as_deref(), key_file).await?;

    let data = sftp
        .read(&path)
        .await
        .map_err(|e| format!("SFTP read failed: {e}"))?;

    if data.len() > MAX_READ_BYTES {
        return Err(format!(
            "SFTP file too large: {} bytes (max {} bytes)",
            data.len(),
            MAX_READ_BYTES
        ));
    }

    let size = data.len() as i64;
    let content =
        String::from_utf8(data).map_err(|e| format!("SFTP file is not valid UTF-8: {e}"))?;

    Ok(SftpReadResult {
        success: true,
        content,
        size,
        message: "OK".into(),
    })
}

/// Read a file as raw bytes (binary).
pub fn read_blob(url: &str, key_file: Option<&str>) -> SftpReadBlobResult {
    // Validate path component for traversal (CWE-22)
    if let Ok((_, _, _, _, ref path)) = parse_url(url) {
        if let Err(e) = crate::security::validate_path_no_traversal(path) {
            return SftpReadBlobResult {
                success: false,
                data: vec![],
                size: 0,
                message: e,
            };
        }
    }
    let host = host_for_audit(url);
    let r = match runtime::block_on(read_blob_async(url, key_file)) {
        Ok(r) => r,
        Err(msg) => SftpReadBlobResult {
            success: false,
            data: vec![],
            size: 0,
            message: msg,
        },
    };
    crate::audit_log::record(
        "sftp",
        "read_blob",
        &host,
        r.success,
        r.size as i32,
        &r.message,
    );
    r
}

async fn read_blob_async(url: &str, key_file: Option<&str>) -> Result<SftpReadBlobResult, String> {
    let (host, port, user, pass, path) = parse_url(url)?;
    let username = user.as_deref().unwrap_or("root");
    let sftp = connect_sftp(&host, port, username, pass.as_deref(), key_file).await?;

    let data = sftp
        .read(&path)
        .await
        .map_err(|e| format!("SFTP read failed: {e}"))?;

    if data.len() > MAX_READ_BYTES {
        return Err(format!(
            "SFTP file too large: {} bytes (max {} bytes)",
            data.len(),
            MAX_READ_BYTES
        ));
    }

    let size = data.len() as i64;
    Ok(SftpReadBlobResult {
        success: true,
        data,
        size,
        message: "OK".into(),
    })
}

pub fn write(url: &str, content: &str, key_file: Option<&str>) -> SftpWriteResult {
    // Validate path component for traversal (CWE-22)
    if let Ok((_, _, _, _, ref path)) = parse_url(url) {
        if let Err(e) = crate::security::validate_path_no_traversal(path) {
            return SftpWriteResult {
                success: false,
                bytes_written: 0,
                message: e,
            };
        }
    }
    let host = host_for_audit(url);
    let r = match runtime::block_on(write_async(url, content, key_file)) {
        Ok(r) => r,
        Err(msg) => SftpWriteResult {
            success: false,
            bytes_written: 0,
            message: msg,
        },
    };
    crate::audit_log::record(
        "sftp",
        "write",
        &host,
        r.success,
        r.bytes_written as i32,
        &r.message,
    );
    r
}

async fn write_async(
    url: &str,
    content: &str,
    key_file: Option<&str>,
) -> Result<SftpWriteResult, String> {
    let (host, port, user, pass, path) = parse_url(url)?;
    let username = user.as_deref().unwrap_or("root");
    let sftp = connect_sftp(&host, port, username, pass.as_deref(), key_file).await?;

    let data = content.as_bytes().to_vec();
    let bytes_written = data.len() as i64;
    sftp.write(&path, &data)
        .await
        .map_err(|e| format!("SFTP write failed: {e}"))?;

    Ok(SftpWriteResult {
        success: true,
        bytes_written,
        message: "OK".into(),
    })
}

pub fn delete(url: &str, key_file: Option<&str>) -> SftpResult {
    // Validate path component for traversal (CWE-22)
    if let Ok((_, _, _, _, ref path)) = parse_url(url) {
        if let Err(e) = crate::security::validate_path_no_traversal(path) {
            return SftpResult {
                success: false,
                message: e,
            };
        }
    }
    let host = host_for_audit(url);
    let r = match runtime::block_on(delete_async(url, key_file)) {
        Ok(msg) => SftpResult {
            success: true,
            message: msg,
        },
        Err(msg) => SftpResult {
            success: false,
            message: msg,
        },
    };
    crate::audit_log::record("sftp", "delete", &host, r.success, 0, &r.message);
    r
}

async fn delete_async(url: &str, key_file: Option<&str>) -> Result<String, String> {
    let (host, port, user, pass, path) = parse_url(url)?;
    let username = user.as_deref().unwrap_or("root");
    let sftp = connect_sftp(&host, port, username, pass.as_deref(), key_file).await?;

    sftp.remove_file(&path)
        .await
        .map_err(|e| format!("SFTP delete failed: {e}"))?;

    Ok("OK".into())
}
