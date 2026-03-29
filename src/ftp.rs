// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use suppaftp::FtpStream;

use crate::ftp_cache;

/// Scrub credentials from a URL for safe inclusion in error messages (CWE-532).
fn scrub_url(url: &str) -> String {
    if let Some(at) = url.find('@') {
        if let Some(scheme_end) = url.find("://") {
            return format!("{}://***@{}", &url[..scheme_end], &url[at + 1..]);
        }
    }
    url.to_string()
}

/// Binary read result (for ftp_read_blob).
pub struct FtpReadBlobResult {
    pub success: bool,
    pub data: Vec<u8>,
    pub size: i64,
    pub message: String,
}

pub struct FtpResult {
    pub success: bool,
    pub message: String,
}

pub struct FtpReadResult {
    pub success: bool,
    pub content: String,
    pub size: i64,
    pub message: String,
}

pub struct FtpWriteResult {
    pub success: bool,
    pub bytes_written: i64,
    pub message: String,
}

pub struct FtpEntry {
    pub name: String,
    pub size: i64,
    pub is_dir: bool,
}

/// Parse FTP URL: ftp://[user:pass@]host[:port]/path
#[allow(clippy::type_complexity)]
pub fn parse_url(
    url: &str,
) -> Result<(String, u16, Option<String>, Option<String>, String), String> {
    let rest = url
        .strip_prefix("ftp://")
        .or_else(|| url.strip_prefix("ftps://"))
        .ok_or_else(|| "URL must start with ftp:// or ftps://".to_string())?;

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
        let port: u16 = hostport[colon + 1..].parse().unwrap_or(21);
        (hostport[..colon].to_string(), port)
    } else {
        (hostport.to_string(), 21)
    };

    Ok((host, port, user, pass, path))
}

/// Parsed FTP connection details for cache return.
struct FtpConn {
    stream: FtpStream,
    host: String,
    port: u16,
    username: String,
    path: String,
}

/// Maximum file read size: 256 MiB. Prevents OOM from unbounded reads (CWE-400).
const MAX_READ_BYTES: usize = 256 * 1024 * 1024;

fn connect_and_login(url: &str) -> Result<FtpConn, String> {
    let (host, port, user, pass, path) = parse_url(url)?;

    // SSRF protection: block connections to private/reserved IPs (CWE-918)
    crate::security::validate_no_ssrf_host(&host)?;
    // Path traversal prevention (CWE-22)
    crate::security::validate_path_no_traversal(&path)?;

    let username = user.unwrap_or_else(|| "anonymous".to_string());
    let password = pass.unwrap_or_else(|| "duck_net@".to_string());

    let stream = ftp_cache::get_or_connect(&host, port, &username, &password)
        .map_err(|e| format!("{} ({})", e, scrub_url(url)))?;

    Ok(FtpConn {
        stream,
        host,
        port,
        username,
        path,
    })
}

impl FtpConn {
    fn return_to_cache(self) {
        ftp_cache::return_to_cache(&self.host, self.port, &self.username, self.stream);
    }
}

pub fn list(url: &str) -> Result<Vec<FtpEntry>, String> {
    let mut conn = connect_and_login(url)?;

    let listing = conn
        .stream
        .list(Some(&conn.path))
        .map_err(|e| format!("FTP list failed: {e}"))?;

    let mut entries = Vec::new();
    for line in &listing {
        if let Some(entry) = parse_list_line(line) {
            entries.push(entry);
        }
    }

    conn.return_to_cache();
    Ok(entries)
}

pub fn read(url: &str) -> FtpReadResult {
    match read_inner(url) {
        Ok(r) => r,
        Err(msg) => FtpReadResult {
            success: false,
            content: String::new(),
            size: 0,
            message: msg,
        },
    }
}

fn read_inner(url: &str) -> Result<FtpReadResult, String> {
    let mut conn = connect_and_login(url)?;

    let data = conn
        .stream
        .retr_as_buffer(&conn.path)
        .map_err(|e| format!("FTP read failed: {e}"))?;

    let buf = data.into_inner();
    if buf.len() > MAX_READ_BYTES {
        conn.return_to_cache();
        return Err(format!(
            "FTP file too large: {} bytes (max {} bytes)",
            buf.len(),
            MAX_READ_BYTES
        ));
    }
    let size = buf.len() as i64;
    let content =
        String::from_utf8(buf).map_err(|e| format!("FTP file is not valid UTF-8: {e}"))?;

    conn.return_to_cache();
    Ok(FtpReadResult {
        success: true,
        content,
        size,
        message: "OK".into(),
    })
}

/// Read a file as raw bytes (binary).
pub fn read_blob(url: &str) -> FtpReadBlobResult {
    match read_blob_inner(url) {
        Ok(r) => r,
        Err(msg) => FtpReadBlobResult {
            success: false,
            data: vec![],
            size: 0,
            message: msg,
        },
    }
}

fn read_blob_inner(url: &str) -> Result<FtpReadBlobResult, String> {
    let mut conn = connect_and_login(url)?;

    let data = conn
        .stream
        .retr_as_buffer(&conn.path)
        .map_err(|e| format!("FTP read failed: {e}"))?;

    let buf = data.into_inner();
    if buf.len() > MAX_READ_BYTES {
        conn.return_to_cache();
        return Err(format!(
            "FTP file too large: {} bytes (max {} bytes)",
            buf.len(),
            MAX_READ_BYTES
        ));
    }
    let size = buf.len() as i64;
    conn.return_to_cache();
    Ok(FtpReadBlobResult {
        success: true,
        data: buf,
        size,
        message: "OK".into(),
    })
}

pub fn write(url: &str, content: &str) -> FtpWriteResult {
    match write_inner(url, content) {
        Ok(r) => r,
        Err(msg) => FtpWriteResult {
            success: false,
            bytes_written: 0,
            message: msg,
        },
    }
}

fn write_inner(url: &str, content: &str) -> Result<FtpWriteResult, String> {
    let mut conn = connect_and_login(url)?;

    let data = content.as_bytes();
    let mut cursor = std::io::Cursor::new(data);
    conn.stream
        .put_file(&conn.path, &mut cursor)
        .map_err(|e| format!("FTP write failed: {e}"))?;

    let bytes_written = data.len() as i64;
    conn.return_to_cache();
    Ok(FtpWriteResult {
        success: true,
        bytes_written,
        message: "OK".into(),
    })
}

pub fn delete(url: &str) -> FtpResult {
    match delete_inner(url) {
        Ok(msg) => FtpResult {
            success: true,
            message: msg,
        },
        Err(msg) => FtpResult {
            success: false,
            message: msg,
        },
    }
}

fn delete_inner(url: &str) -> Result<String, String> {
    let mut conn = connect_and_login(url)?;

    conn.stream
        .rm(&conn.path)
        .map_err(|e| format!("FTP delete failed: {e}"))?;

    conn.return_to_cache();
    Ok("OK".into())
}

/// Parse a Unix-style FTP LIST line.
fn parse_list_line(line: &str) -> Option<FtpEntry> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 9 {
        // Try simple format: just a filename
        if parts.len() == 1 {
            return Some(FtpEntry {
                name: parts[0].to_string(),
                size: -1,
                is_dir: false,
            });
        }
        return None;
    }

    let perms = parts[0];
    let is_dir = perms.starts_with('d');
    let size: i64 = parts[4].parse().unwrap_or(-1);
    let name = parts[8..].join(" ");

    // Skip . and ..
    if name == "." || name == ".." {
        return None;
    }

    Some(FtpEntry { name, size, is_dir })
}
