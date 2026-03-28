use suppaftp::FtpStream;

/// Scrub credentials from a URL for safe inclusion in error messages (CWE-532).
fn scrub_url(url: &str) -> String {
    if let Some(at) = url.find('@') {
        if let Some(scheme_end) = url.find("://") {
            return format!("{}://***@{}", &url[..scheme_end], &url[at + 1..]);
        }
    }
    url.to_string()
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
pub fn parse_url(url: &str) -> Result<(String, u16, Option<String>, Option<String>, String), String> {
    let rest = url.strip_prefix("ftp://")
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
                (Some(ui[..colon].to_string()), Some(ui[colon + 1..].to_string()))
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

fn connect_and_login(url: &str) -> Result<(FtpStream, String), String> {
    let (host, port, user, pass, path) = parse_url(url)?;
    let addr = format!("{host}:{port}");
    let mut ftp = FtpStream::connect(&addr)
        .map_err(|e| format!("FTP connection failed to {}: {e}", scrub_url(url)))?;

    let username = user.as_deref().unwrap_or("anonymous");
    let password = pass.as_deref().unwrap_or("duck_net@");
    ftp.login(username, password)
        .map_err(|e| format!("FTP login failed: {e}"))?;

    Ok((ftp, path))
}

pub fn list(url: &str) -> Result<Vec<FtpEntry>, String> {
    let (mut ftp, path) = connect_and_login(url)?;

    let listing = ftp.list(Some(&path))
        .map_err(|e| format!("FTP list failed: {e}"))?;

    let mut entries = Vec::new();
    for line in &listing {
        if let Some(entry) = parse_list_line(line) {
            entries.push(entry);
        }
    }

    ftp.quit().ok();
    Ok(entries)
}

pub fn read(url: &str) -> FtpReadResult {
    match read_inner(url) {
        Ok(r) => r,
        Err(msg) => FtpReadResult { success: false, content: String::new(), size: 0, message: msg },
    }
}

fn read_inner(url: &str) -> Result<FtpReadResult, String> {
    let (mut ftp, path) = connect_and_login(url)?;

    let data = ftp.retr_as_buffer(&path)
        .map_err(|e| format!("FTP read failed: {e}"))?;

    let buf = data.into_inner();
    let size = buf.len() as i64;
    let content = String::from_utf8(buf)
        .map_err(|e| format!("FTP file is not valid UTF-8: {e}"))?;

    ftp.quit().ok();
    Ok(FtpReadResult { success: true, content, size, message: "OK".into() })
}

pub fn write(url: &str, content: &str) -> FtpWriteResult {
    match write_inner(url, content) {
        Ok(r) => r,
        Err(msg) => FtpWriteResult { success: false, bytes_written: 0, message: msg },
    }
}

fn write_inner(url: &str, content: &str) -> Result<FtpWriteResult, String> {
    let (mut ftp, path) = connect_and_login(url)?;

    let data = content.as_bytes();
    let mut cursor = std::io::Cursor::new(data);
    ftp.put_file(&path, &mut cursor)
        .map_err(|e| format!("FTP write failed: {e}"))?;

    let bytes_written = data.len() as i64;
    ftp.quit().ok();
    Ok(FtpWriteResult { success: true, bytes_written, message: "OK".into() })
}

pub fn delete(url: &str) -> FtpResult {
    match delete_inner(url) {
        Ok(msg) => FtpResult { success: true, message: msg },
        Err(msg) => FtpResult { success: false, message: msg },
    }
}

fn delete_inner(url: &str) -> Result<String, String> {
    let (mut ftp, path) = connect_and_login(url)?;

    ftp.rm(&path)
        .map_err(|e| format!("FTP delete failed: {e}"))?;

    ftp.quit().ok();
    Ok("OK".into())
}

/// Parse a Unix-style FTP LIST line.
fn parse_list_line(line: &str) -> Option<FtpEntry> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 9 {
        // Try simple format: just a filename
        if parts.len() == 1 {
            return Some(FtpEntry { name: parts[0].to_string(), size: -1, is_dir: false });
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
