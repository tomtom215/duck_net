use std::sync::Arc;

use crate::runtime;

pub struct SftpResult {
    pub success: bool,
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
pub fn parse_url(url: &str) -> Result<(String, u16, Option<String>, Option<String>, String), String> {
    let rest = url.strip_prefix("sftp://")
        .ok_or_else(|| "URL must start with sftp://".to_string())?;

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
        let port: u16 = hostport[colon + 1..].parse().unwrap_or(22);
        (hostport[..colon].to_string(), port)
    } else {
        (hostport.to_string(), 22)
    };

    Ok((host, port, user, pass, path))
}

/// SSH client handler that accepts all host keys.
struct SshHandler;

impl russh::client::Handler for SshHandler {
    type Error = russh::Error;

    fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        std::future::ready(Ok(true))
    }
}

async fn connect_sftp(
    host: &str,
    port: u16,
    user: &str,
    pass: Option<&str>,
    key_file: Option<&str>,
) -> Result<russh_sftp::client::SftpSession, String> {
    let config = russh::client::Config::default();
    let mut session = russh::client::connect(
        Arc::new(config),
        (host, port),
        SshHandler,
    ).await.map_err(|e| format!("SSH connection failed: {e}"))?;

    // Authenticate
    if let Some(key_path) = key_file {
        let key_data = std::fs::read_to_string(key_path)
            .map_err(|e| format!("Failed to read key file {key_path}: {e}"))?;
        let key = russh::keys::decode_secret_key(&key_data, None)
            .map_err(|e| format!("Failed to parse key file: {e}"))?;
        let key_with_alg = russh::keys::key::PrivateKeyWithHashAlg::new(Arc::new(key), None);
        let auth = session.authenticate_publickey(user, key_with_alg).await
            .map_err(|e| format!("SSH public key auth failed: {e}"))?;
        if !auth.success() {
            return Err("SSH public key authentication rejected".into());
        }
    } else if let Some(password) = pass {
        let auth = session.authenticate_password(user, password).await
            .map_err(|e| format!("SSH password auth failed: {e}"))?;
        if !auth.success() {
            return Err("SSH password authentication rejected".into());
        }
    } else {
        return Err("SFTP requires either password or key_file for authentication".into());
    }

    // Open SFTP channel
    let channel = session.channel_open_session().await
        .map_err(|e| format!("SSH channel open failed: {e}"))?;
    channel.request_subsystem(true, "sftp").await
        .map_err(|e| format!("SFTP subsystem request failed: {e}"))?;

    let sftp = russh_sftp::client::SftpSession::new(channel.into_stream()).await
        .map_err(|e| format!("SFTP session init failed: {e}"))?;

    Ok(sftp)
}

pub fn list(url: &str, key_file: Option<&str>) -> Result<Vec<SftpEntry>, String> {
    runtime::block_on(list_async(url, key_file))
}

async fn list_async(url: &str, key_file: Option<&str>) -> Result<Vec<SftpEntry>, String> {
    let (host, port, user, pass, path) = parse_url(url)?;
    let username = user.as_deref().unwrap_or("root");
    let sftp = connect_sftp(&host, port, username, pass.as_deref(), key_file).await?;

    let entries = sftp.read_dir(&path).await
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
    match runtime::block_on(read_async(url, key_file)) {
        Ok(r) => r,
        Err(msg) => SftpReadResult { success: false, content: String::new(), size: 0, message: msg },
    }
}

async fn read_async(url: &str, key_file: Option<&str>) -> Result<SftpReadResult, String> {
    let (host, port, user, pass, path) = parse_url(url)?;
    let username = user.as_deref().unwrap_or("root");
    let sftp = connect_sftp(&host, port, username, pass.as_deref(), key_file).await?;

    let data = sftp.read(&path).await
        .map_err(|e| format!("SFTP read failed: {e}"))?;

    let size = data.len() as i64;
    let content = String::from_utf8(data)
        .map_err(|e| format!("SFTP file is not valid UTF-8: {e}"))?;

    Ok(SftpReadResult { success: true, content, size, message: "OK".into() })
}

pub fn write(url: &str, content: &str, key_file: Option<&str>) -> SftpWriteResult {
    match runtime::block_on(write_async(url, content, key_file)) {
        Ok(r) => r,
        Err(msg) => SftpWriteResult { success: false, bytes_written: 0, message: msg },
    }
}

async fn write_async(url: &str, content: &str, key_file: Option<&str>) -> Result<SftpWriteResult, String> {
    let (host, port, user, pass, path) = parse_url(url)?;
    let username = user.as_deref().unwrap_or("root");
    let sftp = connect_sftp(&host, port, username, pass.as_deref(), key_file).await?;

    let data = content.as_bytes().to_vec();
    let bytes_written = data.len() as i64;
    sftp.write(&path, &data).await
        .map_err(|e| format!("SFTP write failed: {e}"))?;

    Ok(SftpWriteResult { success: true, bytes_written, message: "OK".into() })
}

pub fn delete(url: &str, key_file: Option<&str>) -> SftpResult {
    match runtime::block_on(delete_async(url, key_file)) {
        Ok(msg) => SftpResult { success: true, message: msg },
        Err(msg) => SftpResult { success: false, message: msg },
    }
}

async fn delete_async(url: &str, key_file: Option<&str>) -> Result<String, String> {
    let (host, port, user, pass, path) = parse_url(url)?;
    let username = user.as_deref().unwrap_or("root");
    let sftp = connect_sftp(&host, port, username, pass.as_deref(), key_file).await?;

    sftp.remove_file(&path).await
        .map_err(|e| format!("SFTP delete failed: {e}"))?;

    Ok("OK".into())
}
