// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::sync::Arc;

use base64::Engine as _;

use crate::runtime;

/// Maximum command output size: 64 MiB per stream.
/// Prevents OOM from unbounded output buffering (CWE-400).
const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

/// SSH command execution timeout in seconds.
const DEFAULT_TIMEOUT_SECS: u64 = 30;

pub struct SshExecResult {
    pub success: bool,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Validate SSH hostname to prevent injection (CWE-78).
/// Allows alphanumeric, dots, hyphens, colons (IPv6), and brackets.
fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
}

/// Validate username: alphanumeric, underscore, hyphen, dot only.
fn is_valid_user(user: &str) -> bool {
    if user.is_empty() || user.len() > 64 {
        return false;
    }
    user.chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Execute a command on a remote host via SSH.
///
/// Authenticates with a private key file (PEM/OpenSSH format).
/// Validates all inputs before establishing connection.
///
/// Security: Host key verification via known_hosts (TOFU model).
/// Rejects changed host keys to prevent MITM attacks (CWE-295).
pub fn exec(host: &str, port: u16, user: &str, key_file: &str, command: &str) -> SshExecResult {
    if !is_valid_host(host) {
        return SshExecResult {
            success: false,
            exit_code: -1,
            stdout: String::new(),
            stderr: "Invalid hostname: contains disallowed characters".to_string(),
        };
    }

    if !is_valid_user(user) {
        return SshExecResult {
            success: false,
            exit_code: -1,
            stdout: String::new(),
            stderr: "Invalid username: contains disallowed characters".to_string(),
        };
    }

    // Validate command for injection attacks (CWE-78)
    if let Err(e) =
        crate::security::validate_ssh_command(command, crate::security::ssh_strict_commands())
    {
        return SshExecResult {
            success: false,
            exit_code: -1,
            stdout: String::new(),
            stderr: e,
        };
    }

    if port == 0 {
        return SshExecResult {
            success: false,
            exit_code: -1,
            stdout: String::new(),
            stderr: "Invalid port: 0".to_string(),
        };
    }

    runtime::block_on(exec_async(host, port, user, key_file, command))
}

/// Execute a command via SSH with password authentication.
pub fn exec_password(
    host: &str,
    port: u16,
    user: &str,
    password: &str,
    command: &str,
) -> SshExecResult {
    if !is_valid_host(host) {
        return SshExecResult {
            success: false,
            exit_code: -1,
            stdout: String::new(),
            stderr: "Invalid hostname: contains disallowed characters".to_string(),
        };
    }

    if !is_valid_user(user) {
        return SshExecResult {
            success: false,
            exit_code: -1,
            stdout: String::new(),
            stderr: "Invalid username: contains disallowed characters".to_string(),
        };
    }

    // Validate command for injection attacks (CWE-78)
    if let Err(e) =
        crate::security::validate_ssh_command(command, crate::security::ssh_strict_commands())
    {
        return SshExecResult {
            success: false,
            exit_code: -1,
            stdout: String::new(),
            stderr: e,
        };
    }

    if port == 0 {
        return SshExecResult {
            success: false,
            exit_code: -1,
            stdout: String::new(),
            stderr: "Invalid port: 0".to_string(),
        };
    }

    runtime::block_on(exec_password_async(host, port, user, password, command))
}

/// SSH client handler with host key verification.
/// Reads ~/.ssh/known_hosts. Accepts keys on first use (TOFU).
/// Rejects changed keys to prevent MITM attacks (CWE-295).
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

        let result = match check_known_hosts(&host, &key_type, &key_data) {
            KnownHostResult::Matched => true,
            KnownHostResult::NotFound => true, // TOFU
            KnownHostResult::Changed => false, // Potential MITM
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
            let hosts_field = parts[0];
            let line_key_type = parts[1];
            let line_key_data = parts[2];

            let host_matches = hosts_field.split(',').any(|h| {
                let h = h.trim_matches(&['[', ']'] as &[char]);
                h == host || h.split(':').next() == Some(host)
            });

            if host_matches {
                if line_key_type == key_type && line_key_data == key_data {
                    return KnownHostResult::Matched;
                } else if line_key_type == key_type {
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

async fn connect_ssh(
    host: &str,
    port: u16,
    user: &str,
    auth: SshAuth<'_>,
) -> Result<russh::client::Handle<SshHandler>, String> {
    // SSRF protection: block connections to private/reserved IPs (CWE-918)
    crate::security::validate_no_ssrf_host(host)?;

    let config = russh::client::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS)),
        ..Default::default()
    };
    let handler = SshHandler {
        expected_host: host.to_string(),
    };

    let mut session = russh::client::connect(Arc::new(config), (host, port), handler)
        .await
        .map_err(|e| format!("SSH connection failed: {e}"))?;

    match auth {
        SshAuth::Key(key_path) => {
            let key_data = std::fs::read_to_string(key_path)
                .map_err(|e| format!("Failed to read key file: {e}"))?;
            let key = russh::keys::decode_secret_key(&key_data, None)
                .map_err(|e| format!("Failed to parse key file: {e}"))?;
            let key_with_alg = russh::keys::key::PrivateKeyWithHashAlg::new(Arc::new(key), None);
            let auth_result = session
                .authenticate_publickey(user, key_with_alg)
                .await
                .map_err(|e| format!("SSH public key auth failed: {e}"))?;
            if !auth_result.success() {
                return Err("SSH public key authentication rejected".into());
            }
        }
        SshAuth::Password(password) => {
            let auth_result = session
                .authenticate_password(user, password)
                .await
                .map_err(|e| format!("SSH password auth failed: {e}"))?;
            if !auth_result.success() {
                return Err("SSH password authentication rejected".into());
            }
        }
    }

    Ok(session)
}

enum SshAuth<'a> {
    Key(&'a str),
    Password(&'a str),
}

async fn exec_async(
    host: &str,
    port: u16,
    user: &str,
    key_file: &str,
    command: &str,
) -> SshExecResult {
    match exec_inner(host, port, user, SshAuth::Key(key_file), command).await {
        Ok(r) => r,
        Err(e) => SshExecResult {
            success: false,
            exit_code: -1,
            stdout: String::new(),
            stderr: e,
        },
    }
}

async fn exec_password_async(
    host: &str,
    port: u16,
    user: &str,
    password: &str,
    command: &str,
) -> SshExecResult {
    match exec_inner(host, port, user, SshAuth::Password(password), command).await {
        Ok(r) => r,
        Err(e) => SshExecResult {
            success: false,
            exit_code: -1,
            stdout: String::new(),
            stderr: e,
        },
    }
}

async fn exec_inner(
    host: &str,
    port: u16,
    user: &str,
    auth: SshAuth<'_>,
    command: &str,
) -> Result<SshExecResult, String> {
    let session = connect_ssh(host, port, user, auth).await?;

    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|e| format!("SSH channel open failed: {e}"))?;

    channel
        .exec(true, command)
        .await
        .map_err(|e| format!("SSH exec failed: {e}"))?;

    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();
    let mut exit_code: Option<u32> = None;

    let timeout = tokio::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS);
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let msg = tokio::time::timeout_at(deadline, channel.wait()).await;
        match msg {
            Err(_) => {
                return Ok(SshExecResult {
                    success: false,
                    exit_code: -1,
                    stdout: String::from_utf8_lossy(&stdout_buf).to_string(),
                    stderr: "Command timed out".to_string(),
                });
            }
            Ok(None) => break,
            Ok(Some(russh::ChannelMsg::Data { data })) => {
                if stdout_buf.len() + data.len() <= MAX_OUTPUT_BYTES {
                    stdout_buf.extend_from_slice(&data);
                }
            }
            Ok(Some(russh::ChannelMsg::ExtendedData { data, ext })) => {
                if ext == 1 && stderr_buf.len() + data.len() <= MAX_OUTPUT_BYTES {
                    stderr_buf.extend_from_slice(&data);
                }
            }
            Ok(Some(russh::ChannelMsg::ExitStatus { exit_status })) => {
                exit_code = Some(exit_status);
            }
            Ok(Some(_)) => {}
        }
    }

    let code = exit_code.unwrap_or(0) as i32;
    Ok(SshExecResult {
        success: code == 0,
        exit_code: code,
        stdout: String::from_utf8_lossy(&stdout_buf).to_string(),
        stderr: String::from_utf8_lossy(&stderr_buf).to_string(),
    })
}

// ---------------------------------------------------------------------------
// SCP file transfer support
// ---------------------------------------------------------------------------

pub struct ScpReadResult {
    pub success: bool,
    pub data: String,
    pub size: i64,
    pub message: String,
}

pub struct ScpWriteResult {
    pub success: bool,
    pub bytes_written: i64,
    pub message: String,
}

/// Escape single quotes for safe shell usage in single-quoted strings.
fn shell_escape_path(path: &str) -> String {
    path.replace('\'', "'\\''")
}

/// Validate a remote file path for SCP operations.
/// Includes path traversal prevention (CWE-22).
fn validate_remote_path(path: &str) -> Result<(), String> {
    // Use centralized path traversal validation
    crate::security::validate_path_no_traversal(path)
}

/// Read a remote file via SCP (key-based authentication).
pub fn scp_read(
    host: &str,
    port: u16,
    user: &str,
    key_file: &str,
    remote_path: &str,
) -> ScpReadResult {
    if !is_valid_host(host) {
        return ScpReadResult {
            success: false,
            data: String::new(),
            size: 0,
            message: "Invalid hostname: contains disallowed characters".to_string(),
        };
    }
    if !is_valid_user(user) {
        return ScpReadResult {
            success: false,
            data: String::new(),
            size: 0,
            message: "Invalid username: contains disallowed characters".to_string(),
        };
    }
    if port == 0 {
        return ScpReadResult {
            success: false,
            data: String::new(),
            size: 0,
            message: "Invalid port: 0".to_string(),
        };
    }
    if let Err(e) = validate_remote_path(remote_path) {
        return ScpReadResult {
            success: false,
            data: String::new(),
            size: 0,
            message: e,
        };
    }

    runtime::block_on(scp_read_async(
        host,
        port,
        user,
        SshAuth::Key(key_file),
        remote_path,
    ))
}

/// Read a remote file via SCP (password authentication).
pub fn scp_read_password(
    host: &str,
    port: u16,
    user: &str,
    password: &str,
    remote_path: &str,
) -> ScpReadResult {
    if !is_valid_host(host) {
        return ScpReadResult {
            success: false,
            data: String::new(),
            size: 0,
            message: "Invalid hostname: contains disallowed characters".to_string(),
        };
    }
    if !is_valid_user(user) {
        return ScpReadResult {
            success: false,
            data: String::new(),
            size: 0,
            message: "Invalid username: contains disallowed characters".to_string(),
        };
    }
    if port == 0 {
        return ScpReadResult {
            success: false,
            data: String::new(),
            size: 0,
            message: "Invalid port: 0".to_string(),
        };
    }
    if let Err(e) = validate_remote_path(remote_path) {
        return ScpReadResult {
            success: false,
            data: String::new(),
            size: 0,
            message: e,
        };
    }

    runtime::block_on(scp_read_async(
        host,
        port,
        user,
        SshAuth::Password(password),
        remote_path,
    ))
}

/// Write data to a remote file via SCP (key-based authentication).
pub fn scp_write(
    host: &str,
    port: u16,
    user: &str,
    key_file: &str,
    remote_path: &str,
    data: &str,
) -> ScpWriteResult {
    if !is_valid_host(host) {
        return ScpWriteResult {
            success: false,
            bytes_written: 0,
            message: "Invalid hostname: contains disallowed characters".to_string(),
        };
    }
    if !is_valid_user(user) {
        return ScpWriteResult {
            success: false,
            bytes_written: 0,
            message: "Invalid username: contains disallowed characters".to_string(),
        };
    }
    if port == 0 {
        return ScpWriteResult {
            success: false,
            bytes_written: 0,
            message: "Invalid port: 0".to_string(),
        };
    }
    if let Err(e) = validate_remote_path(remote_path) {
        return ScpWriteResult {
            success: false,
            bytes_written: 0,
            message: e,
        };
    }
    if data.len() > MAX_OUTPUT_BYTES {
        return ScpWriteResult {
            success: false,
            bytes_written: 0,
            message: format!(
                "Data size {} exceeds maximum of {} bytes",
                data.len(),
                MAX_OUTPUT_BYTES
            ),
        };
    }

    runtime::block_on(scp_write_async(
        host,
        port,
        user,
        SshAuth::Key(key_file),
        remote_path,
        data,
    ))
}

/// Write data to a remote file via SCP (password authentication).
pub fn scp_write_password(
    host: &str,
    port: u16,
    user: &str,
    password: &str,
    remote_path: &str,
    data: &str,
) -> ScpWriteResult {
    if !is_valid_host(host) {
        return ScpWriteResult {
            success: false,
            bytes_written: 0,
            message: "Invalid hostname: contains disallowed characters".to_string(),
        };
    }
    if !is_valid_user(user) {
        return ScpWriteResult {
            success: false,
            bytes_written: 0,
            message: "Invalid username: contains disallowed characters".to_string(),
        };
    }
    if port == 0 {
        return ScpWriteResult {
            success: false,
            bytes_written: 0,
            message: "Invalid port: 0".to_string(),
        };
    }
    if let Err(e) = validate_remote_path(remote_path) {
        return ScpWriteResult {
            success: false,
            bytes_written: 0,
            message: e,
        };
    }
    if data.len() > MAX_OUTPUT_BYTES {
        return ScpWriteResult {
            success: false,
            bytes_written: 0,
            message: format!(
                "Data size {} exceeds maximum of {} bytes",
                data.len(),
                MAX_OUTPUT_BYTES
            ),
        };
    }

    runtime::block_on(scp_write_async(
        host,
        port,
        user,
        SshAuth::Password(password),
        remote_path,
        data,
    ))
}

async fn scp_read_async(
    host: &str,
    port: u16,
    user: &str,
    auth: SshAuth<'_>,
    remote_path: &str,
) -> ScpReadResult {
    let session = match connect_ssh(host, port, user, auth).await {
        Ok(s) => s,
        Err(e) => {
            return ScpReadResult {
                success: false,
                data: String::new(),
                size: 0,
                message: e,
            }
        }
    };

    let mut channel = match session.channel_open_session().await {
        Ok(c) => c,
        Err(e) => {
            return ScpReadResult {
                success: false,
                data: String::new(),
                size: 0,
                message: format!("SSH channel open failed: {e}"),
            }
        }
    };

    let escaped = shell_escape_path(remote_path);
    let command = format!("cat -- '{escaped}'");

    if let Err(e) = channel.exec(true, command.as_str()).await {
        return ScpReadResult {
            success: false,
            data: String::new(),
            size: 0,
            message: format!("SSH exec failed: {e}"),
        };
    }

    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();
    let mut exit_code: Option<u32> = None;

    let timeout = tokio::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS);
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let msg = tokio::time::timeout_at(deadline, channel.wait()).await;
        match msg {
            Err(_) => {
                return ScpReadResult {
                    success: false,
                    data: String::from_utf8_lossy(&stdout_buf).to_string(),
                    size: stdout_buf.len() as i64,
                    message: "Read timed out".to_string(),
                };
            }
            Ok(None) => break,
            Ok(Some(russh::ChannelMsg::Data { data })) => {
                if stdout_buf.len() + data.len() <= MAX_OUTPUT_BYTES {
                    stdout_buf.extend_from_slice(&data);
                }
            }
            Ok(Some(russh::ChannelMsg::ExtendedData { data, ext })) => {
                if ext == 1 && stderr_buf.len() + data.len() <= MAX_OUTPUT_BYTES {
                    stderr_buf.extend_from_slice(&data);
                }
            }
            Ok(Some(russh::ChannelMsg::ExitStatus { exit_status })) => {
                exit_code = Some(exit_status);
            }
            Ok(Some(_)) => {}
        }
    }

    let code = exit_code.unwrap_or(0);
    let data = String::from_utf8_lossy(&stdout_buf).to_string();
    let size = data.len() as i64;

    if code == 0 {
        ScpReadResult {
            success: true,
            data,
            size,
            message: String::new(),
        }
    } else {
        let stderr_msg = String::from_utf8_lossy(&stderr_buf).to_string();
        ScpReadResult {
            success: false,
            data,
            size,
            message: if stderr_msg.is_empty() {
                format!("Remote cat exited with code {code}")
            } else {
                stderr_msg
            },
        }
    }
}

async fn scp_write_async(
    host: &str,
    port: u16,
    user: &str,
    auth: SshAuth<'_>,
    remote_path: &str,
    data: &str,
) -> ScpWriteResult {
    let session = match connect_ssh(host, port, user, auth).await {
        Ok(s) => s,
        Err(e) => {
            return ScpWriteResult {
                success: false,
                bytes_written: 0,
                message: e,
            }
        }
    };

    let mut channel = match session.channel_open_session().await {
        Ok(c) => c,
        Err(e) => {
            return ScpWriteResult {
                success: false,
                bytes_written: 0,
                message: format!("SSH channel open failed: {e}"),
            }
        }
    };

    let escaped = shell_escape_path(remote_path);
    let command = format!("cat > '{escaped}'");

    if let Err(e) = channel.exec(true, command.as_str()).await {
        return ScpWriteResult {
            success: false,
            bytes_written: 0,
            message: format!("SSH exec failed: {e}"),
        };
    }

    // Send the data through the channel stdin.
    if let Err(e) = channel.data(data.as_bytes()).await {
        return ScpWriteResult {
            success: false,
            bytes_written: 0,
            message: format!("Failed to send data: {e}"),
        };
    }

    // Send EOF to signal end of input.
    if let Err(e) = channel.eof().await {
        return ScpWriteResult {
            success: false,
            bytes_written: 0,
            message: format!("Failed to send EOF: {e}"),
        };
    }

    // Wait for exit status.
    let mut exit_code: Option<u32> = None;
    let mut stderr_buf = Vec::new();

    let timeout = tokio::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS);
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let msg = tokio::time::timeout_at(deadline, channel.wait()).await;
        match msg {
            Err(_) => {
                return ScpWriteResult {
                    success: false,
                    bytes_written: 0,
                    message: "Write timed out".to_string(),
                };
            }
            Ok(None) => break,
            Ok(Some(russh::ChannelMsg::ExtendedData { data, ext })) => {
                if ext == 1 && stderr_buf.len() + data.len() <= MAX_OUTPUT_BYTES {
                    stderr_buf.extend_from_slice(&data);
                }
            }
            Ok(Some(russh::ChannelMsg::ExitStatus { exit_status })) => {
                exit_code = Some(exit_status);
            }
            Ok(Some(_)) => {}
        }
    }

    let code = exit_code.unwrap_or(0);

    if code == 0 {
        ScpWriteResult {
            success: true,
            bytes_written: data.len() as i64,
            message: String::new(),
        }
    } else {
        let stderr_msg = String::from_utf8_lossy(&stderr_buf).to_string();
        ScpWriteResult {
            success: false,
            bytes_written: 0,
            message: if stderr_msg.is_empty() {
                format!("Remote cat exited with code {code}")
            } else {
                stderr_msg
            },
        }
    }
}
