// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use crate::runtime;
use crate::ssh::{
    connect_ssh, is_valid_host, is_valid_user, SshAuth, DEFAULT_TIMEOUT_SECS, MAX_OUTPUT_BYTES,
};

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
    // SSRF protection: block connections to private/reserved IPs (CWE-918)
    if let Err(e) = crate::security::validate_no_ssrf_host(host) {
        return ScpReadResult {
            success: false,
            data: String::new(),
            size: 0,
            message: e,
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

    let r = runtime::block_on(scp_read_async(
        host,
        port,
        user,
        SshAuth::Key(key_file),
        remote_path,
    ));
    crate::audit_log::record("scp", "read", host, r.success, r.size as i32, &r.message);
    r
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
    // SSRF protection (CWE-918)
    if let Err(e) = crate::security::validate_no_ssrf_host(host) {
        return ScpReadResult {
            success: false,
            data: String::new(),
            size: 0,
            message: e,
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

    let r = runtime::block_on(scp_read_async(
        host,
        port,
        user,
        SshAuth::Password(password),
        remote_path,
    ));
    crate::audit_log::record(
        "scp",
        "read_password",
        host,
        r.success,
        r.size as i32,
        &r.message,
    );
    r
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
    // SSRF protection (CWE-918)
    if let Err(e) = crate::security::validate_no_ssrf_host(host) {
        return ScpWriteResult {
            success: false,
            bytes_written: 0,
            message: e,
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

    let r = runtime::block_on(scp_write_async(
        host,
        port,
        user,
        SshAuth::Key(key_file),
        remote_path,
        data,
    ));
    crate::audit_log::record(
        "scp",
        "write",
        host,
        r.success,
        r.bytes_written as i32,
        &r.message,
    );
    r
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
    // SSRF protection (CWE-918)
    if let Err(e) = crate::security::validate_no_ssrf_host(host) {
        return ScpWriteResult {
            success: false,
            bytes_written: 0,
            message: e,
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

    let r = runtime::block_on(scp_write_async(
        host,
        port,
        user,
        SshAuth::Password(password),
        remote_path,
        data,
    ));
    crate::audit_log::record(
        "scp",
        "write_password",
        host,
        r.success,
        r.bytes_written as i32,
        &r.message,
    );
    r
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
