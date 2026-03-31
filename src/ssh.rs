// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::sync::Arc;

use base64::Engine as _;

use crate::runtime;

/// Maximum command output size: 64 MiB per stream.
/// Prevents OOM from unbounded output buffering (CWE-400).
pub(crate) const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

/// SSH command execution timeout in seconds.
pub(crate) const DEFAULT_TIMEOUT_SECS: u64 = 30;

pub struct SshExecResult {
    pub success: bool,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Validate SSH hostname to prevent injection (CWE-78).
/// Allows alphanumeric, dots, hyphens, colons (IPv6), and brackets.
pub(crate) fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
}

/// Validate username: alphanumeric, underscore, hyphen, dot only.
pub(crate) fn is_valid_user(user: &str) -> bool {
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
pub(crate) struct SshHandler {
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
            KnownHostResult::NotFound => {
                // Warn about TOFU host key verification (CWE-295)
                crate::security_warnings::warn_tofu("SSH", "TOFU_SSH");
                // Persist the key to ~/.ssh/known_hosts so subsequent connections
                // benefit from key-pinning rather than re-issuing TOFU each time.
                let _ = append_known_host(&host, &key_type, &key_data);
                true
            }
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

/// Append a newly-learned host key to ~/.ssh/known_hosts.
///
/// On first TOFU acceptance, we persist the key so that future connections
/// see `Matched` instead of `NotFound`, turning TOFU into proper key-pinning.
/// Failures are silently ignored — if the file cannot be written (read-only FS,
/// container, etc.) the TOFU warning was already emitted and the connection proceeds.
fn append_known_host(host: &str, key_type: &str, key_data: &str) -> std::io::Result<()> {
    use std::io::Write;

    let path = dirs_known_hosts()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "HOME not set"))?;

    // Ensure ~/.ssh/ directory exists with 0700 permissions
    if let Some(parent) = std::path::Path::new(&path).parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
            }
        }
    }

    // Append host key in known_hosts format: "host keytype keydata\n"
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Set 0600 on newly-created file
        let meta = file.metadata()?;
        if meta.len() == 0 {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
    }

    writeln!(file, "{host} {key_type} {key_data}")?;
    Ok(())
}

fn dirs_known_hosts() -> Option<String> {
    std::env::var("HOME")
        .ok()
        .map(|h| format!("{h}/.ssh/known_hosts"))
}

pub(crate) async fn connect_ssh(
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

pub(crate) enum SshAuth<'a> {
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
