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

        let outcome = check_known_hosts(&host, &key_type, &key_data);
        let result = match outcome {
            KnownHostResult::Matched => true,
            KnownHostResult::Revoked => {
                // @revoked marker — reject unconditionally.
                eprintln!(
                    "[duck_net] CRITICAL: SSH host key for '{}' is marked @revoked in known_hosts — connection refused.",
                    host
                );
                false
            }
            KnownHostResult::NotFound => match crate::security::ssh_tofu_mode() {
                crate::security::TofuMode::Strict => {
                    eprintln!(
                        "[duck_net] SSH host '{}' not in known_hosts and TOFU mode is 'strict' — connection refused. \
                         Pre-populate ~/.ssh/known_hosts or use duck_net_set_ssh_tofu('warn' | 'auto').",
                        host
                    );
                    false
                }
                crate::security::TofuMode::Warn => {
                    crate::security_warnings::warn_tofu("SSH", "TOFU_SSH");
                    // Warn-only: do NOT persist, so the next connection re-prompts.
                    true
                }
                crate::security::TofuMode::Auto => {
                    crate::security_warnings::warn_tofu("SSH", "TOFU_SSH");
                    let _ = append_known_host(&host, &key_type, &key_data);
                    true
                }
            },
            KnownHostResult::Changed => false, // Potential MITM
        };
        std::future::ready(Ok(result))
    }
}

enum KnownHostResult {
    Matched,
    NotFound,
    Changed,
    Revoked,
}

fn check_known_hosts(host: &str, key_type: &str, key_data: &str) -> KnownHostResult {
    let paths = [
        dirs_known_hosts(),
        Some("/etc/ssh/ssh_known_hosts".to_string()),
    ];

    // Normalise the host for matching: strip surrounding brackets and any
    // trailing :port (IPv6 addresses in known_hosts use [ipv6]:port form).
    let target = normalize_known_host_entry(host);

    let mut seen_matching_key_type = false;

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
            // Parse: [marker] hosts-field keytype keydata [comment]
            let mut parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            // Optional @cert-authority / @revoked marker.
            let marker = if parts[0].starts_with('@') {
                let m = parts.remove(0);
                Some(m)
            } else {
                None
            };
            if parts.len() < 3 {
                continue;
            }

            let hosts_field = parts[0];
            let line_key_type = parts[1];
            let line_key_data = parts[2];

            let host_matches = if let Some(hashed) = hosts_field.strip_prefix("|1|") {
                // Hashed: |1|salt-b64|hash-b64
                matches_hashed_known_host(hashed, &target)
            } else {
                hosts_field
                    .split(',')
                    .any(|h| known_host_entry_matches(h, &target))
            };

            if !host_matches {
                continue;
            }

            // Handle @revoked marker immediately.
            if marker == Some("@revoked") && line_key_type == key_type && line_key_data == key_data
            {
                return KnownHostResult::Revoked;
            }
            // @cert-authority entries are CA certificates, not leaf host keys;
            // treat them as "no leaf match" so the caller falls through to
            // TOFU. Proper CA validation would require verifying the key was
            // signed by this CA, which russh handles separately.
            if marker == Some("@cert-authority") {
                continue;
            }

            if line_key_type == key_type && line_key_data == key_data {
                return KnownHostResult::Matched;
            } else if line_key_type == key_type {
                seen_matching_key_type = true;
            }
        }
    }

    if seen_matching_key_type {
        KnownHostResult::Changed
    } else {
        KnownHostResult::NotFound
    }
}

/// Normalise a host string for known_hosts comparison.
/// Strips brackets, lowercases, and discards any trailing :port.
fn normalize_known_host_entry(host: &str) -> String {
    let s = host.trim();
    // Bracketed IPv6: [::1]:22
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return rest[..end].to_ascii_lowercase();
        }
    }
    // Plain IPv6 (contains >= 2 colons — a port-suffixed host has exactly one)
    if s.matches(':').count() >= 2 {
        return s.to_ascii_lowercase();
    }
    // Hostname[:port]
    if let Some(colon) = s.rfind(':') {
        let after = &s[colon + 1..];
        if after.chars().all(|c| c.is_ascii_digit()) {
            return s[..colon].to_ascii_lowercase();
        }
    }
    s.to_ascii_lowercase()
}

/// Check whether a single entry in a comma-separated hosts field matches a
/// normalized target host. Handles bracketed IPv6 and trailing port suffixes.
fn known_host_entry_matches(entry: &str, target_lc: &str) -> bool {
    let e = entry.trim();
    let normalised = normalize_known_host_entry(e);
    normalised == target_lc
}

/// Match a hashed known_hosts entry (`|1|salt|hash`) against a plaintext host.
/// `hashed_suffix` is everything after the `|1|` marker.
fn matches_hashed_known_host(hashed_suffix: &str, target_lc: &str) -> bool {
    use base64::Engine as _;
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    type HmacSha1 = Hmac<Sha1>;

    let mut parts = hashed_suffix.split('|');
    let salt_b64 = match parts.next() {
        Some(s) => s,
        None => return false,
    };
    let hash_b64 = match parts.next() {
        Some(s) => s,
        None => return false,
    };

    let salt = match base64::engine::general_purpose::STANDARD.decode(salt_b64) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let expected = match base64::engine::general_purpose::STANDARD.decode(hash_b64) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let mut mac = match HmacSha1::new_from_slice(&salt) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(target_lc.as_bytes());
    let computed = mac.finalize().into_bytes();

    crate::security::constant_time_eq(&computed, &expected)
}

/// Process-level lock used to serialise known_hosts appends across concurrent
/// DuckDB sessions / tokio tasks. Combined with POSIX `O_APPEND` (which is
/// atomic for writes below `PIPE_BUF`, typically 4096 bytes) and the fact that
/// a single known_hosts entry is well below that limit, this prevents
/// corruption (CWE-362).
static KNOWN_HOSTS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Append a newly-learned host key to ~/.ssh/known_hosts.
///
/// On first TOFU acceptance we persist the key so future connections see
/// `Matched` instead of `NotFound`, turning TOFU into proper key-pinning.
/// Failures are silently ignored — if the file cannot be written (read-only
/// FS, container, etc.) the TOFU warning was already emitted and the
/// connection proceeds.
///
/// Concurrency:
/// - Intra-process: serialised via [`KNOWN_HOSTS_LOCK`].
/// - Inter-process: relies on POSIX `O_APPEND` atomicity (writes ≤ `PIPE_BUF`
///   are guaranteed not to interleave). A single known_hosts line is ~200 B.
fn append_known_host(host: &str, key_type: &str, key_data: &str) -> std::io::Result<()> {
    use std::io::Write;

    let _guard = KNOWN_HOSTS_LOCK.lock().unwrap_or_else(|p| p.into_inner());

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

    // Normalise the hostname so check_known_hosts can match it later.
    let host_for_entry = normalize_known_host_entry(host);

    // Append host key in known_hosts format: "host keytype keydata\n"
    // On POSIX, O_APPEND makes the write atomic with respect to other writers.
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

    writeln!(file, "{host_for_entry} {key_type} {key_data}")?;
    file.sync_all().ok();
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
            // Validate key file permissions before reading.
            // SSH private keys must be owner-readable only (0600 / 0400).
            // A world- or group-readable key could be exfiltrated by any local
            // user or process, defeating the purpose of key-based auth (CWE-732).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let metadata = std::fs::metadata(key_path)
                    .map_err(|e| format!("Cannot access key file '{}': {e}", key_path))?;
                let mode = metadata.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    return Err(format!(
                        "Key file '{}' has insecure permissions ({:04o}). \
                         SSH private keys must be readable only by the owner. \
                         Fix with: chmod 600 '{}'",
                        key_path, mode, key_path
                    ));
                }
            }

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
    let success = code == 0;

    // Audit log: record SSH exec outcome (command scrubbed of any credential
    // patterns; host is already validated as non-private by connect_ssh).
    crate::audit_log::record(
        "ssh",
        "exec",
        host,
        success,
        code,
        if success { "" } else { "non-zero exit code" },
    );

    Ok(SshExecResult {
        success,
        exit_code: code,
        stdout: String::from_utf8_lossy(&stdout_buf).to_string(),
        stderr: String::from_utf8_lossy(&stderr_buf).to_string(),
    })
}
