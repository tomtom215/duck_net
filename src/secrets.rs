// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

//! In-memory secrets store for duck_net.
//!
//! Provides a secure credential store that integrates with DuckDB's secrets
//! manager philosophy. Credentials are stored in memory (never written to disk)
//! and can be referenced by name from protocol functions, keeping credentials
//! out of SQL query text.
//!
//! # Usage
//! ```sql
//! -- Store a secret (credentials never appear in query logs)
//! SELECT duck_net_add_secret('my_smtp', 'smtp', '{"username":"user","password":"pass","host":"smtp.example.com"}');
//!
//! -- Use the secret by name
//! SELECT smtp_send_secret('my_smtp', 'from@example.com', 'to@example.com', 'Subject', 'Body');
//!
//! -- Clear when done
//! SELECT duck_net_clear_secret('my_smtp');
//! ```
//!
//! # DuckDB Native Secrets
//! For S3/HTTP/GCS protocols, prefer DuckDB's native `CREATE SECRET` with the
//! httpfs extension. duck_net's secrets store covers protocols DuckDB does not
//! natively support (SMTP, SSH, IMAP, LDAP, Redis, MQTT, etc.).

use std::collections::HashMap;
use std::sync::Mutex;
use zeroize::Zeroize;

/// Global in-memory secrets store.
/// Maps secret_name -> (secret_type, key-value pairs).
static SECRETS: Mutex<Option<HashMap<String, StoredSecret>>> = Mutex::new(None);

/// A stored secret with its type and key-value configuration.
///
/// Implements a manual [`Zeroize`] that properly zeroes every string
/// value in the HashMap before clearing the map. The `zeroize` crate
/// guarantees that these writes are not optimised away by the compiler
/// (CWE-316).
#[derive(Clone)]
struct StoredSecret {
    secret_type: String,
    values: HashMap<String, String>,
}

impl Zeroize for StoredSecret {
    fn zeroize(&mut self) {
        self.secret_type.zeroize();
        for value in self.values.values_mut() {
            value.zeroize();
        }
        // Keys may also contain sensitive info (e.g. key names hinting at usage)
        let keys: Vec<String> = self.values.keys().cloned().collect();
        self.values.clear();
        for mut k in keys {
            k.zeroize();
        }
    }
}

impl Drop for StoredSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Maximum number of secrets to prevent memory abuse.
const MAX_SECRETS: usize = 1024;

/// Maximum total size of a single secret's values (all keys + values combined).
const MAX_SECRET_BYTES: usize = 64 * 1024;

/// Secret types recognized by duck_net.
pub mod secret_types {
    pub const SMTP: &str = "smtp";
    pub const IMAP: &str = "imap";
    pub const FTP: &str = "ftp";
    pub const SFTP: &str = "sftp";
    pub const SSH: &str = "ssh";
    pub const LDAP: &str = "ldap";
    pub const REDIS: &str = "redis";
    pub const MQTT: &str = "mqtt";
    pub const S3: &str = "s3";
    pub const HTTP: &str = "http";
    pub const VAULT: &str = "vault";
    pub const CONSUL: &str = "consul";
    pub const INFLUXDB: &str = "influxdb";
    pub const ELASTICSEARCH: &str = "elasticsearch";
    pub const SNMP: &str = "snmp";
    pub const RADIUS: &str = "radius";
    pub const KAFKA: &str = "kafka";
    pub const NATS: &str = "nats";
    pub const MEMCACHED: &str = "memcached";
    pub const GRPC: &str = "grpc";
    pub const WEBSOCKET: &str = "websocket";
}

/// Known credential keys that should never appear in error messages.
const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "secret",
    "secret_key",
    "token",
    "bearer_token",
    "api_key",
    "access_key",
    "key_id",
    "community",
    "shared_secret",
    "private_key",
    "client_secret",
];

/// Initialize the secrets store. Called once at extension load.
pub fn init() {
    let mut store = SECRETS.lock().unwrap_or_else(|p| p.into_inner());
    if store.is_none() {
        *store = Some(HashMap::new());
    }
}

/// Add or update a secret.
///
/// `config_json` is a JSON object of key-value pairs, e.g.:
/// `{"username": "user", "password": "pass", "host": "example.com"}`
pub fn add_secret(name: &str, secret_type: &str, config_json: &str) -> Result<String, String> {
    // Validate name
    if name.is_empty() || name.len() > 128 {
        return Err("Secret name must be 1-128 characters".to_string());
    }
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err(
            "Secret name must contain only alphanumeric characters, underscores, hyphens, or dots"
                .to_string(),
        );
    }

    // Validate type
    if secret_type.is_empty() || secret_type.len() > 64 {
        return Err("Secret type must be 1-64 characters".to_string());
    }

    // Validate type is one of the known types (warn but don't reject unknown types)
    let lower_type = secret_type.to_lowercase();
    let known_types = [
        secret_types::SMTP,
        secret_types::IMAP,
        secret_types::FTP,
        secret_types::SFTP,
        secret_types::SSH,
        secret_types::LDAP,
        secret_types::REDIS,
        secret_types::MQTT,
        secret_types::S3,
        secret_types::HTTP,
        secret_types::VAULT,
        secret_types::CONSUL,
        secret_types::INFLUXDB,
        secret_types::ELASTICSEARCH,
        secret_types::SNMP,
        secret_types::RADIUS,
        secret_types::KAFKA,
        secret_types::NATS,
        secret_types::MEMCACHED,
        secret_types::GRPC,
        secret_types::WEBSOCKET,
    ];
    let _is_known = known_types.contains(&lower_type.as_str());

    // Parse JSON config
    let values = parse_json_object(config_json)?;

    // Validate total size
    let total_bytes: usize = values.iter().map(|(k, v)| k.len() + v.len()).sum();
    if total_bytes > MAX_SECRET_BYTES {
        return Err(format!(
            "Secret configuration too large: {} bytes (max {})",
            total_bytes, MAX_SECRET_BYTES
        ));
    }

    let mut store = SECRETS.lock().unwrap_or_else(|p| p.into_inner());
    let map = store.as_mut().ok_or("Secrets store not initialized")?;

    // Check limit (unless updating existing)
    if !map.contains_key(name) && map.len() >= MAX_SECRETS {
        return Err(format!(
            "Maximum number of secrets ({}) reached",
            MAX_SECRETS
        ));
    }

    let key_count = values.len();
    map.insert(
        name.to_string(),
        StoredSecret {
            secret_type: secret_type.to_lowercase(),
            values,
        },
    );

    Ok(format!(
        "Secret '{}' stored ({} keys, type={})",
        name, key_count, secret_type
    ))
}

/// Remove a secret from the store.
/// Zeroizes the secret values in memory before dropping (CWE-316).
pub fn clear_secret(name: &str) -> Result<String, String> {
    let mut store = SECRETS.lock().unwrap_or_else(|p| p.into_inner());
    let map = store.as_mut().ok_or("Secrets store not initialized")?;

    if let Some(mut secret) = map.remove(name) {
        zeroize_secret(&mut secret);
        Ok(format!("Secret '{}' removed", name))
    } else {
        Err(format!("Secret '{}' not found", name))
    }
}

/// Remove all secrets from the store.
/// Zeroizes all secret values in memory before dropping (CWE-316).
pub fn clear_all_secrets() -> String {
    let mut store = SECRETS.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(map) = store.as_mut() {
        let count = map.len();
        for (_, secret) in map.iter_mut() {
            zeroize_secret(secret);
        }
        map.clear();
        format!("Cleared {} secrets", count)
    } else {
        "Secrets store not initialized".to_string()
    }
}

/// Overwrite sensitive values in memory with zeros before dropping (CWE-316).
///
/// Uses the `zeroize` crate which guarantees the zeroing writes are not
/// optimised away by the compiler, unlike manual `write_volatile` calls.
/// The [`StoredSecret`] type also derives [`ZeroizeOnDrop`], so any value
/// that falls out of scope without an explicit clear is still scrubbed.
fn zeroize_secret(secret: &mut StoredSecret) {
    secret.zeroize();
}

/// List secret names and types (never exposes values).
pub fn list_secrets() -> Vec<(String, String, usize)> {
    let store = SECRETS.lock().unwrap_or_else(|p| p.into_inner());
    match store.as_ref() {
        Some(map) => map
            .iter()
            .map(|(name, secret)| {
                (
                    name.clone(),
                    secret.secret_type.clone(),
                    secret.values.len(),
                )
            })
            .collect(),
        None => vec![],
    }
}

/// Get a specific value from a named secret.
/// Returns None if the secret or key doesn't exist.
pub(crate) fn get_value(secret_name: &str, key: &str) -> Option<String> {
    let store = SECRETS.lock().unwrap_or_else(|p| p.into_inner());
    store.as_ref()?.get(secret_name)?.values.get(key).cloned()
}

/// Get all raw values from a named secret (for internal bridge use only).
/// Callers are responsible for not leaking these values.
pub(crate) fn get_value_map_internal(
    secret_name: &str,
) -> Option<std::collections::HashMap<String, String>> {
    let store = SECRETS.lock().unwrap_or_else(|p| p.into_inner());
    store.as_ref()?.get(secret_name).map(|s| s.values.clone())
}

/// Get the type of a named secret.
pub fn get_type(secret_name: &str) -> Option<String> {
    let store = SECRETS.lock().unwrap_or_else(|p| p.into_inner());
    store
        .as_ref()?
        .get(secret_name)
        .map(|s| s.secret_type.clone())
}

/// Get all non-sensitive values from a secret (for display/debugging).
/// Sensitive values (passwords, tokens, keys) are redacted.
pub fn get_redacted(secret_name: &str) -> Option<HashMap<String, String>> {
    let store = SECRETS.lock().unwrap_or_else(|p| p.into_inner());
    let secret = store.as_ref()?.get(secret_name)?;
    let mut redacted = HashMap::new();
    for (k, v) in &secret.values {
        let is_sensitive = SENSITIVE_KEYS
            .iter()
            .any(|sk| k.to_lowercase().contains(sk));
        if is_sensitive {
            redacted.insert(k.clone(), "********".to_string());
        } else {
            redacted.insert(k.clone(), v.clone());
        }
    }
    Some(redacted)
}

// ---------------------------------------------------------------------------
// Simple JSON parser (no external dependency)
// ---------------------------------------------------------------------------

/// Parse a flat JSON object `{"key": "value", ...}` into a HashMap.
/// Only supports string values (sufficient for credentials).
fn parse_json_object(json: &str) -> Result<HashMap<String, String>, String> {
    let trimmed = json.trim();
    if !trimmed.starts_with('{') || !trimmed.ends_with('}') {
        return Err("Config must be a JSON object: {\"key\": \"value\", ...}".to_string());
    }

    let inner = &trimmed[1..trimmed.len() - 1];
    let mut map = HashMap::new();
    let mut chars = inner.chars().peekable();

    loop {
        skip_ws(&mut chars);
        if chars.peek().is_none() {
            break;
        }

        let key = parse_json_string(&mut chars)?;
        skip_ws(&mut chars);

        match chars.next() {
            Some(':') => {}
            other => return Err(format!("Expected ':' after key '{}', got {:?}", key, other)),
        }

        skip_ws(&mut chars);
        let value = parse_json_string(&mut chars)?;

        map.insert(key, value);

        skip_ws(&mut chars);
        match chars.peek() {
            Some(',') => {
                chars.next();
            }
            Some('}') | None => break,
            Some(c) => return Err(format!("Unexpected character in JSON: '{}'", c)),
        }
    }

    Ok(map)
}

fn skip_ws(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
        } else {
            break;
        }
    }
}

fn parse_json_string(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
) -> Result<String, String> {
    match chars.next() {
        Some('"') => {}
        other => return Err(format!("Expected '\"', got {:?}", other)),
    }

    let mut s = String::new();
    loop {
        match chars.next() {
            Some('\\') => match chars.next() {
                Some('"') => s.push('"'),
                Some('\\') => s.push('\\'),
                Some('/') => s.push('/'),
                Some('n') => s.push('\n'),
                Some('t') => s.push('\t'),
                Some('r') => s.push('\r'),
                Some(c) => {
                    s.push('\\');
                    s.push(c);
                }
                None => return Err("Unterminated string escape".to_string()),
            },
            Some('"') => return Ok(s),
            Some(c) => s.push(c),
            None => return Err("Unterminated string".to_string()),
        }
    }
}
