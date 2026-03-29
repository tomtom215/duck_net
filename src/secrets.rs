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

/// Global in-memory secrets store.
/// Maps secret_name -> (secret_type, key-value pairs).
static SECRETS: Mutex<Option<HashMap<String, StoredSecret>>> = Mutex::new(None);

/// A stored secret with its type and key-value configuration.
#[derive(Clone)]
struct StoredSecret {
    secret_type: String,
    values: HashMap<String, String>,
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
    let mut store = SECRETS.lock().unwrap();
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
    let total_bytes: usize = values
        .iter()
        .map(|(k, v)| k.len() + v.len())
        .sum();
    if total_bytes > MAX_SECRET_BYTES {
        return Err(format!(
            "Secret configuration too large: {} bytes (max {})",
            total_bytes, MAX_SECRET_BYTES
        ));
    }

    let mut store = SECRETS.lock().unwrap();
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
pub fn clear_secret(name: &str) -> Result<String, String> {
    let mut store = SECRETS.lock().unwrap();
    let map = store.as_mut().ok_or("Secrets store not initialized")?;

    if map.remove(name).is_some() {
        Ok(format!("Secret '{}' removed", name))
    } else {
        Err(format!("Secret '{}' not found", name))
    }
}

/// Remove all secrets from the store.
pub fn clear_all_secrets() -> String {
    let mut store = SECRETS.lock().unwrap();
    if let Some(map) = store.as_mut() {
        let count = map.len();
        map.clear();
        format!("Cleared {} secrets", count)
    } else {
        "Secrets store not initialized".to_string()
    }
}

/// List secret names and types (never exposes values).
pub fn list_secrets() -> Vec<(String, String, usize)> {
    let store = SECRETS.lock().unwrap();
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
pub fn get_value(secret_name: &str, key: &str) -> Option<String> {
    let store = SECRETS.lock().unwrap();
    store
        .as_ref()?
        .get(secret_name)?
        .values
        .get(key)
        .cloned()
}

/// Get the type of a named secret.

pub fn get_type(secret_name: &str) -> Option<String> {
    let store = SECRETS.lock().unwrap();
    store
        .as_ref()?
        .get(secret_name)
        .map(|s| s.secret_type.clone())
}

/// Get all non-sensitive values from a secret (for display/debugging).
/// Sensitive values (passwords, tokens, keys) are redacted.

pub fn get_redacted(secret_name: &str) -> Option<HashMap<String, String>> {
    let store = SECRETS.lock().unwrap();
    let secret = store.as_ref()?.get(secret_name)?;
    let mut redacted = HashMap::new();
    for (k, v) in &secret.values {
        let is_sensitive = SENSITIVE_KEYS.iter().any(|sk| {
            k.to_lowercase().contains(sk)
        });
        if is_sensitive {
            redacted.insert(k.clone(), "********".to_string());
        } else {
            redacted.insert(k.clone(), v.clone());
        }
    }
    Some(redacted)
}

/// Resolve S3 credentials from a named secret.
/// Returns (endpoint, access_key, secret_key, region) if all required fields exist.
pub fn resolve_s3(secret_name: &str) -> Result<(String, String, String, String), String> {
    let store = SECRETS.lock().unwrap();
    let map = store.as_ref().ok_or("Secrets store not initialized")?;
    let secret = map
        .get(secret_name)
        .ok_or_else(|| format!("Secret '{}' not found", secret_name))?;

    let access_key = secret
        .values
        .get("key_id")
        .or_else(|| secret.values.get("access_key"))
        .ok_or_else(|| format!("Secret '{}' missing 'key_id' or 'access_key'", secret_name))?
        .clone();

    let secret_key = secret
        .values
        .get("secret")
        .or_else(|| secret.values.get("secret_key"))
        .ok_or_else(|| format!("Secret '{}' missing 'secret' or 'secret_key'", secret_name))?
        .clone();

    let region = secret
        .values
        .get("region")
        .cloned()
        .unwrap_or_else(|| "us-east-1".to_string());

    let endpoint = secret
        .values
        .get("endpoint")
        .cloned()
        .unwrap_or_else(|| "https://s3.amazonaws.com".to_string());

    Ok((endpoint, access_key, secret_key, region))
}

/// Resolve HTTP auth credentials from a named secret.
/// Returns (bearer_token, extra_headers).

pub fn resolve_http(secret_name: &str) -> Result<Vec<(String, String)>, String> {
    let store = SECRETS.lock().unwrap();
    let map = store.as_ref().ok_or("Secrets store not initialized")?;
    let secret = map
        .get(secret_name)
        .ok_or_else(|| format!("Secret '{}' not found", secret_name))?;

    let mut headers = Vec::new();

    if let Some(token) = secret.values.get("bearer_token").or(secret.values.get("token")) {
        headers.push(("Authorization".to_string(), format!("Bearer {}", token)));
    }

    if let Some(user) = secret.values.get("username") {
        if let Some(pass) = secret.values.get("password") {
            use base64::Engine as _;
            let encoded = base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", user, pass));
            headers.push(("Authorization".to_string(), format!("Basic {}", encoded)));
        }
    }

    Ok(headers)
}

/// Resolve generic credentials: returns (username, password) if present.

pub fn resolve_credentials(secret_name: &str) -> Result<(Option<String>, Option<String>), String> {
    let store = SECRETS.lock().unwrap();
    let map = store.as_ref().ok_or("Secrets store not initialized")?;
    let secret = map
        .get(secret_name)
        .ok_or_else(|| format!("Secret '{}' not found", secret_name))?;

    let username = secret.values.get("username").cloned();
    let password = secret.values.get("password").cloned();

    Ok((username, password))
}

/// Resolve a token-based secret (Vault, Consul, InfluxDB, etc.).
pub fn resolve_token(secret_name: &str) -> Result<String, String> {
    let store = SECRETS.lock().unwrap();
    let map = store.as_ref().ok_or("Secrets store not initialized")?;
    let secret = map
        .get(secret_name)
        .ok_or_else(|| format!("Secret '{}' not found", secret_name))?;

    secret
        .values
        .get("token")
        .or_else(|| secret.values.get("bearer_token"))
        .or_else(|| secret.values.get("api_key"))
        .cloned()
        .ok_or_else(|| {
            format!(
                "Secret '{}' missing 'token', 'bearer_token', or 'api_key'",
                secret_name
            )
        })
}

/// Resolve SSH credentials from a named secret.
/// Returns (username, auth) where auth is either a key_file path or password.

pub fn resolve_ssh(
    secret_name: &str,
) -> Result<(String, Option<String>, Option<String>), String> {
    let store = SECRETS.lock().unwrap();
    let map = store.as_ref().ok_or("Secrets store not initialized")?;
    let secret = map
        .get(secret_name)
        .ok_or_else(|| format!("Secret '{}' not found", secret_name))?;

    let username = secret
        .values
        .get("username")
        .or_else(|| secret.values.get("user"))
        .cloned()
        .unwrap_or_else(|| "root".to_string());

    let key_file = secret.values.get("key_file").cloned();
    let password = secret.values.get("password").cloned();

    if key_file.is_none() && password.is_none() {
        return Err(format!(
            "Secret '{}' must have 'key_file' or 'password'",
            secret_name
        ));
    }

    Ok((username, key_file, password))
}

/// Resolve SNMP community string from a secret.

pub fn resolve_community(secret_name: &str) -> Result<String, String> {
    get_value(secret_name, "community")
        .ok_or_else(|| format!("Secret '{}' missing 'community'", secret_name))
}

/// Resolve RADIUS shared secret from a secret.

pub fn resolve_shared_secret(secret_name: &str) -> Result<String, String> {
    get_value(secret_name, "shared_secret")
        .or_else(|| get_value(secret_name, "secret"))
        .ok_or_else(|| format!("Secret '{}' missing 'shared_secret'", secret_name))
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
            other => {
                return Err(format!(
                    "Expected ':' after key '{}', got {:?}",
                    key, other
                ))
            }
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
