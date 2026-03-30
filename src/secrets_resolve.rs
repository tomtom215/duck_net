// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

//! Secret resolution functions for duck_net.
//!
//! These functions resolve named secrets into protocol-specific credential
//! tuples. They read from the shared in-memory secrets store defined in
//! [`crate::secrets`].

use crate::secrets::get_value;

/// Resolved S3 credentials from a named secret.
#[allow(dead_code)]
pub struct S3Creds {
    pub endpoint: String,
    pub access_key: String,
    pub secret_key: String,
    pub region: String,
    /// STS session token for temporary credentials (optional).
    pub session_token: Option<String>,
    /// Whether to enforce SSL (default: true).
    pub use_ssl: bool,
}

/// Resolve S3 credentials from a named secret.
///
/// Accepts DuckDB-compatible field names (KEY_ID, SECRET, REGION, ENDPOINT,
/// SESSION_TOKEN, USE_SSL) as well as alternative aliases.
pub fn resolve_s3(secret_name: &str) -> Result<S3Creds, String> {
    let access_key = get_value(secret_name, "key_id")
        .or_else(|| get_value(secret_name, "access_key"))
        .ok_or_else(|| format!("Secret '{}' missing 'key_id' or 'access_key'", secret_name))?;

    let secret_key = get_value(secret_name, "secret")
        .or_else(|| get_value(secret_name, "secret_key"))
        .ok_or_else(|| format!("Secret '{}' missing 'secret' or 'secret_key'", secret_name))?;

    let region = get_value(secret_name, "region").unwrap_or_else(|| "us-east-1".to_string());

    let endpoint = get_value(secret_name, "endpoint")
        .unwrap_or_else(|| "https://s3.amazonaws.com".to_string());

    // STS session token for temporary credentials
    let session_token = get_value(secret_name, "session_token");

    // use_ssl: default true; false only when explicitly set to "false"
    let use_ssl = get_value(secret_name, "use_ssl")
        .map(|v| !v.eq_ignore_ascii_case("false"))
        .unwrap_or(true);

    Ok(S3Creds {
        endpoint,
        access_key,
        secret_key,
        region,
        session_token,
        use_ssl,
    })
}

/// Resolve HTTP auth credentials from a named secret.
/// Returns (bearer_token, extra_headers).
pub fn resolve_http(secret_name: &str) -> Result<Vec<(String, String)>, String> {
    let mut headers = Vec::new();

    if let Some(token) =
        get_value(secret_name, "bearer_token").or_else(|| get_value(secret_name, "token"))
    {
        headers.push(("Authorization".to_string(), format!("Bearer {}", token)));
    }

    if let Some(user) = get_value(secret_name, "username") {
        if let Some(pass) = get_value(secret_name, "password") {
            use base64::Engine as _;
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", user, pass));
            headers.push(("Authorization".to_string(), format!("Basic {}", encoded)));
        }
    }

    Ok(headers)
}

/// Resolve generic credentials: returns (username, password) if present.
pub fn resolve_credentials(secret_name: &str) -> Result<(Option<String>, Option<String>), String> {
    // Verify the secret exists by checking the type (any stored secret has a type).
    crate::secrets::get_type(secret_name)
        .ok_or_else(|| format!("Secret '{}' not found", secret_name))?;

    let username = get_value(secret_name, "username");
    let password = get_value(secret_name, "password");

    Ok((username, password))
}

/// Resolve a token-based secret (Vault, Consul, InfluxDB, etc.).
pub fn resolve_token(secret_name: &str) -> Result<String, String> {
    get_value(secret_name, "token")
        .or_else(|| get_value(secret_name, "bearer_token"))
        .or_else(|| get_value(secret_name, "api_key"))
        .ok_or_else(|| {
            format!(
                "Secret '{}' missing 'token', 'bearer_token', or 'api_key'",
                secret_name
            )
        })
}

/// Resolve SSH credentials from a named secret.
/// Returns (username, auth) where auth is either a key_file path or password.
pub fn resolve_ssh(secret_name: &str) -> Result<(String, Option<String>, Option<String>), String> {
    let username = get_value(secret_name, "username")
        .or_else(|| get_value(secret_name, "user"))
        .unwrap_or_else(|| "root".to_string());

    let key_file = get_value(secret_name, "key_file");
    let password = get_value(secret_name, "password");

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
// DuckDB Secrets Manager Integration
// ---------------------------------------------------------------------------

/// DuckDB secret type names that map to DuckDB's native CREATE SECRET types.
/// For S3/HTTP/GCS protocols, users should prefer DuckDB's native secrets:
///
/// ```sql
/// -- DuckDB native S3 secret (preferred for S3 operations)
/// CREATE SECRET my_s3 (TYPE s3, KEY_ID 'AKIA...', SECRET '...', REGION 'us-east-1');
///
/// -- DuckDB native HTTP secret (preferred for HTTP auth)
/// CREATE SECRET my_http (TYPE http, BEARER_TOKEN 'token...');
///
/// -- duck_net secrets for protocols DuckDB doesn't natively support
/// SELECT duck_net_add_secret('my_smtp', 'smtp', '{"host":"smtp.example.com","username":"u","password":"p"}');
/// SELECT duck_net_add_secret('my_redis', 'redis', '{"password":"secret"}');
/// ```
///
/// duck_net's S3 functions accept the same key names as DuckDB's native S3 secrets
/// (KEY_ID, SECRET, REGION, ENDPOINT) so credentials can be managed consistently.
/// DuckDB Secrets Manager bridge.
///
/// Provides interoperability with DuckDB's native `CREATE SECRET` mechanism.
/// For S3/HTTP/GCS/R2 protocols, users should prefer DuckDB's native secrets
/// which are managed by the httpfs extension:
///
/// ```sql
/// -- DuckDB native S3 secret (preferred for S3 operations)
/// CREATE SECRET my_s3 (TYPE s3, KEY_ID 'AKIA...', SECRET '...', REGION 'us-east-1');
///
/// -- DuckDB native HTTP secret (preferred for HTTP auth)
/// CREATE SECRET my_http (TYPE http, BEARER_TOKEN 'token...');
///
/// -- Persistent secrets survive DuckDB restarts (stored in ~/.duckdb/stored_secrets)
/// CREATE PERSISTENT SECRET my_s3_prod (TYPE s3, KEY_ID '...', SECRET '...', SCOPE 's3://prod-bucket');
///
/// -- duck_net secrets for protocols DuckDB doesn't natively support
/// SELECT duck_net_add_secret('my_smtp', 'smtp', '{"host":"smtp.example.com","username":"u","password":"p"}');
/// SELECT duck_net_add_secret('my_redis', 'redis', '{"password":"secret"}');
/// ```
///
/// duck_net's S3 functions accept the same key names as DuckDB's native S3 secrets
/// (KEY_ID, SECRET, REGION, ENDPOINT) so credentials can be managed consistently.
///
/// ## Supported DuckDB Secret Types
///
/// | Secret type | Service / protocol | Extension |
/// |---|---|---|
/// | `s3` | AWS S3 | httpfs |
/// | `gcs` | Google Cloud Storage | httpfs |
/// | `r2` | Cloudflare R2 | httpfs |
/// | `http` | HTTP and HTTPS | httpfs |
/// | `azure` | Azure Blob Storage | azure |
///
/// ## Scoped Secrets
///
/// DuckDB supports scoped secrets that apply to specific path prefixes:
///
/// ```sql
/// CREATE SECRET org1_secret (TYPE s3, KEY_ID '...', SECRET '...', SCOPE 's3://org1-bucket');
/// CREATE SECRET org2_secret (TYPE s3, KEY_ID '...', SECRET '...', SCOPE 's3://org2-bucket');
/// -- Queries automatically pick the correct secret based on path prefix
/// ```
///
/// ## Security Notes
///
/// - DuckDB persistent secrets are stored in **unencrypted** binary format on disk.
/// - duck_net's in-memory secrets are zeroized on clear and never written to disk.
/// - For maximum security, use duck_net's in-memory secrets for sensitive protocols
///   and DuckDB's native secrets for S3/HTTP where the httpfs extension manages them.
/// - Use `FROM duckdb_secrets()` to list active DuckDB secrets (values are redacted).
/// - Use `FROM which_secret('s3://path', 's3')` to see which secret applies to a path.
#[allow(dead_code)]
pub mod duckdb_compat {
    /// Key name mapping: DuckDB native S3 secret field names.
    /// These match the `CREATE SECRET (TYPE s3, ...)` parameter names.
    pub const S3_KEY_ID: &str = "key_id";
    pub const S3_SECRET: &str = "secret";
    pub const S3_REGION: &str = "region";
    pub const S3_ENDPOINT: &str = "endpoint";
    pub const S3_SESSION_TOKEN: &str = "session_token";
    pub const S3_USE_SSL: &str = "use_ssl";
    pub const S3_URL_STYLE: &str = "url_style";

    /// Key name mapping: DuckDB native HTTP secret field names.
    /// These match the `CREATE SECRET (TYPE http, ...)` parameter names.
    pub const HTTP_BEARER_TOKEN: &str = "bearer_token";
    pub const HTTP_EXTRA_HEADERS: &str = "extra_http_headers";

    /// Key name mapping: DuckDB native GCS secret field names.
    /// GCS uses HMAC keys via `CREATE SECRET (TYPE gcs, ...)`.
    pub const GCS_KEY_ID: &str = "key_id";
    pub const GCS_SECRET: &str = "secret";

    /// Key name mapping: DuckDB native R2 secret field names.
    /// R2 uses `CREATE SECRET (TYPE r2, ...)` with an ACCOUNT_ID.
    pub const R2_KEY_ID: &str = "key_id";
    pub const R2_SECRET: &str = "secret";
    pub const R2_ACCOUNT_ID: &str = "account_id";

    /// Generate a SQL statement that creates a DuckDB-native secret from a
    /// duck_net secret, enabling interoperability.
    ///
    /// Returns `None` if the secret type is not a DuckDB-native type.
    pub fn to_duckdb_create_sql(
        name: &str,
        secret_type: &str,
        values: &std::collections::HashMap<String, String>,
    ) -> Option<String> {
        let st = secret_type.to_lowercase();
        match st.as_str() {
            "s3" => {
                let mut parts = vec![format!("CREATE SECRET {name} (TYPE s3")];
                if let Some(v) = values.get(S3_KEY_ID) {
                    parts.push(format!(", KEY_ID '{}'", escape_sql_string(v)));
                }
                if let Some(v) = values.get(S3_SECRET) {
                    parts.push(format!(", SECRET '{}'", escape_sql_string(v)));
                }
                if let Some(v) = values.get(S3_REGION) {
                    parts.push(format!(", REGION '{}'", escape_sql_string(v)));
                }
                if let Some(v) = values.get(S3_ENDPOINT) {
                    parts.push(format!(", ENDPOINT '{}'", escape_sql_string(v)));
                }
                if let Some(v) = values.get(S3_SESSION_TOKEN) {
                    parts.push(format!(", SESSION_TOKEN '{}'", escape_sql_string(v)));
                }
                parts.push(")".to_string());
                Some(parts.join(""))
            }
            "http" => {
                let mut parts = vec![format!("CREATE SECRET {name} (TYPE http")];
                if let Some(v) = values.get(HTTP_BEARER_TOKEN) {
                    parts.push(format!(", BEARER_TOKEN '{}'", escape_sql_string(v)));
                }
                parts.push(")".to_string());
                Some(parts.join(""))
            }
            "gcs" => {
                let mut parts = vec![format!("CREATE SECRET {name} (TYPE gcs")];
                if let Some(v) = values.get(GCS_KEY_ID) {
                    parts.push(format!(", KEY_ID '{}'", escape_sql_string(v)));
                }
                if let Some(v) = values.get(GCS_SECRET) {
                    parts.push(format!(", SECRET '{}'", escape_sql_string(v)));
                }
                parts.push(")".to_string());
                Some(parts.join(""))
            }
            "r2" => {
                let mut parts = vec![format!("CREATE SECRET {name} (TYPE r2")];
                if let Some(v) = values.get(R2_KEY_ID) {
                    parts.push(format!(", KEY_ID '{}'", escape_sql_string(v)));
                }
                if let Some(v) = values.get(R2_SECRET) {
                    parts.push(format!(", SECRET '{}'", escape_sql_string(v)));
                }
                if let Some(v) = values.get(R2_ACCOUNT_ID) {
                    parts.push(format!(", ACCOUNT_ID '{}'", escape_sql_string(v)));
                }
                parts.push(")".to_string());
                Some(parts.join(""))
            }
            _ => None,
        }
    }

    /// Escape a string value for inclusion in a SQL string literal.
    /// Doubles single quotes per SQL standard.
    fn escape_sql_string(s: &str) -> String {
        s.replace('\'', "''")
    }
}
