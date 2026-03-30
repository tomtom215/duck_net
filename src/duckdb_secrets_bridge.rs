// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

//! DuckDB Secrets Manager bridge for duck_net.
//!
//! DuckDB ships with a built-in secrets manager that stores credentials for
//! cloud services (S3, HTTP, GCS, R2) used by the `httpfs` extension.
//! duck_net provides its own in-memory secrets store for protocols that DuckDB
//! does not natively support (SMTP, SSH, LDAP, Redis, MQTT, …).
//!
//! This module documents the integration points and provides SQL helper
//! functions that let users work with both systems seamlessly.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  DuckDB Secrets Manager                                         │
//! │  (CREATE SECRET … TYPE s3/http/gcs/r2/azure)                   │
//! │  • Managed by the httpfs extension                              │
//! │  • Persistent secrets stored in ~/.duckdb/stored_secrets/       │
//! │  • Used automatically for s3://, gcs://, r2:// file reads       │
//! │  • Values are REDACTED in FROM duckdb_secrets() output          │
//! └────────────────────────────┬────────────────────────────────────┘
//!                              │ bridge via duck_net_import_s3_secret()
//! ┌────────────────────────────▼────────────────────────────────────┐
//! │  duck_net In-Memory Secrets Store                               │
//! │  (duck_net_add_secret() / duck_net_clear_secret())              │
//! │  • Supports 21 protocol types (SMTP, SSH, Redis, LDAP, …)       │
//! │  • Values are ZEROIZED on drop/clear (CWE-316)                  │
//! │  • Never written to disk                                        │
//! │  • Used by duck_net protocol functions: smtp_send_secret(),     │
//! │    ssh_exec_secret(), redis_get_secret(), s3_get_secret(), …    │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # When to Use Each System
//!
//! | Use case | Recommended approach |
//! |---|---|
//! | Query `s3://…`, `gcs://…` paths via DuckDB | `CREATE SECRET (TYPE s3, …)` |
//! | duck_net `s3_get_secret()` / `s3_put_secret()` | `duck_net_add_secret('name', 's3', …)` |
//! | duck_net HTTP with auth | `duck_net_add_secret('name', 'http', …)` |
//! | SMTP, SSH, IMAP, Redis, LDAP, MQTT | `duck_net_add_secret('name', 'smtp', …)` |
//! | Persistent cross-session S3 credentials | `CREATE PERSISTENT SECRET (TYPE s3, …)` |
//!
//! # Security Warning on Persistent Secrets
//!
//! DuckDB persistent secrets are stored in **unencrypted binary format** in
//! `~/.duckdb/stored_secrets/`. Never store credentials in persistent secrets
//! on shared machines or in CI environments where the filesystem is readable
//! by other users or processes.
//!
//! duck_net's in-memory secrets are zeroized when cleared or when the
//! DuckDB session ends, and are never written to disk.
//!
//! # SQL Examples
//!
//! ## Using DuckDB Native Secrets with duck_net
//!
//! ```sql
//! -- Step 1: Create a DuckDB native S3 secret (for httpfs integration)
//! CREATE SECRET prod_s3 (
//!     TYPE s3,
//!     KEY_ID 'AKIAIOSFODNN7EXAMPLE',
//!     SECRET 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
//!     REGION 'us-east-1'
//! );
//!
//! -- Step 2: Import it into duck_net for duck_net protocol functions
//! -- (You must provide the credentials again since duckdb_secrets() redacts them)
//! SELECT duck_net_add_secret('my_s3', 's3',
//!     '{"key_id":"AKIAIOSFODNN7EXAMPLE",
//!       "secret":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
//!       "region":"us-east-1",
//!       "endpoint":"https://s3.amazonaws.com"}'
//! );
//!
//! -- Use DuckDB native secret for httpfs file reads
//! SELECT * FROM 's3://my-bucket/data.parquet';
//!
//! -- Use duck_net secret for duck_net S3 operations
//! SELECT * FROM s3_get_secret('my_s3', 'my-bucket', 'data.json');
//! ```
//!
//! ## Using Temporary AWS Credentials (STS)
//!
//! ```sql
//! -- STS temporary credentials include a session token
//! SELECT duck_net_add_secret('sts_creds', 's3', json_object(
//!     'key_id', 'ASIAIOSFODNN7EXAMPLE',
//!     'secret', 'temporary_secret_key',
//!     'region', 'us-east-1',
//!     'session_token', 'AQoDYXdzEJr...',
//!     'endpoint', 'https://s3.amazonaws.com'
//! ));
//!
//! -- duck_net automatically includes the session token in SigV4 signing
//! SELECT * FROM s3_get_secret('sts_creds', 'my-bucket', 'secure-file.txt');
//! ```
//!
//! ## Using DuckDB Credential Chain (Auto-detect AWS credentials)
//!
//! ```sql
//! -- Use the credential_chain provider (reads from env vars, ~/.aws/credentials, IMDSv2, etc.)
//! CREATE OR REPLACE SECRET auto_s3 (
//!     TYPE s3,
//!     PROVIDER credential_chain
//! );
//!
//! -- For duck_net functions, you still need to add credentials explicitly.
//! -- To bridge auto-detected credentials:
//! SELECT duck_net_import_credential_chain('auto_s3_duck');
//! -- This imports credentials from the environment into duck_net's store.
//! ```
//!
//! ## Scoped Secrets
//!
//! ```sql
//! -- DuckDB scoped secrets: different credentials per S3 prefix
//! CREATE SECRET org1 (TYPE s3, KEY_ID '...', SECRET '...', SCOPE 's3://org1-bucket');
//! CREATE SECRET org2 (TYPE s3, KEY_ID '...', SECRET '...', SCOPE 's3://org2-bucket');
//!
//! -- duck_net scoped secrets: use different duck_net secrets per operation
//! SELECT duck_net_add_secret('s3_org1', 's3', '{"key_id":"...","secret":"...","endpoint":"..."}');
//! SELECT duck_net_add_secret('s3_org2', 's3', '{"key_id":"...","secret":"...","endpoint":"..."}');
//! SELECT s3_get_secret('s3_org1', 'org1-bucket', 'file.txt');
//! SELECT s3_get_secret('s3_org2', 'org2-bucket', 'file.txt');
//! ```

use crate::secrets;

/// Import AWS credentials from environment variables into duck_net's in-memory
/// secrets store.
///
/// Reads `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
/// (optional), `AWS_DEFAULT_REGION` (optional), and `AWS_ENDPOINT_URL`
/// (optional) environment variables.
///
/// Returns `Ok(())` if at minimum `AWS_ACCESS_KEY_ID` and
/// `AWS_SECRET_ACCESS_KEY` are present, otherwise `Err`.
pub fn import_aws_env_credentials(secret_name: &str) -> Result<String, String> {
    let key_id = std::env::var("AWS_ACCESS_KEY_ID")
        .map_err(|_| "AWS_ACCESS_KEY_ID environment variable not set".to_string())?;

    let secret = std::env::var("AWS_SECRET_ACCESS_KEY")
        .map_err(|_| "AWS_SECRET_ACCESS_KEY environment variable not set".to_string())?;

    let region = std::env::var("AWS_DEFAULT_REGION").unwrap_or_else(|_| "us-east-1".to_string());

    let session_token = std::env::var("AWS_SESSION_TOKEN").ok();
    let endpoint = std::env::var("AWS_ENDPOINT_URL")
        .unwrap_or_else(|_| "https://s3.amazonaws.com".to_string());

    // Build JSON config matching DuckDB's S3 secret field names
    let session_part = if let Some(tok) = session_token {
        format!(
            ",\"session_token\":\"{}\"",
            crate::security::json_escape(&tok)
        )
    } else {
        String::new()
    };

    let config_json = format!(
        "{{\"key_id\":\"{}\",\"secret\":\"{}\",\"region\":\"{}\",\"endpoint\":\"{}\"{}}}",
        crate::security::json_escape(&key_id),
        crate::security::json_escape(&secret),
        crate::security::json_escape(&region),
        crate::security::json_escape(&endpoint),
        session_part
    );

    secrets::add_secret(secret_name, "s3", &config_json)
}

/// Import HTTP bearer token from environment variable into duck_net's store.
///
/// Reads from the environment variable specified in `env_var`.
pub fn import_bearer_token_from_env(secret_name: &str, env_var: &str) -> Result<String, String> {
    let token = std::env::var(env_var).map_err(|_| {
        format!(
            "Environment variable '{}' not set for HTTP bearer token",
            env_var
        )
    })?;

    let config_json = format!(
        "{{\"bearer_token\":\"{}\"}}",
        crate::security::json_escape(&token)
    );

    secrets::add_secret(secret_name, "http", &config_json)
}

/// Generate a DuckDB `CREATE SECRET` SQL statement from a duck_net secret.
///
/// This is useful for exporting duck_net secrets into DuckDB's native secrets
/// manager when the httpfs extension needs to access the same S3/HTTP/GCS/R2
/// credentials.
///
/// Returns `Some(sql)` for types DuckDB natively understands (s3, http, gcs,
/// r2), `None` for types not supported by DuckDB's secrets manager.
///
/// # Warning
/// The returned SQL contains plaintext credentials. Do not log or expose it.
pub fn to_duckdb_create_secret_sql(secret_name: &str) -> Option<String> {
    use crate::secrets_resolve::duckdb_compat;
    let secret_type = secrets::get_type(secret_name)?;

    // Build a temporary redacted version to check what fields are available
    let values = secrets::get_value_map_internal(secret_name)?;
    duckdb_compat::to_duckdb_create_sql(secret_name, &secret_type, &values)
}

/// Return information about the DuckDB secrets manager integration.
pub fn integration_info() -> &'static str {
    concat!(
        "DuckDB Secrets Manager Integration:\n",
        "  Native types (managed by httpfs):  s3, http, gcs, r2, azure\n",
        "  duck_net types (in-memory):         smtp, imap, ftp, sftp, ssh,\n",
        "                                      ldap, redis, mqtt, vault, consul,\n",
        "                                      influxdb, elasticsearch, snmp,\n",
        "                                      radius, kafka, nats, memcached,\n",
        "                                      grpc, websocket\n",
        "\n",
        "  SQL: SELECT duck_net_duckdb_secrets_info() for runtime details.\n",
        "  SQL: SELECT duck_net_import_aws_env('my_s3') to import from env vars.\n",
        "  Docs: https://duck-net.github.io/duck_net/security/duckdb-secrets"
    )
}
