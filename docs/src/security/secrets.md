# Secrets Management

duck_net provides an in-memory secrets manager that keeps credentials out of SQL query text and log files.

## Overview

```sql
-- Store a secret
SELECT duck_net_add_secret('name', 'type', '{"key": "value", ...}');

-- Use a secret with protocol functions
SELECT smtp_send_secret('name', 'from@example.com', 'to@example.com', 'Subject', 'Body');

-- List secrets (values are redacted)
FROM duck_net_secrets();

-- View a specific secret (sensitive values redacted)
SELECT duck_net_secret_redacted('name');

-- Get a specific value from a secret
SELECT duck_net_secret('name', 'key');

-- Remove a secret (zeroized in memory)
SELECT duck_net_clear_secret('name');

-- Remove all secrets
SELECT duck_net_clear_all_secrets();
```

## Supported Secret Types

| Type | Protocol | Required Keys | Optional Keys |
|------|----------|--------------|---------------|
| `smtp` | Email sending | `host` | `port`, `username`, `password`, `use_tls` |
| `imap` | Email reading | `username`, `password` | -- |
| `ssh` | Remote execution | `key_file` or `password` | `username` |
| `ftp` | File transfer | -- | `username`, `password` |
| `sftp` | Secure file transfer | `key_file` or `password` | `username` |
| `ldap` | Directory services | `username`, `password` | -- |
| `redis` | Cache/KV store | `host` | `port`, `password`, `db` |
| `s3` | Object storage | `key_id`, `secret` | `region`, `endpoint`, `session_token` |
| `http` | HTTP APIs | `bearer_token` or `username`+`password` | -- |
| `vault` | HashiCorp Vault | `token` | -- |
| `consul` | Service discovery | `token` | -- |
| `influxdb` | Time series | `token` | -- |
| `elasticsearch` | Search | `token` or `username`+`password` | -- |
| `snmp` | Network management | `community` | -- |
| `radius` | Authentication | `shared_secret` | -- |
| `kafka` | Messaging | -- | `username`, `password` |
| `nats` | Messaging | -- | `token`, `username`, `password` |
| `mqtt` | IoT messaging | -- | `username`, `password` |
| `grpc` | RPC | -- | `token` |
| `websocket` | Real-time | -- | `token` |
| `memcached` | Caching | -- | `host`, `port` |

## Secret-Aware Functions

Each protocol has a `_secret` variant that uses stored credentials:

```sql
-- S3 with secrets
SELECT s3_get_secret('my_s3', 'bucket', 'key');
SELECT s3_put_secret('my_s3', 'bucket', 'key', 'data');
SELECT s3_list_secret('my_s3', 'bucket', 'prefix');

-- HTTP with secrets
SELECT http_get_secret('my_api', 'https://api.example.com/data');
SELECT http_post_secret('my_api', 'https://api.example.com/data', '{"key": "value"}');

-- SSH with secrets
SELECT ssh_exec_secret('my_server', 'hostname', 'uptime');

-- Redis with secrets
SELECT redis_get_secret('my_redis', 'cache_key');
SELECT redis_set_secret('my_redis', 'cache_key', 'value');

-- LDAP with secrets
SELECT ldap_search_secret('my_ldap', 'ldaps://ldap.example.com', 'dc=example,dc=com', '(cn=*)', 'cn,mail');
```

## Security Properties

- **In-memory only**: Secrets are never written to disk
- **Zeroization**: Secret values are scrubbed using the `zeroize` crate, which guarantees the zeroing writes are not optimized away by the compiler (CWE-316)
- **ZeroizeOnDrop**: Secrets are automatically zeroized when dropped, even on unexpected exits
- **Bounded storage**: Maximum 1,024 secrets, 64 KiB per secret
- **Redacted display**: Sensitive keys (`password`, `secret`, `token`, `api_key`, `private_key`, `client_secret`, etc.) are always redacted
- **Name validation**: Secret names must be 1-128 characters, alphanumeric with underscores, hyphens, and dots
- **Error scrubbing**: Credential values are scrubbed from all error messages, including Authorization headers and AUTH PLAIN payloads

## AWS Temporary Credentials (STS)

For assumed roles, ECS task roles, Lambda execution roles, and other STS-based credentials, include `session_token` in the secret:

```sql
SELECT duck_net_add_secret('sts_role', 's3', json_object(
    'key_id',        'ASIAIOSFODNN7EXAMPLE',
    'secret',        'temporary_secret_key',
    'region',        'us-east-1',
    'session_token', 'AQoDYXdzEJr...'
));
SELECT * FROM s3_get_secret('sts_role', 'my-bucket', 'data.json');
```

Or load credentials directly from the standard AWS environment variables:

```sql
-- Reads AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN,
-- AWS_DEFAULT_REGION, and AWS_ENDPOINT_URL
SELECT duck_net_import_aws_env('my_s3');
```

## Security Warning: Raw Credential Access

`duck_net_secret(name, key)` returns the raw credential value and emits a `SECRET_VALUE_EXPOSED` HIGH-severity warning. Prefer protocol-specific `_secret()` functions to avoid exposing credentials directly.

## DuckDB Native Secrets

For S3, HTTP, GCS, and R2 protocols, prefer DuckDB's native secrets manager. See [DuckDB Native Secrets](./duckdb-secrets.md) for details.

## Security Utilities

duck_net exposes utility functions for credential handling:

```sql
-- Scrub credentials from a URL
SELECT duck_net_scrub_url('redis://password@host:6379');
-- Returns: redis://***@host:6379

-- Scrub credentials from an error message
SELECT duck_net_scrub_error('Connection failed: password=secret123 at host');
-- Returns: Connection failed: password=******** at host

-- View complete security configuration
SELECT duck_net_security_status();
```
