# Hardening Guide

This guide covers best practices for deploying duck_net securely in production environments.

## Production Readiness Checklist

### Essential (Do Before Deployment)

- [ ] SSRF protection is enabled (default): `SELECT duck_net_security_status();`
- [ ] SSH strict mode is enabled (default)
- [ ] All secrets use `duck_net_add_secret()` instead of inline credentials
- [ ] TLS variants used for all protocols (`ftps://`, `ldaps://`, `imaps://`, `smtps://`, etc.)
- [ ] Security warnings reviewed: `FROM duck_net_security_warnings();`
- [ ] No `PLAINTEXT_*` or `NO_AUTH_*` warnings in production
- [ ] No `S3_OVER_HTTP` warnings (S3 endpoints must use HTTPS)
- [ ] No `HTTP_REDIRECT_HTTPS_TO_HTTP` warnings (redirects must not downgrade from HTTPS)

### Recommended

- [ ] Rate limiting configured for external APIs: `SELECT duck_net_set_rate_limit(10.0);`
- [ ] Domain-specific rate limits for partner APIs
- [ ] Timeouts configured: `SELECT duck_net_set_timeout(30);`
- [ ] DuckDB native secrets used for S3/HTTP/GCS/R2
- [ ] Persistent secrets directory permissions restricted (`chmod 700 ~/.duckdb/stored_secrets`)
- [ ] Network egress filtering applied (firewall rules)
- [ ] Use `duck_net_import_aws_env()` for AWS environments instead of hardcoded keys
- [ ] STS/assumed-role credentials include `session_token` field in duck_net secrets

### Advanced

- [ ] DNS resolution controlled (prevents DNS rebinding)
- [ ] Monitoring tracks unusual protocol usage patterns
- [ ] Secret rotation procedures documented
- [ ] Audit logging enabled for credential access

## Protocol-Specific Hardening

### HTTP / HTTPS
- Always use `https://` for production endpoints
- Use `duck_net_set_timeout()` to prevent hanging connections
- Configure retries with `duck_net_set_retries()` for resilience
- Use rate limiting: `duck_net_set_rate_limit()` and `duck_net_set_domain_rate_limits()`
- Tokens sent over `http://` trigger a `CRITICAL` severity warning
- Redirect chains are validated at each hop; HTTPS→HTTP downgrades emit `HTTP_REDIRECT_HTTPS_TO_HTTP`
- HTTP header names and values are validated against RFC 7230 (CRLF injection blocked)

### SSH
- Keep strict mode enabled: `SELECT duck_net_set_ssh_strict(true);`
- Pre-populate `~/.ssh/known_hosts` to avoid TOFU vulnerabilities
- Use key-based authentication over password authentication
- Use the secret-aware `ssh_exec_secret()` to avoid credentials in queries
- Private key files should have `600` permissions

### Email (SMTP / IMAP)
- Always use `smtps://` or STARTTLS (enforced by duck_net for authenticated SMTP)
- Always use `imaps://` for IMAP connections
- Store credentials with `duck_net_add_secret()` of type `smtp` or `imap`
- Plaintext IMAP/SMTP with credentials triggers security warnings

### Redis
- Use `rediss://` (Redis over TLS) in production
- Always set a password: `redis://password@host:6379`
- Store credentials with `duck_net_add_secret()` of type `redis`
- Consider using Redis ACLs for command-level access control

### LDAP
- Always use `ldaps://` in production
- Bind with a dedicated service account, not admin credentials
- Use the secret-aware `ldap_search_secret()` function
- LDAP filters are validated for balanced parentheses and null bytes
- Plaintext LDAP bind triggers security warnings

### S3 / Cloud Storage
- Prefer DuckDB's native `CREATE SECRET (TYPE s3)` for S3 credentials
- Use scoped secrets for multi-account environments
- Enable SSE-KMS via the `KMS_KEY_ID` option for server-side encryption
- Use `credential_chain` provider for AWS environments (no hardcoded keys)
- S3 endpoints **must** use HTTPS; `http://` endpoints emit `S3_OVER_HTTP` HIGH warning
- For STS/assumed roles, include `session_token` in the secret to sign `x-amz-security-token`
- Use `duck_net_import_aws_env()` to load credentials from environment automatically:

```sql
SELECT duck_net_import_aws_env('my_s3');
SELECT * FROM s3_get_secret('my_s3', 'my-bucket', 'data.json');
```

### Messaging (MQTT, Kafka, AMQP, NATS)
- Use TLS variants: `mqtts://`, `amqps://`, `nats+tls://`
- Configure authentication for all messaging brokers
- Kafka: Use a dedicated Kafka extension with SASL/TLS for production

### Infrastructure (SNMP, Syslog, IPMI)
- **SNMP**: SNMPv2c community strings are sent in plaintext; use for read-only monitoring only
- **Syslog**: UDP syslog has no encryption; route through a TLS-capable syslog relay
- **IPMI**: v1.5 has no authentication; restrict network access to BMC interfaces
- **RADIUS**: Shared secrets should be long and random

### Memcached
- Memcached has **no built-in authentication**; only deploy on trusted networks
- Consider using Redis with auth as an alternative
- All Memcached connections trigger a `NO_AUTH_MEMCACHED` warning

### SCP / SFTP
- Both enforce SSRF protection and path traversal validation
- Use key-based authentication over passwords
- File paths are checked for `..` traversal, null bytes, and length limits

## Network Segmentation

For maximum security, deploy duck_net in an environment where:
1. SSRF protection remains enabled (blocks private IPs)
2. Outbound network access is restricted to known endpoints
3. DNS resolution is controlled (prevents DNS rebinding)
4. Monitoring tracks unusual protocol usage patterns

## CI / Airgapped Environments

For environments that legitimately need to reach private IPs:

```sql
-- Disable SSRF protection for local development or CI
SELECT duck_net_set_ssrf_protection(false);

-- Suppress security warnings in CI output
SELECT duck_net_set_security_warnings(false);
```

> **Warning**: Never disable SSRF protection in production. Use these settings only for development, CI pipelines, or airgapped environments where all network destinations are trusted.

## DuckDB Persistent Secrets Warning

DuckDB persistent secrets (`CREATE PERSISTENT SECRET`) are stored in **unencrypted binary format** on disk at `~/.duckdb/stored_secrets/`. Consider:

- Restricting directory permissions: `chmod 700 ~/.duckdb/stored_secrets/`
- Using duck_net's in-memory secrets for highly sensitive credentials
- Rotating persistent secrets periodically
- Not using persistent secrets in shared or multi-tenant environments

## Auditing Security Status

```sql
-- View complete security configuration
SELECT duck_net_security_status();

-- Review all security warnings
FROM duck_net_security_warnings();

-- Check which DuckDB secret applies to a path
FROM which_secret('s3://my-bucket/file.parquet', 's3');

-- List all DuckDB secrets (values redacted)
FROM duckdb_secrets();

-- List all duck_net secrets (values redacted)
FROM duck_net_secrets();
```
