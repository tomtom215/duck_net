# Security Architecture

duck_net is a DuckDB extension that exposes 49+ network protocols to SQL queries. This document describes the security architecture, threat model, and hardening measures implemented to protect against misuse.

## Threat Model

Running network operations from SQL introduces unique risks:

1. **SSRF (Server-Side Request Forgery)** - Queries could target internal infrastructure (cloud metadata endpoints, local services)
2. **Credential Exposure** - Credentials in SQL queries appear in logs, history, and error messages
3. **Injection Attacks** - User-supplied values could inject into protocol messages (LDAP, XML, JSON, SMTP headers)
4. **Resource Exhaustion** - Unbounded responses or recursive parsing could cause OOM/stack overflow
5. **Command Injection** - SSH commands could execute arbitrary shell commands on remote hosts
6. **Path Traversal** - File paths in FTP/SFTP/WebDAV could escape intended directories

## Security Controls

### SSRF Protection (CWE-918)

All 49+ protocols validate destination hosts against private/reserved IP ranges before connecting. This blocks access to:

- Loopback addresses (`127.0.0.0/8`, `::1`)
- Private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- Link-local (`169.254.0.0/16`, `fe80::/10`) - blocks cloud metadata endpoints
- CGN (`100.64.0.0/10`), benchmark (`198.18.0.0/15`), documentation ranges
- IPv6 unique local (`fc00::/7`)
- IPv4-mapped IPv6 addresses (checks the embedded IPv4)

DNS resolution is performed **before** connection to prevent DNS rebinding attacks. Failed DNS resolution is blocked by default.

```sql
-- Disable SSRF protection for local development only
SELECT duck_net_set_ssrf_protection(false);
```

### Credential Management

#### duck_net Secrets Manager

Credentials should **never** appear directly in SQL queries. duck_net provides an in-memory secrets manager:

```sql
-- Store credentials (never appears in query logs)
SELECT duck_net_add_secret('my_smtp', 'smtp', '{"host":"smtp.example.com","username":"user","password":"pass"}');

-- Use by reference
SELECT smtp_send_secret('my_smtp', 'from@example.com', 'to@example.com', 'Subject', 'Body');

-- Clear when done (zeroizes memory)
SELECT duck_net_clear_secret('my_smtp');
```

Secrets-aware functions are available for: S3, HTTP, SMTP, SSH, IMAP, Vault, Consul, InfluxDB, SNMP, RADIUS, Redis, LDAP.

#### DuckDB Native Secrets

For S3/HTTP/GCS protocols, prefer DuckDB's native `CREATE SECRET` with the httpfs extension:

```sql
-- DuckDB native S3 secret (preferred for S3 operations)
CREATE SECRET my_s3 (TYPE s3, KEY_ID 'AKIA...', SECRET '...', REGION 'us-east-1');

-- DuckDB native HTTP secret (for bearer token auth)
CREATE SECRET my_http (TYPE http, BEARER_TOKEN 'token...');
```

duck_net's secrets manager covers protocols DuckDB does not natively support (SMTP, SSH, IMAP, LDAP, Redis, MQTT, etc.).

#### Credential Scrubbing (CWE-532)

Error messages are scrubbed to remove credential patterns:

- URLs: `scheme://user:pass@host` becomes `scheme://***@host`
- Parameter patterns: `password=value` becomes `password=********`
- Sensitive keys in secrets are redacted when listing

#### Zeroization (CWE-316)

When secrets are cleared, values are overwritten with zeros using volatile writes before being freed. This prevents credentials from lingering in freed memory.

### Input Validation

| Category | Protection | CWE |
|----------|-----------|-----|
| URL length | Max 65,536 characters | CWE-400 |
| Hostname format | Alphanumeric, dots, hyphens, colons only; max 253 chars | CWE-918 |
| Port range | Must be 1-65535 | - |
| Path traversal | `..` components blocked in all file path parameters | CWE-22 |
| SSH commands | Shell metacharacters (`;`, `\|`, `&`, `$`, `` ` ``) blocked in strict mode | CWE-78 |
| SMTP headers | CRLF injection sanitized, dot-stuffing in body | CWE-93 |
| LDAP filters | RFC 4515 escaping available for filter values | CWE-90 |
| CalDAV timestamps | ISO 8601 format validation prevents XML injection | CWE-91 |
| NATS credentials | JSON-escaped to prevent protocol injection | CWE-116 |
| Elasticsearch indices | Validated against path traversal, restricted character set | CWE-22 |
| SNMP community strings | Length-limited (max 255), null byte rejection | CWE-400 |

### Response Size Limits (CWE-400)

| Protocol | Max Response Size |
|----------|------------------|
| HTTP/HTTPS | 256 MiB |
| gRPC | 16 MiB |
| WebSocket | 16 MiB |
| Redis | 16 MiB |
| ZeroMQ | 16 MiB |
| IMAP | 10 MiB |
| NATS | 16 MiB |
| SNMP | 65,535 bytes |
| SIP | 4,096 bytes |
| RADIUS | 4,096 bytes |

Redis RESP array parsing is depth-limited (max 8 levels) and element-limited (max 100,000 elements) to prevent stack overflow and memory exhaustion.

### Timeouts

All network operations enforce timeouts to prevent hanging queries:

| Protocol Category | Default Timeout |
|-------------------|----------------|
| HTTP/HTTPS | 30 seconds (configurable) |
| TCP protocols (Redis, NATS, SMTP, etc.) | 10 seconds |
| UDP protocols (DNS, NTP, SNMP, STUN, SIP) | 5-10 seconds |
| SSH/SFTP | 30 seconds |

```sql
-- Configure HTTP timeout
SELECT duck_net_set_timeout(60);
```

### TLS

- All TLS connections use **rustls** (pure Rust, no OpenSSL dependency)
- Certificate verification via **webpki-roots** (Mozilla's trusted CA bundle)
- No fallback to plaintext when TLS is expected (SMTP STARTTLS verifies upgrade)
- SSH connections verify host keys against `~/.ssh/known_hosts` (TOFU on first connect)

### Rate Limiting

```sql
-- Global rate limit
SELECT duck_net_set_rate_limit(10); -- 10 requests/second

-- Per-domain rate limits
SELECT duck_net_set_domain_rate_limits('api.example.com:5,*.internal.com:2');
```

### Cryptographic Random Number Generation

All protocol operations requiring randomness (RADIUS authenticators, SIP Call-IDs/branches, STUN transaction IDs) use the OS CSPRNG via the `getrandom` crate. No weak PRNG is used for security-relevant operations.

## Audit Checklist

Run `duck_net_security_status()` to get a JSON summary of current security configuration:

```sql
SELECT duck_net_security_status();
```

Returns:
```json
{
  "ssrf_protection": true,
  "ssh_strict_commands": true,
  "secrets_stored": 0,
  "global_rate_limit_rps": 0,
  "http_timeout_secs": 30,
  "http_max_retries": 0,
  "duckdb_native_secrets": "Use CREATE SECRET (TYPE s3/http) for S3 and HTTP protocols",
  "duck_net_secrets": "Use duck_net_add_secret() for SMTP, SSH, LDAP, Redis, MQTT, etc."
}
```

## Reporting Security Issues

If you discover a security vulnerability, please report it responsibly by opening a private security advisory on the GitHub repository.

## Design Principles

1. **Secure by default** - SSRF protection, SSH strict mode, and TLS verification are enabled by default
2. **Defense in depth** - Multiple layers of validation (URL parsing, hostname validation, IP resolution, SSRF check)
3. **Least privilege** - Functions only expose the minimum capability needed
4. **No telemetry** - Zero phone-home tracking, zero external analytics
5. **Memory safety** - Written in Rust with no `unsafe` outside of FFI boundary code
6. **Credential hygiene** - Secrets manager, credential scrubbing, zeroization
