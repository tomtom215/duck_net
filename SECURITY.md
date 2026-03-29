# Security Architecture

duck_net is a DuckDB extension that exposes 49+ network protocols to SQL queries. This document describes the security architecture, threat model, and hardening measures implemented to protect against misuse.

## Threat Model

Running network operations from SQL introduces unique risks:

1. **SSRF (Server-Side Request Forgery)** — Queries could target internal infrastructure (cloud metadata endpoints, local services)
2. **Credential Exposure** — Credentials in SQL queries appear in logs, history, and error messages
3. **Injection Attacks** — User-supplied values could inject into protocol messages (LDAP, XML, JSON, SMTP headers, SOAP actions)
4. **Resource Exhaustion** — Unbounded responses or recursive parsing could cause OOM/stack overflow
5. **Command Injection** — SSH commands could execute arbitrary shell commands on remote hosts
6. **Path Traversal** — File paths in FTP/SFTP/WebDAV could escape intended directories
7. **Open Redirect** — Pagination "next URL" could redirect to malicious endpoints
8. **Weak Randomness** — Predictable transaction IDs or nonces could enable spoofing

## Security Controls

### SSRF Protection (CWE-918)

**All** protocols validate destination hosts against private/reserved IP ranges before connecting. This includes HTTP, gRPC, FTP, SFTP, SSH, SMTP, IMAP, LDAP, Redis, MQTT, NATS, AMQP, Kafka, WebSocket, Memcached, ZeroMQ, Syslog, SIP, STUN, NTP/PTP, SNMP, IPMI, WHOIS, TLS inspection, Elasticsearch, InfluxDB, Prometheus, Vault, Consul, and DNS-over-HTTPS.

Blocked ranges:

- Loopback addresses (`127.0.0.0/8`, `::1`)
- Private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- Link-local (`169.254.0.0/16`, `fe80::/10`) — blocks cloud metadata endpoints
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

Credentials should **never** appear directly in SQL queries. duck_net provides an in-memory secrets manager with zeroization:

```sql
-- Store credentials (never appears in query logs)
SELECT duck_net_add_secret('my_smtp', 'smtp', '{"host":"smtp.example.com","username":"user","password":"pass"}');

-- Use by reference
SELECT smtp_send_secret('my_smtp', 'from@example.com', 'to@example.com', 'Subject', 'Body');

-- Clear when done (zeroizes memory)
SELECT duck_net_clear_secret('my_smtp');
```

Secrets-aware functions are available for: S3, HTTP, SMTP, SSH, IMAP, Vault, Consul, InfluxDB, SNMP, RADIUS, Redis, LDAP.

#### DuckDB Native Secrets Manager Integration

For S3/HTTP/GCS/R2 protocols, prefer DuckDB's native `CREATE SECRET` with the httpfs extension. DuckDB's secrets manager provides:

- **Scoped secrets** — different storage prefixes use different credentials
- **Persistent secrets** — survive DuckDB restarts (stored in `~/.duckdb/stored_secrets`)
- **Automatic selection** — `which_secret()` shows which secret applies to a path

```sql
-- DuckDB native S3 secret (preferred for S3 operations)
CREATE SECRET my_s3 (TYPE s3, KEY_ID 'AKIA...', SECRET '...', REGION 'us-east-1');

-- Scoped secrets: different credentials per bucket
CREATE SECRET org1 (TYPE s3, KEY_ID '...', SECRET '...', SCOPE 's3://org1-bucket');
CREATE SECRET org2 (TYPE s3, KEY_ID '...', SECRET '...', SCOPE 's3://org2-bucket');

-- DuckDB native HTTP secret (for bearer token auth)
CREATE SECRET my_http (TYPE http, BEARER_TOKEN 'token...');

-- HTTP proxy configuration via secrets
CREATE SECRET proxy (TYPE http, HTTP_PROXY 'http://proxy:8080');

-- GCS (Google Cloud Storage) via HMAC keys
CREATE SECRET my_gcs (TYPE gcs, KEY_ID 'GOOG...', SECRET '...');

-- Cloudflare R2
CREATE SECRET my_r2 (TYPE r2, KEY_ID '...', SECRET '...', ACCOUNT_ID '...');

-- Persistent secrets (survive restarts; stored unencrypted on disk)
CREATE PERSISTENT SECRET prod_s3 (TYPE s3, KEY_ID '...', SECRET '...', SCOPE 's3://prod-');

-- Check which secret applies to a path
SELECT * FROM which_secret('s3://org1-bucket/file.parquet', 's3');

-- List all secrets (values redacted)
SELECT * FROM duckdb_secrets();

-- Drop a persistent secret
DROP PERSISTENT SECRET prod_s3;
```

duck_net's S3 functions accept the same key names as DuckDB's native S3 secrets (`KEY_ID`, `SECRET`, `REGION`, `ENDPOINT`) so credentials can be managed consistently. duck_net's secrets manager covers protocols DuckDB does not natively support (SMTP, SSH, IMAP, LDAP, Redis, MQTT, etc.).

> **Warning:** DuckDB persistent secrets are stored in **unencrypted** binary format on disk. duck_net's in-memory secrets are zeroized on clear and never written to disk.

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
| DNS hostnames | Validated for length, null bytes, and format | CWE-20 |
| Port range | Must be 1-65535 | — |
| Path traversal | `..` components blocked in FTP, SFTP, and all file path parameters | CWE-22 |
| SSH commands | Shell metacharacters (`;`, `\|`, `&`, `$`, `` ` ``) blocked in strict mode | CWE-78 |
| SMTP headers | CRLF injection sanitized, dot-stuffing in body | CWE-93 |
| SOAP actions | CR/LF/NUL stripped to prevent HTTP header injection | CWE-113 |
| LDAP filters | RFC 4515 escaping available for filter values | CWE-90 |
| CalDAV timestamps | ISO 8601 format validation prevents XML injection | CWE-91 |
| NATS credentials | JSON-escaped to prevent protocol injection | CWE-116 |
| Elasticsearch indices | Validated against path traversal, restricted character set | CWE-22 |
| SNMP community strings | Length-limited (max 255), null byte rejection | CWE-400 |
| SNMP walk iteration | Capped at 10,000 entries to prevent unbounded loops | CWE-400 |
| MQTT payloads | Capped at 16 MiB to prevent OOM | CWE-400 |
| AMQP messages | Capped at 16 MiB; exchange/routing_key max 255 chars | CWE-400 |
| Kafka key/value | Key max 1 MiB, value max 16 MiB | CWE-400 |
| Syslog messages | Max 65,000 bytes; control character rejection in hostname/app_name | CWE-93 |
| WHOIS queries | Max 256 characters; referred servers validated against SSRF | CWE-918 |
| Pagination URLs | Next-page URLs validated for scheme (HTTP/HTTPS) and SSRF | CWE-601 |

### Response Size Limits (CWE-400)

| Protocol | Max Response Size |
|----------|------------------|
| HTTP/HTTPS | 256 MiB |
| FTP/SFTP | 256 MiB |
| gRPC | 16 MiB |
| WebSocket | 16 MiB |
| Redis | 16 MiB |
| ZeroMQ | 16 MiB |
| NATS | 16 MiB |
| IMAP | 10 MiB |
| Memcached | 1 MiB |
| WHOIS | 64 KiB |
| SNMP | 65,535 bytes |
| SIP | 4,096 bytes |
| RADIUS | 4,096 bytes |
| STUN | 548 bytes |
| IPMI | 1,024 bytes |

Redis RESP array parsing is depth-limited (max 8 levels) and element-limited (max 100,000 elements) to prevent stack overflow and memory exhaustion.

### Recursion Depth Limits (CWE-674)

| Parser | Max Depth |
|--------|-----------|
| Vault JSON | 128 levels |
| gRPC Protobuf | 16 levels |
| Redis RESP | 8 levels |
| mDNS compression | 128 pointer hops |

### Timeouts

All network operations enforce timeouts to prevent hanging queries:

| Protocol Category | Default Timeout |
|-------------------|----------------|
| HTTP/HTTPS | 30 seconds (configurable) |
| gRPC (connect + TLS + response) | 30 seconds |
| TCP protocols (Redis, NATS, SMTP, etc.) | 10 seconds |
| UDP protocols (DNS, NTP, SNMP, STUN, SIP) | 5-10 seconds |
| SSH/SFTP | 30 seconds |
| TLS inspection | 15 seconds |

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

Rate limiter buckets are automatically evicted after 5 minutes of inactivity and capped at 10,000 tracked domains to prevent unbounded memory growth.

### Cryptographic Random Number Generation (CWE-338)

All protocol operations requiring randomness use the OS CSPRNG via the `getrandom` crate:

- RADIUS authenticators (16 bytes)
- SIP Call-IDs, branches, and tags
- STUN transaction IDs (12 bytes)
- NTP transmit timestamps
- Secret manager identifiers

**No weak PRNG or time-based seeds** are used for any security-relevant operations. If the OS entropy source is unavailable (should never happen on supported platforms), the extension panics rather than falling back to insecure randomness.

### Memory Safety

- FTP connection cache bounded to 32 entries with 60-second TTL
- Rate limiter bounded to 10,000 domain entries with stale eviction
- Secrets store bounded to 1,024 entries with 64 KiB per-secret limit
- JSON escape handling guards against trailing backslash out-of-bounds reads

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
  "duckdb_native_secrets": "Use CREATE SECRET (TYPE s3/http/gcs/r2) for cloud storage and HTTP protocols",
  "duck_net_secrets": "Use duck_net_add_secret() for SMTP, SSH, LDAP, Redis, MQTT, etc."
}
```

## Reporting Security Issues

If you discover a security vulnerability, please report it responsibly by opening a private security advisory on the GitHub repository.

## Design Principles

1. **Secure by default** — SSRF protection, SSH strict mode, and TLS verification are enabled by default
2. **Defense in depth** — Multiple layers of validation (URL parsing, hostname validation, IP resolution, SSRF check)
3. **Fail closed** — Unresolvable hosts are blocked; unavailable OS entropy panics rather than falling back to weak randomness
4. **Least privilege** — Functions only expose the minimum capability needed
5. **No telemetry** — Zero phone-home tracking, zero external analytics
6. **Memory safety** — Written in Rust with no `unsafe` outside of FFI boundary code
7. **Credential hygiene** — Secrets manager, credential scrubbing, zeroization
8. **Bounded resources** — All caches, parsers, and response buffers have enforced limits
