# duck_net

**49+ network protocols as DuckDB SQL functions**, written in pure Rust.

Query HTTP APIs, send emails, execute SSH commands, read from Redis, publish to Kafka, search LDAP directories — all from SQL.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Quick Start

```sql
-- Load the extension
LOAD 'path/to/duck_net.duckdb_extension';

-- Query a JSON API
SELECT (http_get('https://api.github.com/repos/duckdb/duckdb')).body;

-- POST with custom headers
SELECT (http_post(
    'https://httpbin.org/post',
    MAP {'Content-Type': 'application/json'},
    '{"key": "value"}'
)).body;

-- Store credentials securely (never in query text)
SELECT duck_net_add_secret('my_api', 'http', '{"bearer_token": "sk-..."}');
SELECT (http_get_secret('my_api', 'https://api.example.com/data')).body;

-- Check security status
SELECT duck_net_security_status();
FROM duck_net_security_warnings();
```

## Supported Protocols (49+)

| Category | Protocols |
|----------|-----------|
| **Web** | HTTP/S, GraphQL, SOAP, OData, WebDAV, WebSocket, gRPC, JSON-RPC, XML-RPC |
| **DNS** | DNS (A/AAAA/PTR/TXT/MX), DNS-over-HTTPS, mDNS/Bonjour |
| **Email** | SMTP/SMTPS, IMAP/IMAPS |
| **File Transfer** | FTP/FTPS, SFTP, SCP |
| **Remote Execution** | SSH (key + password auth) |
| **Directory** | LDAP/LDAPS (search, bind, add, modify, delete) |
| **Cache/KV** | Redis, Memcached |
| **Cloud Storage** | S3-compatible (AWS, MinIO, GCS, R2) |
| **Messaging** | MQTT, AMQP/RabbitMQ, Apache Kafka, NATS, ZeroMQ |
| **Monitoring** | Prometheus, Elasticsearch, InfluxDB |
| **Service Discovery** | HashiCorp Consul, HashiCorp Vault |
| **Network** | Ping, WHOIS, STUN, BGP Looking Glass |
| **Time** | NTP, PTP (Precision Time Protocol) |
| **Infrastructure** | SNMP (v2c), Syslog (RFC 5424), IPMI, RADIUS |
| **Certificates** | TLS Inspect, OCSP, CalDAV |

## Documentation

Full documentation is available in the [docs/](docs/) directory:

- **[Getting Started](docs/src/quickstart.md)** — Installation and first queries
- **[Protocol Reference](docs/src/reference.md)** — All 49+ functions with signatures
- **[Security Architecture](docs/src/security/architecture.md)** — Threat model and defense layers
- **[Secrets Management](docs/src/security/secrets.md)** — In-memory credential store
- **[DuckDB Secrets Integration](docs/src/security/duckdb-secrets.md)** — Native CREATE SECRET support
- **[Security Warnings](docs/src/security/warnings.md)** — Runtime insecure configuration alerts
- **[Hardening Guide](docs/src/security/hardening.md)** — Production deployment checklist
- **[SSRF Protection](docs/src/security/ssrf.md)** — Private IP blocking

## Security Highlights

| Protection | Description |
|-----------|-------------|
| SSRF protection | Blocks private/reserved IPs across all protocols (CWE-918) |
| Secrets manager | In-memory credentials with zeroization; never on disk |
| DuckDB secrets | Native `CREATE SECRET` for S3/HTTP/GCS/R2 |
| Security warnings | Runtime alerts for plaintext protocols, missing auth, weak crypto |
| Input validation | URL length, hostname format, path traversal, injection prevention |
| TLS everywhere | Pure Rust `rustls`; no OpenSSL dependency |
| Response limits | 256 MiB HTTP, 16 MiB gRPC/WS/Redis, 10 MiB IMAP |
| CSPRNG | OS entropy via `getrandom`; panics instead of weak fallback |
| Credential scrubbing | Passwords/tokens redacted in all error messages |

```sql
-- Security audit
SELECT duck_net_security_status();

-- View any security warnings from this session
FROM duck_net_security_warnings();

-- Disable SSRF for local dev (re-enable for production!)
SELECT duck_net_set_ssrf_protection(false);
```

## Secrets Management

Keep credentials out of SQL query text:

```sql
-- Store
SELECT duck_net_add_secret('mail', 'smtp',
    '{"host":"smtp.gmail.com","port":"587","username":"me@gmail.com","password":"app-pass"}');

-- Use
SELECT smtp_send_secret('mail', 'me@gmail.com', 'team@co.com', 'Alert', 'Error rate high');

-- List (values redacted)
FROM duck_net_secrets();

-- Clear (zeroized in memory)
SELECT duck_net_clear_secret('mail');
```

For S3/HTTP, prefer DuckDB's native secrets:

```sql
CREATE SECRET my_s3 (TYPE s3, KEY_ID 'AKIA...', SECRET '...', REGION 'us-east-1');
```

See [DuckDB Secrets Integration](docs/src/security/duckdb-secrets.md) for details.

## Building

```bash
git clone https://github.com/tomtom215/duck_net.git
cd duck_net
cargo build --release
```

Requires Rust 1.85+ (MSRV). The extension is built to `target/release/libduck_net.so`.

```sql
-- Load (unsigned)
LOAD 'target/release/libduck_net.so';
```

## Architecture

- **Pure Rust** — No C dependencies. Built on `rustls` for TLS, `quack-rs` for DuckDB FFI.
- **Modular** — Each protocol is a self-contained module with its own FFI bindings.
- **Security-first** — Centralized validation in `security.rs`, all credentials in `secrets.rs`.
- **Bounded** — Every buffer, cache, and response has enforced limits.

## License

[MIT](LICENSE)
