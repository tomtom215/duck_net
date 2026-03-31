> [!CAUTION]
> ## Here Be Dragons
>
> **This extension is highly experimental and has not been reviewed or validated by security researchers.**
>
> Neither the author nor any AI assistant is a credentialed security professional. The hardening features in this codebase (SSRF protection, credential zeroization, audit logging, etc.) represent good-faith engineering effort — they are **not** a substitute for a professional security audit.
>
> Beyond that, there are deep architectural reasons why a database engine should never talk directly to the network: exfiltration of sensitive data, SSRF attacks pivoting through your database host, credential leakage into query logs, denial-of-service via unbounded connections, and more.
>
> **If you use this extension in a production environment and end up on the front page of a security blog, that's on you — and honestly, kind of on you for reading this warning and continuing anyway.**
>
> **Why does this exist?** This project grew out of a specific frustration: while evaluating other network-capable DuckDB extensions, analytics and telemetry were discovered built into them — quietly phoning home as a side effect of loading a SQL extension. That felt wrong. So this was built from scratch, with full visibility into every network call it makes. What started as a minimal HTTP client gradually grew to support more and more protocols, because once you have the plumbing in place, the next one is always "just one more." Here we are.
>
> **An unexpected side effect: improving [quack-rs](https://github.com/tomtom215/quack-rs).** duck_net is built on quack-rs, a safe Rust wrapper for the DuckDB extension FFI. quack-rs itself was originally motivated by [duckdb-behavioral](https://github.com/tomtom215/duckdb-behavioral) — a much more narrowly scoped project that, while useful, never pushed the FFI wrapper hard enough to expose its rough edges. duck_net changed that. Implementing 50+ protocols across table functions, scalar callbacks, streaming results, and complex type mappings surfaced real gaps — missing APIs, ergonomic friction, unsafe patterns that needed proper abstractions — and drove meaningful improvements back into quack-rs that benefit anyone building DuckDB extensions in Rust. If quack-rs is useful to you, some of the credit belongs to this project's willingness to stress-test it.
>
> This project exists for research, internal tooling, and the joy of absurdly powerful SQL. Use it in isolated environments, behind strict network controls, and never against data you cannot afford to lose or expose.
>
> *["Here be dragons"](https://en.wikipedia.org/wiki/Here_be_dragons) — the old cartographer's warning for uncharted, dangerous territory. Consider this README the edge of the known map.*

---

# duck_net

**50+ network protocols as DuckDB SQL functions**, written in pure Rust.

Query HTTP APIs, send emails, execute SSH commands, read from Redis, publish to Kafka, search LDAP directories — all from SQL.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Quick Start

```sql
-- Load the extension
LOAD 'target/release/libduck_net.so';

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
- **[Protocol Reference](docs/src/reference.md)** — All 50+ functions with signatures
- **[Security Architecture](docs/src/security/architecture.md)** — Threat model and defense layers
- **[Secrets Management](docs/src/security/secrets.md)** — In-memory credential store
- **[DuckDB Secrets Integration](docs/src/security/duckdb-secrets.md)** — Native CREATE SECRET support
- **[Security Warnings](docs/src/security/warnings.md)** — Runtime insecure configuration alerts
- **[Hardening Guide](docs/src/security/hardening.md)** — Production deployment checklist
- **[SSRF Protection](docs/src/security/ssrf.md)** — Private IP blocking

## Security Highlights

| Protection | Description |
|-----------|-------------|
| SSRF protection | Blocks all private/reserved IPv4 + IPv6 ranges (CWE-918); full coverage: CGN, NAT64, Teredo, 6to4 |
| Redirect SSRF | Manual redirect following with per-hop SSRF check; HTTPS→HTTP downgrade warning |
| Header injection | RFC 7230 validation for header names and values; CRLF injection blocked (CWE-113) |
| Secrets manager | In-memory credentials with `zeroize` crate (compiler-resistant zeroing) |
| DuckDB secrets | Native `CREATE SECRET` for S3/HTTP/GCS/R2 with scoped, persistent, and STS support |
| AWS STS support | `session_token` in S3 secrets or `duck_net_import_aws_env()` for assumed roles |
| Security warnings | Runtime alerts for plaintext protocols, missing auth, S3 over HTTP, redirect downgrade |
| Input validation | URL length, hostname format, path traversal, LDAP filter, query size limits |
| TLS everywhere | Pure Rust `rustls`; no OpenSSL dependency |
| Response limits | 256 MiB HTTP, 16 MiB gRPC/WS/Redis, 10 MiB IMAP, 1 MiB query payloads |
| CSPRNG | OS entropy via `getrandom`; panics instead of weak fallback |
| Credential scrubbing | Passwords, tokens, Authorization headers redacted in all error messages |

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

-- Rotate credentials atomically (old values zeroized before replacement)
SELECT duck_net_rotate_secret('mail', '{"host":"smtp.gmail.com","password":"new-pass"}');

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

Requires Rust 1.88+ (MSRV). The extension is built to `target/release/libduck_net.so`.

```sql
-- Load (unsigned)
LOAD 'target/release/libduck_net.so';
```

## Protocol Opt-In

Only core web protocols are enabled by default (HTTP, DNS, TLS, GraphQL, OAuth2, WHOIS, secrets, audit log). Everything else must be explicitly enabled in a config file to reduce attack surface.

```bash
# Create ~/.config/duck_net/protocols and list what you need:
echo "ssh" >> ~/.config/duck_net/protocols
echo "smtp" >> ~/.config/duck_net/protocols
echo "redis" >> ~/.config/duck_net/protocols
```

```sql
-- From DuckDB: see all protocols and their enabled status
SELECT * FROM duck_net_protocols();

-- Generate a fully-commented config template
SELECT duck_net_generate_config();
```

See [docs/src/installation.md](docs/src/installation.md) for full details.

## Audit Logging

```sql
-- Enable session audit log
SELECT duck_net_set_audit_logging(true);

-- Review all network operations made this session (credentials scrubbed)
SELECT * FROM duck_net_audit_log();

-- JSON summary
SELECT duck_net_audit_log_status();
```

## Architecture

- **Pure Rust** — No C dependencies. Built on `rustls` for TLS, `quack-rs` for DuckDB FFI.
- **Modular** — Each protocol is a self-contained module with its own FFI bindings.
- **Secure by default** — Core web only; all other protocols opt-in via config file.
- **Security-first** — Centralized validation in `security.rs`, all credentials in `secrets.rs`.
- **Bounded** — Every buffer, cache, and response has enforced limits.

## License

[MIT](LICENSE)
