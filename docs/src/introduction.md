# duck_net

**49+ network protocols as DuckDB SQL functions.**

duck_net is a DuckDB extension that brings network protocol support directly into SQL queries. Query HTTP APIs, send emails, execute SSH commands, read from Redis, publish to Kafka — all from the comfort of SQL.

## Why duck_net?

- **Pure SQL**: No external scripts, no ETL pipelines. Query APIs and services directly.
- **49+ Protocols**: HTTP, gRPC, WebSocket, SMTP, IMAP, SSH, FTP, SFTP, Redis, MQTT, Kafka, NATS, LDAP, S3, and many more.
- **Security First**: SSRF protection, credential scrubbing, input validation, TLS by default, and a comprehensive secrets manager.
- **Pure Rust**: No C dependencies. Built on rustls for TLS, eliminating OpenSSL.
- **DuckDB Native**: Integrates with DuckDB's secrets manager for S3/HTTP/GCS credentials.

## Quick Example

```sql
-- Query a JSON API
SELECT (http_get('https://api.example.com/data')).body;

-- Send an email using stored credentials
SELECT duck_net_add_secret('mail', 'smtp', '{"host":"smtp.gmail.com","username":"me@gmail.com","password":"app-password"}');
SELECT smtp_send_secret('mail', 'me@gmail.com', 'team@example.com', 'Report', 'Daily report attached');

-- Execute a remote command via SSH
SELECT (ssh_exec('myserver.com', 22, 'deploy', '/path/to/key', 'uptime')).stdout;

-- Check security status
SELECT duck_net_security_status();
FROM duck_net_security_warnings();
```

## Architecture

duck_net is built as a DuckDB loadable extension in Rust using the [quack-rs](https://github.com/tomtom215/quack-rs) SDK. Each protocol is implemented as a self-contained module with its own FFI bindings, input validation, and security controls.

Key design decisions:
- **Centralized security**: All validation flows through `security.rs`
- **In-memory secrets**: Credentials never touch disk via duck_net
- **Bounded resources**: Every buffer, cache, and response has enforced limits
- **Fail closed**: Unresolved hosts are blocked, weak randomness panics
