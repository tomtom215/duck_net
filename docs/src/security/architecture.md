# Security Architecture

duck_net is designed with a security-first architecture. Every protocol module enforces input validation, output bounds, and network safety checks through a centralized security layer.

## Threat Model

| Threat | CWE | Mitigation |
|--------|-----|------------|
| Server-Side Request Forgery | CWE-918 | Block private/reserved IPs by default |
| Credential Exposure in Logs | CWE-532 | Scrub URLs and error messages |
| Command Injection (SSH) | CWE-78 | Shell metacharacter validation |
| Path Traversal (FTP/SFTP/SCP) | CWE-22 | Block `..`, null bytes, long paths |
| LDAP Injection | CWE-90 | RFC 4515 filter escaping |
| CRLF Injection (SMTP) | CWE-93 | Header and body sanitization |
| Resource Exhaustion | CWE-400 | Response size limits on all protocols |
| Stack Overflow | CWE-674 | Recursion depth limits (Protobuf, Redis, mDNS) |
| Weak Randomness | CWE-338 | OS CSPRNG via `getrandom` (panics on failure) |
| Open Redirect | CWE-601 | Pagination URL scheme + SSRF validation |
| Cleartext Credentials | CWE-312 | In-memory secrets with zeroization |

## Defense in Depth

### Layer 1: Input Validation
Every protocol validates its inputs before establishing any network connection:
- URL length limits (64 KiB)
- Hostname validation (alphanumeric, dots, hyphens, colons)
- Port range enforcement (1-65535)
- Protocol-specific validation (MQTT topics, LDAP filters, SSH commands)

### Layer 2: Network Safety (SSRF)
Before any TCP/UDP connection, the target hostname is resolved and checked against private/reserved IP ranges. This prevents SQL queries from reaching internal services.

### Layer 3: Transport Security
- **TLS**: Pure Rust via `rustls` with Mozilla CA bundle (`webpki-roots`)
- **SSH**: Host key verification via `known_hosts` (TOFU model)
- **No Fallback**: SMTP STARTTLS cannot be downgraded

### Layer 4: Response Bounds
Every protocol enforces maximum response sizes to prevent memory exhaustion:

| Protocol | Max Response |
|----------|-------------|
| HTTP/HTTPS | 256 MiB |
| FTP/SFTP | 256 MiB |
| gRPC/WebSocket/Redis/ZeroMQ/NATS | 16 MiB |
| IMAP | 10 MiB |
| Memcached | 1 MiB |
| SSH command output | 64 MiB |
| WHOIS | 64 KiB |

### Layer 5: Credential Protection
- In-memory secrets with volatile zeroization on clear
- Credential scrubbing in all error messages
- Redacted display in `duck_net_secrets()` table function
- DuckDB native secrets integration for S3/HTTP

### Layer 6: Security Warnings
Runtime warnings when protocols are used in potentially insecure configurations (plaintext, no auth, weak crypto). Warnings are informational and never block operations.

## Cryptographic Randomness

All random values use OS-provided entropy via the `getrandom` crate:
- RADIUS authenticators (16 bytes)
- SIP Call-IDs, branches, tags
- STUN transaction IDs (12 bytes)
- NTP transmit timestamps

The extension **panics** if OS entropy is unavailable — it never falls back to weak randomness.
