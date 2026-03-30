# Security Architecture

duck_net is designed with a security-first architecture. Every protocol module enforces input validation, output bounds, and network safety checks through a centralized security layer.

## Threat Model

| Threat | CWE | Mitigation |
|--------|-----|------------|
| Server-Side Request Forgery | CWE-918 | Block all private/reserved IPv4 and IPv6 ranges by default (incl. CGN, NAT64, Teredo, 6to4) |
| Redirect-based SSRF | CWE-918 | Manual redirect following with per-hop SSRF validation; 10-hop limit |
| HTTP Header Injection | CWE-113 | RFC 7230 header name/value validation; CRLF in header values blocked |
| HTTP Redirect Downgrade | CWE-319 | Warning emitted when HTTPS redirects to HTTP |
| S3 Over Plaintext HTTP | CWE-319 | Warning emitted when S3 endpoint uses `http://` |
| Credential Exposure in Logs | CWE-532 | Scrub URLs, error messages, Authorization headers |
| Command Injection (SSH) | CWE-78 | Shell metacharacter validation (strict mode) |
| Path Traversal (FTP/SFTP/SCP) | CWE-22 | Block `..`, null bytes, long paths |
| LDAP Injection | CWE-90 | RFC 4515 filter escaping + filter validation |
| CRLF Injection (SMTP) | CWE-93 | Header and body sanitization |
| Resource Exhaustion | CWE-400 | Response size limits + query payload limits |
| Stack Overflow | CWE-674 | Recursion depth limits (Protobuf, Redis, mDNS) |
| Weak Randomness | CWE-338 | OS CSPRNG via `getrandom` (panics on failure) |
| Cleartext Credentials | CWE-312 | In-memory secrets with `zeroize` crate; `duck_net_secret()` warns |
| Plaintext Transmission | CWE-319 | Security warnings for all plaintext protocols |
| Weak Authentication | CWE-327 | Warnings for SNMPv2c, IPMIv1.5, etc. |
| Missing Authentication | CWE-306 | Warnings for Memcached, ZeroMQ, etc. |
| Integer Overflow | CWE-190 | Safe length validation before type casts |

## Defense in Depth

### Layer 1: Input Validation
Every protocol validates its inputs before establishing any network connection:
- URL length limits (64 KiB)
- Hostname validation (alphanumeric, dots, hyphens, colons, underscores)
- Port range enforcement (1-65535)
- Protocol-specific validation (MQTT topics, LDAP filters, SSH commands)
- Query payload size limits (1 MiB for GraphQL/Elasticsearch queries)

### Layer 2: Network Safety (SSRF)
Before any TCP/UDP connection, the target hostname is resolved and checked against private/reserved IP ranges. This prevents SQL queries from reaching internal services.

Covered IP ranges:
- `127.0.0.0/8` (loopback)
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918 private)
- `169.254.0.0/16` (link-local / cloud metadata)
- `100.64.0.0/10` (carrier-grade NAT)
- `198.18.0.0/15` (benchmark)
- `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (documentation)
- IPv6: `::1`, `fc00::/7` (unique local), `fe80::/10` (link-local), `ff00::/8` (multicast)
- IPv6: `2001::/32` (Teredo), `2002::/16` (6to4 with private embedded IPv4), `64:ff9b::/96` (NAT64), `2001:db8::/32` (documentation)
- IPv4-mapped IPv6 (`::ffff:0:0/96`): checked for embedded private IPv4

Redirect chains are validated per-hop — SSRF protection applies to each intermediate destination, not just the final URL.

### Layer 3: Transport Security
- **TLS**: Pure Rust via `rustls` (no OpenSSL dependency) with Mozilla CA bundle (`webpki-roots`)
- **SSH**: Host key verification via `known_hosts` (TOFU model with warnings)
- **No Fallback**: SMTP STARTTLS cannot be downgraded
- **Platform Verification**: Optional system certificate store support

### Layer 4: Response Bounds
Every protocol enforces maximum response sizes to prevent memory exhaustion:

| Protocol | Max Response |
|----------|-------------|
| HTTP/HTTPS | 256 MiB |
| FTP/SFTP | 256 MiB |
| SSH command output | 64 MiB |
| gRPC/WebSocket/Redis/ZeroMQ/NATS | 16 MiB |
| IMAP | 10 MiB |
| Memcached | 1 MiB |
| WHOIS | 64 KiB |
| GraphQL/ES query payloads | 1 MiB (input) |

### Layer 5: Credential Protection
- In-memory secrets with `zeroize` crate (compiler-resistant zeroing)
- `ZeroizeOnDrop` trait ensures secrets are scrubbed even on unexpected drops
- Credential scrubbing in all error messages (URLs, Authorization headers, AUTH PLAIN)
- Redacted display in `duck_net_secrets()` table function
- DuckDB native secrets integration for S3/HTTP/GCS/R2

### Layer 6: Security Warnings
Runtime warnings when protocols are used in potentially insecure configurations:
- **PLAINTEXT_***: Protocol running without encryption
- **NO_AUTH_***: Protocol without authentication mechanism
- **WEAK_CRYPTO_***: Weak cryptographic implementation (SNMPv2c, IPMIv1.5)
- **TOFU_***: Trust-on-first-use host key verification
- **S3_OVER_HTTP**: S3 endpoint using plaintext HTTP (HIGH)
- **HTTP_REDIRECT_HTTPS_TO_HTTP**: HTTP redirect chain downgraded from HTTPS to HTTP (HIGH)
- **SECRET_VALUE_EXPOSED**: `duck_net_secret()` returned a raw credential value (HIGH)

Warnings are informational and never block operations, supporting CI pipelines, airgapped systems, and development environments.

## Cryptographic Randomness

All random values use OS-provided entropy via the `getrandom` crate:
- RADIUS authenticators (16 bytes)
- SIP Call-IDs, branches, tags
- STUN transaction IDs (12 bytes)
- NTP transmit timestamps

The extension **panics** if OS entropy is unavailable -- it never falls back to weak randomness.

## Memory Safety

- Pure Rust implementation (no C/C++ code except DuckDB FFI boundary)
- `zeroize` crate for cryptographic-grade memory clearing
- Mutex-protected global state for configuration
- Atomic operations for boolean flags
- Bounded allocations with pre-validated sizes
