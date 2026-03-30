# Security Architecture

> For the full security documentation, see [docs/src/security/](docs/src/security/).

## Overview

duck_net enforces security at every layer: input validation, network safety (SSRF), transport encryption (TLS), response bounds, credential protection with `zeroize`-based memory clearing, and runtime security warnings.

## Threat Model

| Threat | CWE | Mitigation |
|--------|-----|------------|
| Server-Side Request Forgery | CWE-918 | Block all private/reserved IPv4 and IPv6 ranges by default (including CGN, benchmark, NAT64, Teredo, 6to4 ranges) |
| Redirect-based SSRF | CWE-918 | Manual redirect following with per-hop SSRF validation; redirect limit of 10 |
| Credential Exposure in Logs | CWE-532 | Scrub URLs, error messages, and Authorization headers before returning to SQL |
| HTTP Header Injection | CWE-113 | RFC 7230 header name/value validation; CRLF in header values is blocked |
| Command Injection (SSH) | CWE-78 | Shell metacharacter validation (strict mode on by default) |
| Path Traversal (FTP/SFTP/SCP) | CWE-22 | Block `..`, null bytes, long paths |
| LDAP Injection | CWE-90 | RFC 4515 filter escaping + filter validation |
| CRLF Injection (SMTP) | CWE-93 | Header and body sanitization |
| HTTP Redirect Downgrade | CWE-319 | Warning emitted when HTTPS redirect goes to HTTP |
| S3 Over Plaintext HTTP | CWE-319 | Warning emitted when S3 endpoint uses `http://` |
| Resource Exhaustion | CWE-400 | Response size limits + query payload limits |
| Stack Overflow | CWE-674 | Recursion depth limits (Protobuf, Redis, mDNS) |
| Weak Randomness | CWE-338 | OS CSPRNG via `getrandom` (panics on failure) |
| Cleartext Credentials | CWE-312 | In-memory secrets with `zeroize` crate (compiler-resistant); `duck_net_secret()` warns |
| Plaintext Protocols | CWE-319 | Runtime security warnings for all plaintext usage |
| Integer Overflow | CWE-190 | Safe length validation before type casts |
| Missing Authentication | CWE-306 | Warnings for Memcached, ZeroMQ, etc. |
| Incomplete SSRF IPv6 | CWE-918 | Full IPv6 private range coverage: fc00::/7, fe80::/10, ff00::/8, 2001::/32 (Teredo), 2002::/16 (6to4), 64:ff9b::/96 (NAT64), 2001:db8::/32 (docs) |

## Security Functions

```sql
-- Audit current configuration
SELECT duck_net_security_status();

-- View security warnings (plaintext, no-auth, weak crypto)
FROM duck_net_security_warnings();

-- SSRF protection (enabled by default)
SELECT duck_net_set_ssrf_protection(true);

-- SSH strict mode (enabled by default)
SELECT duck_net_set_ssh_strict(true);

-- Suppress warnings for CI/testing
SELECT duck_net_set_security_warnings(false);

-- Credential utilities
SELECT duck_net_scrub_url('redis://password@host:6379');
SELECT duck_net_scrub_error('password=secret123');
```

## Reporting Vulnerabilities

Please report security vulnerabilities via GitHub Issues or by contacting the maintainer directly. Do not open public issues for critical vulnerabilities.

## Further Reading

- [Security Architecture](docs/src/security/architecture.md) -- Full threat model and defense layers
- [SSRF Protection](docs/src/security/ssrf.md) -- Private IP blocking details
- [Secrets Management](docs/src/security/secrets.md) -- In-memory credential store with `zeroize`
- [DuckDB Secrets](docs/src/security/duckdb-secrets.md) -- Native `CREATE SECRET` integration
- [Security Warnings](docs/src/security/warnings.md) -- Runtime alert system
- [Hardening Guide](docs/src/security/hardening.md) -- Production deployment checklist
