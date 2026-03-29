# SSRF Protection

Server-Side Request Forgery (SSRF) is the primary threat when a database extension makes network requests based on user-supplied URLs. duck_net blocks connections to private and reserved IP ranges by default.

## Blocked IP Ranges

| Range | Description |
|-------|-------------|
| `127.0.0.0/8` | Loopback |
| `10.0.0.0/8` | Private (RFC 1918) |
| `172.16.0.0/12` | Private (RFC 1918) |
| `192.168.0.0/16` | Private (RFC 1918) |
| `169.254.0.0/16` | Link-local / Cloud metadata |
| `100.64.0.0/10` | Carrier-grade NAT |
| `198.18.0.0/15` | Benchmark testing |
| `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | Documentation |
| `::1` | IPv6 loopback |
| `fc00::/7` | IPv6 unique local |
| `fe80::/10` | IPv6 link-local |
| IPv4-mapped IPv6 | Checked for embedded private IPv4 |

## Configuration

```sql
-- Check current SSRF protection status
SELECT duck_net_security_status();

-- Disable for local development (NOT recommended for production)
SELECT duck_net_set_ssrf_protection(false);

-- Re-enable
SELECT duck_net_set_ssrf_protection(true);
```

## DNS Rebinding Prevention

When SSRF protection is enabled and a hostname cannot be resolved, the connection is **blocked** rather than retried. This prevents DNS rebinding attacks where an attacker's DNS server returns a private IP on the second resolution.

## CI/Airgapped Systems

For CI pipelines or airgapped environments where you need to reach internal services:

```sql
-- Disable SSRF protection for the session
SELECT duck_net_set_ssrf_protection(false);

-- Your internal service calls here
SELECT (http_get('http://internal-api:8080/health')).status;

-- Re-enable before any untrusted input
SELECT duck_net_set_ssrf_protection(true);
```

> **Warning**: Disabling SSRF protection allows SQL queries to reach any network endpoint, including cloud metadata services (`169.254.169.254`). Only disable in trusted environments.
