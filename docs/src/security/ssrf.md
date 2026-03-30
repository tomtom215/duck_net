# SSRF Protection

Server-Side Request Forgery (SSRF) is the primary threat when a database extension makes network requests based on user-supplied URLs. duck_net blocks connections to private and reserved IP ranges by default.

## Blocked IP Ranges

### IPv4

| Range | Description |
|-------|-------------|
| `127.0.0.0/8` | Loopback |
| `10.0.0.0/8` | Private (RFC 1918) |
| `172.16.0.0/12` | Private (RFC 1918) |
| `192.168.0.0/16` | Private (RFC 1918) |
| `169.254.0.0/16` | Link-local / Cloud metadata (`169.254.169.254`) |
| `100.64.0.0/10` | Carrier-grade NAT (RFC 6598) |
| `198.18.0.0/15` | Benchmark testing (RFC 2544) |
| `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | Documentation (RFC 5737) |

### IPv6

| Range | Description |
|-------|-------------|
| `::1` | Loopback |
| `fc00::/7` | Unique local (RFC 4193) |
| `fe80::/10` | Link-local |
| `ff00::/8` | Multicast |
| `2001::/32` | Teredo (RFC 4380) |
| `2002::/16` | 6to4 — also blocked when embedded IPv4 is private |
| `64:ff9b::/96` | NAT64 (RFC 6146) |
| `2001:db8::/32` | Documentation (RFC 3849) |
| `::ffff:0:0/96` | IPv4-mapped — checked for embedded private IPv4 |

## Configuration

```sql
-- Check current SSRF protection status
SELECT duck_net_security_status();

-- Disable for local development (NOT recommended for production)
SELECT duck_net_set_ssrf_protection(false);

-- Re-enable
SELECT duck_net_set_ssrf_protection(true);
```

## Redirect-Based SSRF

A common SSRF bypass is to pass an innocuous initial URL that redirects to a private endpoint. duck_net defends against this by handling HTTP redirects manually and revalidating the SSRF policy at each hop:

1. The initial URL is SSRF-checked before the first request.
2. Each `Location` header in a redirect response is parsed and SSRF-checked before following.
3. A redirect chain of more than **10 hops** is terminated with an error.
4. If any intermediate URL resolves to a blocked address, the entire chain is rejected.

An HTTPS→HTTP downgrade in a redirect chain emits an `HTTP_REDIRECT_HTTPS_TO_HTTP` HIGH-severity warning.

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
