# Network Utilities (Ping / WHOIS / STUN / BGP)

duck_net provides utility functions for network diagnostics and information lookups.

## Functions

| Function | Parameters | Returns |
|----------|-----------|---------|
| `ping` | `(host)` | VARCHAR (round-trip time or error) |
| `ping` | `(host, timeout_secs)` | VARCHAR |
| `traceroute` | `(host)` with named params | Table: hop, ip, rtt |
| `whois_lookup` | `(domain)` | VARCHAR (WHOIS response) |
| `whois_query` | `(query)` | VARCHAR (raw WHOIS response) |
| `stun_lookup` | `(server)` | VARCHAR (JSON with public IP and port) |
| `bgp_route` | `(prefix)` | VARCHAR (JSON route data) |
| `bgp_prefix_overview` | `(prefix)` | VARCHAR (JSON prefix overview) |
| `bgp_asn_info` | `(asn)` | VARCHAR (JSON ASN details) |

## Ping

```sql
-- Ping a host
SELECT ping('example.com');

-- With custom timeout (seconds)
SELECT ping('example.com', 5);
```

## Traceroute

```sql
-- Trace the route to a host
FROM traceroute('example.com');

-- With custom max hops
FROM traceroute('example.com', max_hops := 20);
```

## WHOIS

```sql
-- Domain WHOIS lookup
SELECT whois_lookup('example.com');

-- Raw WHOIS query (for IP addresses, ASNs, etc.)
SELECT whois_query('93.184.216.34');
```

## STUN (NAT Discovery)

Discover your public IP address and port using a STUN server:

```sql
SELECT stun_lookup('stun.l.google.com:19302');
```

## BGP (via RIPEstat API)

Query Border Gateway Protocol routing information:

```sql
-- Get routing data for a prefix
SELECT bgp_route('93.184.216.0/24');

-- Get prefix overview (origin ASN, visibility)
SELECT bgp_prefix_overview('8.8.8.0/24');

-- Get ASN details
SELECT bgp_asn_info('AS15169');
```

## Practical Examples

```sql
-- Check if a host is reachable
SELECT ping('db.example.com') AS latency;

-- Look up domain registration info
SELECT whois_lookup('duckdb.org');

-- Discover your public IP for NAT traversal
SELECT stun_lookup('stun.l.google.com:19302');
```

## Security Considerations

- Ping and traceroute targets are validated against [SSRF rules](../security/ssrf.md) to prevent internal network probing.
- WHOIS responses are capped at 64 KiB.
- STUN transaction IDs use cryptographic randomness.
- BGP queries use the RIPEstat public API over HTTPS.
