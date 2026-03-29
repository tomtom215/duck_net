# DNS / DoH / mDNS

duck_net provides DNS resolution functions using system resolvers, DNS-over-HTTPS (DoH), and multicast DNS (mDNS) for local service discovery.

## Functions

| Function | Parameters | Returns |
|----------|-----------|---------|
| `dns_lookup` | `(hostname)` | VARCHAR (first resolved IP) |
| `dns_lookup_a` | `(hostname)` | VARCHAR (first IPv4 address) |
| `dns_lookup_aaaa` | `(hostname)` | VARCHAR (first IPv6 address) |
| `dns_reverse` | `(ip_address)` | VARCHAR (reverse DNS hostname) |
| `dns_txt` | `(hostname)` | VARCHAR (TXT records) |
| `dns_mx` | `(hostname)` | VARCHAR (MX records) |
| `doh_lookup` | `(domain, record_type)` | VARCHAR (JSON result) |
| `doh_lookup` | `(resolver_url, domain, record_type)` | VARCHAR (JSON result) |
| `mdns_discover` | `(service_type)` with named params | Table: varies by implementation |

## Standard DNS

```sql
-- Resolve a hostname to an IP
SELECT dns_lookup('example.com');

-- IPv4 only
SELECT dns_lookup_a('example.com');

-- IPv6 only
SELECT dns_lookup_aaaa('example.com');

-- Reverse lookup
SELECT dns_reverse('93.184.216.34');

-- TXT records (SPF, DKIM, etc.)
SELECT dns_txt('example.com');

-- MX records
SELECT dns_mx('example.com');
```

## DNS-over-HTTPS (DoH)

Query DNS records over encrypted HTTPS using public resolvers:

```sql
-- Using default resolver (Cloudflare)
SELECT doh_lookup('example.com', 'A');
SELECT doh_lookup('example.com', 'AAAA');
SELECT doh_lookup('example.com', 'MX');

-- Using a custom resolver
SELECT doh_lookup('https://dns.google/dns-query', 'example.com', 'A');
```

## Multicast DNS (mDNS)

Discover services on the local network:

```sql
-- Discover HTTP services (default 3-second timeout)
FROM mdns_discover('_http._tcp.local');

-- With custom timeout (milliseconds)
FROM mdns_discover('_ipp._tcp.local', timeout := 5000);
```

## Practical Examples

```sql
-- Check if a domain has SPF configured
SELECT dns_txt('example.com') LIKE '%v=spf1%' AS has_spf;

-- Resolve all mail servers for a domain
SELECT dns_mx('gmail.com');

-- Compare system DNS vs DoH results
SELECT
    dns_lookup_a('example.com') AS system_dns,
    doh_lookup('example.com', 'A') AS doh_result;
```

## Security Considerations

- DNS results used internally (e.g., for SSRF checks) always use system resolution, not DoH.
- mDNS is limited to local network discovery and enforces recursion depth limits.
- DoH resolver URLs are validated against [SSRF rules](../security/ssrf.md).
