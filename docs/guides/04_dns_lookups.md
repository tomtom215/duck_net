# Implementation Guide: DNS Lookups

## Goal

Scalar functions for DNS resolution. Primary use case: enriching log data with hostnames, IP geolocation prep, security analysis.

## SQL Interface

```sql
-- Forward lookup: hostname → IP addresses
SELECT dns_lookup('example.com');
-- Returns: ['93.184.216.34', '2606:2800:220:1:248:1893:25c8:1946']

-- Reverse lookup: IP → hostname
SELECT dns_reverse('93.184.216.34');
-- Returns: 'example.com' (or NULL if no PTR record)

-- A records only (IPv4)
SELECT dns_lookup_a('example.com');
-- Returns: ['93.184.216.34']

-- AAAA records only (IPv6)
SELECT dns_lookup_aaaa('example.com');
-- Returns: ['2606:2800:220:1:248:1893:25c8:1946']

-- TXT records (SPF, DKIM, verification tokens)
SELECT dns_txt('example.com');
-- Returns: ['v=spf1 -all', 'google-site-verification=...']

-- MX records (mail servers)
SELECT dns_mx('example.com');
-- Returns: [{'priority': 10, 'host': 'mail.example.com'}]
-- Type: LIST(STRUCT(priority INTEGER, host VARCHAR))

-- Practical usage: enrich web server logs
SELECT
    client_ip,
    dns_reverse(client_ip) AS hostname,
    request_path,
    status_code
FROM access_logs
WHERE status_code >= 400;
```

## Functions

| Function | Signature | Returns |
|----------|-----------|---------|
| `dns_lookup` | `(hostname VARCHAR)` | `VARCHAR[]` (all IPs, v4 and v6) |
| `dns_lookup_a` | `(hostname VARCHAR)` | `VARCHAR[]` (IPv4 only) |
| `dns_lookup_aaaa` | `(hostname VARCHAR)` | `VARCHAR[]` (IPv6 only) |
| `dns_reverse` | `(ip VARCHAR)` | `VARCHAR` (hostname or NULL) |
| `dns_txt` | `(hostname VARCHAR)` | `VARCHAR[]` (TXT record values) |
| `dns_mx` | `(hostname VARCHAR)` | `LIST(STRUCT(priority INTEGER, host VARCHAR))` |

## Architecture

### File Structure

```
src/
  dns.rs            # Pure DNS resolution logic
  ffi/
    mod.rs          # Updated: register DNS functions
    scalars.rs      # HTTP scalar functions (existing)
    dns.rs          # DNS scalar function callbacks + registration
```

### DNS Resolution Approach

**Option A: System resolver (std::net)**
```rust
use std::net::ToSocketAddrs;

fn lookup(hostname: &str) -> Vec<String> {
    let addr = format!("{hostname}:0");
    addr.to_socket_addrs()
        .map(|addrs| addrs.map(|a| a.ip().to_string()).collect())
        .unwrap_or_default()
}
```
- Pro: Zero dependencies, uses OS resolver, respects /etc/hosts and nsswitch.conf
- Con: No TXT/MX records, no record type control, blocks on system DNS timeout
- Con: Reverse lookup requires platform-specific code (libc `getnameinfo`)

**Option B: hickory-dns (formerly trust-dns)**
```rust
use hickory_resolver::Resolver;
use hickory_resolver::config::*;

fn lookup(hostname: &str) -> Vec<String> {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
    let response = resolver.lookup_ip(hostname).unwrap();
    response.iter().map(|ip| ip.to_string()).collect()
}
```
- Pro: Full DNS record type support (A, AAAA, TXT, MX, CNAME, SRV, etc.)
- Pro: Pure Rust, configurable timeouts, caching
- Con: Adds a dependency (~moderate size)

**Recommendation**: Use **hickory-dns** (`hickory-resolver` crate). The whole point of DNS functions is record-type-specific queries. `std::net` can only resolve to IP addresses — no TXT, no MX, no PTR control. hickory-dns is the standard Rust DNS library, pure Rust, well-maintained.

### Dependency

```toml
hickory-resolver = { version = "0.25", default-features = false, features = ["system-config"] }
```

Check latest version as of the implementation date. The `system-config` feature reads `/etc/resolv.conf` for upstream DNS servers.

**Important**: hickory-resolver has a tokio async API by default. For our sync context, use the `hickory-resolver` sync API or `block_on` a minimal runtime. Check if hickory-resolver offers a sync resolver in the latest version. If not, consider the `blocking` approach:

```rust
use std::sync::LazyLock;
use hickory_resolver::TokioAsyncResolver;
use tokio::runtime::Runtime;

static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| {
    Runtime::new().expect("Failed to create tokio runtime for DNS")
});

static RESOLVER: LazyLock<TokioAsyncResolver> = LazyLock::new(|| {
    RUNTIME.block_on(async {
        TokioAsyncResolver::tokio_from_system_conf()
            .expect("Failed to create DNS resolver")
    })
});

fn lookup(hostname: &str) -> Vec<String> {
    RUNTIME.block_on(async {
        RESOLVER.lookup_ip(hostname).await
            .map(|r| r.iter().map(|ip| ip.to_string()).collect())
            .unwrap_or_default()
    })
}
```

**Concern**: Adding tokio as a dependency for DNS is heavy. Alternatives:
1. Check if hickory-resolver has a sync API
2. Use `trust-dns-resolver` older version with sync support
3. Use libc `getaddrinfo` + `getnameinfo` directly (covers A/AAAA/PTR but not TXT/MX)
4. Implement a minimal DNS client over UDP (DNS wire format is simple)

**Evaluate at implementation time**: Check the dependency tree impact of hickory-resolver. If it pulls in tokio and adds 50+ crates, consider implementing a minimal DNS-over-UDP client instead. The DNS wire protocol is well-documented and a basic query/response client is ~200 lines.

### Return Type: LIST(VARCHAR)

For `dns_lookup`, `dns_lookup_a`, `dns_lookup_aaaa`, `dns_txt`: return `LIST(VARCHAR)`.

quack-rs has `LogicalType::list(TypeId::Varchar)` — this works! And `ListVector` for writing output. These functions can use quack-rs builders.

### Return Type: LIST(STRUCT(priority INTEGER, host VARCHAR))

For `dns_mx`: return `LIST(STRUCT(priority INTEGER, host VARCHAR))`.

This is a nested complex type — same quack-rs gap as the HTTP response type. Use raw libduckdb-sys for type creation and registration.

### Registration

For simple return types (LIST(VARCHAR)), use quack-rs `ScalarFunctionBuilder`:
```rust
con.register_scalar(
    ScalarFunctionBuilder::new("dns_lookup")
        .param(TypeId::Varchar)
        .returns_logical(LogicalType::list(TypeId::Varchar))
        .function(dns_lookup_callback),
)?;
```

For `dns_mx` (LIST(STRUCT)), use raw registration (same pattern as HTTP functions).

For `dns_reverse` (VARCHAR, nullable), use quack-rs builder with default null handling.

## Estimated Scope

- `dns.rs`: ~150 lines (resolver setup, lookup functions for each record type)
- `ffi/dns.rs`: ~200 lines (callbacks + registration for 6 functions)
- `ffi/mod.rs`: ~5 lines (wire up)
- Dependency evaluation: ~1 hour (tokio impact, sync alternatives)
- Total: ~350 lines + dependency decision

## Key Risks

- **Dependency weight**: hickory-resolver may pull in tokio, adding significant compile time and binary size. Must evaluate and potentially implement a lightweight alternative.
- **Blocking DNS**: DNS queries block the DuckDB worker thread. System DNS typically times out in 5-30 seconds. For bulk lookups on large tables, this could be slow. Document that DNS functions are I/O-bound and not suitable for millions of rows.
- **Caching**: DNS results should be cached (TTL-aware) to avoid redundant queries when the same hostname appears in multiple rows. A simple `HashMap<String, (Instant, Vec<String>)>` with TTL-based eviction would help.
- **Platform differences**: System resolver behavior varies between Linux, macOS, and Windows. hickory-resolver with `system-config` handles this; a custom implementation would need platform-specific code.

## Testing

- Unit tests: mock DNS responses (hickory-resolver supports custom name servers)
- Integration tests: resolve well-known domains (google.com, example.com)
- Edge cases: invalid hostnames, IPv6-only hosts, NXDOMAIN, timeout handling
