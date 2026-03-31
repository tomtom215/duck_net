# Installation

## From Source

```bash
# Clone the repository
git clone https://github.com/tomtom215/duck_net.git
cd duck_net

# Build the extension
cargo build --release

# The extension is built to:
# target/release/libduck_net.so
```

### Requirements

- Rust 1.88+ (MSRV)
- DuckDB 1.5.1+ (built against libduckdb-sys `=1.10501.0`)
- A C compiler (for libduckdb-sys)

## Loading the Extension

```sql
-- Load (unsigned — use the full path to the .so file)
LOAD 'target/release/libduck_net.so';

-- Verify it loaded
SELECT duck_net_security_status();
```

## Verifying Installation

After loading, confirm the core protocols are available:

```sql
-- Test HTTP (always-on core protocol)
SELECT (http_get('https://httpbin.org/get')).status;
-- Should return: 200

-- Test DNS (always-on core protocol)
SELECT dns_lookup('example.com', 'A');

-- View which protocols are enabled
SELECT * FROM duck_net_protocols()
ORDER BY "group", protocol;

-- Check security configuration
SELECT duck_net_security_status();

-- List any security warnings
FROM duck_net_security_warnings();
```

## Protocol Opt-In

Only core web protocols are enabled by default. Additional protocols must be
listed in a plain-text config file before loading the extension.

### Config file locations (first found wins)

| Priority | Path |
|----------|------|
| 1 | `$DUCK_NET_CONFIG` (environment variable) |
| 2 | `~/.config/duck_net/protocols` |
| 3 | `~/.duck_net_protocols` |

### File format

One protocol name per line. Lines starting with `#` are ignored.

```text
# ~/.config/duck_net/protocols

# Remote execution
ssh

# Email
smtp
imap

# Databases
redis
```

### Generating a config template

```sql
-- Prints a fully-commented template you can save directly
SELECT duck_net_generate_config();
```

### Checking what is enabled

```sql
SELECT protocol, "group", enabled, description
FROM duck_net_protocols()
ORDER BY "group", protocol;
```

### Always-on core protocols

These are registered unconditionally regardless of the config file:

| Protocol | SQL functions |
|----------|--------------|
| HTTP/HTTPS | `http_get`, `http_post`, `http_put`, `http_patch`, `http_delete`, `http_head`, `http_options`, `http_request`, `http_post_multipart`, `http_paginate` |
| SOAP | `soap_request`, `soap12_request`, `soap_extract_body`, `soap_is_fault`, `soap_fault_string` |
| GraphQL | `graphql_query`, `graphql_has_errors`, `graphql_extract_errors` |
| OAuth2 | `http_oauth2_token` |
| DNS | `dns_lookup`, `dns_lookup_a`, `dns_lookup_aaaa`, `dns_reverse`, `dns_txt`, `dns_mx` |
| DNS-over-HTTPS | `doh_lookup` |
| TLS / OCSP | `tls_inspect`, `ocsp_check` |
| WHOIS | `whois_lookup`, `whois_query` |
| Secrets | `duck_net_add_secret`, `duck_net_clear_secret`, `duck_net_rotate_secret`, and more |
| Security | `duck_net_security_status`, `duck_net_security_warnings()`, and more |
| Audit log | `duck_net_set_audit_logging`, `duck_net_audit_log()`, and more |
| Configuration | `duck_net_set_timeout`, `duck_net_set_retries`, `duck_net_set_rate_limit`, and more |
