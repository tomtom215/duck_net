# duck_net Roadmap

## Design Principle

Every feature must pass this filter: **Does it map naturally to DuckDB's synchronous, batch-oriented, pull-based execution model?**

- Scalar functions: stateless, row-in → row-out
- Table functions: produce a finite, pull-based result set
- No persistent connections, no push-based streaming, no background threads

Protocols that are request-response and stateless are excellent fits. Protocols that are streaming, session-oriented, or push-based are not.

## v0.1.0 — Shipped

- All HTTP methods: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS
- Generic `http_request(method, url, headers, body)`
- Native STRUCT return type with MAP headers
- Multipart/file upload (`http_post_multipart`)
- Connection pooling (ureq Agent)
- rustls TLS (pure Rust, no OpenSSL)

## Priority 1: Production-Grade HTTP (REST + SOAP)

### 1a. Retry with Configurable Backoff
Configurable retry for transient failures (5xx, timeouts, 429). Exponential backoff. DuckDB settings for max_retries, backoff_ms, retryable_statuses.

### 1b. Rate Limiting
Token bucket per domain. Prevents API throttling when calling endpoints across many rows. Global or per-domain config via DuckDB settings.

### 1c. Paginated API Consumption (Table Function)
`http_paginate` table function. Follows next-links (Link header or JSON path) or increments page/offset parameters. Returns one row per page.

### 1d. Authentication Helpers
- `http_basic_auth(user, pass)` → `'Basic <base64>'`
- `http_bearer_auth(token)` → `'Bearer <token>'`
- `http_oauth2_token(token_url, client_id, client_secret)` → `'Bearer <access_token>'`

### 1e. SOAP Support
- `soap_request(url, action, body_xml)` — wraps XML in SOAP envelope, sets headers, sends POST
- `soap12_request(url, action, body_xml)` — SOAP 1.2 variant
- `soap_extract_body(xml)` — extracts content from `<soap:Body>`
- `soap_is_fault(xml)` / `soap_fault_string(xml)` — fault detection
- SOAP header blocks for WS-Security username tokens, WS-Addressing
- Zero new dependencies (string manipulation + existing HTTP client)

## Priority 2: FTP/SFTP File Operations

Enterprise file exchange. Complements httpfs (HTTP/S3) with FTP/SFTP coverage for finance, healthcare, government, supply chain.

### 2a. ftp_list, sftp_list (table functions)
### 2b. ftp_read, sftp_read (scalar functions)
### 2c. ftp_write, sftp_write (scalar functions)
### 2d. ftp_delete, sftp_delete (scalar functions)

Dependencies: suppaftp (sync FTP/FTPS), russh + russh-sftp (async SFTP, tokio already in tree).

## Priority 3: DNS Lookups

Scalar functions for DNS resolution. Perfect fit for log enrichment and network analysis.

### 3a. dns_lookup, dns_reverse, dns_txt, dns_mx

## Priority 4: SMTP Send

Fire-and-forget email sending from SQL. Useful for alerting on query results.

### 4a. smtp_send

## Rejected Protocols

| Protocol | Reason |
|----------|--------|
| WebSockets | Push-based streaming. No natural mapping to DuckDB functions. "Connect-send-receive-disconnect" is just worse HTTP. |
| MQTT Subscribe | Push-based streaming. Same fundamental mismatch as WebSockets. |
| MQTT Publish | Feasible but extremely niche. Who publishes MQTT from SQL? |
| XMPP | Deeply stateful, session-oriented, streaming. Zero SQL use case. |
| gRPC | Request-response fits, but protobuf handling is enormous complexity for marginal gain over HTTP+JSON. Revisit if demand materializes. |

## Implementation Guides

| Guide | Feature | Est. Lines |
|-------|---------|-----------|
| [01](guides/01_http_retry_backoff.md) | HTTP retry with backoff | ~100 |
| [02](guides/02_http_pagination_table_function.md) | Paginated API table function | ~300 |
| [03](guides/03_http_auth_helpers.md) | Auth helpers (Basic, Bearer, OAuth2) | ~125 |
| [04](guides/04_dns_lookups.md) | DNS lookups | ~350 |
| [05](guides/05_smtp_send.md) | SMTP send | ~310 |
| [06](guides/06_ftp_sftp.md) | FTP/SFTP file operations | ~1,150 |
| [07](guides/07_rest_soap_enterprise.md) | Enterprise REST + SOAP | ~420 |
