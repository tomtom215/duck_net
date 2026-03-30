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

## v0.2.0 — Shipped

17 new protocol modules across three tiers, expanding duck_net from a pure HTTP extension into a comprehensive networking toolkit.

### Tier 1: High-Value Business Protocols

| Module | Functions | Description |
|--------|-----------|-------------|
| **GraphQL** | `graphql_query(url, query, [variables])`, `graphql_has_errors`, `graphql_extract_errors` | Query GraphQL APIs with optional variables and error inspection |
| **WebDAV** | `webdav_list` (table), `webdav_read`, `webdav_write`, `webdav_delete`, `webdav_mkcol` | Full WebDAV file management via PROPFIND, GET, PUT, DELETE, MKCOL |
| **LDAP** | `ldap_search` (table), `ldap_bind` | LDAP directory search (flattened dn/attribute/value) and bind authentication |
| **TLS Inspect** | `tls_inspect(host, [port])` | Connect to a TLS server and extract X.509 certificate details (subject, issuer, SANs, expiry, algorithms) |
| **WHOIS** | `whois_lookup`, `whois_query` | Raw WHOIS text and structured domain info (registrar, dates, nameservers, status) |
| **OData** | `odata_query`, `odata_paginate` (table), `odata_extract_count` | OData queries with $filter/$select/$top/$orderby/$expand; automatic pagination via @odata.nextLink (v4) and __next (v2 JSON); total count via @odata.count (v4) and __count (v2 JSON) |
| **JSON-RPC / XML-RPC** | `jsonrpc_call(url, method, [params])`, `xmlrpc_call` | JSON-RPC 2.0 and XML-RPC remote procedure calls |

### Tier 2: Infrastructure & Monitoring

| Module | Functions | Description |
|--------|-----------|-------------|
| **IMAP** | `imap_list` (table), `imap_fetch` | List and fetch email messages from IMAP servers (plain and TLS) |
| **SNMP** | `snmp_get`, `snmp_walk` (table) | SNMPv2c GET and GETNEXT walk for network device monitoring. Hand-rolled BER/ASN.1 encoding |
| **Ping / Traceroute** | `ping(host, [timeout])`, `traceroute` (table) | ICMP ping and traceroute via system commands with input validation |

### Tier 3: Specialized Protocols

| Module | Functions | Description |
|--------|-----------|-------------|
| **NTP** | `ntp_query` | Query NTP servers for time offset, delay, stratum, and reference ID |
| **SIP** | `sip_options(host, [port])` | SIP OPTIONS ping to check VoIP server availability |
| **CalDAV / CardDAV** | `caldav_events` (table), `carddav_contacts` (table) | List calendar events (with time-range filter) and address book contacts |
| **Syslog** | `syslog_send(host, message, [facility, severity, ...])` | Send RFC 5424 syslog messages over UDP |
| **AWS SigV4** | `aws_sigv4_sign(method, url, headers, body, access_key, secret_key, region)` | Sign HTTP requests with AWS Signature Version 4 |
| **AMQP** | `amqp_publish(url, exchange, routing_key, message, [content_type])` | Publish messages to RabbitMQ/AMQP brokers |
| **Kafka** | `kafka_produce(brokers, topic, [key], value)` | Produce messages to Apache Kafka topics |

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

## v0.3.0 — Shipped

13 new protocol modules closing identified security and infrastructure gaps. All protocols implement strict input validation, timeouts, and size limits.

### New Tier 1: High Impact

| Module | Functions | Description |
|--------|-----------|-------------|
| **SSH/SCP** | `ssh_exec(host, user, key, command)`, `ssh_exec_password` | Remote command execution via SSH. Host key verification via known_hosts (TOFU). Uses existing `russh` dependency |
| **Redis** | `redis_get`, `redis_set`, `redis_keys` | Cache/config lookups from SQL. Raw RESP protocol — zero external Redis dependencies |
| **gRPC** | `grpc_call(url, service, method, json_payload)` | Unary gRPC over HTTP/2 (h2 crate). JSON-in/JSON-out sidesteps protobuf complexity |
| **WebSocket (one-shot)** | `ws_request(url, message, [timeout])` | Send one message, wait for one response, close. Health checks and simple RPC-over-WS |

### New Tier 2: Infrastructure

| Module | Functions | Description |
|--------|-----------|-------------|
| **MQTT Publish** | `mqtt_publish(broker, topic, payload)` | Fire-and-forget at QoS 0. Raw MQTT 3.1.1 — zero external MQTT dependencies. IoT data pipelines feeding DuckDB |
| **Memcached** | `memcached_get`, `memcached_set` | ASCII protocol over TCP. Simpler than Redis, still common in production |
| **Prometheus** | `prometheus_query`, `prometheus_query_range` | Pull metrics into SQL for ad-hoc analysis. Dedicated functions handle the Prometheus response format |
| **Elasticsearch** | `es_search`, `es_count`, `es_cat` | Structured helpers for _search, _count, _cat endpoints with index name validation |

### New Tier 3: Niche but Clean Fits

| Module | Functions | Description |
|--------|-----------|-------------|
| **RADIUS** | `radius_auth(host, secret, username, password)` | Auth testing for network infrastructure. RFC 2865 with response authenticator verification |
| **DNS-over-HTTPS** | `doh_lookup(resolver_url, domain, type)` | Privacy-aware DNS over encrypted HTTPS. Default: Cloudflare |
| **mDNS/Bonjour** | `mdns_discover(service_type)` (table) | Local network service discovery via multicast DNS (RFC 6762) |
| **STUN** | `stun_lookup(server)` | Public IP/port discovery. One UDP round-trip (RFC 5389) |
| **BGP Looking Glass** | `bgp_route(prefix)`, `bgp_prefix_overview`, `bgp_asn_info` | Network routing analysis via RIPE RIS public API |

## v0.3.1 — Security Audit & Hardening

Comprehensive security audit and hardening pass across all 49+ protocol implementations.

### Security Fixes

| Issue | Fix | CWE |
|-------|-----|-----|
| **Weak PRNG in RADIUS/SIP** | Replaced time-based xorshift with OS CSPRNG (`getrandom`) | CWE-338 |
| **CalDAV XML injection** | ISO 8601 timestamp validation before XML interpolation | CWE-91 |
| **NATS JSON injection** | Proper RFC 8259 JSON escaping for credentials in CONNECT payload | CWE-116 |
| **Redis stack overflow** | Depth-limited RESP array parsing (max 8 levels, 100K elements) | CWE-674 |
| **OCSP buffer overread** | Bounds-checked slice access in all DER/ASN.1 parsing | CWE-125 |
| **Missing SSRF in AMQP** | Added `validate_no_ssrf()` to AMQP connection | CWE-918 |
| **Missing SSRF in Kafka** | Added per-broker SSRF validation | CWE-918 |
| **Missing SSRF in ZeroMQ** | Added `validate_no_ssrf_host()` to ZMQ connections | CWE-918 |
| **Missing SSRF in SIP** | Added SSRF + host validation to SIP OPTIONS | CWE-918 |
| **Missing SSRF in OCSP** | Added SSRF validation before TLS connection | CWE-918 |
| **Missing SSRF in RADIUS** | Added SSRF validation before UDP connection | CWE-918 |
| **SNMP community length** | Added max 255 character limit with null byte rejection | CWE-400 |
| **Kafka topic validation** | Added name length limit (1-249) and null byte check | - |

### New Security Features

| Feature | Description |
|---------|-------------|
| **LDAP filter escaping** | `security::ldap_escape_filter_value()` per RFC 4515 |
| **URL length validation** | `security::validate_url_length()` — max 64KB |
| **Port validation** | `security::validate_port()` — 1-65535 |
| **Host validation** | `security::validate_host()` — shared across protocols |
| **JSON escaping** | `security::json_escape()` — RFC 8259 compliant |
| **Cryptographic RNG** | `security::random_bytes()` / `random_hex()` — OS CSPRNG |

### Secrets Manager Expansion

New secrets-aware protocol functions:

| Function | Description |
|----------|-------------|
| `redis_get_secret(secret, key)` | Redis GET with stored password |
| `redis_set_secret(secret, key, value)` | Redis SET with stored password |
| `ldap_search_secret(secret, url, base, filter, attrs)` | LDAP search with stored bind credentials |

### DuckDB Secrets Manager Compatibility

duck_net's secrets manager uses the same key names as DuckDB's native `CREATE SECRET`:
- S3: `KEY_ID`, `SECRET`, `REGION`, `ENDPOINT`
- HTTP: `BEARER_TOKEN`, `EXTRA_HTTP_HEADERS`

For S3/HTTP/GCS, users should prefer DuckDB's native secrets. duck_net covers protocols DuckDB doesn't natively support.

## Rejected Protocols

| Protocol | Reason |
|----------|--------|
| MQTT Subscribe | Push-based streaming. Fundamental mismatch with DuckDB's pull model. |
| XMPP | Deeply stateful, session-oriented, streaming. Zero SQL use case. |
| QUIC / HTTP/3 | Transport-layer protocol. DuckDB doesn't control socket-level details; ureq handles connections. No user-facing benefit. |
| Raw TCP/UDP | Too low-level for SQL. Specific protocols (WHOIS, NTP, SIP, SNMP, RADIUS, STUN, mDNS) already use raw sockets internally. |

## v0.4.0 — In Progress

### Security Hardening & DuckDB Secrets Integration

| Feature | Status | Description |
|---------|--------|-------------|
| Security warnings subsystem | Done | Runtime alerts for plaintext protocols, missing auth, weak crypto |
| DuckDB secrets manager integration | Done | Bridge to native `CREATE SECRET` for S3/HTTP/GCS/R2 |
| Plaintext protocol warnings | Done | Warnings for MQTT, Redis, FTP, LDAP, AMQP, Kafka, NATS, WebSocket, ZeroMQ, Syslog |
| No-auth protocol warnings | Done | Warnings for Memcached (no built-in auth) |
| Token-over-HTTP warnings | Done | Critical warnings for Consul/Vault tokens over plaintext |
| Weak auth warnings | Done | Warnings for SNMPv2c and IPMI v1.5 |
| SSH TOFU warnings | Done | Warning on first-time host key acceptance |
| Module refactoring | Done | All files under 600 lines for modularity |
| mdBook documentation | Done | Professional, searchable documentation with per-protocol guides |
| `duck_net_security_warnings()` | Done | Table function to query all session warnings |
| `duck_net_set_security_warnings()` | Done | Suppress warnings for CI/airgapped systems |

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
