# duck_net

A DuckDB extension providing comprehensive HTTP/HTTPS network client operations, written in Rust using the [quack-rs](https://github.com/tomtom215/quack-rs) SDK.

## Functions

All functions return `STRUCT(status INTEGER, reason VARCHAR, headers MAP(VARCHAR, VARCHAR), body VARCHAR)`.

### No-Body Methods

| Function | Signatures |
|----------|-----------|
| `http_get` | `(url VARCHAR)`, `(url VARCHAR, headers MAP(VARCHAR, VARCHAR))` |
| `http_delete` | `(url VARCHAR)`, `(url VARCHAR, headers MAP(VARCHAR, VARCHAR))` |
| `http_head` | `(url VARCHAR)`, `(url VARCHAR, headers MAP(VARCHAR, VARCHAR))` |
| `http_options` | `(url VARCHAR)`, `(url VARCHAR, headers MAP(VARCHAR, VARCHAR))` |

### Body Methods

| Function | Signatures |
|----------|-----------|
| `http_post` | `(url VARCHAR, body VARCHAR)`, `(url VARCHAR, headers MAP(VARCHAR, VARCHAR), body VARCHAR)` |
| `http_put` | `(url VARCHAR, body VARCHAR)`, `(url VARCHAR, headers MAP(VARCHAR, VARCHAR), body VARCHAR)` |
| `http_patch` | `(url VARCHAR, body VARCHAR)`, `(url VARCHAR, headers MAP(VARCHAR, VARCHAR), body VARCHAR)` |

### Multipart/File Upload

| Function | Signatures |
|----------|-----------|
| `http_post_multipart` | `(url VARCHAR, form_fields MAP(VARCHAR, VARCHAR), file_fields MAP(VARCHAR, VARCHAR))`, `(url VARCHAR, headers MAP(VARCHAR, VARCHAR), form_fields MAP(VARCHAR, VARCHAR), file_fields MAP(VARCHAR, VARCHAR))` |

- `form_fields`: text key-value pairs sent as form fields
- `file_fields`: maps field names to local file paths — files are read, MIME type auto-detected, and uploaded
- Content-Type (`multipart/form-data; boundary=...`) is set automatically

### Generic

| Function | Signature |
|----------|-----------|
| `http_request` | `(method VARCHAR, url VARCHAR, headers MAP(VARCHAR, VARCHAR), body VARCHAR)` |

### Authentication Helpers

| Function | Signature | Returns |
|----------|-----------|---------|
| `http_basic_auth` | `(username VARCHAR, password VARCHAR)` | `VARCHAR` — `Basic <base64>` header value |
| `http_bearer_auth` | `(token VARCHAR)` | `VARCHAR` — `Bearer <token>` header value |
| `http_oauth2_token` | `(token_url, client_id, client_secret)`, `(token_url, client_id, client_secret, scope)` | `VARCHAR` — `Bearer <access_token>` from OAuth2 Client Credentials grant |

### SOAP

All `soap_request` / `soap12_request` return the same STRUCT as HTTP functions.

| Function | Signatures |
|----------|-----------|
| `soap_request` | `(url, action, body_xml)`, `(url, action, body_xml, headers MAP)`, `(url, action, body_xml, soap_header)`, `(url, action, body_xml, soap_header, headers MAP)` |
| `soap12_request` | `(url, action, body_xml)`, `(url, action, body_xml, soap_header)`, `(url, action, body_xml, soap_header, headers MAP)` |
| `soap_extract_body` | `(xml VARCHAR) → VARCHAR` — extracts content from `<soap:Body>` |
| `soap_is_fault` | `(xml VARCHAR) → BOOLEAN` — checks for SOAP fault |
| `soap_fault_string` | `(xml VARCHAR) → VARCHAR` — extracts fault string (NULL if not a fault) |

### Pagination (Table Function)

```sql
-- Offset-based pagination
SELECT * FROM http_paginate(
    'https://api.example.com/users?page={page}&per_page=100',
    page_param := 'page', start_page := 1, max_pages := 10
);

-- Cursor/next-link pagination
SELECT * FROM http_paginate(
    'https://api.example.com/users',
    next_url_path := '$.next', max_pages := 50
);
-- Returns: (page INTEGER, status INTEGER, headers MAP, body VARCHAR)
```

### Rate Limiting

| Function | Signature | Returns |
|----------|-----------|---------|
| `duck_net_set_rate_limit` | `(requests_per_second INTEGER)` | `VARCHAR` — global rate limit. 0 to disable |
| `duck_net_set_domain_rate_limits` | `(config VARCHAR)` | `VARCHAR` — per-domain limits. JSON: `{"domain": rps}` or `domain=rps,domain2=rps`. Supports `*.domain.com` wildcards |
| `duck_net_set_retries` | `(max_retries INTEGER, backoff_ms INTEGER)` | `VARCHAR` — configures retry with exponential backoff |
| `duck_net_set_retry_statuses` | `(statuses VARCHAR)` | `VARCHAR` — comma-separated HTTP status codes to retry on (e.g., `'429,500,502,503,504'`) |
| `duck_net_set_timeout` | `(seconds INTEGER)` | `VARCHAR` — sets global HTTP timeout |

### DNS Lookups

| Function | Signature | Returns |
|----------|-----------|---------|
| `dns_lookup` | `(hostname VARCHAR)` | `VARCHAR[]` — all IPs (v4 + v6) |
| `dns_lookup_a` | `(hostname VARCHAR)` | `VARCHAR[]` — IPv4 only |
| `dns_lookup_aaaa` | `(hostname VARCHAR)` | `VARCHAR[]` — IPv6 only |
| `dns_reverse` | `(ip VARCHAR)` | `VARCHAR` — hostname (NULL if not found) |
| `dns_txt` | `(hostname VARCHAR)` | `VARCHAR[]` — TXT records |
| `dns_mx` | `(hostname VARCHAR)` | `VARCHAR[]` — MX records as `"priority\thost"` |

### SMTP Send

| Function | Signatures |
|----------|-----------|
| `smtp_send` | `(server, from, to, subject, body)`, `(server, from, to, subject, body, username, password)` |

Returns `STRUCT(success BOOLEAN, message VARCHAR)`. Server URL: `smtp://host:port` or `smtps://host:port`.

### FTP/SFTP File Operations

| Function | Signature | Returns |
|----------|-----------|---------|
| `ftp_read` | `(url VARCHAR)` | `STRUCT(success BOOLEAN, content VARCHAR, size BIGINT, message VARCHAR)` |
| `ftp_write` | `(url VARCHAR, content VARCHAR)` | `STRUCT(success BOOLEAN, bytes_written BIGINT, message VARCHAR)` |
| `ftp_delete` | `(url VARCHAR)` | `STRUCT(success BOOLEAN, message VARCHAR)` |
| `sftp_read` | `(url VARCHAR)`, `(url VARCHAR, key_file VARCHAR)` | `STRUCT(success BOOLEAN, content VARCHAR, size BIGINT, message VARCHAR)` |
| `sftp_write` | `(url VARCHAR, content VARCHAR)` | `STRUCT(success BOOLEAN, bytes_written BIGINT, message VARCHAR)` |
| `sftp_delete` | `(url VARCHAR)` | `STRUCT(success BOOLEAN, message VARCHAR)` |
| `ftp_read_blob` | `(url VARCHAR)` | `STRUCT(success BOOLEAN, data BLOB, size BIGINT, message VARCHAR)` |
| `sftp_read_blob` | `(url VARCHAR)`, `(url VARCHAR, key_file VARCHAR)` | `STRUCT(success BOOLEAN, data BLOB, size BIGINT, message VARCHAR)` |

Table functions for directory listing:

```sql
SELECT * FROM ftp_list('ftp://user:pass@host/path/');   -- (name, size, is_dir)
SELECT * FROM sftp_list('sftp://user:pass@host/path/'); -- (name, size, is_dir)
SELECT * FROM sftp_list('sftp://user@host/path/', key_file := '/path/to/key');
```

URL format: `ftp://[user:pass@]host[:port]/path`, `sftp://[user:pass@]host[:port]/path`

FTP connections are cached with 60-second TTL for efficient bulk operations.

### SSH Remote Execution

| Function | Signatures | Returns |
|----------|-----------|---------|
| `ssh_exec` | `(host, user, key_file, command)`, `(host, port, user, key_file, command)` | `STRUCT(success BOOLEAN, exit_code INTEGER, stdout VARCHAR, stderr VARCHAR)` |
| `ssh_exec_password` | `(host, user, password, command)` | `STRUCT(success BOOLEAN, exit_code INTEGER, stdout VARCHAR, stderr VARCHAR)` |

Host key verification via `~/.ssh/known_hosts` (TOFU model). Rejects changed keys to prevent MITM attacks.

### Redis

| Function | Signatures | Returns |
|----------|-----------|---------|
| `redis_get` | `(url, key)` | `STRUCT(success BOOLEAN, value VARCHAR)` |
| `redis_set` | `(url, key, value)`, `(url, key, value, ttl_secs BIGINT)` | `STRUCT(success BOOLEAN, value VARCHAR)` |
| `redis_keys` | `(url, pattern)` | `STRUCT(success BOOLEAN, keys VARCHAR[], message VARCHAR)` |

URL format: `redis://[password@]host[:port][/db]`. Raw RESP protocol implementation — zero external Redis dependencies.

### gRPC

| Function | Signature | Returns |
|----------|-----------|---------|
| `grpc_call` | `(url, service, method, json_payload)` | `STRUCT(success BOOLEAN, status_code INTEGER, body VARCHAR, grpc_status INTEGER, grpc_message VARCHAR)` |

URL schemes: `grpc://host:port` (plaintext h2c), `grpcs://host:port` (TLS). Native HTTP/2 transport via `h2` crate.

### WebSocket (One-Shot)

| Function | Signatures | Returns |
|----------|-----------|---------|
| `ws_request` | `(url, message)`, `(url, message, timeout_secs INTEGER)` | `STRUCT(success BOOLEAN, response VARCHAR, message VARCHAR)` |

Sends one message, waits for one response, closes. Supports `ws://` and `wss://` (TLS via rustls).

### MQTT Publish

| Function | Signature | Returns |
|----------|-----------|---------|
| `mqtt_publish` | `(broker, topic, payload)` | `STRUCT(success BOOLEAN, message VARCHAR)` |

Fire-and-forget publish at QoS 0. Broker format: `mqtt://[user:pass@]host[:port]` or bare `host:port`. Raw MQTT 3.1.1 protocol — zero external MQTT dependencies.

### Memcached

| Function | Signatures | Returns |
|----------|-----------|---------|
| `memcached_get` | `(host, key)` | `STRUCT(success BOOLEAN, value VARCHAR, message VARCHAR)` |
| `memcached_set` | `(host, key, value)`, `(host, key, value, ttl INTEGER)` | `STRUCT(success BOOLEAN, value VARCHAR, message VARCHAR)` |

Host format: `host[:port]` (default 11211). ASCII protocol over TCP — zero external Memcached dependencies.

### Prometheus

| Function | Signatures | Returns |
|----------|-----------|---------|
| `prometheus_query` | `(url, promql)` | `STRUCT(success BOOLEAN, result_type VARCHAR, body VARCHAR, message VARCHAR)` |
| `prometheus_query_range` | `(url, promql, start, end, step)` | `STRUCT(success BOOLEAN, result_type VARCHAR, body VARCHAR, message VARCHAR)` |

Queries the Prometheus HTTP API. Returns full JSON response for ad-hoc SQL analysis.

### Elasticsearch

| Function | Signatures | Returns |
|----------|-----------|---------|
| `es_search` | `(url, index, query_json)` | `STRUCT(success BOOLEAN, body VARCHAR, message VARCHAR)` |
| `es_count` | `(url, index, query_json)` | `STRUCT(success BOOLEAN, body VARCHAR, message VARCHAR)` |
| `es_cat` | `(url, endpoint)` | `STRUCT(success BOOLEAN, body VARCHAR, message VARCHAR)` |

Index name validation prevents path traversal. `es_cat` endpoints return JSON format.

### RADIUS Authentication

| Function | Signatures | Returns |
|----------|-----------|---------|
| `radius_auth` | `(host, secret, username, password)`, `(host, port, secret, username, password)` | `STRUCT(success BOOLEAN, code INTEGER, code_name VARCHAR, message VARCHAR)` |

RFC 2865 Access-Request with password encryption. Response authenticator verification prevents spoofing.

### DNS-over-HTTPS (DoH)

| Function | Signatures | Returns |
|----------|-----------|---------|
| `doh_lookup` | `(domain, type)`, `(resolver_url, domain, type)` | `STRUCT(success BOOLEAN, records VARCHAR[], message VARCHAR)` |

Privacy-aware DNS over encrypted HTTPS. Default resolver: Cloudflare. Supports A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT, CAA, and more.

### mDNS / Bonjour (Table Function)

```sql
SELECT * FROM mdns_discover('_http._tcp.local');
-- Returns: (instance_name VARCHAR, hostname VARCHAR, port INTEGER, ips VARCHAR[], txt VARCHAR[])

SELECT * FROM mdns_discover('_ssh._tcp.local', timeout := 5);
```

Local network service discovery via multicast DNS (RFC 6762).

### STUN

| Function | Signature | Returns |
|----------|-----------|---------|
| `stun_lookup` | `(server VARCHAR)` | `STRUCT(success BOOLEAN, public_ip VARCHAR, public_port INTEGER, message VARCHAR)` |

Discover public IP/port via a single UDP round-trip (RFC 5389). Server format: `host[:port]` or `stun://host[:port]`.

### BGP Looking Glass

| Function | Signature | Returns |
|----------|-----------|---------|
| `bgp_route` | `(prefix VARCHAR)` | `STRUCT(success BOOLEAN, body VARCHAR, message VARCHAR)` |
| `bgp_prefix_overview` | `(prefix VARCHAR)` | `STRUCT(success BOOLEAN, body VARCHAR, message VARCHAR)` |
| `bgp_asn_info` | `(asn VARCHAR)` | `STRUCT(success BOOLEAN, body VARCHAR, message VARCHAR)` |

Network routing analysis via RIPE RIS public API. Prefix format: CIDR notation (e.g., `1.0.0.0/24`).

## Usage Examples

```sql
-- Simple GET
SELECT http_get('https://httpbin.org/get');

-- GET with custom headers
SELECT http_get('https://api.example.com/data', MAP{'Authorization': 'Bearer token123'});

-- Access individual response fields
SELECT (http_get('https://httpbin.org/get')).status;
SELECT (http_get('https://httpbin.org/get')).body;
SELECT (http_get('https://httpbin.org/get')).headers;

-- POST with JSON body
SELECT http_post(
    'https://httpbin.org/post',
    MAP{'Content-Type': 'application/json'},
    '{"key": "value"}'
);

-- POST without custom headers
SELECT http_post('https://httpbin.org/post', '{"key": "value"}');

-- PUT
SELECT http_put(
    'https://httpbin.org/put',
    MAP{'Content-Type': 'application/json'},
    '{"updated": true}'
);

-- DELETE
SELECT http_delete('https://api.example.com/resource/123');

-- HEAD (response body is always empty)
SELECT http_head('https://httpbin.org/get');

-- Generic request with any method
SELECT http_request(
    'PATCH',
    'https://httpbin.org/patch',
    MAP{'Content-Type': 'application/json'},
    '{"partial": "update"}'
);

-- Multipart file upload
SELECT http_post_multipart(
    'https://httpbin.org/post',
    MAP{'description': 'My upload'},     -- form fields
    MAP{'file': '/path/to/document.pdf'}  -- file fields (field_name -> file_path)
);

-- Multipart with auth headers
SELECT http_post_multipart(
    'https://api.example.com/upload',
    MAP{'Authorization': 'Bearer token123'},  -- headers
    MAP{'title': 'Report Q4'},                -- form fields
    MAP{'attachment': '/tmp/report.pdf'}      -- file fields
);

-- Authentication helpers
SELECT http_get(
    'https://api.example.com/data',
    MAP{'Authorization': http_basic_auth('user', 'pass')}
);

SELECT http_get(
    'https://api.example.com/data',
    MAP{'Authorization': http_bearer_auth('my-jwt-token')}
);

-- OAuth2 Client Credentials
SELECT http_get(
    'https://api.example.com/data',
    MAP{'Authorization': http_oauth2_token(
        'https://auth.example.com/oauth/token',
        'client_id',
        'client_secret'
    )}
);

-- SOAP 1.1 request
SELECT soap_request(
    'https://soap.example.com/Service',
    'http://example.com/GetAccount',
    '<GetAccount xmlns="http://example.com/"><Id>123</Id></GetAccount>'
);

-- SOAP with WS-Security header
SELECT soap_request(
    'https://bank.example.com/PaymentService',
    'urn:ProcessPayment',
    '<ProcessPayment><Amount>1000</Amount></ProcessPayment>',
    '<wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
       <wsse:UsernameToken>
         <wsse:Username>svc</wsse:Username>
         <wsse:Password>pass</wsse:Password>
       </wsse:UsernameToken>
     </wsse:Security>'
);

-- Parse SOAP response
SELECT soap_extract_body(
    (soap_request('https://...', 'urn:GetData', '<GetData/>')).body
);

-- Rate limiting (throttle to 10 req/s across all domains)
SELECT duck_net_set_rate_limit(10);

-- Paginate through an API
SELECT page, status, body
FROM http_paginate(
    'https://api.example.com/items?page={page}',
    page_param := 'page', start_page := 1, max_pages := 5
);

-- DNS lookups
SELECT dns_lookup('example.com');        -- ['93.184.216.34', '2606:2800:...']
SELECT dns_lookup_a('example.com');      -- ['93.184.216.34']
SELECT dns_reverse('8.8.8.8');           -- 'dns.google'
SELECT dns_txt('example.com');           -- TXT records
SELECT dns_mx('gmail.com');              -- MX records

-- SMTP send
SELECT smtp_send(
    'smtp://mail.example.com:587',
    'alerts@example.com', 'ops@example.com',
    'Alert: High Error Rate',
    'Error rate exceeded 5% threshold.'
);

-- SMTP with authentication
SELECT smtp_send(
    'smtps://smtp.gmail.com:465',
    'from@gmail.com', 'to@example.com',
    'Subject', 'Body',
    'from@gmail.com', 'app-password'
);

-- FTP operations
SELECT ftp_read('ftp://user:pass@ftp.example.com/data/report.csv');
SELECT ftp_write('ftp://user:pass@ftp.example.com/outbox/file.csv', 'col1,col2\nval1,val2');
SELECT ftp_delete('ftp://user:pass@ftp.example.com/old/file.txt');

-- SFTP operations
SELECT sftp_read('sftp://user:pass@sftp.example.com/data/export.csv');
SELECT sftp_read('sftp://user@host/path/file.txt', '/home/user/.ssh/id_ed25519');
SELECT sftp_write('sftp://user:pass@host/uploads/data.csv', 'csv,data');
SELECT sftp_delete('sftp://user:pass@host/processed/old.csv');

-- Use in queries with tables
SELECT
    url,
    (http_get(url)).status AS status,
    (http_get(url)).body AS body
FROM (VALUES ('https://httpbin.org/get'), ('https://httpbin.org/ip')) AS t(url);

-- SSH remote execution
SELECT ssh_exec('server.example.com', 'deploy', '/home/deploy/.ssh/id_ed25519', 'uptime');
SELECT ssh_exec_password('server.example.com', 'admin', 'password', 'df -h');

-- Redis cache operations
SELECT redis_get('redis://localhost:6379', 'config:timeout');
SELECT redis_set('redis://localhost:6379', 'session:abc', '{"user":"tom"}');
SELECT redis_set('redis://localhost:6379', 'cache:key', 'value', 3600);  -- 1 hour TTL
SELECT redis_keys('redis://localhost:6379', 'session:*');

-- gRPC unary call
SELECT grpc_call('grpc://localhost:50051', 'mypackage.MyService', 'GetItem', '{"id": 42}');

-- WebSocket one-shot request-response
SELECT ws_request('ws://echo.websocket.org', '{"action": "ping"}');
SELECT ws_request('wss://api.example.com/ws', '{"subscribe": "ticker"}', 30);

-- MQTT publish (IoT data pipeline)
SELECT mqtt_publish('mqtt://broker.example.com:1883', 'sensors/temperature', '{"value": 22.5}');

-- Memcached cache operations
SELECT memcached_get('localhost:11211', 'user:profile:123');
SELECT memcached_set('localhost:11211', 'user:profile:123', '{"name":"Tom"}', 300);

-- Prometheus ad-hoc analysis
SELECT prometheus_query('http://prometheus:9090', 'rate(http_requests_total[5m])');
SELECT prometheus_query_range(
    'http://prometheus:9090', 'up', '2024-01-01T00:00:00Z', '2024-01-02T00:00:00Z', '1h'
);

-- Elasticsearch queries from SQL
SELECT es_search('http://localhost:9200', 'logs-*', '{"query":{"match":{"level":"error"}}}');
SELECT es_count('http://localhost:9200', 'logs-*', '{"query":{"range":{"@timestamp":{"gte":"now-1h"}}}}');
SELECT es_cat('http://localhost:9200', 'indices');

-- RADIUS auth testing
SELECT radius_auth('radius.example.com', 'shared-secret', 'testuser', 'testpass');

-- DNS-over-HTTPS (privacy-aware DNS)
SELECT doh_lookup('example.com', 'A');
SELECT doh_lookup('https://dns.google/resolve', 'example.com', 'AAAA');

-- mDNS/Bonjour service discovery
SELECT * FROM mdns_discover('_http._tcp.local');

-- STUN public IP discovery
SELECT stun_lookup('stun.l.google.com:19302');

-- BGP routing analysis
SELECT bgp_route('8.8.8.0/24');
SELECT bgp_prefix_overview('1.1.1.0/24');
SELECT bgp_asn_info('AS13335');
```

## Response Format

Every function returns a STRUCT with four fields:

| Field | Type | Description |
|-------|------|-------------|
| `status` | `INTEGER` | HTTP status code (200, 404, etc.). `0` indicates a connection/transport error. |
| `reason` | `VARCHAR` | HTTP reason phrase ("OK", "Not Found") or error message when status is 0. |
| `headers` | `MAP(VARCHAR, VARCHAR)` | Response headers as key-value pairs. |
| `body` | `VARCHAR` | Response body text. Empty for HEAD requests. |

## Building

```bash
cargo build --release
```

The extension shared library will be at `target/release/libduck_net.so` (Linux), `.dylib` (macOS), or `.dll` (Windows).

### Loading in DuckDB

```sql
LOAD 'path/to/libduck_net.so';
```

For unsigned extensions:
```bash
duckdb -unsigned -cmd "LOAD 'target/release/libduck_net.so';"
```

## Architecture

- **`src/http.rs`** — Pure HTTP client logic using [ureq](https://crates.io/crates/ureq). No DuckDB dependencies. Testable independently.
- **`src/ffi/scalars.rs`** — DuckDB scalar function registration and callbacks. Reads input vectors, calls HTTP, writes output STRUCT with MAP headers.
- **`src/ffi/mod.rs`** — Coordinator that wires registration to the DuckDB connection.
- **`src/lib.rs`** — Extension entry point using `quack_rs::entry_point_v2!`.

## Security

See [SECURITY.md](SECURITY.md) for the full security architecture document.

### Security Highlights

| Category | Protection | CWE |
|----------|-----------|-----|
| **SSRF protection** | All 49+ protocols validate destination IPs against private/reserved ranges before connecting | CWE-918 |
| **Credential management** | In-memory secrets manager with zeroization; credentials never in SQL query text | CWE-316, CWE-532 |
| **DuckDB secrets compat** | For S3/HTTP/GCS/R2, use DuckDB native `CREATE SECRET`; duck_net covers SMTP, SSH, LDAP, Redis, etc. | — |
| **Response size limits** | HTTP 256 MiB, gRPC/WS/Redis/NATS/MQTT/Kafka 16 MiB, IMAP 10 MiB, Memcached 1 MiB | CWE-400 |
| **Input validation** | URL length (64KB max), hostname format, port range, path traversal prevention | CWE-22, CWE-400 |
| **SSH command injection** | Shell metacharacters blocked in strict mode (default) | CWE-78 |
| **SMTP injection** | CRLF sanitization in headers, dot-stuffing in body | CWE-93 |
| **SOAP header injection** | CR/LF/NUL stripped from SOAPAction to prevent HTTP header splitting | CWE-113 |
| **LDAP filter injection** | RFC 4515 escaping for filter values | CWE-90 |
| **XML injection** | CalDAV timestamp validation prevents XML attribute injection | CWE-91 |
| **JSON injection** | NATS credentials JSON-escaped per RFC 8259 | CWE-116 |
| **Recursion depth limits** | Vault JSON (128), gRPC protobuf (16), Redis RESP (8), mDNS (128) | CWE-674 |
| **OCSP bounds checking** | All DER parsing uses bounds-checked slice access | CWE-125 |
| **Cryptographic randomness** | All protocols use OS CSPRNG via `getrandom`; panics on unavailability instead of weak fallback | CWE-338 |
| **TLS** | rustls (pure Rust, no OpenSSL); webpki-roots CA bundle; no plaintext fallback | CWE-295 |
| **Timeouts** | All operations have enforced timeouts (5-30s) including gRPC TCP connect | CWE-400 |
| **Credential scrubbing** | URLs and error messages redact passwords, tokens, API keys | CWE-532 |
| **Host key verification** | SSH/SFTP verify against `~/.ssh/known_hosts` (TOFU on first connect) | CWE-295 |
| **Pagination safety** | Next-page URLs validated for scheme and SSRF before following | CWE-601 |
| **Syslog validation** | Message size limits; control character rejection in hostname/app_name | CWE-93 |
| **Memory bounds** | Rate limiter (10K domains), FTP cache (32), secrets (1024) with eviction | CWE-400 |
| **RADIUS authenticator** | Response authenticator verified per RFC 2865 to prevent spoofing | — |
| **STUN transaction ID** | CSPRNG-generated; response matched to prevent spoofing | CWE-338 |
| **No telemetry** | Zero phone-home, zero tracking, zero analytics | — |

### Secrets-Aware Functions

| Function | Description |
|----------|-------------|
| `duck_net_add_secret(name, type, config_json)` | Store credentials in memory |
| `duck_net_clear_secret(name)` | Remove and zeroize a secret |
| `duck_net_clear_all_secrets()` | Remove all secrets |
| `duck_net_secrets()` | Table function listing all stored secrets (redacted) |
| `duck_net_security_status()` | JSON audit of current security configuration |
| `smtp_send_secret(secret, from, to, subject, body)` | SMTP with stored credentials |
| `ssh_exec_secret(secret, host, command)` | SSH with stored key/password |
| `s3_get_secret(secret, bucket, key)` | S3 GET with stored credentials |
| `s3_put_secret(secret, bucket, key, body)` | S3 PUT with stored credentials |
| `s3_list_secret(secret, bucket, prefix)` | S3 LIST with stored credentials |
| `http_get_secret(secret, url)` | HTTP GET with stored auth |
| `http_post_secret(secret, url, body)` | HTTP POST with stored auth |
| `vault_read_secret(secret, url, path)` | Vault with stored token |
| `consul_get_secret(secret, url, key)` | Consul with stored token |
| `influxdb_query_secret(secret, url, org, query)` | InfluxDB with stored token |
| `snmp_get_secret(secret, host, oid)` | SNMP with stored community string |
| `radius_auth_secret(secret, host, user, pass)` | RADIUS with stored shared secret |
| `imap_fetch_secret(secret, url, mailbox, uid)` | IMAP with stored credentials |
| `redis_get_secret(secret, key)` | Redis with stored password |
| `redis_set_secret(secret, key, value)` | Redis with stored password |
| `ldap_search_secret(secret, url, base, filter, attrs)` | LDAP with stored bind credentials |

## Dependencies

Minimal dependency set:

| Crate | Version | Purpose |
|-------|---------|---------|
| `quack-rs` | 0.8.0 | DuckDB extension SDK (zero raw C API needed) |
| `libduckdb-sys` | 1.10501.0 | DuckDB C API bindings (v1.5.1) |
| `ureq` | 3.3.0 | Sync HTTP client (rustls TLS, gzip) |
| `base64` | 0.22.0 | Base64 encoding for HTTP Basic auth |
| `hickory-resolver` | 0.25.0 | Async DNS resolver (A, AAAA, PTR, TXT, MX) |
| `suppaftp` | 8.0.0 | Sync FTP/FTPS client |
| `russh` | 0.58.0 | Async SSH client (for SFTP + SSH exec) |
| `russh-sftp` | 2.1.0 | SFTP subsystem over russh |
| `rustls` | 0.23.0 | TLS for SMTP STARTTLS, gRPC, WebSocket |
| `tokio` | 1.x | Async runtime (shared by DNS, SFTP, SSH, gRPC) |
| `tungstenite` | 0.24.0 | WebSocket client (one-shot request-response) |
| `h2` | 0.4.0 | HTTP/2 transport for gRPC |
| `tokio-rustls` | 0.26.0 | Async TLS connector for gRPC |
| `md5` | 0.7.0 | RADIUS password hashing (RFC 2865) |
| `getrandom` | 0.3.0 | Cryptographic random number generation (OS CSPRNG) |

## Improvements Over query-farm/httpclient

| Feature | httpclient | duck_net |
|---------|-----------|----------|
| HTTP methods | GET, HEAD, POST | GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS + generic |
| Return type | JSON string (double-parse needed) | Native STRUCT with typed fields |
| Response headers | HEAD only | All methods |
| Header type | MAP in, JSON string out | MAP in, MAP out |
| Timeout | Hardcoded 10s | Configurable (30s default) |
| Connection pooling | None (new client per request) | Yes (ureq Agent) |
| TLS | OpenSSL (C dependency) | rustls (pure Rust) |
| Multipart/file upload | No | Yes (`http_post_multipart` with auto MIME detection) |
| Content types | Hardcoded JSON/form | User-controlled via headers |
| Telemetry | Phones home | None |
| Language | C++ | Rust (memory safe) |

## License

MIT
