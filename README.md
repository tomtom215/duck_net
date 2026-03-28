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

| Protection | Implementation |
|-----------|---------------|
| **URL scheme validation** | Only `http://` and `https://` allowed (SSRF mitigation, CWE-918) |
| **Response body size limit** | 256 MiB max prevents OOM from unbounded responses (CWE-400) |
| **TLS** | rustls (pure Rust, no OpenSSL). System CA roots for certificate validation |
| **Timeouts** | 30-second global timeout per request (connect + transfer) |
| **Retry with backoff** | Configurable exponential backoff with 60s cap per delay (prevents thundering herd) |
| **Connection pooling** | Single global ureq Agent reuses TCP connections (HTTP keep-alive) |
| **FTP connection caching** | Cached with 60-second TTL, NOOP keepalive check, max 32 connections |
| **SFTP host key verification** | Reads `~/.ssh/known_hosts`, TOFU on first connect, rejects changed keys (CWE-295) |
| **Credential scrubbing** | FTP/SFTP error messages replace `user:pass` with `***` (CWE-532) |
| **SMTP injection prevention** | CRLF sanitization in headers, dot-stuffing in body (CWE-93) |
| **HTTP proxy support** | Automatic — ureq reads `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` environment variables |
| **No telemetry** | Zero phone-home, zero tracking |

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
| `russh` | 0.58.0 | Async SSH client (for SFTP) |
| `russh-sftp` | 2.1.0 | SFTP subsystem over russh |
| `rustls` | 0.23.0 | TLS for SMTP STARTTLS |
| `tokio` | 1.x | Async runtime (shared by DNS + SFTP) |

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
