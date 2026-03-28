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

## Dependencies

Minimal dependency set:

| Crate | Version | Purpose |
|-------|---------|---------|
| `quack-rs` | 0.7.1 | DuckDB extension SDK |
| `libduckdb-sys` | 1.10501.0 | DuckDB C API bindings (v1.5.1) |
| `ureq` | 3.3.0 | Sync HTTP client (rustls TLS, gzip) |

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
