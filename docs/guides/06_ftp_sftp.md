# Implementation Guide: FTP/SFTP File Operations

## Why This Matters

SFTP and FTP remain the backbone of enterprise file exchange:
- **Finance**: Bank reconciliation files, payment batches, SWIFT messages
- **Healthcare**: HL7/FHIR data feeds, claims processing, lab results
- **Government**: Regulatory filings, census data, interagency transfers
- **Supply chain**: EDI documents, inventory feeds, shipping manifests
- **Legacy integration**: Decades of automated processes built on (S)FTP

httpfs covers HTTP and S3. No existing DuckDB extension covers FTP or SFTP. This fills a real gap.

## SQL Interface

### Directory Listing (Table Functions)

```sql
-- List files on an FTP server
SELECT * FROM ftp_list('ftp://user:pass@ftp.example.com/data/');
-- Returns:
-- | name VARCHAR | size BIGINT | modified TIMESTAMP | is_dir BOOLEAN | permissions VARCHAR |

-- List files on an SFTP server
SELECT * FROM sftp_list('sftp://user:pass@sftp.example.com/uploads/');

-- Filter for recent CSV files
SELECT name, size, modified
FROM sftp_list('sftp://user:pass@host/inbox/')
WHERE name LIKE '%.csv' AND modified > '2026-03-01';

-- SFTP with key-based auth (key file path)
SELECT * FROM sftp_list(
    'sftp://user@host/path/',
    key_file := '/home/user/.ssh/id_ed25519'
);
```

### File Read (Scalar Functions)

```sql
-- Read a file as text
SELECT ftp_read('ftp://user:pass@host/reports/daily.csv');
-- Returns: STRUCT(success BOOLEAN, content VARCHAR, size BIGINT, message VARCHAR)

-- Read and immediately parse as CSV
SELECT * FROM read_csv(
    sftp_read('sftp://user:pass@host/data/export.csv').content
);

-- Bulk read files discovered via listing
SELECT
    name,
    sftp_read('sftp://user:pass@host/inbox/' || name).content AS data
FROM sftp_list('sftp://user:pass@host/inbox/')
WHERE name LIKE '%.json';
```

### File Write (Scalar Functions)

```sql
-- Upload content to FTP
SELECT ftp_write(
    'ftp://user:pass@host/outbox/report.csv',
    'col1,col2\nval1,val2\n'
);
-- Returns: STRUCT(success BOOLEAN, bytes_written BIGINT, message VARCHAR)

-- Export query results to SFTP
SELECT sftp_write(
    'sftp://user:pass@host/exports/summary.csv',
    (SELECT string_agg(col1 || ',' || col2, chr(10)) FROM my_table)
);
```

### File Delete (Scalar Functions)

```sql
-- Delete a file
SELECT ftp_delete('ftp://user:pass@host/processed/old_file.csv');
-- Returns: STRUCT(success BOOLEAN, message VARCHAR)

-- Delete after processing
SELECT sftp_delete('sftp://user:pass@host/inbox/' || name)
FROM sftp_list('sftp://user:pass@host/inbox/')
WHERE name LIKE '%.csv' AND modified < '2026-01-01';
```

## Functions Summary

### FTP Functions

| Function | Type | Signature | Returns |
|----------|------|-----------|---------|
| `ftp_list` | Table | `(url VARCHAR, [username VARCHAR, password VARCHAR])` | `name, size, modified, is_dir, permissions` |
| `ftp_read` | Scalar | `(url VARCHAR)` | `STRUCT(success BOOLEAN, content VARCHAR, size BIGINT, message VARCHAR)` |
| `ftp_write` | Scalar | `(url VARCHAR, content VARCHAR)` | `STRUCT(success BOOLEAN, bytes_written BIGINT, message VARCHAR)` |
| `ftp_delete` | Scalar | `(url VARCHAR)` | `STRUCT(success BOOLEAN, message VARCHAR)` |

### SFTP Functions

| Function | Type | Signature | Returns |
|----------|------|-----------|---------|
| `sftp_list` | Table | `(url VARCHAR, [key_file VARCHAR])` | `name, size, modified, is_dir, permissions` |
| `sftp_read` | Scalar | `(url VARCHAR, [key_file VARCHAR])` | `STRUCT(success BOOLEAN, content VARCHAR, size BIGINT, message VARCHAR)` |
| `sftp_write` | Scalar | `(url VARCHAR, content VARCHAR, [key_file VARCHAR])` | `STRUCT(success BOOLEAN, bytes_written BIGINT, message VARCHAR)` |
| `sftp_delete` | Scalar | `(url VARCHAR, [key_file VARCHAR])` | `STRUCT(success BOOLEAN, message VARCHAR)` |

## Architecture

### File Structure

```
src/
  ftp.rs            # Pure FTP client logic (no DuckDB deps)
  sftp.rs           # Pure SFTP client logic (no DuckDB deps)
  url_parse.rs      # Shared URL parsing: scheme, user, pass, host, port, path
  ffi/
    mod.rs          # Updated: register FTP/SFTP functions
    scalars.rs      # HTTP scalar functions (existing)
    ftp.rs          # FTP scalar function callbacks + registration
    sftp.rs         # SFTP scalar function callbacks + registration
    ftp_table.rs    # ftp_list table function
    sftp_table.rs   # sftp_list table function
```

### URL Parsing

All functions accept URLs in standard format:
```
ftp://[user:pass@]host[:port]/path
ftps://[user:pass@]host[:port]/path
sftp://[user:pass@]host[:port]/path
```

Implement a shared URL parser:

```rust
pub struct ParsedUrl {
    pub scheme: Scheme,        // Ftp, Ftps, Sftp
    pub username: Option<String>,
    pub password: Option<String>,
    pub host: String,
    pub port: u16,             // default: 21 (FTP/FTPS), 22 (SFTP)
    pub path: String,
}

pub enum Scheme {
    Ftp,   // port 21
    Ftps,  // port 990 (implicit) or 21 (explicit/STARTTLS)
    Sftp,  // port 22
}
```

Use the `url` crate (already in our dependency tree via ureq) for parsing, then map the scheme.

### Connection Pooling Strategy

FTP and SFTP connections are expensive (TCP + TLS/SSH handshake). For scalar functions called per-row, reconnecting each time would be devastating for performance.

**Approach**: Connection cache keyed by `(host, port, username)`:

```rust
use std::sync::Mutex;
use std::collections::HashMap;
use std::time::Instant;

struct ConnectionCache<T> {
    connections: Mutex<HashMap<String, (T, Instant)>>,
    ttl: Duration,
}
```

Connections are reused within a query and evicted after a TTL (e.g., 60 seconds of inactivity). The cache key is `"{user}@{host}:{port}"`.

**FTP**: suppaftp's `FtpStream` is not `Send`, so the cache must be thread-local or behind a Mutex with single-thread access. Since DuckDB scalar functions may be called from multiple threads, use a `Mutex<HashMap<...>>` and hold the lock only during the operation.

**SFTP**: russh sessions are async. Wrap with a single-threaded tokio runtime stored in a `LazyLock`.

## Dependencies

### FTP: suppaftp

```toml
suppaftp = { version = "8.0", default-features = false, features = ["rustls-ring"] }
```

- Sync API (no async runtime needed for FTP)
- rustls for FTPS (reuses our existing rustls dependency tree, `ring` crypto provider)
- No native-tls/OpenSSL required

**Key suppaftp methods used:**
- `FtpStream::connect(addr)` / `connect_timeout(addr, duration)`
- `ftp.login(user, pass)`
- `ftp.list(Some(path))` → `Vec<String>` (raw LIST output, needs parsing)
- `ftp.nlst(Some(path))` → `Vec<String>` (file names only)
- `ftp.retr_as_buffer(filename)` → `Vec<u8>` (download)
- `ftp.put_file(filename, &mut reader)` → bytes written
- `ftp.rm(filename)` → delete
- `ftp.size(filename)` → file size
- `ftp.quit()`

**LIST parsing**: suppaftp's `list()` returns raw LIST output strings. These are not standardized (varies by FTP server OS). Consider using `mlsd()` (MLSD command) which returns machine-parseable output. Fall back to LIST with heuristic parsing if MLSD is not supported.

### SFTP: russh + russh-sftp

```toml
russh = { version = "0.58", default-features = false }
russh-sftp = { version = "2.1" }
```

- Pure Rust SSH implementation
- Async API (needs tokio runtime — already in our dependency tree)
- Supports password and key-based authentication

**Key russh-sftp operations:**
- `SftpSession::new()` → create SFTP subsystem
- `sftp.read_dir(path)` → directory listing with metadata
- `sftp.open(path)` / `sftp.read()` → file download
- `sftp.create(path)` / `sftp.write()` → file upload
- `sftp.remove_file(path)` → delete
- `sftp.metadata(path)` → file metadata (size, modified, permissions)

**Async wrapper**: Since russh is async, wrap in a shared tokio runtime:

```rust
use std::sync::LazyLock;
use tokio::runtime::Runtime;

static TOKIO_RT: LazyLock<Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime")
});

// Usage:
fn sftp_read(url: &str) -> Result<Vec<u8>, String> {
    TOKIO_RT.block_on(async {
        sftp_read_async(url).await
    })
}
```

Use `new_current_thread()` (not `new_multi_thread()`) to minimize overhead. The runtime is only used for SSH/SFTP protocol handling.

## Table Function: ftp_list / sftp_list

### Bind Phase

Parse URL, validate credentials. Store connection parameters.

```rust
struct ListBindData {
    url: ParsedUrl,
    key_file: Option<String>,  // SFTP only
}
```

Output columns:
- `name` (VARCHAR) — file/directory name
- `size` (BIGINT) — size in bytes (-1 if unknown)
- `modified` (TIMESTAMP) — last modified time (NULL if unknown)
- `is_dir` (BOOLEAN) — true if directory
- `permissions` (VARCHAR) — permission string (e.g., "rwxr-xr-x") or NULL

### Init Phase

Connect to server, authenticate, perform directory listing, store results.

```rust
struct ListInitData {
    entries: Vec<FileEntry>,
    cursor: usize,
}
```

Perform the listing eagerly in init (not lazily in scan) because:
1. FTP LIST/MLSD returns all entries at once anyway
2. Simplifies error handling (fail at init, not mid-scan)
3. Connection can be released immediately

### Scan Phase

Emit rows from the cached entry list, `STANDARD_VECTOR_SIZE` rows per call.

### Registration

Table function with 1 required param (url) and optional named params (key_file for SFTP, username/password for explicit credentials).

```rust
con.register_table(
    TableFunctionBuilder::new("ftp_list")
        .param(TypeId::Varchar)                      // url
        .named_param("username", TypeId::Varchar)
        .named_param("password", TypeId::Varchar)
        .bind(ftp_list_bind)
        .init(ftp_list_init)
        .scan(ftp_list_scan),
)?;

con.register_table(
    TableFunctionBuilder::new("sftp_list")
        .param(TypeId::Varchar)                      // url
        .named_param("key_file", TypeId::Varchar)
        .bind(sftp_list_bind)
        .init(sftp_list_init)
        .scan(sftp_list_scan),
)?;
```

## Scalar Functions: read / write / delete

### Return Types

**ftp_read / sftp_read**:
`STRUCT(success BOOLEAN, content VARCHAR, size BIGINT, message VARCHAR)`

This is a simple struct (all TypeId members) — can use quack-rs `ScalarFunctionBuilder` with `returns_logical(LogicalType::struct_type(...))`. No raw C API needed.

**ftp_write / sftp_write**:
`STRUCT(success BOOLEAN, bytes_written BIGINT, message VARCHAR)`

Same — simple struct, quack-rs builder works.

**ftp_delete / sftp_delete**:
`STRUCT(success BOOLEAN, message VARCHAR)`

Same.

### Registration

All scalar functions can use quack-rs `ScalarFunctionBuilder` since their return types only contain simple TypeId members. This is a win — no raw C API needed.

```rust
con.register_scalar(
    ScalarFunctionBuilder::new("ftp_read")
        .param(TypeId::Varchar)  // url (with embedded credentials)
        .returns_logical(LogicalType::struct_type(&[
            ("success", TypeId::Boolean),
            ("content", TypeId::Varchar),
            ("size",    TypeId::BigInt),
            ("message", TypeId::Varchar),
        ]))
        .function(ftp_read_callback),
)?;
```

### Binary Files

`ftp_read` returns VARCHAR — fine for text files (CSV, JSON, XML, EDI). For binary files, consider adding `ftp_read_blob` returning `STRUCT(success BOOLEAN, content BLOB, ...)`. BLOB support in quack-rs uses `TypeId::Blob` and `VectorWriter::write_blob()` (verify this exists).

## Implementation Order

1. **URL parser** (`url_parse.rs`) — shared by all functions, implement first
2. **FTP scalar functions** — simplest, pure sync, validates the pattern
3. **FTP table function** (ftp_list) — slightly more complex, table function lifecycle
4. **SFTP scalar functions** — adds async wrapper complexity
5. **SFTP table function** (sftp_list) — combines async + table function
6. **Connection caching** — performance optimization, add after correctness is proven
7. **FTPS support** — STARTTLS upgrade via suppaftp's rustls feature

## Estimated Scope

| Component | Lines (approx) |
|-----------|----------------|
| `url_parse.rs` | 60 |
| `ftp.rs` (pure logic) | 150 |
| `sftp.rs` (pure logic + async wrapper) | 200 |
| `ffi/ftp.rs` (scalar callbacks + registration) | 150 |
| `ffi/sftp.rs` (scalar callbacks + registration) | 150 |
| `ffi/ftp_table.rs` (table function) | 180 |
| `ffi/sftp_table.rs` (table function) | 180 |
| Connection cache | 80 |
| **Total** | **~1,150** |

## Key Risks

### FTP LIST Parsing
FTP's LIST command output is not standardized. Unix servers return `ls -l` format, Windows servers return different formats. MLSD (RFC 3659) is machine-parseable but not universally supported.

**Mitigation**: Try MLSD first, fall back to LIST with heuristic parsing. suppaftp may have parsing helpers. If not, implement a basic Unix-format LIST parser (~40 lines).

### SFTP Authentication Complexity
SFTP supports password, public key, keyboard-interactive, and agent-based auth. Supporting all of these from SQL is challenging.

**Recommendation for v1**: Support password (from URL) and key file (from named parameter). Add SSH agent support later if demanded.

### Large File Handling
`ftp_read` loads the entire file into memory as a VARCHAR. For multi-GB files, this will OOM.

**Mitigation**: Document a size limit (e.g., 100MB default). For larger files, recommend using the file system approach (download to local disk, then `read_csv('/local/path')`). Consider adding a `max_size` parameter.

### Connection Lifetime in Scalar Functions
When `ftp_read` is called for 1000 rows (1000 files), opening and closing a connection per row would be catastrophically slow.

**Mitigation**: Connection caching (described above). The cache holds connections open for 60 seconds, reusing them across rows in the same query. Critical for any realistic workload.

### Thread Safety
DuckDB may call scalar functions from multiple threads. FTP connections are not thread-safe.

**Mitigation**: Use per-thread connection caching (thread-local storage) or a mutex-protected pool. For FTP, `thread_local!` with `RefCell<HashMap<...>>` is simplest. For SFTP (async), the tokio runtime must be `Send`-safe.

## Future Extensions

### Replacement Scan (Transparent File Access)

The ultimate goal — register (S)FTP as a DuckDB file system so users can do:

```sql
SELECT * FROM 'sftp://user:pass@host/data/sales.parquet';
COPY results TO 'ftp://host/outbox/results.csv';
```

This is significantly more complex than scalar/table functions because:
1. DuckDB file readers (Parquet, CSV) use random access (`seek` + `read`)
2. FTP supports random access via REST command (restart position)
3. SFTP supports random access via read offsets
4. Need to implement DuckDB's FileSystem interface via the C API

**Approach**: After scalar/table functions are stable, implement a `VirtualFileSystem` that:
- Intercepts `ftp://`, `ftps://`, `sftp://` URLs
- Downloads files to a temp directory on first access
- Serves reads from the local cache
- Cleans up on connection close

This is a separate, larger project. The scalar/table functions provide immediate value while the file system approach is developed.
