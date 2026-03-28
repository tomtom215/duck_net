# Implementation Guide: Paginated API Consumption (Table Function)

## Goal

A table function that follows paginated API responses, returning each page's data as rows. This is the single most impactful HTTP enhancement — it turns duck_net from a "call one endpoint" tool into a "consume an entire API" tool.

## SQL Interface

```sql
-- Offset-based pagination
SELECT * FROM http_paginate(
    'https://api.example.com/users?page={page}&per_page=100',
    page_param := 'page',
    start_page := 1,
    max_pages := 10
);

-- Cursor/next-link pagination (follow Link header or JSON field)
SELECT * FROM http_paginate(
    'https://api.example.com/users',
    next_url_path := '$.next',    -- JSON path to next URL
    max_pages := 50
);

-- Returns one row per page:
-- | page INTEGER | status INTEGER | headers MAP(VARCHAR,VARCHAR) | body VARCHAR |
```

## Architecture

This is a **table function** (not scalar). It uses quack-rs `TableFunctionBuilder` with the bind → init → scan lifecycle.

### File Structure

```
src/
  ffi/
    mod.rs          # Updated: register table functions too
    scalars.rs      # Existing scalar functions
    table.rs        # NEW: http_paginate table function
  http.rs           # No changes needed — reuses execute()
  pagination.rs     # NEW: Pure pagination logic
```

### Pagination Strategy

```rust
pub enum PaginationStrategy {
    /// Increment a page/offset parameter: url_template has {page} or {offset}
    PageNumber {
        param_name: String,   // "page" or "offset"
        start: i64,
        increment: i64,       // 1 for page-based, page_size for offset-based
    },
    /// Follow a "next" URL from the response body (JSON path) or Link header
    NextUrl {
        json_path: Option<String>,  // e.g. "$.next" or "$.pagination.next_url"
        use_link_header: bool,      // follow RFC 8288 Link: <url>; rel="next"
    },
}
```

### Table Function Phases

#### Bind Phase

Reads parameters, validates the URL template, determines pagination strategy.

```rust
struct PaginateBindData {
    base_url: String,
    strategy: PaginationStrategy,
    max_pages: i64,
    headers: Vec<(String, String)>,
}
```

Output columns:
- `page` (INTEGER) — 1-based page number
- `status` (INTEGER) — HTTP status code
- `headers` (MAP(VARCHAR, VARCHAR)) — response headers
- `body` (VARCHAR) — response body

Register via `BindInfo::add_result_column()`.

#### Init Phase

```rust
struct PaginateInitData {
    current_page: i64,
    next_url: Option<String>,
    done: bool,
}
```

#### Scan Phase

Each call to scan:
1. If `done`, set output chunk size to 0 and return
2. Construct the URL for the current page
3. Call `http::execute(Method::Get, url, headers, None)`
4. Write one row to output: page number, status, headers, body
5. Determine next URL:
   - PageNumber: increment counter
   - NextUrl: parse response body/headers for next link
6. If no next URL, or page >= max_pages, or status != 2xx: set `done = true`
7. Set output chunk size to 1

### Registration

```rust
con.register_table(
    TableFunctionBuilder::new("http_paginate")
        .param(TypeId::Varchar)                    // url or url template
        .named_param("page_param", TypeId::Varchar)
        .named_param("start_page", TypeId::BigInt)
        .named_param("max_pages", TypeId::BigInt)
        .named_param("next_url_path", TypeId::Varchar)
        .named_param("headers", ???)               // MAP type — may need raw API
        .bind(paginate_bind)
        .init(paginate_init)
        .scan(paginate_scan),
)?;
```

**Note**: Named parameters with MAP type may require raw registration (same quack-rs gap as with scalar return types). Verify whether `TableFunctionBuilder::named_param_logical()` exists.

### JSON Path Extraction

For `NextUrl` strategy, we need to extract a URL from the JSON response body. Options:

1. **Use DuckDB's built-in JSON functions** — not directly accessible from C API callbacks
2. **Simple JSON path extraction** — implement a minimal `$.field.subfield` extractor (no full JSONPath)
3. **Add serde_json dependency** — parse JSON, navigate path

Recommendation: implement a minimal dot-path extractor without adding serde_json. Keep it to simple paths like `$.next`, `$.data.pagination.next_url`. This covers 95% of real API pagination patterns.

```rust
/// Extract a string value from JSON using a simple dot-path.
/// Supports: $.field, $.field.subfield, $.field.subfield.deep
/// Does NOT support: arrays, wildcards, filters
fn json_dot_path(json: &str, path: &str) -> Option<String> {
    // Strip "$." prefix
    // Split on "."
    // Navigate through JSON string manually or with minimal parsing
}
```

### Link Header Parsing

RFC 8288 Link headers look like:
```
Link: <https://api.example.com/users?page=2>; rel="next", <https://api.example.com/users?page=50>; rel="last"
```

Parse to extract the URL with `rel="next"`. This is simple string parsing — no dependency needed.

### Dependencies

None beyond what already exists. JSON path extraction and Link header parsing are implemented manually.

### Estimated Scope

- `pagination.rs`: ~100 lines (strategy enum, URL construction, next-URL extraction)
- `ffi/table.rs`: ~200 lines (bind/init/scan callbacks, output writing)
- `ffi/mod.rs`: ~5 lines (register table function)
- Tests: SQL logic tests with mock HTTP server

### Key Risks

- **MAP-type named parameters** may require raw registration (quack-rs gap)
- **JSON path extraction** without a JSON parser is fragile for deeply nested paths. May need serde_json for correctness.
- **Rate limiting**: rapid sequential page fetches may trigger API rate limits. Consider adding a `delay_ms` named parameter for inter-request delay.
- **Return type registration**: same quack-rs gap (STRUCT with MAP requires raw API). Can reuse the `create_response_type()` helper from scalars.rs (extract to shared module).

### Future Extensions

- `http_paginate_post` for APIs that use POST for pagination (e.g., Elasticsearch scroll)
- Parallel page fetching (multiple pages concurrently) — complex, requires careful thread management
- Automatic JSON array flattening: instead of returning one row per page, return one row per item in a JSON array field
