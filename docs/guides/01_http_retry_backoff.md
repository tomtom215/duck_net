# Implementation Guide: HTTP Retry with Configurable Backoff

## Goal

Add configurable retry behavior for transient HTTP failures (5xx, timeouts, connection errors) with exponential backoff.

## SQL Interface

```sql
-- Per-session configuration via DuckDB settings
SET duck_net_max_retries = 3;
SET duck_net_retry_backoff_ms = 1000;    -- initial backoff in ms
SET duck_net_retry_backoff_factor = 2.0; -- exponential multiplier
SET duck_net_retry_on_status = '429,500,502,503,504';

-- All existing functions automatically use these settings
SELECT http_get('https://flaky-api.example.com/data');
```

## Architecture

### Config Registration

Register DuckDB configuration options during extension init. quack-rs has `config_option.rs` — check if it supports registering custom settings. If not, use raw `duckdb_create_config_option` from libduckdb-sys.

```
src/
  config.rs       # RetryConfig struct, reads from DuckDB settings
  http.rs          # Updated to accept RetryConfig
```

### RetryConfig

```rust
pub struct RetryConfig {
    pub max_retries: u32,         // default: 3
    pub backoff_ms: u64,          // default: 1000
    pub backoff_factor: f64,      // default: 2.0
    pub retryable_statuses: Vec<u16>, // default: [429, 500, 502, 503, 504]
}
```

### Retry Loop in http.rs

```rust
pub fn execute_with_retry(config: &RetryConfig, ...) -> HttpResponse {
    for attempt in 0..=config.max_retries {
        let resp = execute(method, url, headers, body);
        if attempt < config.max_retries && is_retryable(&resp, config) {
            let delay = config.backoff_ms * config.backoff_factor.powi(attempt as i32) as u64;
            std::thread::sleep(Duration::from_millis(delay));
            continue;
        }
        return resp;
    }
    unreachable!()
}

fn is_retryable(resp: &HttpResponse, config: &RetryConfig) -> bool {
    resp.status == 0 || config.retryable_statuses.contains(&resp.status)
}
```

### Reading Config in Callbacks

The scalar function callback receives `duckdb_function_info`. From this, extract the client context to read DuckDB settings:

```rust
// In callback:
let info = duckdb_scalar_function_get_extra_info(info);
// Or use duckdb_function_get_local_state / duckdb_function_get_global_state
```

**Open question**: How to access DuckDB settings from within a scalar function callback. Options:
1. Read settings during `register_all` and store in a global `AtomicU32`/etc.
2. Use `extra_info` to pass config pointer
3. Access client context from `duckdb_function_info` (if the C API supports it)

Research needed: check DuckDB C API for `duckdb_get_config_option` or similar that works from within function callbacks.

### Dependencies

None. Uses `std::thread::sleep` for backoff.

### Estimated Scope

- Config struct: ~30 lines
- Retry loop: ~30 lines
- Config option registration: ~50 lines (depends on DuckDB C API)
- Callback updates: ~20 lines per callback (or centralized wrapper)
- Tests: verify retry count, backoff timing, retryable status filtering

### Key Risks

- **Thread::sleep blocks the DuckDB worker thread.** For short backoffs (1-4s) this is acceptable. For long backoffs, it could stall other queries. Document this clearly.
- **Config option registration** may require DuckDB 1.5+ C API features. Verify availability in libduckdb-sys 1.10501.0.
