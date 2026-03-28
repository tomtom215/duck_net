# quack-rs Gaps: Resolved in v0.8.0

All five gaps originally identified during duck_net development against quack-rs v0.7.1
have been resolved in quack-rs v0.8.0 (released 2026-03-28).

duck_net now uses **zero raw libduckdb-sys** for type creation and function registration.

## Status

| Gap | Description | Resolution in v0.8.0 |
|-----|-------------|----------------------|
| #1 | No `LogicalType::from_raw()` | `LogicalType::from_raw(ptr)` added |
| #2 | `struct_type()` only accepts `TypeId` | `struct_type_from_logical(&[(&str, LogicalType)])` added |
| #3 | `list()` / `map()` only accept `TypeId` | `list_from_logical()` and `map_from_logical()` added |
| #4 | `MapVector` not in prelude | `MapVector`, `StructVector`, `ListVector` now in prelude |
| #5 | No `extra_info` on scalar builders | `ScalarOverloadBuilder::extra_info()` and `ScalarFunctionBuilder::extra_info()` added |

## Migration Impact

Before (v0.7.1): 100% raw C API for type creation and function registration (~200 lines of unsafe FFI).

After (v0.8.0): All type creation uses `LogicalType` builders. All function registration uses
`ScalarFunctionSetBuilder` / `ScalarOverloadBuilder`. Callback consolidation via `extra_info`
reduced 14 macro-generated callbacks to 4 unified callbacks. Net reduction: ~140 lines of unsafe code eliminated.

## Example: Response Type (Before vs After)

**Before (raw libduckdb-sys):**
```rust
unsafe fn create_response_type() -> duckdb_logical_type {
    let status_type = duckdb_create_logical_type(DUCKDB_TYPE_DUCKDB_TYPE_INTEGER);
    let map_key = duckdb_create_logical_type(DUCKDB_TYPE_DUCKDB_TYPE_VARCHAR);
    let map_val = duckdb_create_logical_type(DUCKDB_TYPE_DUCKDB_TYPE_VARCHAR);
    let headers_type = duckdb_create_map_type(map_key, map_val);
    // ... 20+ lines of manual handle management and cleanup
}
```

**After (quack-rs 0.8.0):**
```rust
fn response_type() -> LogicalType {
    let headers_map = LogicalType::map_from_logical(
        &LogicalType::new(TypeId::Varchar),
        &LogicalType::new(TypeId::Varchar),
    );
    LogicalType::struct_type_from_logical(&[
        ("status", LogicalType::new(TypeId::Integer)),
        ("reason", LogicalType::new(TypeId::Varchar)),
        ("headers", headers_map),
        ("body", LogicalType::new(TypeId::Varchar)),
    ])
}
```
