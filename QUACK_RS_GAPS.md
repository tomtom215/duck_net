# quack-rs Gaps and Migration Debt

## Resolved in v0.8.0

All five gaps originally identified during duck_net development against quack-rs v0.7.1
have been resolved in quack-rs v0.8.0 (released 2026-03-28).

| Gap | Description | Resolution in v0.8.0 |
|-----|-------------|----------------------|
| #1 | No `LogicalType::from_raw()` | `LogicalType::from_raw(ptr)` added |
| #2 | `struct_type()` only accepts `TypeId` | `struct_type_from_logical(&[(&str, LogicalType)])` added |
| #3 | `list()` / `map()` only accept `TypeId` | `list_from_logical()` and `map_from_logical()` added |
| #4 | `MapVector` not in prelude | `MapVector`, `StructVector`, `ListVector` now in prelude |
| #5 | No `extra_info` on scalar builders | `ScalarOverloadBuilder::extra_info()` and `ScalarFunctionBuilder::extra_info()` added |

## Resolved in v0.10.0 (migration debt eliminated 2026-03-30)

The following APIs existed in v0.10.0 but duck_net retained legacy raw calls as migration
debt. All raw calls have now been replaced with the safe quack-rs equivalents.

| Gap (debt) | Raw call | v0.10.0 replacement | Files migrated |
|------------|----------|--------------------|--------------------|
| #6 | `duckdb_data_chunk_set_size(output, n)` | `DataChunk::from_raw(output).set_size(n)` / `out_chunk.set_size(n)` | ftp, sftp, webdav, mdns, ping, caldav, imap, ldap, odata, snmp, security_warnings, table, secrets_protocols_ext |
| #7 | `duckdb_struct_vector_get_child` + `duckdb_vector_assign_string_element_len` | `StructWriter::write_blob(row, field, &bytes)` | ftp, sftp |
| #8 (partial) | `duckdb_vector_get_validity` + `duckdb_validity_row_is_valid` | `VectorReader::from_vector(v, n).is_valid(idx)` | scalars |
| #9 | `duckdb_get_varchar` + `CStr` + `duckdb_free` + `duckdb_destroy_value` | `bind.get_parameter_value(n).as_str_or_default()` | webdav, mdns, ping |
| #10 | `duckdb_get_int64` + `duckdb_destroy_value` | `bind.get_named_parameter_value("name").as_i64()` | mdns, ping |

## Remaining quack-rs Gap (#8 partial — open)

One API surface is still missing in quack-rs v0.10.0:

| Gap | Description | Workaround |
|-----|-------------|------------|
| #8 (partial) | `StructWriter` has no method to obtain a child **vector** for a `LIST`- or `MAP`-typed struct field. Needed when a STRUCT return type contains a `LIST<VARCHAR>` field that must be written via `write_string_list`. | Continue using `duckdb_struct_vector_get_child(output, n)` for these cases. |

**Affected files** (5 raw calls remain, all for LIST-typed STRUCT children):
- `src/ffi/grpc.rs:40` — `services_vec` for `LIST<VARCHAR>` services field
- `src/ffi/tls_inspect.rs:37, 84` — `san_names_vec` for `LIST<VARCHAR>` SAN names field
- `src/ffi/s3.rs:107` — `keys_vec` for `LIST<VARCHAR>` object keys field
- `src/ffi/secrets_protocols_ext.rs:189` — `keys_vec` for `LIST<VARCHAR>` secret keys field

**Proposed quack-rs enhancement**: Add `StructWriter::child_list_vector(field_idx: usize) -> duckdb_vector`
(or a higher-level `write_string_list` method) so these callers can be fully migrated.

## Migration Impact

Before (v0.7.1): 100% raw C API for type creation and function registration (~200 lines of unsafe FFI).

After (v0.8.0): All type creation uses `LogicalType` builders. All function registration uses
`ScalarFunctionSetBuilder` / `ScalarOverloadBuilder`. Callback consolidation via `extra_info`
reduced 14 macro-generated callbacks to 4 unified callbacks. Net reduction: ~140 lines of unsafe code eliminated.

After (v0.10.0 migration, 2026-03-30): All scan callbacks and scalar callbacks use quack-rs safe
APIs for chunk sizing, blob writes, validity checks, and parameter extraction. Only 5 raw calls
remain — all for the unresolved gap #8 (LIST-typed child vectors of STRUCT outputs).
Net additional reduction: ~60 lines of unsafe FFI replaced.

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
