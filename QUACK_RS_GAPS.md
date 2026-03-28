# quack-rs Gaps Found During duck_net Development

Issues encountered while building the duck_net HTTP client extension using quack-rs v0.7.1.

## 1. No `LogicalType::from_raw()` Constructor

**Problem**: `LogicalType` has `as_raw()` and `into_raw()` to extract the raw `duckdb_logical_type` handle, but there is no way to construct a `LogicalType` from an existing raw handle.

**Impact**: When you need to create complex types using raw libduckdb-sys calls (e.g., because of gap #2), you cannot wrap the result back into a `LogicalType` to use with quack-rs builders like `ScalarFunctionBuilder::returns_logical()`.

**Workaround**: Use raw libduckdb-sys for the entire function registration instead of the quack-rs builder pattern.

**Suggested Fix**: Add `unsafe fn from_raw(ptr: duckdb_logical_type) -> Self` constructor, with documentation noting the caller must ensure the handle is valid and that `LogicalType` will take ownership (calling `duckdb_destroy_logical_type` on drop).

## 2. `LogicalType::struct_type()` Only Accepts `TypeId`

**Problem**: `LogicalType::struct_type(fields: &[(&str, TypeId)])` only accepts simple `TypeId` values for struct member types. It cannot create STRUCT types with complex member types like `MAP(VARCHAR, VARCHAR)` or `LIST(INTEGER)`.

**Impact**: Common return types like `STRUCT(status INTEGER, headers MAP(VARCHAR, VARCHAR), body VARCHAR)` cannot be expressed using the quack-rs type system. This forces developers to drop to raw libduckdb-sys for type creation, which cascades into needing raw registration (due to gap #1).

**Workaround**: Use raw `duckdb_create_struct_type()` with manually managed `duckdb_logical_type` handles.

**Suggested Fix**: Add `LogicalType::struct_type_from_logical(fields: &[(&str, LogicalType)])` that accepts `LogicalType` values for member types. The existing `struct_type(&[(&str, TypeId)])` can remain as a convenience shortcut.

## 3. Same Limitation on `list()` and `map()`

**Problem**: `LogicalType::list(element_type: TypeId)` and `LogicalType::map(key_type: TypeId, value_type: TypeId)` only accept `TypeId`, not `LogicalType`.

**Impact**: Cannot create nested complex types like `LIST(STRUCT(...))` or `MAP(VARCHAR, LIST(INTEGER))`.

**Suggested Fix**: Add overloads or new methods:
- `LogicalType::list_from_logical(element: LogicalType)`
- `LogicalType::map_from_logical(key: LogicalType, value: LogicalType)`

## 4. `MapVector` Not Exported in Prelude

**Problem**: `MapVector` (and `StructVector`, `ListVector`) are not re-exported in `quack_rs::prelude::*`. They must be imported explicitly from `quack_rs::vector::complex::MapVector`.

**Impact**: Minor ergonomic issue. Since these types are needed whenever working with complex DuckDB types (which is common), they should be readily available.

**Suggested Fix**: Add `MapVector`, `StructVector`, and `ListVector` to the prelude re-exports.

## 5. No Builder Support for Scalar Function `extra_info`

**Problem**: `ScalarFunctionBuilder` does not expose a way to set extra_info on scalar functions (equivalent to `duckdb_scalar_function_set_extra_info`). This is useful for parameterizing callbacks — e.g., using the same callback function for multiple HTTP methods by storing the method in extra_info.

**Impact**: Forces either (a) creating separate callback functions for each variant, or (b) dropping to raw libduckdb-sys for registration.

**Suggested Fix**: Add `.extra_info(data: *mut c_void, destroy: Option<duckdb_delete_callback_t>)` to `ScalarFunctionBuilder`.

## Summary

Gaps #1 and #2 together meant that 100% of duck_net's scalar function registration had to use raw libduckdb-sys instead of quack-rs builders. The clean builder pattern (which works well for simple types) breaks down when return types involve any nesting of complex types.

Fixing gaps #1 + #2 would allow duck_net to use `ScalarFunctionBuilder::returns_logical()` with custom complex types. Fixing #4 is a one-line prelude change. Fixing #5 would eliminate the need for macro-generated callback wrappers.
