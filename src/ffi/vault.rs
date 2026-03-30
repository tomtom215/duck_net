// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::vault;


// ===== Return Types =====

fn vault_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("data", LogicalType::new(TypeId::Varchar)),
        ("lease_duration", LogicalType::new(TypeId::BigInt)),
        ("renewable", LogicalType::new(TypeId::Boolean)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

fn vault_health_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("initialized", LogicalType::new(TypeId::Boolean)),
        ("sealed", LogicalType::new(TypeId::Boolean)),
        ("standby", LogicalType::new(TypeId::Boolean)),
        ("version", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// ===== Output Helpers =====

/// Write a VaultResult into the output STRUCT vector at the given row.
unsafe fn write_vault_result(output: duckdb_vector, row: usize, r: &vault::VaultResult) {
    let mut sw = StructWriter::new(output, 5);

    sw.write_bool(row, 0, r.success);
    sw.write_varchar(row, 1, &r.data);
    sw.write_i64(row, 2, r.lease_duration);
    sw.write_bool(row, 3, r.renewable);
    sw.write_varchar(row, 4, &r.message);
}

/// Write a VaultHealthResult into the output STRUCT vector at the given row.
unsafe fn write_vault_health(output: duckdb_vector, row: usize, r: &vault::VaultHealthResult) {
    let mut sw = StructWriter::new(output, 6);

    sw.write_bool(row, 0, r.success);
    sw.write_bool(row, 1, r.initialized);
    sw.write_bool(row, 2, r.sealed);
    sw.write_bool(row, 3, r.standby);
    sw.write_varchar(row, 4, &r.version);
    sw.write_varchar(row, 5, &r.message);
}

// ===== Callbacks =====

// vault_read(url, token, path) -> STRUCT
quack_rs::scalar_callback!(cb_vault_read, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let token_reader = unsafe { chunk.reader(1) };
    let path_reader = unsafe { chunk.reader(2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let token = unsafe { token_reader.read_str(row) };
        let path = unsafe { path_reader.read_str(row) };
        let result = vault::read(url, token, path);
        unsafe { write_vault_result(output, row, &result) };
    }
});

// vault_write(url, token, path, data_json) -> STRUCT
quack_rs::scalar_callback!(cb_vault_write, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let token_reader = unsafe { chunk.reader(1) };
    let path_reader = unsafe { chunk.reader(2) };
    let data_reader = unsafe { chunk.reader(3) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let token = unsafe { token_reader.read_str(row) };
        let path = unsafe { path_reader.read_str(row) };
        let data_json = unsafe { data_reader.read_str(row) };
        let result = vault::write(url, token, path, data_json);
        unsafe { write_vault_result(output, row, &result) };
    }
});

// vault_list(url, token, path) -> STRUCT
quack_rs::scalar_callback!(cb_vault_list, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let token_reader = unsafe { chunk.reader(1) };
    let path_reader = unsafe { chunk.reader(2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let token = unsafe { token_reader.read_str(row) };
        let path = unsafe { path_reader.read_str(row) };
        let result = vault::list(url, token, path);
        unsafe { write_vault_result(output, row, &result) };
    }
});

// vault_health(url) -> STRUCT
quack_rs::scalar_callback!(cb_vault_health, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let result = vault::health(url);
        unsafe { write_vault_health(output, row, &result) };
    }
});

// ===== Registration =====

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    // vault_read(url, token, path) -> STRUCT
    ScalarFunctionBuilder::new("vault_read")
        .param(TypeId::Varchar)
        .param(TypeId::Varchar)
        .param(TypeId::Varchar)
        .returns_logical(vault_result_type())
        .function(cb_vault_read)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // vault_write(url, token, path, data_json) -> STRUCT
    ScalarFunctionBuilder::new("vault_write")
        .param(TypeId::Varchar)
        .param(TypeId::Varchar)
        .param(TypeId::Varchar)
        .param(TypeId::Varchar)
        .returns_logical(vault_result_type())
        .function(cb_vault_write)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // vault_list(url, token, path) -> STRUCT
    ScalarFunctionBuilder::new("vault_list")
        .param(TypeId::Varchar)
        .param(TypeId::Varchar)
        .param(TypeId::Varchar)
        .returns_logical(vault_result_type())
        .function(cb_vault_list)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // vault_health(url) -> STRUCT
    ScalarFunctionBuilder::new("vault_health")
        .param(TypeId::Varchar)
        .returns_logical(vault_health_type())
        .function(cb_vault_health)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
