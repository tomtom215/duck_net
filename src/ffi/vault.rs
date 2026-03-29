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
    let mut success_w = StructVector::field_writer(output, 0);
    let mut data_w = StructVector::field_writer(output, 1);
    let mut lease_w = StructVector::field_writer(output, 2);
    let mut renewable_w = StructVector::field_writer(output, 3);
    let mut message_w = StructVector::field_writer(output, 4);

    success_w.write_bool(row, r.success);
    data_w.write_varchar(row, &r.data);
    lease_w.write_i64(row, r.lease_duration);
    renewable_w.write_bool(row, r.renewable);
    message_w.write_varchar(row, &r.message);
}

/// Write a VaultHealthResult into the output STRUCT vector at the given row.
unsafe fn write_vault_health(output: duckdb_vector, row: usize, r: &vault::VaultHealthResult) {
    let mut success_w = StructVector::field_writer(output, 0);
    let mut init_w = StructVector::field_writer(output, 1);
    let mut sealed_w = StructVector::field_writer(output, 2);
    let mut standby_w = StructVector::field_writer(output, 3);
    let mut version_w = StructVector::field_writer(output, 4);
    let mut message_w = StructVector::field_writer(output, 5);

    success_w.write_bool(row, r.success);
    init_w.write_bool(row, r.initialized);
    sealed_w.write_bool(row, r.sealed);
    standby_w.write_bool(row, r.standby);
    version_w.write_varchar(row, &r.version);
    message_w.write_varchar(row, &r.message);
}

// ===== Callbacks =====

/// vault_read(url, token, path) -> STRUCT
unsafe extern "C" fn cb_vault_read(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let token_reader = chunk.reader(1);
    let path_reader = chunk.reader(2);

    for row in 0..row_count {
        let url = url_reader.read_str(row);
        let token = token_reader.read_str(row);
        let path = path_reader.read_str(row);
        let result = vault::read(url, token, path);
        write_vault_result(output, row, &result);
    }
}

/// vault_write(url, token, path, data_json) -> STRUCT
unsafe extern "C" fn cb_vault_write(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let token_reader = chunk.reader(1);
    let path_reader = chunk.reader(2);
    let data_reader = chunk.reader(3);

    for row in 0..row_count {
        let url = url_reader.read_str(row);
        let token = token_reader.read_str(row);
        let path = path_reader.read_str(row);
        let data_json = data_reader.read_str(row);
        let result = vault::write(url, token, path, data_json);
        write_vault_result(output, row, &result);
    }
}

/// vault_list(url, token, path) -> STRUCT
unsafe extern "C" fn cb_vault_list(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let token_reader = chunk.reader(1);
    let path_reader = chunk.reader(2);

    for row in 0..row_count {
        let url = url_reader.read_str(row);
        let token = token_reader.read_str(row);
        let path = path_reader.read_str(row);
        let result = vault::list(url, token, path);
        write_vault_result(output, row, &result);
    }
}

/// vault_health(url) -> STRUCT
unsafe extern "C" fn cb_vault_health(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);

    for row in 0..row_count {
        let url = url_reader.read_str(row);
        let result = vault::health(url);
        write_vault_health(output, row, &result);
    }
}

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
