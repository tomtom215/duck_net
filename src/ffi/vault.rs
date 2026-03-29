// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::vault;

use super::scalars::write_varchar;

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
unsafe fn write_vault_result(output: duckdb_vector, row: idx_t, r: &vault::VaultResult) {
    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let data_vec = duckdb_struct_vector_get_child(output, 1);
    let lease_vec = duckdb_struct_vector_get_child(output, 2);
    let renewable_vec = duckdb_struct_vector_get_child(output, 3);
    let message_vec = duckdb_struct_vector_get_child(output, 4);

    let sd = duckdb_vector_get_data(success_vec) as *mut bool;
    *sd.add(row as usize) = r.success;

    write_varchar(data_vec, row, &r.data);

    let ld = duckdb_vector_get_data(lease_vec) as *mut i64;
    *ld.add(row as usize) = r.lease_duration;

    let rd = duckdb_vector_get_data(renewable_vec) as *mut bool;
    *rd.add(row as usize) = r.renewable;

    write_varchar(message_vec, row, &r.message);
}

/// Write a VaultHealthResult into the output STRUCT vector at the given row.
unsafe fn write_vault_health(output: duckdb_vector, row: idx_t, r: &vault::VaultHealthResult) {
    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let init_vec = duckdb_struct_vector_get_child(output, 1);
    let sealed_vec = duckdb_struct_vector_get_child(output, 2);
    let standby_vec = duckdb_struct_vector_get_child(output, 3);
    let version_vec = duckdb_struct_vector_get_child(output, 4);
    let message_vec = duckdb_struct_vector_get_child(output, 5);

    let sd = duckdb_vector_get_data(success_vec) as *mut bool;
    *sd.add(row as usize) = r.success;

    let id = duckdb_vector_get_data(init_vec) as *mut bool;
    *id.add(row as usize) = r.initialized;

    let se = duckdb_vector_get_data(sealed_vec) as *mut bool;
    *se.add(row as usize) = r.sealed;

    let st = duckdb_vector_get_data(standby_vec) as *mut bool;
    *st.add(row as usize) = r.standby;

    write_varchar(version_vec, row, &r.version);
    write_varchar(message_vec, row, &r.message);
}

// ===== Callbacks =====

/// vault_read(url, token, path) -> STRUCT
unsafe extern "C" fn cb_vault_read(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let token_reader = VectorReader::new(input, 1);
    let path_reader = VectorReader::new(input, 2);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let token = token_reader.read_str(row as usize);
        let path = path_reader.read_str(row as usize);
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
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let token_reader = VectorReader::new(input, 1);
    let path_reader = VectorReader::new(input, 2);
    let data_reader = VectorReader::new(input, 3);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let token = token_reader.read_str(row as usize);
        let path = path_reader.read_str(row as usize);
        let data_json = data_reader.read_str(row as usize);
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
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let token_reader = VectorReader::new(input, 1);
    let path_reader = VectorReader::new(input, 2);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let token = token_reader.read_str(row as usize);
        let path = path_reader.read_str(row as usize);
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
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
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
