// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::consul;

use super::scalars::write_varchar;

fn kv_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("value", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

/// consul_get(url, key, token) -> STRUCT(success, value, message)
unsafe extern "C" fn cb_consul_get(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let key_reader = chunk.reader(1);
    let token_reader = chunk.reader(2);

    let mut success_writer = StructVector::field_writer(output, 0);
    let value_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let key = key_reader.read_str(row as usize);
        let token = token_reader.read_str(row as usize);

        let result = consul::consul_get(url, key, token);

        unsafe { success_writer.write_bool(row as usize, result.success) };
        write_varchar(value_vec, row, &result.value);
        write_varchar(message_vec, row, &result.message);
    }
}

/// consul_set(url, key, value, token) -> STRUCT(success, value, message)
unsafe extern "C" fn cb_consul_set(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let key_reader = chunk.reader(1);
    let value_reader = chunk.reader(2);
    let token_reader = chunk.reader(3);

    let mut success_writer = StructVector::field_writer(output, 0);
    let value_out_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let key = key_reader.read_str(row as usize);
        let value = value_reader.read_str(row as usize);
        let token = token_reader.read_str(row as usize);

        let result = consul::consul_set(url, key, value, token);

        unsafe { success_writer.write_bool(row as usize, result.success) };
        write_varchar(value_out_vec, row, &result.value);
        write_varchar(message_vec, row, &result.message);
    }
}

/// consul_delete(url, key, token) -> STRUCT(success, value, message)
unsafe extern "C" fn cb_consul_delete(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let key_reader = chunk.reader(1);
    let token_reader = chunk.reader(2);

    let mut success_writer = StructVector::field_writer(output, 0);
    let value_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let key = key_reader.read_str(row as usize);
        let token = token_reader.read_str(row as usize);

        let result = consul::consul_delete(url, key, token);

        unsafe { success_writer.write_bool(row as usize, result.success) };
        write_varchar(value_vec, row, &result.value);
        write_varchar(message_vec, row, &result.message);
    }
}

/// etcd_get(url, key) -> STRUCT(success, value, message)
unsafe extern "C" fn cb_etcd_get(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let key_reader = chunk.reader(1);

    let mut success_writer = StructVector::field_writer(output, 0);
    let value_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let key = key_reader.read_str(row as usize);

        let result = consul::etcd_get(url, key);

        unsafe { success_writer.write_bool(row as usize, result.success) };
        write_varchar(value_vec, row, &result.value);
        write_varchar(message_vec, row, &result.message);
    }
}

/// etcd_put(url, key, value) -> STRUCT(success, value, message)
unsafe extern "C" fn cb_etcd_put(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let key_reader = chunk.reader(1);
    let value_reader = chunk.reader(2);

    let mut success_writer = StructVector::field_writer(output, 0);
    let value_out_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let key = key_reader.read_str(row as usize);
        let value = value_reader.read_str(row as usize);

        let result = consul::etcd_put(url, key, value);

        unsafe { success_writer.write_bool(row as usize, result.success) };
        write_varchar(value_out_vec, row, &result.value);
        write_varchar(message_vec, row, &result.message);
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    // consul_get(url, key, token) -> STRUCT(success, value, message)
    ScalarFunctionBuilder::new("consul_get")
        .param(v) // url
        .param(v) // key
        .param(v) // token
        .returns_logical(kv_result_type())
        .function(cb_consul_get)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // consul_set(url, key, value, token) -> STRUCT(success, value, message)
    ScalarFunctionBuilder::new("consul_set")
        .param(v) // url
        .param(v) // key
        .param(v) // value
        .param(v) // token
        .returns_logical(kv_result_type())
        .function(cb_consul_set)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // consul_delete(url, key, token) -> STRUCT(success, value, message)
    ScalarFunctionBuilder::new("consul_delete")
        .param(v) // url
        .param(v) // key
        .param(v) // token
        .returns_logical(kv_result_type())
        .function(cb_consul_delete)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // etcd_get(url, key) -> STRUCT(success, value, message)
    ScalarFunctionBuilder::new("etcd_get")
        .param(v) // url
        .param(v) // key
        .returns_logical(kv_result_type())
        .function(cb_etcd_get)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // etcd_put(url, key, value) -> STRUCT(success, value, message)
    ScalarFunctionBuilder::new("etcd_put")
        .param(v) // url
        .param(v) // key
        .param(v) // value
        .returns_logical(kv_result_type())
        .function(cb_etcd_put)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
