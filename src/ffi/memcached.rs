// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::memcached;

use super::scalars::write_varchar;

fn memcached_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("value", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

/// memcached_get(host, key) -> STRUCT(success, value, message)
unsafe extern "C" fn cb_memcached_get(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let host_reader = chunk.reader(0);
    let key_reader = chunk.reader(1);

    let mut success_w = StructVector::field_writer(output, 0);
    let value_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let key = key_reader.read_str(row as usize);

        let result = memcached::get(host, key);

        success_w.write_bool(row as usize, result.success);
        write_varchar(value_vec, row, &result.value);
        write_varchar(message_vec, row, &result.message);
    }
}

/// memcached_set(host, key, value) -> STRUCT (TTL = 0, never expire)
unsafe extern "C" fn cb_memcached_set(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let host_reader = chunk.reader(0);
    let key_reader = chunk.reader(1);
    let value_reader = chunk.reader(2);

    let mut success_w = StructVector::field_writer(output, 0);
    let value_out_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let key = key_reader.read_str(row as usize);
        let value = value_reader.read_str(row as usize);

        let result = memcached::set(host, key, value, 0);

        success_w.write_bool(row as usize, result.success);
        write_varchar(value_out_vec, row, &result.value);
        write_varchar(message_vec, row, &result.message);
    }
}

/// memcached_set(host, key, value, ttl) -> STRUCT
unsafe extern "C" fn cb_memcached_set_ttl(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let host_reader = chunk.reader(0);
    let key_reader = chunk.reader(1);
    let value_reader = chunk.reader(2);
    let ttl_reader = chunk.reader(3);

    let mut success_w = StructVector::field_writer(output, 0);
    let value_out_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let key = key_reader.read_str(row as usize);
        let value = value_reader.read_str(row as usize);
        let ttl = ttl_reader.read_i32(row as usize) as u32;

        let result = memcached::set(host, key, value, ttl);

        success_w.write_bool(row as usize, result.success);
        write_varchar(value_out_vec, row, &result.value);
        write_varchar(message_vec, row, &result.message);
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    // memcached_get(host, key)
    ScalarFunctionBuilder::new("memcached_get")
        .param(v) // host
        .param(v) // key
        .returns_logical(memcached_result_type())
        .function(cb_memcached_get)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // memcached_set: 3 or 4 params
    ScalarFunctionSetBuilder::new("memcached_set")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // host
                .param(v) // key
                .param(v) // value
                .returns_logical(memcached_result_type())
                .function(cb_memcached_set)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // host
                .param(v) // key
                .param(v) // value
                .param(TypeId::Integer) // ttl_secs
                .returns_logical(memcached_result_type())
                .function(cb_memcached_set_ttl)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con)?;

    Ok(())
}
