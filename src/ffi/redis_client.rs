// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::redis_client;

use super::dns::write_string_list;
use super::scalars::write_varchar;

fn redis_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("value", LogicalType::new(TypeId::Varchar)),
    ])
}

fn redis_keys_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        (
            "keys",
            LogicalType::list_from_logical(&LogicalType::new(TypeId::Varchar)),
        ),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

/// redis_get(url, key) -> STRUCT(success, value)
unsafe extern "C" fn cb_redis_get(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let key_reader = chunk.reader(1);

    let mut success_w = StructVector::field_writer(output, 0);
    let value_vec = StructVector::get_child(output, 1);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let key = key_reader.read_str(row as usize);

        let result = redis_client::get(url, key);

        success_w.write_bool(row as usize, result.success);
        write_varchar(value_vec, row as usize, &result.value);
    }
}

/// redis_set(url, key, value) -> STRUCT(success, value)
unsafe extern "C" fn cb_redis_set(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let key_reader = chunk.reader(1);
    let value_reader = chunk.reader(2);

    let mut success_w = StructVector::field_writer(output, 0);
    let value_vec = StructVector::get_child(output, 1);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let key = key_reader.read_str(row as usize);
        let value = value_reader.read_str(row as usize);

        let result = redis_client::set(url, key, value);

        success_w.write_bool(row as usize, result.success);
        write_varchar(value_vec, row as usize, &result.value);
    }
}

/// redis_set(url, key, value, ttl_secs) -> STRUCT(success, value)
unsafe extern "C" fn cb_redis_set_ex(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let key_reader = chunk.reader(1);
    let value_reader = chunk.reader(2);
    let ttl_reader = chunk.reader(3);

    let mut success_w = StructVector::field_writer(output, 0);
    let value_vec = StructVector::get_child(output, 1);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let key = key_reader.read_str(row as usize);
        let value = value_reader.read_str(row as usize);
        let ttl = ttl_reader.read_i64(row as usize);

        let result = redis_client::set_ex(url, key, value, ttl);

        success_w.write_bool(row as usize, result.success);
        write_varchar(value_vec, row as usize, &result.value);
    }
}

/// redis_keys(url, pattern) -> STRUCT(success, keys, message)
unsafe extern "C" fn cb_redis_keys(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let pattern_reader = chunk.reader(1);

    let mut success_w = StructVector::field_writer(output, 0);
    let keys_vec = StructVector::get_child(output, 1);
    let message_vec = StructVector::get_child(output, 2);
    let mut list_offset: usize = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let pattern = pattern_reader.read_str(row as usize);

        let result = redis_client::keys(url, pattern);

        success_w.write_bool(row as usize, result.success);
        write_string_list(keys_vec, row as usize, &result.keys, &mut list_offset);
        write_varchar(message_vec, row as usize, &result.message);
    }
}

/// redis_del(url, key) -> STRUCT(success, value)
unsafe extern "C" fn cb_redis_del(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let key_reader = chunk.reader(1);

    let mut success_w = StructVector::field_writer(output, 0);
    let value_vec = StructVector::get_child(output, 1);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let key = key_reader.read_str(row as usize);

        let result = redis_client::del(url, key);

        success_w.write_bool(row as usize, result.success);
        write_varchar(value_vec, row as usize, &result.value);
    }
}

/// redis_expire(url, key, ttl_secs) -> STRUCT(success, value)
unsafe extern "C" fn cb_redis_expire(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let key_reader = chunk.reader(1);
    let ttl_reader = chunk.reader(2);

    let mut success_w = StructVector::field_writer(output, 0);
    let value_vec = StructVector::get_child(output, 1);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let key = key_reader.read_str(row as usize);
        let ttl = ttl_reader.read_i64(row as usize);

        let result = redis_client::expire(url, key, ttl);

        success_w.write_bool(row as usize, result.success);
        write_varchar(value_vec, row as usize, &result.value);
    }
}

/// redis_hget(url, key, field) -> STRUCT(success, value)
unsafe extern "C" fn cb_redis_hget(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let key_reader = chunk.reader(1);
    let field_reader = chunk.reader(2);

    let mut success_w = StructVector::field_writer(output, 0);
    let value_vec = StructVector::get_child(output, 1);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let key = key_reader.read_str(row as usize);
        let field = field_reader.read_str(row as usize);

        let result = redis_client::hget(url, key, field);

        success_w.write_bool(row as usize, result.success);
        write_varchar(value_vec, row as usize, &result.value);
    }
}

/// redis_hset(url, key, field, value) -> STRUCT(success, value)
unsafe extern "C" fn cb_redis_hset(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let key_reader = chunk.reader(1);
    let field_reader = chunk.reader(2);
    let value_reader = chunk.reader(3);

    let mut success_w = StructVector::field_writer(output, 0);
    let value_vec = StructVector::get_child(output, 1);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let key = key_reader.read_str(row as usize);
        let field = field_reader.read_str(row as usize);
        let value = value_reader.read_str(row as usize);

        let result = redis_client::hset(url, key, field, value);

        success_w.write_bool(row as usize, result.success);
        write_varchar(value_vec, row as usize, &result.value);
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    // redis_get(url, key) -> STRUCT
    ScalarFunctionBuilder::new("redis_get")
        .param(v) // url
        .param(v) // key
        .returns_logical(redis_result_type())
        .function(cb_redis_get)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // redis_set: 3 or 4 params
    ScalarFunctionSetBuilder::new("redis_set")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // url
                .param(v) // key
                .param(v) // value
                .returns_logical(redis_result_type())
                .function(cb_redis_set)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // url
                .param(v) // key
                .param(v) // value
                .param(TypeId::BigInt) // ttl_secs
                .returns_logical(redis_result_type())
                .function(cb_redis_set_ex)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con)?;

    // redis_keys(url, pattern) -> STRUCT(success, keys, message)
    ScalarFunctionBuilder::new("redis_keys")
        .param(v) // url
        .param(v) // pattern
        .returns_logical(redis_keys_result_type())
        .function(cb_redis_keys)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // redis_del(url, key) -> STRUCT
    ScalarFunctionBuilder::new("redis_del")
        .param(v)
        .param(v)
        .returns_logical(redis_result_type())
        .function(cb_redis_del)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // redis_expire(url, key, ttl_secs) -> STRUCT
    ScalarFunctionBuilder::new("redis_expire")
        .param(v)
        .param(v)
        .param(TypeId::BigInt)
        .returns_logical(redis_result_type())
        .function(cb_redis_expire)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // redis_hget(url, key, field) -> STRUCT
    ScalarFunctionBuilder::new("redis_hget")
        .param(v)
        .param(v)
        .param(v)
        .returns_logical(redis_result_type())
        .function(cb_redis_hget)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // redis_hset(url, key, field, value) -> STRUCT
    ScalarFunctionBuilder::new("redis_hset")
        .param(v)
        .param(v)
        .param(v)
        .param(v)
        .returns_logical(redis_result_type())
        .function(cb_redis_hset)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
