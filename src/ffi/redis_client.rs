// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use quack_rs::prelude::*;

use crate::redis_client;

use super::dns::write_string_list;

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

// redis_get(url, key) -> STRUCT(success, value)
quack_rs::scalar_callback!(cb_redis_get, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let key_reader = unsafe { chunk.reader(1) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let key = unsafe { key_reader.read_str(row) };

        let result = redis_client::get(url, key);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.value) };
    }
});

// redis_set(url, key, value) -> STRUCT(success, value)
quack_rs::scalar_callback!(cb_redis_set, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let key_reader = unsafe { chunk.reader(1) };
    let value_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let key = unsafe { key_reader.read_str(row) };
        let value = unsafe { value_reader.read_str(row) };

        let result = redis_client::set(url, key, value);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.value) };
    }
});

// redis_set(url, key, value, ttl_secs) -> STRUCT(success, value)
quack_rs::scalar_callback!(cb_redis_set_ex, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let key_reader = unsafe { chunk.reader(1) };
    let value_reader = unsafe { chunk.reader(2) };
    let ttl_reader = unsafe { chunk.reader(3) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let key = unsafe { key_reader.read_str(row) };
        let value = unsafe { value_reader.read_str(row) };
        let ttl = unsafe { ttl_reader.read_i64(row) };

        let result = redis_client::set_ex(url, key, value, ttl);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.value) };
    }
});

// redis_keys(url, pattern) -> STRUCT(success, keys, message)
quack_rs::scalar_callback!(cb_redis_keys, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let pattern_reader = unsafe { chunk.reader(1) };

    let mut sw = unsafe { StructWriter::new(output, 3) };
    let keys_vec = sw.child_vector(1);
    let mut list_offset: usize = 0;

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let pattern = unsafe { pattern_reader.read_str(row) };

        let result = redis_client::keys(url, pattern);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { write_string_list(keys_vec, row, &result.keys, &mut list_offset) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

// redis_del(url, key) -> STRUCT(success, value)
quack_rs::scalar_callback!(cb_redis_del, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let key_reader = unsafe { chunk.reader(1) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let key = unsafe { key_reader.read_str(row) };

        let result = redis_client::del(url, key);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.value) };
    }
});

// redis_expire(url, key, ttl_secs) -> STRUCT(success, value)
quack_rs::scalar_callback!(cb_redis_expire, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let key_reader = unsafe { chunk.reader(1) };
    let ttl_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let key = unsafe { key_reader.read_str(row) };
        let ttl = unsafe { ttl_reader.read_i64(row) };

        let result = redis_client::expire(url, key, ttl);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.value) };
    }
});

// redis_hget(url, key, field) -> STRUCT(success, value)
quack_rs::scalar_callback!(cb_redis_hget, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let key_reader = unsafe { chunk.reader(1) };
    let field_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let key = unsafe { key_reader.read_str(row) };
        let field = unsafe { field_reader.read_str(row) };

        let result = redis_client::hget(url, key, field);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.value) };
    }
});

// redis_hset(url, key, field, value) -> STRUCT(success, value)
quack_rs::scalar_callback!(cb_redis_hset, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let key_reader = unsafe { chunk.reader(1) };
    let field_reader = unsafe { chunk.reader(2) };
    let value_reader = unsafe { chunk.reader(3) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let key = unsafe { key_reader.read_str(row) };
        let field = unsafe { field_reader.read_str(row) };
        let value = unsafe { value_reader.read_str(row) };

        let result = redis_client::hset(url, key, field, value);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.value) };
    }
});

pub unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    // redis_get(url, key) -> STRUCT
    ScalarFunctionBuilder::new("redis_get")
        .param(v) // url
        .param(v) // key
        .returns_logical(redis_result_type())
        .function(cb_redis_get)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

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
        .register(con.as_raw_connection())?;

    // redis_keys(url, pattern) -> STRUCT(success, keys, message)
    ScalarFunctionBuilder::new("redis_keys")
        .param(v) // url
        .param(v) // pattern
        .returns_logical(redis_keys_result_type())
        .function(cb_redis_keys)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // redis_del(url, key) -> STRUCT
    ScalarFunctionBuilder::new("redis_del")
        .param(v)
        .param(v)
        .returns_logical(redis_result_type())
        .function(cb_redis_del)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // redis_expire(url, key, ttl_secs) -> STRUCT
    ScalarFunctionBuilder::new("redis_expire")
        .param(v)
        .param(v)
        .param(TypeId::BigInt)
        .returns_logical(redis_result_type())
        .function(cb_redis_expire)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // redis_hget(url, key, field) -> STRUCT
    ScalarFunctionBuilder::new("redis_hget")
        .param(v)
        .param(v)
        .param(v)
        .returns_logical(redis_result_type())
        .function(cb_redis_hget)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // redis_hset(url, key, field, value) -> STRUCT
    ScalarFunctionBuilder::new("redis_hset")
        .param(v)
        .param(v)
        .param(v)
        .param(v)
        .returns_logical(redis_result_type())
        .function(cb_redis_hset)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    Ok(())
}
