// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::memcached;


fn memcached_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("value", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// memcached_get(host, key) -> STRUCT(success, value, message)
quack_rs::scalar_callback!(cb_memcached_get, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let key_reader = unsafe { chunk.reader(1) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row as usize) };
        let key = unsafe { key_reader.read_str(row as usize) };

        let result = memcached::get(host, key);

        unsafe { sw.write_bool(row as usize, 0, result.success) };
        unsafe { sw.write_varchar(row as usize, 1, &result.value) };
        unsafe { sw.write_varchar(row as usize, 2, &result.message) };
    }
});

// memcached_set(host, key, value) -> STRUCT (TTL = 0, never expire)
quack_rs::scalar_callback!(cb_memcached_set, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let key_reader = unsafe { chunk.reader(1) };
    let value_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row as usize) };
        let key = unsafe { key_reader.read_str(row as usize) };
        let value = unsafe { value_reader.read_str(row as usize) };

        let result = memcached::set(host, key, value, 0);

        unsafe { sw.write_bool(row as usize, 0, result.success) };
        unsafe { sw.write_varchar(row as usize, 1, &result.value) };
        unsafe { sw.write_varchar(row as usize, 2, &result.message) };
    }
});

// memcached_set(host, key, value, ttl) -> STRUCT
quack_rs::scalar_callback!(cb_memcached_set_ttl, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let key_reader = unsafe { chunk.reader(1) };
    let value_reader = unsafe { chunk.reader(2) };
    let ttl_reader = unsafe { chunk.reader(3) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row as usize) };
        let key = unsafe { key_reader.read_str(row as usize) };
        let value = unsafe { value_reader.read_str(row as usize) };
        let ttl = unsafe { ttl_reader.read_i32(row as usize) } as u32;

        let result = memcached::set(host, key, value, ttl);

        unsafe { sw.write_bool(row as usize, 0, result.success) };
        unsafe { sw.write_varchar(row as usize, 1, &result.value) };
        unsafe { sw.write_varchar(row as usize, 2, &result.message) };
    }
});

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
