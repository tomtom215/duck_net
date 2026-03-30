// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::s3;

use super::dns::write_string_list;

fn s3_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("body", LogicalType::new(TypeId::Varchar)),
        ("status", LogicalType::new(TypeId::Integer)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

fn s3_list_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        (
            "keys",
            LogicalType::list_from_logical(&LogicalType::new(TypeId::Varchar)),
        ),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// s3_get(endpoint, bucket, key, access_key, secret_key, region) -> STRUCT(success, body, status, message)
quack_rs::scalar_callback!(cb_s3_get, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let endpoint_reader = unsafe { chunk.reader(0) };
    let bucket_reader = unsafe { chunk.reader(1) };
    let key_reader = unsafe { chunk.reader(2) };
    let access_key_reader = unsafe { chunk.reader(3) };
    let secret_key_reader = unsafe { chunk.reader(4) };
    let region_reader = unsafe { chunk.reader(5) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let endpoint = unsafe { endpoint_reader.read_str(row) };
        let bucket = unsafe { bucket_reader.read_str(row) };
        let key = unsafe { key_reader.read_str(row) };
        let access_key = unsafe { access_key_reader.read_str(row) };
        let secret_key = unsafe { secret_key_reader.read_str(row) };
        let region = unsafe { region_reader.read_str(row) };

        let result = s3::s3_get(endpoint, bucket, key, access_key, secret_key, region, None);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.body) };
        unsafe { sw.write_i32(row, 2, result.status) };
        unsafe { sw.write_varchar(row, 3, &result.message) };
    }
});

// s3_put(endpoint, bucket, key, body, access_key, secret_key, region) -> STRUCT(success, body, status, message)
quack_rs::scalar_callback!(cb_s3_put, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let endpoint_reader = unsafe { chunk.reader(0) };
    let bucket_reader = unsafe { chunk.reader(1) };
    let key_reader = unsafe { chunk.reader(2) };
    let body_reader = unsafe { chunk.reader(3) };
    let access_key_reader = unsafe { chunk.reader(4) };
    let secret_key_reader = unsafe { chunk.reader(5) };
    let region_reader = unsafe { chunk.reader(6) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let endpoint = unsafe { endpoint_reader.read_str(row) };
        let bucket = unsafe { bucket_reader.read_str(row) };
        let key = unsafe { key_reader.read_str(row) };
        let body = unsafe { body_reader.read_str(row) };
        let access_key = unsafe { access_key_reader.read_str(row) };
        let secret_key = unsafe { secret_key_reader.read_str(row) };
        let region = unsafe { region_reader.read_str(row) };

        let result = s3::s3_put(
            endpoint, bucket, key, body, access_key, secret_key, region, None,
        );

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.body) };
        unsafe { sw.write_i32(row, 2, result.status) };
        unsafe { sw.write_varchar(row, 3, &result.message) };
    }
});

// s3_list(endpoint, bucket, prefix, access_key, secret_key, region) -> STRUCT(success, keys, message)
quack_rs::scalar_callback!(cb_s3_list, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let endpoint_reader = unsafe { chunk.reader(0) };
    let bucket_reader = unsafe { chunk.reader(1) };
    let prefix_reader = unsafe { chunk.reader(2) };
    let access_key_reader = unsafe { chunk.reader(3) };
    let secret_key_reader = unsafe { chunk.reader(4) };
    let region_reader = unsafe { chunk.reader(5) };

    let mut sw = unsafe { StructWriter::new(output, 3) };
    let keys_vec = unsafe { duckdb_struct_vector_get_child(output, 1) };
    let mut list_offset: usize = 0;

    for row in 0..row_count {
        let endpoint = unsafe { endpoint_reader.read_str(row) };
        let bucket = unsafe { bucket_reader.read_str(row) };
        let prefix = unsafe { prefix_reader.read_str(row) };
        let access_key = unsafe { access_key_reader.read_str(row) };
        let secret_key = unsafe { secret_key_reader.read_str(row) };
        let region = unsafe { region_reader.read_str(row) };

        let result = s3::s3_list(
            endpoint, bucket, prefix, access_key, secret_key, region, None,
        );

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { write_string_list(keys_vec, row, &result.keys, &mut list_offset) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    // s3_get(endpoint, bucket, key, access_key, secret_key, region) -> STRUCT
    ScalarFunctionBuilder::new("s3_get")
        .param(v) // endpoint
        .param(v) // bucket
        .param(v) // key
        .param(v) // access_key
        .param(v) // secret_key
        .param(v) // region
        .returns_logical(s3_result_type())
        .function(cb_s3_get)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // s3_put(endpoint, bucket, key, body, access_key, secret_key, region) -> STRUCT
    ScalarFunctionBuilder::new("s3_put")
        .param(v) // endpoint
        .param(v) // bucket
        .param(v) // key
        .param(v) // body
        .param(v) // access_key
        .param(v) // secret_key
        .param(v) // region
        .returns_logical(s3_result_type())
        .function(cb_s3_put)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // s3_list(endpoint, bucket, prefix, access_key, secret_key, region) -> STRUCT
    ScalarFunctionBuilder::new("s3_list")
        .param(v) // endpoint
        .param(v) // bucket
        .param(v) // prefix
        .param(v) // access_key
        .param(v) // secret_key
        .param(v) // region
        .returns_logical(s3_list_result_type())
        .function(cb_s3_list)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
