// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::s3;

use super::dns::write_string_list;
use super::scalars::write_varchar;

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

/// s3_get(endpoint, bucket, key, access_key, secret_key, region) -> STRUCT(success, body, status, message)
unsafe extern "C" fn cb_s3_get(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let endpoint_reader = chunk.reader(0);
    let bucket_reader = chunk.reader(1);
    let key_reader = chunk.reader(2);
    let access_key_reader = chunk.reader(3);
    let secret_key_reader = chunk.reader(4);
    let region_reader = chunk.reader(5);

    let mut success_writer = StructVector::field_writer(output, 0);
    let body_vec = duckdb_struct_vector_get_child(output, 1);
    let mut status_writer = StructVector::field_writer(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let endpoint = endpoint_reader.read_str(row as usize);
        let bucket = bucket_reader.read_str(row as usize);
        let key = key_reader.read_str(row as usize);
        let access_key = access_key_reader.read_str(row as usize);
        let secret_key = secret_key_reader.read_str(row as usize);
        let region = region_reader.read_str(row as usize);

        let result = s3::s3_get(endpoint, bucket, key, access_key, secret_key, region);

        unsafe { success_writer.write_bool(row as usize, result.success) };
        write_varchar(body_vec, row, &result.body);
        unsafe { status_writer.write_i32(row as usize, result.status) };
        write_varchar(message_vec, row, &result.message);
    }
}

/// s3_put(endpoint, bucket, key, body, access_key, secret_key, region) -> STRUCT(success, body, status, message)
unsafe extern "C" fn cb_s3_put(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let endpoint_reader = chunk.reader(0);
    let bucket_reader = chunk.reader(1);
    let key_reader = chunk.reader(2);
    let body_reader = chunk.reader(3);
    let access_key_reader = chunk.reader(4);
    let secret_key_reader = chunk.reader(5);
    let region_reader = chunk.reader(6);

    let mut success_writer = StructVector::field_writer(output, 0);
    let body_vec = duckdb_struct_vector_get_child(output, 1);
    let mut status_writer = StructVector::field_writer(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let endpoint = endpoint_reader.read_str(row as usize);
        let bucket = bucket_reader.read_str(row as usize);
        let key = key_reader.read_str(row as usize);
        let body = body_reader.read_str(row as usize);
        let access_key = access_key_reader.read_str(row as usize);
        let secret_key = secret_key_reader.read_str(row as usize);
        let region = region_reader.read_str(row as usize);

        let result = s3::s3_put(endpoint, bucket, key, body, access_key, secret_key, region);

        unsafe { success_writer.write_bool(row as usize, result.success) };
        write_varchar(body_vec, row, &result.body);
        unsafe { status_writer.write_i32(row as usize, result.status) };
        write_varchar(message_vec, row, &result.message);
    }
}

/// s3_list(endpoint, bucket, prefix, access_key, secret_key, region) -> STRUCT(success, keys, message)
unsafe extern "C" fn cb_s3_list(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let endpoint_reader = chunk.reader(0);
    let bucket_reader = chunk.reader(1);
    let prefix_reader = chunk.reader(2);
    let access_key_reader = chunk.reader(3);
    let secret_key_reader = chunk.reader(4);
    let region_reader = chunk.reader(5);

    let mut success_writer = StructVector::field_writer(output, 0);
    let keys_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);
    let mut list_offset: usize = 0;

    for row in 0..row_count {
        let endpoint = endpoint_reader.read_str(row);
        let bucket = bucket_reader.read_str(row);
        let prefix = prefix_reader.read_str(row);
        let access_key = access_key_reader.read_str(row);
        let secret_key = secret_key_reader.read_str(row);
        let region = region_reader.read_str(row);

        let result = s3::s3_list(endpoint, bucket, prefix, access_key, secret_key, region);

        unsafe { success_writer.write_bool(row, result.success) };
        write_string_list(keys_vec, row, &result.keys, &mut list_offset);
        write_varchar(message_vec, row, &result.message);
    }
}

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
