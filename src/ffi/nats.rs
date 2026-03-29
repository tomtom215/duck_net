// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::nats;

use super::scalars::write_varchar;

fn nats_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

fn nats_request_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("response", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

/// nats_publish(url, subject, payload) -> STRUCT(success, message)
unsafe extern "C" fn cb_nats_publish(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let subject_reader = chunk.reader(1);
    let payload_reader = chunk.reader(2);

    let mut success_w = StructVector::field_writer(output, 0);
    let message_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let subject = subject_reader.read_str(row as usize);
        let payload = payload_reader.read_str(row as usize);

        let result = nats::publish(url, subject, payload);

        success_w.write_bool(row as usize, result.success);
        write_varchar(message_vec, row, &result.message);
    }
}

/// nats_request(url, subject, payload, timeout_ms) -> STRUCT(success, response, message)
unsafe extern "C" fn cb_nats_request(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let subject_reader = chunk.reader(1);
    let payload_reader = chunk.reader(2);
    let timeout_reader = chunk.reader(3);

    let mut success_w = StructVector::field_writer(output, 0);
    let response_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let subject = subject_reader.read_str(row as usize);
        let payload = payload_reader.read_str(row as usize);
        let timeout_ms = timeout_reader.read_i32(row as usize);

        let result = nats::request(url, subject, payload, timeout_ms as u32);

        success_w.write_bool(row as usize, result.success);
        write_varchar(response_vec, row, &result.response);
        write_varchar(message_vec, row, &result.message);
    }
}

/// nats_request(url, subject, payload) -> STRUCT(success, response, message) with 5000ms default timeout
unsafe extern "C" fn cb_nats_request_default(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let subject_reader = chunk.reader(1);
    let payload_reader = chunk.reader(2);

    let mut success_w = StructVector::field_writer(output, 0);
    let response_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let subject = subject_reader.read_str(row as usize);
        let payload = payload_reader.read_str(row as usize);

        let result = nats::request(url, subject, payload, 5000);

        success_w.write_bool(row as usize, result.success);
        write_varchar(response_vec, row, &result.response);
        write_varchar(message_vec, row, &result.message);
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionBuilder::new("nats_publish")
        .param(v) // url
        .param(v) // subject
        .param(v) // payload
        .returns_logical(nats_result_type())
        .function(cb_nats_publish)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // nats_request: 3-param (default 5s timeout) and 4-param overloads
    ScalarFunctionSetBuilder::new("nats_request")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // url
                .param(v) // subject
                .param(v) // payload
                .returns_logical(nats_request_result_type())
                .function(cb_nats_request_default)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // url
                .param(v) // subject
                .param(v) // payload
                .param(TypeId::Integer) // timeout_ms
                .returns_logical(nats_request_result_type())
                .function(cb_nats_request)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con)?;

    Ok(())
}
