// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::websocket;

use super::scalars::write_varchar;

fn ws_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("response", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

/// ws_request(url, message) -> STRUCT(success, response, message)
unsafe extern "C" fn cb_ws_request(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let msg_reader = chunk.reader(1);

    let mut success_writer = StructVector::field_writer(output, 0);
    let response_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let msg = msg_reader.read_str(row as usize);

        let result = websocket::request_default_timeout(url, msg);

        unsafe { success_writer.write_bool(row as usize, result.success) };
        write_varchar(response_vec, row, &result.response);
        write_varchar(message_vec, row, &result.message);
    }
}

/// ws_request(url, message, timeout_secs) -> STRUCT
unsafe extern "C" fn cb_ws_request_timeout(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let msg_reader = chunk.reader(1);
    let timeout_reader = chunk.reader(2);

    let mut success_writer = StructVector::field_writer(output, 0);
    let response_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let msg = msg_reader.read_str(row as usize);
        let timeout = timeout_reader.read_i32(row as usize) as u32;

        let result = websocket::request(url, msg, timeout);

        unsafe { success_writer.write_bool(row as usize, result.success) };
        write_varchar(response_vec, row, &result.response);
        write_varchar(message_vec, row, &result.message);
    }
}

fn ws_multi_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("responses", LogicalType::new(TypeId::Varchar)),
        ("count", LogicalType::new(TypeId::Integer)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

/// ws_multi_request(url, messages, timeout_secs) -> STRUCT(success, responses, count, message)
/// messages is newline-separated VARCHAR
unsafe extern "C" fn cb_ws_multi_request(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let msgs_reader = chunk.reader(1);
    let timeout_reader = chunk.reader(2);

    let mut success_writer = StructVector::field_writer(output, 0);
    let responses_vec = duckdb_struct_vector_get_child(output, 1);
    let mut count_writer = StructVector::field_writer(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let msgs_str = msgs_reader.read_str(row as usize);
        let timeout = timeout_reader.read_i32(row as usize) as u32;

        let msgs: Vec<String> = msgs_str
            .split('\n')
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let result = websocket::multi_request(url, &msgs, timeout);

        unsafe { success_writer.write_bool(row as usize, result.success) };
        write_varchar(responses_vec, row, &result.responses.join("\n"));
        unsafe { count_writer.write_i32(row as usize, result.responses.len() as i32) };
        write_varchar(message_vec, row, &result.message);
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionSetBuilder::new("ws_request")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // url
                .param(v) // message
                .returns_logical(ws_result_type())
                .function(cb_ws_request)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // url
                .param(v) // message
                .param(TypeId::Integer) // timeout_secs
                .returns_logical(ws_result_type())
                .function(cb_ws_request_timeout)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con)?;

    // ws_multi_request(url, messages, timeout_secs) -> STRUCT(success, responses, count, message)
    ScalarFunctionBuilder::new("ws_multi_request")
        .param(v) // url
        .param(v) // messages (newline-separated)
        .param(TypeId::Integer) // timeout_secs
        .returns_logical(ws_multi_result_type())
        .function(cb_ws_multi_request)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
