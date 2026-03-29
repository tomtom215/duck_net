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
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let msg_reader = VectorReader::new(input, 1);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let response_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let msg = msg_reader.read_str(row as usize);

        let result = websocket::request_default_timeout(url, msg);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
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
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let msg_reader = VectorReader::new(input, 1);
    let timeout_data = duckdb_vector_get_data(duckdb_data_chunk_get_vector(input, 2)) as *const i32;

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let response_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let msg = msg_reader.read_str(row as usize);
        let timeout = *timeout_data.add(row as usize) as u32;

        let result = websocket::request(url, msg, timeout);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
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
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let msgs_reader = VectorReader::new(input, 1);
    let timeout_data = duckdb_vector_get_data(duckdb_data_chunk_get_vector(input, 2)) as *const i32;

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let responses_vec = duckdb_struct_vector_get_child(output, 1);
    let count_vec = duckdb_struct_vector_get_child(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let msgs_str = msgs_reader.read_str(row as usize);
        let timeout = *timeout_data.add(row as usize) as u32;

        let msgs: Vec<String> = msgs_str
            .split('\n')
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let result = websocket::multi_request(url, &msgs, timeout);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(responses_vec, row, &result.responses.join("\n"));
        let cd = duckdb_vector_get_data(count_vec) as *mut i32;
        *cd.add(row as usize) = result.responses.len() as i32;
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
