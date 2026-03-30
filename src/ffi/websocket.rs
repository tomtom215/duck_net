// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use quack_rs::prelude::*;

use crate::websocket;

fn ws_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("response", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// ws_request(url, message) -> STRUCT(success, response, message)
quack_rs::scalar_callback!(cb_ws_request, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let msg_reader = unsafe { chunk.reader(1) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let msg = unsafe { msg_reader.read_str(row) };

        let result = websocket::request_default_timeout(url, msg);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.response) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

// ws_request(url, message, timeout_secs) -> STRUCT
quack_rs::scalar_callback!(cb_ws_request_timeout, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let msg_reader = unsafe { chunk.reader(1) };
    let timeout_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let msg = unsafe { msg_reader.read_str(row) };
        let timeout = unsafe { timeout_reader.read_i32(row) } as u32;

        let result = websocket::request(url, msg, timeout);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.response) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

fn ws_multi_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("responses", LogicalType::new(TypeId::Varchar)),
        ("count", LogicalType::new(TypeId::Integer)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// ws_multi_request(url, messages, timeout_secs) -> STRUCT(success, responses, count, message)
// messages is newline-separated VARCHAR
quack_rs::scalar_callback!(cb_ws_multi_request, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let msgs_reader = unsafe { chunk.reader(1) };
    let timeout_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let msgs_str = unsafe { msgs_reader.read_str(row) };
        let timeout = unsafe { timeout_reader.read_i32(row) } as u32;

        let msgs: Vec<String> = msgs_str
            .split('\n')
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let result = websocket::multi_request(url, &msgs, timeout);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.responses.join("\n")) };
        unsafe { sw.write_i32(row, 2, result.responses.len() as i32) };
        unsafe { sw.write_varchar(row, 3, &result.message) };
    }
});

pub unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
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
        .register(con.as_raw_connection())?;

    // ws_multi_request(url, messages, timeout_secs) -> STRUCT(success, responses, count, message)
    ScalarFunctionBuilder::new("ws_multi_request")
        .param(v) // url
        .param(v) // messages (newline-separated)
        .param(TypeId::Integer) // timeout_secs
        .returns_logical(ws_multi_result_type())
        .function(cb_ws_multi_request)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    Ok(())
}
