// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::nats;

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

// nats_publish(url, subject, payload) -> STRUCT(success, message)
quack_rs::scalar_callback!(cb_nats_publish, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let subject_reader = unsafe { chunk.reader(1) };
    let payload_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let subject = unsafe { subject_reader.read_str(row) };
        let payload = unsafe { payload_reader.read_str(row) };

        let result = nats::publish(url, subject, payload);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.message) };
    }
});

// nats_request(url, subject, payload, timeout_ms) -> STRUCT(success, response, message)
quack_rs::scalar_callback!(cb_nats_request, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let subject_reader = unsafe { chunk.reader(1) };
    let payload_reader = unsafe { chunk.reader(2) };
    let timeout_reader = unsafe { chunk.reader(3) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let subject = unsafe { subject_reader.read_str(row) };
        let payload = unsafe { payload_reader.read_str(row) };
        let timeout_ms = unsafe { timeout_reader.read_i32(row) };

        let result = nats::request(url, subject, payload, timeout_ms as u32);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.response) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

// nats_request(url, subject, payload) -> STRUCT(success, response, message) with 5000ms default timeout
quack_rs::scalar_callback!(cb_nats_request_default, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let subject_reader = unsafe { chunk.reader(1) };
    let payload_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let subject = unsafe { subject_reader.read_str(row) };
        let payload = unsafe { payload_reader.read_str(row) };

        let result = nats::request(url, subject, payload, 5000);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.response) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

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
