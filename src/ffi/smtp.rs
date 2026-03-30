// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::smtp::{self, SmtpConfig};


/// STRUCT(success BOOLEAN, message VARCHAR)
fn smtp_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// smtp_send(server, from, to, subject, body) -> STRUCT(success, message)
quack_rs::scalar_callback!(cb_smtp_send_5, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let server_reader = unsafe { chunk.reader(0) };
    let from_reader = unsafe { chunk.reader(1) };
    let to_reader = unsafe { chunk.reader(2) };
    let subject_reader = unsafe { chunk.reader(3) };
    let body_reader = unsafe { chunk.reader(4) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let server = unsafe { server_reader.read_str(row) };
        let (host, port, use_tls) = match smtp::parse_server_url(server) {
            Ok(v) => v,
            Err(e) => {
                unsafe { sw.write_bool(row, 0, false) };
                unsafe { sw.write_varchar(row, 1, &e) };
                continue;
            }
        };

        let config = SmtpConfig {
            host,
            port,
            use_tls,
            from: unsafe { from_reader.read_str(row) }.to_string(),
            to: unsafe { to_reader.read_str(row) }.to_string(),
            subject: unsafe { subject_reader.read_str(row) }.to_string(),
            body: unsafe { body_reader.read_str(row) }.to_string(),
            username: None,
            password: None,
        };

        let result = smtp::send(&config);
        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.message) };
    }
});

// smtp_send(server, from, to, subject, body, username, password) -> STRUCT(success, message)
quack_rs::scalar_callback!(cb_smtp_send_7, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let server_reader = unsafe { chunk.reader(0) };
    let from_reader = unsafe { chunk.reader(1) };
    let to_reader = unsafe { chunk.reader(2) };
    let subject_reader = unsafe { chunk.reader(3) };
    let body_reader = unsafe { chunk.reader(4) };
    let user_reader = unsafe { chunk.reader(5) };
    let pass_reader = unsafe { chunk.reader(6) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let server = unsafe { server_reader.read_str(row) };
        let (host, port, use_tls) = match smtp::parse_server_url(server) {
            Ok(v) => v,
            Err(e) => {
                unsafe { sw.write_bool(row, 0, false) };
                unsafe { sw.write_varchar(row, 1, &e) };
                continue;
            }
        };

        let config = SmtpConfig {
            host,
            port,
            use_tls,
            from: unsafe { from_reader.read_str(row) }.to_string(),
            to: unsafe { to_reader.read_str(row) }.to_string(),
            subject: unsafe { subject_reader.read_str(row) }.to_string(),
            body: unsafe { body_reader.read_str(row) }.to_string(),
            username: Some(unsafe { user_reader.read_str(row) }.to_string()),
            password: Some(unsafe { pass_reader.read_str(row) }.to_string()),
        };

        let result = smtp::send(&config);
        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.message) };
    }
});

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionSetBuilder::new("smtp_send")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .param(v)
                .param(v)
                .param(v)
                .param(v)
                .returns_logical(smtp_result_type())
                .function(cb_smtp_send_5)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .param(v)
                .param(v)
                .param(v)
                .param(v)
                .param(v)
                .param(v)
                .returns_logical(smtp_result_type())
                .function(cb_smtp_send_7)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con)?;

    Ok(())
}
