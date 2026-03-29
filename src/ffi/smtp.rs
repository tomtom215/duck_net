// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::smtp::{self, SmtpConfig};

use super::scalars::write_varchar;

/// STRUCT(success BOOLEAN, message VARCHAR)
fn smtp_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

unsafe fn write_smtp_result(output: duckdb_vector, row: idx_t, success: bool, message: &str) {
    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let message_vec = duckdb_struct_vector_get_child(output, 1);

    let success_data = duckdb_vector_get_data(success_vec) as *mut bool;
    *success_data.add(row as usize) = success;

    write_varchar(message_vec, row, message);
}

/// smtp_send(server, from, to, subject, body) -> STRUCT(success, message)
unsafe extern "C" fn cb_smtp_send_5(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let server_reader = VectorReader::new(input, 0);
    let from_reader = VectorReader::new(input, 1);
    let to_reader = VectorReader::new(input, 2);
    let subject_reader = VectorReader::new(input, 3);
    let body_reader = VectorReader::new(input, 4);

    for row in 0..row_count {
        let server = server_reader.read_str(row as usize);
        let (host, port, use_tls) = match smtp::parse_server_url(server) {
            Ok(v) => v,
            Err(e) => {
                write_smtp_result(output, row, false, &e);
                continue;
            }
        };

        let config = SmtpConfig {
            host,
            port,
            use_tls,
            from: from_reader.read_str(row as usize).to_string(),
            to: to_reader.read_str(row as usize).to_string(),
            subject: subject_reader.read_str(row as usize).to_string(),
            body: body_reader.read_str(row as usize).to_string(),
            username: None,
            password: None,
        };

        let result = smtp::send(&config);
        write_smtp_result(output, row, result.success, &result.message);
    }
}

/// smtp_send(server, from, to, subject, body, username, password) -> STRUCT(success, message)
unsafe extern "C" fn cb_smtp_send_7(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let server_reader = VectorReader::new(input, 0);
    let from_reader = VectorReader::new(input, 1);
    let to_reader = VectorReader::new(input, 2);
    let subject_reader = VectorReader::new(input, 3);
    let body_reader = VectorReader::new(input, 4);
    let user_reader = VectorReader::new(input, 5);
    let pass_reader = VectorReader::new(input, 6);

    for row in 0..row_count {
        let server = server_reader.read_str(row as usize);
        let (host, port, use_tls) = match smtp::parse_server_url(server) {
            Ok(v) => v,
            Err(e) => {
                write_smtp_result(output, row, false, &e);
                continue;
            }
        };

        let config = SmtpConfig {
            host,
            port,
            use_tls,
            from: from_reader.read_str(row as usize).to_string(),
            to: to_reader.read_str(row as usize).to_string(),
            subject: subject_reader.read_str(row as usize).to_string(),
            body: body_reader.read_str(row as usize).to_string(),
            username: Some(user_reader.read_str(row as usize).to_string()),
            password: Some(pass_reader.read_str(row as usize).to_string()),
        };

        let result = smtp::send(&config);
        write_smtp_result(output, row, result.success, &result.message);
    }
}

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
