// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::syslog;

use super::scalars::write_varchar;

fn syslog_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

/// syslog_send(host, facility, severity, message) -> STRUCT(success, message)
unsafe extern "C" fn cb_syslog_send_4(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let host_reader = VectorReader::new(input, 0);
    let facility_reader = VectorReader::new(input, 1);
    let severity_reader = VectorReader::new(input, 2);
    let msg_reader = VectorReader::new(input, 3);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let message_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let facility_str = facility_reader.read_str(row as usize);
        let severity_str = severity_reader.read_str(row as usize);
        let msg = msg_reader.read_str(row as usize);

        let facility = match syslog::facility_from_name(facility_str) {
            Some(f) => f,
            None => {
                let sd = duckdb_vector_get_data(success_vec) as *mut bool;
                *sd.add(row as usize) = false;
                write_varchar(
                    message_vec,
                    row,
                    &format!("Unknown facility: {facility_str}"),
                );
                continue;
            }
        };
        let severity = match syslog::severity_from_name(severity_str) {
            Some(s) => s,
            None => {
                let sd = duckdb_vector_get_data(success_vec) as *mut bool;
                *sd.add(row as usize) = false;
                write_varchar(
                    message_vec,
                    row,
                    &format!("Unknown severity: {severity_str}"),
                );
                continue;
            }
        };

        let result = syslog::send(host, 0, facility, severity, "", "", msg);
        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(message_vec, row, &result.message);
    }
}

/// syslog_send(host, port, facility, severity, hostname, app_name, message)
unsafe extern "C" fn cb_syslog_send_7(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let host_reader = VectorReader::new(input, 0);
    let port_data = duckdb_vector_get_data(duckdb_data_chunk_get_vector(input, 1)) as *const i32;
    let facility_reader = VectorReader::new(input, 2);
    let severity_reader = VectorReader::new(input, 3);
    let hostname_reader = VectorReader::new(input, 4);
    let app_reader = VectorReader::new(input, 5);
    let msg_reader = VectorReader::new(input, 6);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let message_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let port = *port_data.add(row as usize) as u16;
        let facility_str = facility_reader.read_str(row as usize);
        let severity_str = severity_reader.read_str(row as usize);
        let hostname = hostname_reader.read_str(row as usize);
        let app_name = app_reader.read_str(row as usize);
        let msg = msg_reader.read_str(row as usize);

        let facility = match syslog::facility_from_name(facility_str) {
            Some(f) => f,
            None => {
                let sd = duckdb_vector_get_data(success_vec) as *mut bool;
                *sd.add(row as usize) = false;
                write_varchar(
                    message_vec,
                    row,
                    &format!("Unknown facility: {facility_str}"),
                );
                continue;
            }
        };
        let severity = match syslog::severity_from_name(severity_str) {
            Some(s) => s,
            None => {
                let sd = duckdb_vector_get_data(success_vec) as *mut bool;
                *sd.add(row as usize) = false;
                write_varchar(
                    message_vec,
                    row,
                    &format!("Unknown severity: {severity_str}"),
                );
                continue;
            }
        };

        let result = syslog::send(host, port, facility, severity, hostname, app_name, msg);
        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(message_vec, row, &result.message);
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionSetBuilder::new("syslog_send")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // host
                .param(v) // facility
                .param(v) // severity
                .param(v) // message
                .returns_logical(syslog_result_type())
                .function(cb_syslog_send_4)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // host
                .param(TypeId::Integer) // port
                .param(v) // facility
                .param(v) // severity
                .param(v) // hostname
                .param(v) // app_name
                .param(v) // message
                .returns_logical(syslog_result_type())
                .function(cb_syslog_send_7)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con)?;

    Ok(())
}
