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
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let host_reader = chunk.reader(0);
    let facility_reader = chunk.reader(1);
    let severity_reader = chunk.reader(2);
    let msg_reader = chunk.reader(3);

    let mut success_w = StructVector::field_writer(output, 0);
    let message_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let facility_str = facility_reader.read_str(row as usize);
        let severity_str = severity_reader.read_str(row as usize);
        let msg = msg_reader.read_str(row as usize);

        let facility = match syslog::facility_from_name(facility_str) {
            Some(f) => f,
            None => {
                success_w.write_bool(row as usize, false);
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
                success_w.write_bool(row as usize, false);
                write_varchar(
                    message_vec,
                    row,
                    &format!("Unknown severity: {severity_str}"),
                );
                continue;
            }
        };

        let result = syslog::send(host, 0, facility, severity, "", "", msg);
        success_w.write_bool(row as usize, result.success);
        write_varchar(message_vec, row, &result.message);
    }
}

/// syslog_send(host, port, facility, severity, hostname, app_name, message)
unsafe extern "C" fn cb_syslog_send_7(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let host_reader = chunk.reader(0);
    let port_reader = chunk.reader(1);
    let facility_reader = chunk.reader(2);
    let severity_reader = chunk.reader(3);
    let hostname_reader = chunk.reader(4);
    let app_reader = chunk.reader(5);
    let msg_reader = chunk.reader(6);

    let mut success_w = StructVector::field_writer(output, 0);
    let message_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let port = port_reader.read_i32(row as usize) as u16;
        let facility_str = facility_reader.read_str(row as usize);
        let severity_str = severity_reader.read_str(row as usize);
        let hostname = hostname_reader.read_str(row as usize);
        let app_name = app_reader.read_str(row as usize);
        let msg = msg_reader.read_str(row as usize);

        let facility = match syslog::facility_from_name(facility_str) {
            Some(f) => f,
            None => {
                success_w.write_bool(row as usize, false);
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
                success_w.write_bool(row as usize, false);
                write_varchar(
                    message_vec,
                    row,
                    &format!("Unknown severity: {severity_str}"),
                );
                continue;
            }
        };

        let result = syslog::send(host, port, facility, severity, hostname, app_name, msg);
        success_w.write_bool(row as usize, result.success);
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
