// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use quack_rs::prelude::*;

use crate::syslog;

fn syslog_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// syslog_send(host, facility, severity, message) -> STRUCT(success, message)
quack_rs::scalar_callback!(cb_syslog_send_4, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let facility_reader = unsafe { chunk.reader(1) };
    let severity_reader = unsafe { chunk.reader(2) };
    let msg_reader = unsafe { chunk.reader(3) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row) };
        let facility_str = unsafe { facility_reader.read_str(row) };
        let severity_str = unsafe { severity_reader.read_str(row) };
        let msg = unsafe { msg_reader.read_str(row) };

        let facility = match syslog::facility_from_name(facility_str) {
            Some(f) => f,
            None => {
                unsafe { sw.write_bool(row, 0, false) };
                unsafe { sw.write_varchar(row, 1, &format!("Unknown facility: {facility_str}")) };
                continue;
            }
        };
        let severity = match syslog::severity_from_name(severity_str) {
            Some(s) => s,
            None => {
                unsafe { sw.write_bool(row, 0, false) };
                unsafe { sw.write_varchar(row, 1, &format!("Unknown severity: {severity_str}")) };
                continue;
            }
        };

        let result = syslog::send(host, 0, facility, severity, "", "", msg);
        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.message) };
    }
});

// syslog_send(host, port, facility, severity, hostname, app_name, message)
quack_rs::scalar_callback!(cb_syslog_send_7, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let port_reader = unsafe { chunk.reader(1) };
    let facility_reader = unsafe { chunk.reader(2) };
    let severity_reader = unsafe { chunk.reader(3) };
    let hostname_reader = unsafe { chunk.reader(4) };
    let app_reader = unsafe { chunk.reader(5) };
    let msg_reader = unsafe { chunk.reader(6) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row) };
        let port = unsafe { port_reader.read_i32(row) } as u16;
        let facility_str = unsafe { facility_reader.read_str(row) };
        let severity_str = unsafe { severity_reader.read_str(row) };
        let hostname = unsafe { hostname_reader.read_str(row) };
        let app_name = unsafe { app_reader.read_str(row) };
        let msg = unsafe { msg_reader.read_str(row) };

        let facility = match syslog::facility_from_name(facility_str) {
            Some(f) => f,
            None => {
                unsafe { sw.write_bool(row, 0, false) };
                unsafe { sw.write_varchar(row, 1, &format!("Unknown facility: {facility_str}")) };
                continue;
            }
        };
        let severity = match syslog::severity_from_name(severity_str) {
            Some(s) => s,
            None => {
                unsafe { sw.write_bool(row, 0, false) };
                unsafe { sw.write_varchar(row, 1, &format!("Unknown severity: {severity_str}")) };
                continue;
            }
        };

        let result = syslog::send(host, port, facility, severity, hostname, app_name, msg);
        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.message) };
    }
});

pub unsafe fn register_all(con: libduckdb_sys::duckdb_connection) -> Result<(), ExtensionError> {
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
