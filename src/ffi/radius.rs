// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::radius;

use super::scalars::StructWriter;

fn radius_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("code", LogicalType::new(TypeId::Integer)),
        ("code_name", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// radius_auth(host, secret, username, password) -> STRUCT
quack_rs::scalar_callback!(cb_radius_auth, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let secret_reader = unsafe { chunk.reader(1) };
    let user_reader = unsafe { chunk.reader(2) };
    let pass_reader = unsafe { chunk.reader(3) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row as usize) };
        let secret = unsafe { secret_reader.read_str(row as usize) };
        let username = unsafe { user_reader.read_str(row as usize) };
        let password = unsafe { pass_reader.read_str(row as usize) };

        let result = radius::auth_default_port(host, secret, username, password);

        unsafe { sw.write_bool(row as usize, 0, result.success) };
        unsafe { sw.write_i32(row as usize, 1, result.code) };
        unsafe { sw.write_varchar(row as usize, 2, &result.code_name) };
        unsafe { sw.write_varchar(row as usize, 3, &result.message) };
    }
});

// radius_auth(host, port, secret, username, password) -> STRUCT
quack_rs::scalar_callback!(cb_radius_auth_port, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let port_reader = unsafe { chunk.reader(1) };
    let secret_reader = unsafe { chunk.reader(2) };
    let user_reader = unsafe { chunk.reader(3) };
    let pass_reader = unsafe { chunk.reader(4) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row as usize) };
        let port = unsafe { port_reader.read_i32(row as usize) } as u16;
        let secret = unsafe { secret_reader.read_str(row as usize) };
        let username = unsafe { user_reader.read_str(row as usize) };
        let password = unsafe { pass_reader.read_str(row as usize) };

        let result = radius::auth(host, port, secret, username, password);

        unsafe { sw.write_bool(row as usize, 0, result.success) };
        unsafe { sw.write_i32(row as usize, 1, result.code) };
        unsafe { sw.write_varchar(row as usize, 2, &result.code_name) };
        unsafe { sw.write_varchar(row as usize, 3, &result.message) };
    }
});

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionSetBuilder::new("radius_auth")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // host
                .param(v) // secret
                .param(v) // username
                .param(v) // password
                .returns_logical(radius_result_type())
                .function(cb_radius_auth)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // host
                .param(TypeId::Integer) // port
                .param(v) // secret
                .param(v) // username
                .param(v) // password
                .returns_logical(radius_result_type())
                .function(cb_radius_auth_port)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con)?;

    Ok(())
}
