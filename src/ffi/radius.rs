// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::radius;

use super::scalars::write_varchar;

fn radius_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("code", LogicalType::new(TypeId::Integer)),
        ("code_name", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

/// radius_auth(host, secret, username, password) -> STRUCT
unsafe extern "C" fn cb_radius_auth(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let host_reader = chunk.reader(0);
    let secret_reader = chunk.reader(1);
    let user_reader = chunk.reader(2);
    let pass_reader = chunk.reader(3);

    let mut success_writer = StructVector::field_writer(output, 0);
    let mut code_writer = StructVector::field_writer(output, 1);
    let name_vec = duckdb_struct_vector_get_child(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let secret = secret_reader.read_str(row as usize);
        let username = user_reader.read_str(row as usize);
        let password = pass_reader.read_str(row as usize);

        let result = radius::auth_default_port(host, secret, username, password);

        unsafe { success_writer.write_bool(row as usize, result.success) };
        unsafe { code_writer.write_i32(row as usize, result.code) };
        write_varchar(name_vec, row, &result.code_name);
        write_varchar(message_vec, row, &result.message);
    }
}

/// radius_auth(host, port, secret, username, password) -> STRUCT
unsafe extern "C" fn cb_radius_auth_port(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let host_reader = chunk.reader(0);
    let port_reader = chunk.reader(1);
    let secret_reader = chunk.reader(2);
    let user_reader = chunk.reader(3);
    let pass_reader = chunk.reader(4);

    let mut success_writer = StructVector::field_writer(output, 0);
    let mut code_writer = StructVector::field_writer(output, 1);
    let name_vec = duckdb_struct_vector_get_child(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let port = port_reader.read_i32(row as usize) as u16;
        let secret = secret_reader.read_str(row as usize);
        let username = user_reader.read_str(row as usize);
        let password = pass_reader.read_str(row as usize);

        let result = radius::auth(host, port, secret, username, password);

        unsafe { success_writer.write_bool(row as usize, result.success) };
        unsafe { code_writer.write_i32(row as usize, result.code) };
        write_varchar(name_vec, row, &result.code_name);
        write_varchar(message_vec, row, &result.message);
    }
}

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
