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
    let row_count = duckdb_data_chunk_get_size(input);
    let host_reader = VectorReader::new(input, 0);
    let secret_reader = VectorReader::new(input, 1);
    let user_reader = VectorReader::new(input, 2);
    let pass_reader = VectorReader::new(input, 3);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let code_vec = duckdb_struct_vector_get_child(output, 1);
    let name_vec = duckdb_struct_vector_get_child(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let secret = secret_reader.read_str(row as usize);
        let username = user_reader.read_str(row as usize);
        let password = pass_reader.read_str(row as usize);

        let result = radius::auth_default_port(host, secret, username, password);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        let cd = duckdb_vector_get_data(code_vec) as *mut i32;
        *cd.add(row as usize) = result.code;
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
    let row_count = duckdb_data_chunk_get_size(input);
    let host_reader = VectorReader::new(input, 0);
    let port_data = duckdb_vector_get_data(duckdb_data_chunk_get_vector(input, 1)) as *const i32;
    let secret_reader = VectorReader::new(input, 2);
    let user_reader = VectorReader::new(input, 3);
    let pass_reader = VectorReader::new(input, 4);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let code_vec = duckdb_struct_vector_get_child(output, 1);
    let name_vec = duckdb_struct_vector_get_child(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let port = *port_data.add(row as usize) as u16;
        let secret = secret_reader.read_str(row as usize);
        let username = user_reader.read_str(row as usize);
        let password = pass_reader.read_str(row as usize);

        let result = radius::auth(host, port, secret, username, password);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        let cd = duckdb_vector_get_data(code_vec) as *mut i32;
        *cd.add(row as usize) = result.code;
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
