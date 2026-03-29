// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::ssh;

use super::scalars::write_varchar;

fn ssh_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("exit_code", LogicalType::new(TypeId::Integer)),
        ("stdout", LogicalType::new(TypeId::Varchar)),
        ("stderr", LogicalType::new(TypeId::Varchar)),
    ])
}

/// ssh_exec(host, user, key_file, command) -> STRUCT(success, exit_code, stdout, stderr)
unsafe extern "C" fn cb_ssh_exec(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let host_reader = VectorReader::new(input, 0);
    let user_reader = VectorReader::new(input, 1);
    let key_reader = VectorReader::new(input, 2);
    let cmd_reader = VectorReader::new(input, 3);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let exit_vec = duckdb_struct_vector_get_child(output, 1);
    let stdout_vec = duckdb_struct_vector_get_child(output, 2);
    let stderr_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let user = user_reader.read_str(row as usize);
        let key_file = key_reader.read_str(row as usize);
        let command = cmd_reader.read_str(row as usize);

        let result = ssh::exec(host, 22, user, key_file, command);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        let ed = duckdb_vector_get_data(exit_vec) as *mut i32;
        *ed.add(row as usize) = result.exit_code;
        write_varchar(stdout_vec, row, &result.stdout);
        write_varchar(stderr_vec, row, &result.stderr);
    }
}

/// ssh_exec(host, port, user, key_file, command) -> STRUCT
unsafe extern "C" fn cb_ssh_exec_port(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let host_reader = VectorReader::new(input, 0);
    let port_data = duckdb_vector_get_data(duckdb_data_chunk_get_vector(input, 1)) as *const i32;
    let user_reader = VectorReader::new(input, 2);
    let key_reader = VectorReader::new(input, 3);
    let cmd_reader = VectorReader::new(input, 4);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let exit_vec = duckdb_struct_vector_get_child(output, 1);
    let stdout_vec = duckdb_struct_vector_get_child(output, 2);
    let stderr_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let port = *port_data.add(row as usize) as u16;
        let user = user_reader.read_str(row as usize);
        let key_file = key_reader.read_str(row as usize);
        let command = cmd_reader.read_str(row as usize);

        let result = ssh::exec(host, port, user, key_file, command);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        let ed = duckdb_vector_get_data(exit_vec) as *mut i32;
        *ed.add(row as usize) = result.exit_code;
        write_varchar(stdout_vec, row, &result.stdout);
        write_varchar(stderr_vec, row, &result.stderr);
    }
}

/// ssh_exec_password(host, user, password, command) -> STRUCT
unsafe extern "C" fn cb_ssh_exec_password(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let host_reader = VectorReader::new(input, 0);
    let user_reader = VectorReader::new(input, 1);
    let pass_reader = VectorReader::new(input, 2);
    let cmd_reader = VectorReader::new(input, 3);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let exit_vec = duckdb_struct_vector_get_child(output, 1);
    let stdout_vec = duckdb_struct_vector_get_child(output, 2);
    let stderr_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let user = user_reader.read_str(row as usize);
        let password = pass_reader.read_str(row as usize);
        let command = cmd_reader.read_str(row as usize);

        let result = ssh::exec_password(host, 22, user, password, command);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        let ed = duckdb_vector_get_data(exit_vec) as *mut i32;
        *ed.add(row as usize) = result.exit_code;
        write_varchar(stdout_vec, row, &result.stdout);
        write_varchar(stderr_vec, row, &result.stderr);
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    // ssh_exec: key-based auth (4 or 5 params)
    ScalarFunctionSetBuilder::new("ssh_exec")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // host
                .param(v) // user
                .param(v) // key_file
                .param(v) // command
                .returns_logical(ssh_result_type())
                .function(cb_ssh_exec)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // host
                .param(TypeId::Integer) // port
                .param(v) // user
                .param(v) // key_file
                .param(v) // command
                .returns_logical(ssh_result_type())
                .function(cb_ssh_exec_port)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con)?;

    // ssh_exec_password: password auth
    ScalarFunctionBuilder::new("ssh_exec_password")
        .param(v) // host
        .param(v) // user
        .param(v) // password
        .param(v) // command
        .returns_logical(ssh_result_type())
        .function(cb_ssh_exec_password)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
