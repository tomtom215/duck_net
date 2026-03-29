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

fn scp_read_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("data", LogicalType::new(TypeId::Varchar)),
        ("size", LogicalType::new(TypeId::BigInt)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

fn scp_write_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("bytes_written", LogicalType::new(TypeId::BigInt)),
        ("message", LogicalType::new(TypeId::Varchar)),
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

/// scp_read(host, user, key_file, remote_path) -> STRUCT(success, data, size, message)
unsafe extern "C" fn cb_scp_read(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let host_reader = VectorReader::new(input, 0);
    let user_reader = VectorReader::new(input, 1);
    let key_reader = VectorReader::new(input, 2);
    let path_reader = VectorReader::new(input, 3);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let data_vec = duckdb_struct_vector_get_child(output, 1);
    let size_vec = duckdb_struct_vector_get_child(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let user = user_reader.read_str(row as usize);
        let key_file = key_reader.read_str(row as usize);
        let remote_path = path_reader.read_str(row as usize);

        let result = ssh::scp_read(host, 22, user, key_file, remote_path);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(data_vec, row, &result.data);
        let sz = duckdb_vector_get_data(size_vec) as *mut i64;
        *sz.add(row as usize) = result.size;
        write_varchar(message_vec, row, &result.message);
    }
}

/// scp_read(host, port, user, key_file, remote_path) -> STRUCT(success, data, size, message)
unsafe extern "C" fn cb_scp_read_port(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let host_reader = VectorReader::new(input, 0);
    let port_data = duckdb_vector_get_data(duckdb_data_chunk_get_vector(input, 1)) as *const i32;
    let user_reader = VectorReader::new(input, 2);
    let key_reader = VectorReader::new(input, 3);
    let path_reader = VectorReader::new(input, 4);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let data_vec = duckdb_struct_vector_get_child(output, 1);
    let size_vec = duckdb_struct_vector_get_child(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let port = *port_data.add(row as usize) as u16;
        let user = user_reader.read_str(row as usize);
        let key_file = key_reader.read_str(row as usize);
        let remote_path = path_reader.read_str(row as usize);

        let result = ssh::scp_read(host, port, user, key_file, remote_path);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(data_vec, row, &result.data);
        let sz = duckdb_vector_get_data(size_vec) as *mut i64;
        *sz.add(row as usize) = result.size;
        write_varchar(message_vec, row, &result.message);
    }
}

/// scp_read_password(host, user, password, remote_path) -> STRUCT(success, data, size, message)
unsafe extern "C" fn cb_scp_read_password(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let host_reader = VectorReader::new(input, 0);
    let user_reader = VectorReader::new(input, 1);
    let pass_reader = VectorReader::new(input, 2);
    let path_reader = VectorReader::new(input, 3);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let data_vec = duckdb_struct_vector_get_child(output, 1);
    let size_vec = duckdb_struct_vector_get_child(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let user = user_reader.read_str(row as usize);
        let password = pass_reader.read_str(row as usize);
        let remote_path = path_reader.read_str(row as usize);

        let result = ssh::scp_read_password(host, 22, user, password, remote_path);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(data_vec, row, &result.data);
        let sz = duckdb_vector_get_data(size_vec) as *mut i64;
        *sz.add(row as usize) = result.size;
        write_varchar(message_vec, row, &result.message);
    }
}

/// scp_write(host, user, key_file, remote_path, data) -> STRUCT(success, bytes_written, message)
unsafe extern "C" fn cb_scp_write(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let host_reader = VectorReader::new(input, 0);
    let user_reader = VectorReader::new(input, 1);
    let key_reader = VectorReader::new(input, 2);
    let path_reader = VectorReader::new(input, 3);
    let data_reader = VectorReader::new(input, 4);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let bytes_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let user = user_reader.read_str(row as usize);
        let key_file = key_reader.read_str(row as usize);
        let remote_path = path_reader.read_str(row as usize);
        let data = data_reader.read_str(row as usize);

        let result = ssh::scp_write(host, 22, user, key_file, remote_path, data);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        let bw = duckdb_vector_get_data(bytes_vec) as *mut i64;
        *bw.add(row as usize) = result.bytes_written;
        write_varchar(message_vec, row, &result.message);
    }
}

/// scp_write_password(host, user, password, remote_path, data) -> STRUCT(success, bytes_written, message)
unsafe extern "C" fn cb_scp_write_password(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let host_reader = VectorReader::new(input, 0);
    let user_reader = VectorReader::new(input, 1);
    let pass_reader = VectorReader::new(input, 2);
    let path_reader = VectorReader::new(input, 3);
    let data_reader = VectorReader::new(input, 4);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let bytes_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let user = user_reader.read_str(row as usize);
        let password = pass_reader.read_str(row as usize);
        let remote_path = path_reader.read_str(row as usize);
        let data = data_reader.read_str(row as usize);

        let result = ssh::scp_write_password(host, 22, user, password, remote_path, data);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        let bw = duckdb_vector_get_data(bytes_vec) as *mut i64;
        *bw.add(row as usize) = result.bytes_written;
        write_varchar(message_vec, row, &result.message);
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

    // scp_read: key-based auth (4 or 5 params)
    ScalarFunctionSetBuilder::new("scp_read")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // host
                .param(v) // user
                .param(v) // key_file
                .param(v) // remote_path
                .returns_logical(scp_read_result_type())
                .function(cb_scp_read)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // host
                .param(TypeId::Integer) // port
                .param(v) // user
                .param(v) // key_file
                .param(v) // remote_path
                .returns_logical(scp_read_result_type())
                .function(cb_scp_read_port)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con)?;

    // scp_read_password: password auth
    ScalarFunctionBuilder::new("scp_read_password")
        .param(v) // host
        .param(v) // user
        .param(v) // password
        .param(v) // remote_path
        .returns_logical(scp_read_result_type())
        .function(cb_scp_read_password)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // scp_write: key-based auth
    ScalarFunctionBuilder::new("scp_write")
        .param(v) // host
        .param(v) // user
        .param(v) // key_file
        .param(v) // remote_path
        .param(v) // data
        .returns_logical(scp_write_result_type())
        .function(cb_scp_write)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // scp_write_password: password auth
    ScalarFunctionBuilder::new("scp_write_password")
        .param(v) // host
        .param(v) // user
        .param(v) // password
        .param(v) // remote_path
        .param(v) // data
        .returns_logical(scp_write_result_type())
        .function(cb_scp_write_password)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
