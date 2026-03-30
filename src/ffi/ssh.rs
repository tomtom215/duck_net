// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::scp;
use crate::ssh;

use super::scalars::StructWriter;

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

// ssh_exec(host, user, key_file, command) -> STRUCT(success, exit_code, stdout, stderr)
quack_rs::scalar_callback!(cb_ssh_exec, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let user_reader = unsafe { chunk.reader(1) };
    let key_reader = unsafe { chunk.reader(2) };
    let cmd_reader = unsafe { chunk.reader(3) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row as usize) };
        let user = unsafe { user_reader.read_str(row as usize) };
        let key_file = unsafe { key_reader.read_str(row as usize) };
        let command = unsafe { cmd_reader.read_str(row as usize) };

        let result = ssh::exec(host, 22, user, key_file, command);

        unsafe { sw.write_bool(row as usize, 0, result.success) };
        unsafe { sw.write_i32(row as usize, 1, result.exit_code) };
        unsafe { sw.write_varchar(row as usize, 2, &result.stdout) };
        unsafe { sw.write_varchar(row as usize, 3, &result.stderr) };
    }
});

// ssh_exec(host, port, user, key_file, command) -> STRUCT
quack_rs::scalar_callback!(cb_ssh_exec_port, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let port_reader = unsafe { chunk.reader(1) };
    let user_reader = unsafe { chunk.reader(2) };
    let key_reader = unsafe { chunk.reader(3) };
    let cmd_reader = unsafe { chunk.reader(4) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row as usize) };
        let port = unsafe { port_reader.read_i32(row as usize) } as u16;
        let user = unsafe { user_reader.read_str(row as usize) };
        let key_file = unsafe { key_reader.read_str(row as usize) };
        let command = unsafe { cmd_reader.read_str(row as usize) };

        let result = ssh::exec(host, port, user, key_file, command);

        unsafe { sw.write_bool(row as usize, 0, result.success) };
        unsafe { sw.write_i32(row as usize, 1, result.exit_code) };
        unsafe { sw.write_varchar(row as usize, 2, &result.stdout) };
        unsafe { sw.write_varchar(row as usize, 3, &result.stderr) };
    }
});

// ssh_exec_password(host, user, password, command) -> STRUCT
quack_rs::scalar_callback!(cb_ssh_exec_password, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let user_reader = unsafe { chunk.reader(1) };
    let pass_reader = unsafe { chunk.reader(2) };
    let cmd_reader = unsafe { chunk.reader(3) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row as usize) };
        let user = unsafe { user_reader.read_str(row as usize) };
        let password = unsafe { pass_reader.read_str(row as usize) };
        let command = unsafe { cmd_reader.read_str(row as usize) };

        let result = ssh::exec_password(host, 22, user, password, command);

        unsafe { sw.write_bool(row as usize, 0, result.success) };
        unsafe { sw.write_i32(row as usize, 1, result.exit_code) };
        unsafe { sw.write_varchar(row as usize, 2, &result.stdout) };
        unsafe { sw.write_varchar(row as usize, 3, &result.stderr) };
    }
});

// scp_read(host, user, key_file, remote_path) -> STRUCT(success, data, size, message)
quack_rs::scalar_callback!(cb_scp_read, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let user_reader = unsafe { chunk.reader(1) };
    let key_reader = unsafe { chunk.reader(2) };
    let path_reader = unsafe { chunk.reader(3) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row as usize) };
        let user = unsafe { user_reader.read_str(row as usize) };
        let key_file = unsafe { key_reader.read_str(row as usize) };
        let remote_path = unsafe { path_reader.read_str(row as usize) };

        let result = scp::scp_read(host, 22, user, key_file, remote_path);

        unsafe { sw.write_bool(row as usize, 0, result.success) };
        unsafe { sw.write_varchar(row as usize, 1, &result.data) };
        unsafe { sw.write_i64(row as usize, 2, result.size) };
        unsafe { sw.write_varchar(row as usize, 3, &result.message) };
    }
});

// scp_read(host, port, user, key_file, remote_path) -> STRUCT(success, data, size, message)
quack_rs::scalar_callback!(cb_scp_read_port, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let port_reader = unsafe { chunk.reader(1) };
    let user_reader = unsafe { chunk.reader(2) };
    let key_reader = unsafe { chunk.reader(3) };
    let path_reader = unsafe { chunk.reader(4) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row as usize) };
        let port = unsafe { port_reader.read_i32(row as usize) } as u16;
        let user = unsafe { user_reader.read_str(row as usize) };
        let key_file = unsafe { key_reader.read_str(row as usize) };
        let remote_path = unsafe { path_reader.read_str(row as usize) };

        let result = scp::scp_read(host, port, user, key_file, remote_path);

        unsafe { sw.write_bool(row as usize, 0, result.success) };
        unsafe { sw.write_varchar(row as usize, 1, &result.data) };
        unsafe { sw.write_i64(row as usize, 2, result.size) };
        unsafe { sw.write_varchar(row as usize, 3, &result.message) };
    }
});

// scp_read_password(host, user, password, remote_path) -> STRUCT(success, data, size, message)
quack_rs::scalar_callback!(cb_scp_read_password, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let user_reader = unsafe { chunk.reader(1) };
    let pass_reader = unsafe { chunk.reader(2) };
    let path_reader = unsafe { chunk.reader(3) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row as usize) };
        let user = unsafe { user_reader.read_str(row as usize) };
        let password = unsafe { pass_reader.read_str(row as usize) };
        let remote_path = unsafe { path_reader.read_str(row as usize) };

        let result = scp::scp_read_password(host, 22, user, password, remote_path);

        unsafe { sw.write_bool(row as usize, 0, result.success) };
        unsafe { sw.write_varchar(row as usize, 1, &result.data) };
        unsafe { sw.write_i64(row as usize, 2, result.size) };
        unsafe { sw.write_varchar(row as usize, 3, &result.message) };
    }
});

// scp_write(host, user, key_file, remote_path, data) -> STRUCT(success, bytes_written, message)
quack_rs::scalar_callback!(cb_scp_write, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let user_reader = unsafe { chunk.reader(1) };
    let key_reader = unsafe { chunk.reader(2) };
    let path_reader = unsafe { chunk.reader(3) };
    let data_reader = unsafe { chunk.reader(4) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row as usize) };
        let user = unsafe { user_reader.read_str(row as usize) };
        let key_file = unsafe { key_reader.read_str(row as usize) };
        let remote_path = unsafe { path_reader.read_str(row as usize) };
        let data = unsafe { data_reader.read_str(row as usize) };

        let result = scp::scp_write(host, 22, user, key_file, remote_path, data);

        unsafe { sw.write_bool(row as usize, 0, result.success) };
        unsafe { sw.write_i64(row as usize, 1, result.bytes_written) };
        unsafe { sw.write_varchar(row as usize, 2, &result.message) };
    }
});

// scp_write_password(host, user, password, remote_path, data) -> STRUCT(success, bytes_written, message)
quack_rs::scalar_callback!(cb_scp_write_password, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let user_reader = unsafe { chunk.reader(1) };
    let pass_reader = unsafe { chunk.reader(2) };
    let path_reader = unsafe { chunk.reader(3) };
    let data_reader = unsafe { chunk.reader(4) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row as usize) };
        let user = unsafe { user_reader.read_str(row as usize) };
        let password = unsafe { pass_reader.read_str(row as usize) };
        let remote_path = unsafe { path_reader.read_str(row as usize) };
        let data = unsafe { data_reader.read_str(row as usize) };

        let result = scp::scp_write_password(host, 22, user, password, remote_path, data);

        unsafe { sw.write_bool(row as usize, 0, result.success) };
        unsafe { sw.write_i64(row as usize, 1, result.bytes_written) };
        unsafe { sw.write_varchar(row as usize, 2, &result.message) };
    }
});

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
