// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use quack_rs::prelude::*;

use crate::scp;

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

// scp_read(host, port, user, key_file, remote_path) -> STRUCT
quack_rs::scalar_callback!(cb_scp_read, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let port_reader = unsafe { chunk.reader(1) };
    let user_reader = unsafe { chunk.reader(2) };
    let key_reader = unsafe { chunk.reader(3) };
    let path_reader = unsafe { chunk.reader(4) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row) };
        let port = unsafe { port_reader.read_i32(row) } as u16;
        let user = unsafe { user_reader.read_str(row) };
        let key_file = unsafe { key_reader.read_str(row) };
        let remote_path = unsafe { path_reader.read_str(row) };

        let result = scp::scp_read(host, port, user, key_file, remote_path);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.data) };
        unsafe { sw.write_i64(row, 2, result.size) };
        unsafe { sw.write_varchar(row, 3, &result.message) };
    }
});

// scp_read_password(host, port, user, password, remote_path) -> STRUCT
quack_rs::scalar_callback!(cb_scp_read_password, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let port_reader = unsafe { chunk.reader(1) };
    let user_reader = unsafe { chunk.reader(2) };
    let pass_reader = unsafe { chunk.reader(3) };
    let path_reader = unsafe { chunk.reader(4) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row) };
        let port = unsafe { port_reader.read_i32(row) } as u16;
        let user = unsafe { user_reader.read_str(row) };
        let password = unsafe { pass_reader.read_str(row) };
        let remote_path = unsafe { path_reader.read_str(row) };

        let result = scp::scp_read_password(host, port, user, password, remote_path);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.data) };
        unsafe { sw.write_i64(row, 2, result.size) };
        unsafe { sw.write_varchar(row, 3, &result.message) };
    }
});

// scp_write(host, port, user, key_file, remote_path, data) -> STRUCT
quack_rs::scalar_callback!(cb_scp_write, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let port_reader = unsafe { chunk.reader(1) };
    let user_reader = unsafe { chunk.reader(2) };
    let key_reader = unsafe { chunk.reader(3) };
    let path_reader = unsafe { chunk.reader(4) };
    let data_reader = unsafe { chunk.reader(5) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row) };
        let port = unsafe { port_reader.read_i32(row) } as u16;
        let user = unsafe { user_reader.read_str(row) };
        let key_file = unsafe { key_reader.read_str(row) };
        let remote_path = unsafe { path_reader.read_str(row) };
        let data = unsafe { data_reader.read_str(row) };

        let result = scp::scp_write(host, port, user, key_file, remote_path, data);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_i64(row, 1, result.bytes_written) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

// scp_write_password(host, port, user, password, remote_path, data) -> STRUCT
quack_rs::scalar_callback!(cb_scp_write_password, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let port_reader = unsafe { chunk.reader(1) };
    let user_reader = unsafe { chunk.reader(2) };
    let pass_reader = unsafe { chunk.reader(3) };
    let path_reader = unsafe { chunk.reader(4) };
    let data_reader = unsafe { chunk.reader(5) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row) };
        let port = unsafe { port_reader.read_i32(row) } as u16;
        let user = unsafe { user_reader.read_str(row) };
        let password = unsafe { pass_reader.read_str(row) };
        let remote_path = unsafe { path_reader.read_str(row) };
        let data = unsafe { data_reader.read_str(row) };

        let result = scp::scp_write_password(host, port, user, password, remote_path, data);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_i64(row, 1, result.bytes_written) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

pub unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;
    let i = TypeId::Integer;

    // scp_read(host, port, user, key_file, remote_path)
    ScalarFunctionBuilder::new("scp_read")
        .param(v) // host
        .param(i) // port
        .param(v) // user
        .param(v) // key_file
        .param(v) // remote_path
        .returns_logical(scp_read_result_type())
        .function(cb_scp_read)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // scp_read_password(host, port, user, password, remote_path)
    ScalarFunctionBuilder::new("scp_read_password")
        .param(v) // host
        .param(i) // port
        .param(v) // user
        .param(v) // password
        .param(v) // remote_path
        .returns_logical(scp_read_result_type())
        .function(cb_scp_read_password)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // scp_write(host, port, user, key_file, remote_path, data)
    ScalarFunctionBuilder::new("scp_write")
        .param(v) // host
        .param(i) // port
        .param(v) // user
        .param(v) // key_file
        .param(v) // remote_path
        .param(v) // data
        .returns_logical(scp_write_result_type())
        .function(cb_scp_write)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // scp_write_password(host, port, user, password, remote_path, data)
    ScalarFunctionBuilder::new("scp_write_password")
        .param(v) // host
        .param(i) // port
        .param(v) // user
        .param(v) // password
        .param(v) // remote_path
        .param(v) // data
        .returns_logical(scp_write_result_type())
        .function(cb_scp_write_password)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    Ok(())
}
