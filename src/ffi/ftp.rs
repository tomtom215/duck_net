// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::ftp;

// ===== Return Type Helpers =====

pub(super) fn read_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("content", LogicalType::new(TypeId::Varchar)),
        ("size", LogicalType::new(TypeId::BigInt)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

pub(super) fn write_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("bytes_written", LogicalType::new(TypeId::BigInt)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

pub(super) fn delete_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// ===== FTP Scalar Callbacks =====

// ftp_read(url) -> STRUCT(success, content, size, message)
quack_rs::scalar_callback!(cb_ftp_read, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let r = ftp::read(url);

        unsafe { sw.write_bool(row, 0, r.success) };
        unsafe { sw.write_varchar(row, 1, &r.content) };
        unsafe { sw.write_i64(row, 2, r.size) };
        unsafe { sw.write_varchar(row, 3, &r.message) };
    }
});

// ftp_write(url, content) -> STRUCT(success, bytes_written, message)
quack_rs::scalar_callback!(cb_ftp_write, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let content_reader = unsafe { chunk.reader(1) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let content = unsafe { content_reader.read_str(row) };
        let r = ftp::write(url, content);

        unsafe { sw.write_bool(row, 0, r.success) };
        unsafe { sw.write_i64(row, 1, r.bytes_written) };
        unsafe { sw.write_varchar(row, 2, &r.message) };
    }
});

// ftp_delete(url) -> STRUCT(success, message)
quack_rs::scalar_callback!(cb_ftp_delete, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let r = ftp::delete(url);

        unsafe { sw.write_bool(row, 0, r.success) };
        unsafe { sw.write_varchar(row, 1, &r.message) };
    }
});

// ===== Blob Read Result Type =====

pub(super) fn blob_read_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("data", LogicalType::new(TypeId::Blob)),
        ("size", LogicalType::new(TypeId::BigInt)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// ftp_read_blob(url) -> STRUCT(success, data BLOB, size, message)
quack_rs::scalar_callback!(cb_ftp_read_blob, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let r = ftp::read_blob(url);

        unsafe { sw.write_bool(row, 0, r.success) };
        unsafe { sw.write_blob(row, 1, &r.data) };
        unsafe { sw.write_i64(row, 2, r.size) };
        unsafe { sw.write_varchar(row, 3, &r.message) };
    }
});

// ===== FTP List Table Function =====

struct FtpListBindData {
    url: String,
}
struct FtpListInitData {
    entries: Vec<crate::ftp::FtpEntry>,
    idx: usize,
}

unsafe extern "C" fn ftp_list_bind(info: duckdb_bind_info) {
    let bind = BindInfo::new(info);
    let url = bind.get_parameter_value(0).as_str().unwrap_or_default();

    bind.add_result_column("name", TypeId::Varchar);
    bind.add_result_column("size", TypeId::BigInt);
    bind.add_result_column("is_dir", TypeId::Boolean);

    FfiBindData::<FtpListBindData>::set(info, FtpListBindData { url });
}

unsafe extern "C" fn ftp_list_init(info: duckdb_init_info) {
    FfiInitData::<FtpListInitData>::set(
        info,
        FtpListInitData {
            entries: vec![],
            idx: 0,
        },
    );
}

// ftp_list scan callback
quack_rs::table_scan_callback!(ftp_list_scan, |info, output| {
    let bind_data = match unsafe { FfiBindData::<FtpListBindData>::get_from_function(info) } {
        Some(d) => d,
        None => {
            unsafe { DataChunk::from_raw(output).set_size(0) };
            return;
        }
    };
    let init_data = match unsafe { FfiInitData::<FtpListInitData>::get_mut(info) } {
        Some(d) => d,
        None => {
            unsafe { DataChunk::from_raw(output).set_size(0) };
            return;
        }
    };

    // Fetch entries on first scan
    if init_data.entries.is_empty() && init_data.idx == 0 {
        match ftp::list(&bind_data.url) {
            Ok(entries) => init_data.entries = entries,
            Err(e) => {
                let fi = FunctionInfo::new(info);
                fi.set_error(&e);
                unsafe { DataChunk::from_raw(output).set_size(0) };
                return;
            }
        }
    }

    let out_chunk = unsafe { DataChunk::from_raw(output) };
    let mut name_w = unsafe { out_chunk.writer(0) };
    let mut size_w = unsafe { out_chunk.writer(1) };
    let mut is_dir_w = unsafe { out_chunk.writer(2) };

    let mut count: idx_t = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.entries.len() && count < max_chunk {
        let entry = &init_data.entries[init_data.idx];
        unsafe { name_w.write_varchar(count as usize, &entry.name) };
        unsafe { size_w.write_i64(count as usize, entry.size) };
        unsafe { is_dir_w.write_bool(count as usize, entry.is_dir) };
        init_data.idx += 1;
        count += 1;
    }

    unsafe { out_chunk.set_size(count as usize) };
});

// ===== Registration =====

pub unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    // FTP scalar functions
    ScalarFunctionBuilder::new("ftp_read")
        .param(v)
        .returns_logical(read_result_type())
        .function(cb_ftp_read)
        .register(con.as_raw_connection())?;

    ScalarFunctionBuilder::new("ftp_write")
        .param(v)
        .param(v)
        .returns_logical(write_result_type())
        .function(cb_ftp_write)
        .register(con.as_raw_connection())?;

    ScalarFunctionBuilder::new("ftp_delete")
        .param(v)
        .returns_logical(delete_result_type())
        .function(cb_ftp_delete)
        .register(con.as_raw_connection())?;

    // Binary read function
    ScalarFunctionBuilder::new("ftp_read_blob")
        .param(v)
        .returns_logical(blob_read_result_type())
        .function(cb_ftp_read_blob)
        .register(con.as_raw_connection())?;

    // FTP list table function
    TableFunctionBuilder::new("ftp_list")
        .param(TypeId::Varchar)
        .bind(ftp_list_bind)
        .init(ftp_list_init)
        .scan(ftp_list_scan)
        .register(con.as_raw_connection())?;

    // SFTP functions
    super::sftp::register_all(con)?;

    Ok(())
}
