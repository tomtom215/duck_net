// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::sftp;

// ===== SFTP Scalar Callbacks =====

// sftp_read(url) -> STRUCT(success, content, size, message)
quack_rs::scalar_callback!(cb_sftp_read, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let r = sftp::read(url, None);

        unsafe { sw.write_bool(row, 0, r.success) };
        unsafe { sw.write_varchar(row, 1, &r.content) };
        unsafe { sw.write_i64(row, 2, r.size) };
        unsafe { sw.write_varchar(row, 3, &r.message) };
    }
});

// sftp_read(url, key_file) -> STRUCT(success, content, size, message)
quack_rs::scalar_callback!(cb_sftp_read_key, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let key_reader = unsafe { chunk.reader(1) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let key_file = unsafe { key_reader.read_str(row) };
        let r = sftp::read(url, Some(key_file));

        unsafe { sw.write_bool(row, 0, r.success) };
        unsafe { sw.write_varchar(row, 1, &r.content) };
        unsafe { sw.write_i64(row, 2, r.size) };
        unsafe { sw.write_varchar(row, 3, &r.message) };
    }
});

// sftp_write(url, content) -> STRUCT(success, bytes_written, message)
quack_rs::scalar_callback!(cb_sftp_write, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let content_reader = unsafe { chunk.reader(1) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let content = unsafe { content_reader.read_str(row) };
        let r = sftp::write(url, content, None);

        unsafe { sw.write_bool(row, 0, r.success) };
        unsafe { sw.write_i64(row, 1, r.bytes_written) };
        unsafe { sw.write_varchar(row, 2, &r.message) };
    }
});

// sftp_delete(url) -> STRUCT(success, message)
quack_rs::scalar_callback!(cb_sftp_delete, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let r = sftp::delete(url, None);

        unsafe { sw.write_bool(row, 0, r.success) };
        unsafe { sw.write_varchar(row, 1, &r.message) };
    }
});

// sftp_read_blob(url) -> STRUCT(success, data BLOB, size, message)
quack_rs::scalar_callback!(cb_sftp_read_blob, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let r = sftp::read_blob(url, None);

        unsafe { sw.write_bool(row, 0, r.success) };
        unsafe { sw.write_blob(row, 1, &r.data) };
        unsafe { sw.write_i64(row, 2, r.size) };
        unsafe { sw.write_varchar(row, 3, &r.message) };
    }
});

// sftp_read_blob(url, key_file) -> STRUCT(success, data BLOB, size, message)
quack_rs::scalar_callback!(cb_sftp_read_blob_key, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let key_reader = unsafe { chunk.reader(1) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let key_file = unsafe { key_reader.read_str(row) };
        let r = sftp::read_blob(url, Some(key_file));

        unsafe { sw.write_bool(row, 0, r.success) };
        unsafe { sw.write_blob(row, 1, &r.data) };
        unsafe { sw.write_i64(row, 2, r.size) };
        unsafe { sw.write_varchar(row, 3, &r.message) };
    }
});

// ===== SFTP List Table Function =====

struct SftpListBindData {
    url: String,
    key_file: Option<String>,
}
struct SftpListInitData {
    entries: Vec<crate::sftp::SftpEntry>,
    idx: usize,
}

unsafe extern "C" fn sftp_list_bind(info: duckdb_bind_info) {
    let bind = BindInfo::new(info);
    let url = bind.get_parameter_value(0).as_str().unwrap_or_default();

    // Try to read optional key_file named parameter
    let key_val = bind.get_named_parameter_value("key_file");
    let key_file = if key_val.is_null() {
        None
    } else {
        key_val.as_str().ok()
    };

    bind.add_result_column("name", TypeId::Varchar);
    bind.add_result_column("size", TypeId::BigInt);
    bind.add_result_column("is_dir", TypeId::Boolean);

    FfiBindData::<SftpListBindData>::set(info, SftpListBindData { url, key_file });
}

unsafe extern "C" fn sftp_list_init(info: duckdb_init_info) {
    FfiInitData::<SftpListInitData>::set(
        info,
        SftpListInitData {
            entries: vec![],
            idx: 0,
        },
    );
}

// sftp_list scan callback
quack_rs::table_scan_callback!(sftp_list_scan, |info, output| {
    let bind_data = match unsafe { FfiBindData::<SftpListBindData>::get_from_function(info) } {
        Some(d) => d,
        None => {
            unsafe { DataChunk::from_raw(output).set_size(0) };
            return;
        }
    };
    let init_data = match unsafe { FfiInitData::<SftpListInitData>::get_mut(info) } {
        Some(d) => d,
        None => {
            unsafe { DataChunk::from_raw(output).set_size(0) };
            return;
        }
    };

    if init_data.entries.is_empty() && init_data.idx == 0 {
        match sftp::list(&bind_data.url, bind_data.key_file.as_deref()) {
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

    // SFTP scalar functions
    ScalarFunctionSetBuilder::new("sftp_read")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .returns_logical(super::ftp::read_result_type())
                .function(cb_sftp_read),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .param(v)
                .returns_logical(super::ftp::read_result_type())
                .function(cb_sftp_read_key),
        )
        .register(con.as_raw_connection())?;

    ScalarFunctionBuilder::new("sftp_write")
        .param(v)
        .param(v)
        .returns_logical(super::ftp::write_result_type())
        .function(cb_sftp_write)
        .register(con.as_raw_connection())?;

    ScalarFunctionBuilder::new("sftp_delete")
        .param(v)
        .returns_logical(super::ftp::delete_result_type())
        .function(cb_sftp_delete)
        .register(con.as_raw_connection())?;

    ScalarFunctionSetBuilder::new("sftp_read_blob")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .returns_logical(super::ftp::blob_read_result_type())
                .function(cb_sftp_read_blob),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .param(v)
                .returns_logical(super::ftp::blob_read_result_type())
                .function(cb_sftp_read_blob_key),
        )
        .register(con.as_raw_connection())?;

    // SFTP list table function
    TableFunctionBuilder::new("sftp_list")
        .param(TypeId::Varchar)
        .named_param("key_file", TypeId::Varchar)
        .bind(sftp_list_bind)
        .init(sftp_list_init)
        .scan(sftp_list_scan)
        .register(con.as_raw_connection())?;

    Ok(())
}
