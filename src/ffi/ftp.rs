// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::ftp;
use crate::sftp;

// ===== Return Type Helpers =====

fn read_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("content", LogicalType::new(TypeId::Varchar)),
        ("size", LogicalType::new(TypeId::BigInt)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

fn write_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("bytes_written", LogicalType::new(TypeId::BigInt)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

fn delete_result_type() -> LogicalType {
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

// ===== Blob Read Result Type =====

fn blob_read_result_type() -> LogicalType {
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
    let data_vec = unsafe { duckdb_struct_vector_get_child(output, 1) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let r = ftp::read_blob(url);

        unsafe { sw.write_bool(row, 0, r.success) };
        // Write blob data directly
        unsafe {
            duckdb_vector_assign_string_element_len(
                data_vec,
                row as idx_t,
                r.data.as_ptr() as *const _,
                r.data.len() as idx_t,
            );
        }
        unsafe { sw.write_i64(row, 2, r.size) };
        unsafe { sw.write_varchar(row, 3, &r.message) };
    }
});

// sftp_read_blob(url) -> STRUCT(success, data BLOB, size, message)
quack_rs::scalar_callback!(cb_sftp_read_blob, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };

    let mut sw = unsafe { StructWriter::new(output, 4) };
    let data_vec = unsafe { duckdb_struct_vector_get_child(output, 1) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let r = sftp::read_blob(url, None);

        unsafe { sw.write_bool(row, 0, r.success) };
        unsafe {
            duckdb_vector_assign_string_element_len(
                data_vec,
                row as idx_t,
                r.data.as_ptr() as *const _,
                r.data.len() as idx_t,
            );
        }
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
    let data_vec = unsafe { duckdb_struct_vector_get_child(output, 1) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let key_file = unsafe { key_reader.read_str(row) };
        let r = sftp::read_blob(url, Some(key_file));

        unsafe { sw.write_bool(row, 0, r.success) };
        unsafe {
            duckdb_vector_assign_string_element_len(
                data_vec,
                row as idx_t,
                r.data.as_ptr() as *const _,
                r.data.len() as idx_t,
            );
        }
        unsafe { sw.write_i64(row, 2, r.size) };
        unsafe { sw.write_varchar(row, 3, &r.message) };
    }
});

// ===== FTP/SFTP List Table Functions =====

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
            unsafe { duckdb_data_chunk_set_size(output, 0) };
            return;
        }
    };
    let init_data = match unsafe { FfiInitData::<FtpListInitData>::get_mut(info) } {
        Some(d) => d,
        None => {
            unsafe { duckdb_data_chunk_set_size(output, 0) };
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
                unsafe { duckdb_data_chunk_set_size(output, 0) };
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

    unsafe { duckdb_data_chunk_set_size(output, count) };
});

// SFTP list table function
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
            unsafe { duckdb_data_chunk_set_size(output, 0) };
            return;
        }
    };
    let init_data = match unsafe { FfiInitData::<SftpListInitData>::get_mut(info) } {
        Some(d) => d,
        None => {
            unsafe { duckdb_data_chunk_set_size(output, 0) };
            return;
        }
    };

    if init_data.entries.is_empty() && init_data.idx == 0 {
        match sftp::list(&bind_data.url, bind_data.key_file.as_deref()) {
            Ok(entries) => init_data.entries = entries,
            Err(e) => {
                let fi = FunctionInfo::new(info);
                fi.set_error(&e);
                unsafe { duckdb_data_chunk_set_size(output, 0) };
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

    unsafe { duckdb_data_chunk_set_size(output, count) };
});

// ===== Registration =====

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    // FTP scalar functions
    ScalarFunctionBuilder::new("ftp_read")
        .param(v)
        .returns_logical(read_result_type())
        .function(cb_ftp_read)
        .register(con)?;

    ScalarFunctionBuilder::new("ftp_write")
        .param(v)
        .param(v)
        .returns_logical(write_result_type())
        .function(cb_ftp_write)
        .register(con)?;

    ScalarFunctionBuilder::new("ftp_delete")
        .param(v)
        .returns_logical(delete_result_type())
        .function(cb_ftp_delete)
        .register(con)?;

    // SFTP scalar functions
    ScalarFunctionSetBuilder::new("sftp_read")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .returns_logical(read_result_type())
                .function(cb_sftp_read),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .param(v)
                .returns_logical(read_result_type())
                .function(cb_sftp_read_key),
        )
        .register(con)?;

    ScalarFunctionBuilder::new("sftp_write")
        .param(v)
        .param(v)
        .returns_logical(write_result_type())
        .function(cb_sftp_write)
        .register(con)?;

    ScalarFunctionBuilder::new("sftp_delete")
        .param(v)
        .returns_logical(delete_result_type())
        .function(cb_sftp_delete)
        .register(con)?;

    // Binary read functions
    ScalarFunctionBuilder::new("ftp_read_blob")
        .param(v)
        .returns_logical(blob_read_result_type())
        .function(cb_ftp_read_blob)
        .register(con)?;

    ScalarFunctionSetBuilder::new("sftp_read_blob")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .returns_logical(blob_read_result_type())
                .function(cb_sftp_read_blob),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .param(v)
                .returns_logical(blob_read_result_type())
                .function(cb_sftp_read_blob_key),
        )
        .register(con)?;

    // FTP list table function
    TableFunctionBuilder::new("ftp_list")
        .param(TypeId::Varchar)
        .bind(ftp_list_bind)
        .init(ftp_list_init)
        .scan(ftp_list_scan)
        .register(con)?;

    // SFTP list table function
    TableFunctionBuilder::new("sftp_list")
        .param(TypeId::Varchar)
        .named_param("key_file", TypeId::Varchar)
        .bind(sftp_list_bind)
        .init(sftp_list_init)
        .scan(sftp_list_scan)
        .register(con)?;

    Ok(())
}
