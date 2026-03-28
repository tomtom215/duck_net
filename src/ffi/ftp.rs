use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::ftp;
use crate::sftp;

use super::scalars::write_varchar;

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

/// ftp_read(url) -> STRUCT(success, content, size, message)
unsafe extern "C" fn cb_ftp_read(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let content_vec = duckdb_struct_vector_get_child(output, 1);
    let size_vec = duckdb_struct_vector_get_child(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let r = ftp::read(url);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = r.success;
        write_varchar(content_vec, row, &r.content);
        let szd = duckdb_vector_get_data(size_vec) as *mut i64;
        *szd.add(row as usize) = r.size;
        write_varchar(message_vec, row, &r.message);
    }
}

/// ftp_write(url, content) -> STRUCT(success, bytes_written, message)
unsafe extern "C" fn cb_ftp_write(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let content_reader = VectorReader::new(input, 1);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let bytes_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let content = content_reader.read_str(row as usize);
        let r = ftp::write(url, content);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = r.success;
        let bd = duckdb_vector_get_data(bytes_vec) as *mut i64;
        *bd.add(row as usize) = r.bytes_written;
        write_varchar(message_vec, row, &r.message);
    }
}

/// ftp_delete(url) -> STRUCT(success, message)
unsafe extern "C" fn cb_ftp_delete(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let message_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let r = ftp::delete(url);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = r.success;
        write_varchar(message_vec, row, &r.message);
    }
}

// ===== SFTP Scalar Callbacks =====

/// sftp_read(url) -> STRUCT(success, content, size, message)
unsafe extern "C" fn cb_sftp_read(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let content_vec = duckdb_struct_vector_get_child(output, 1);
    let size_vec = duckdb_struct_vector_get_child(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let r = sftp::read(url, None);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = r.success;
        write_varchar(content_vec, row, &r.content);
        let szd = duckdb_vector_get_data(size_vec) as *mut i64;
        *szd.add(row as usize) = r.size;
        write_varchar(message_vec, row, &r.message);
    }
}

/// sftp_read(url, key_file) -> STRUCT(success, content, size, message)
unsafe extern "C" fn cb_sftp_read_key(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let key_reader = VectorReader::new(input, 1);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let content_vec = duckdb_struct_vector_get_child(output, 1);
    let size_vec = duckdb_struct_vector_get_child(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let key_file = key_reader.read_str(row as usize);
        let r = sftp::read(url, Some(key_file));

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = r.success;
        write_varchar(content_vec, row, &r.content);
        let szd = duckdb_vector_get_data(size_vec) as *mut i64;
        *szd.add(row as usize) = r.size;
        write_varchar(message_vec, row, &r.message);
    }
}

/// sftp_write(url, content) -> STRUCT(success, bytes_written, message)
unsafe extern "C" fn cb_sftp_write(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let content_reader = VectorReader::new(input, 1);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let bytes_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let content = content_reader.read_str(row as usize);
        let r = sftp::write(url, content, None);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = r.success;
        let bd = duckdb_vector_get_data(bytes_vec) as *mut i64;
        *bd.add(row as usize) = r.bytes_written;
        write_varchar(message_vec, row, &r.message);
    }
}

/// sftp_delete(url) -> STRUCT(success, message)
unsafe extern "C" fn cb_sftp_delete(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let message_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let r = sftp::delete(url, None);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = r.success;
        write_varchar(message_vec, row, &r.message);
    }
}

// ===== Blob Read Result Type =====

fn blob_read_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("data", LogicalType::new(TypeId::Blob)),
        ("size", LogicalType::new(TypeId::BigInt)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

/// ftp_read_blob(url) -> STRUCT(success, data BLOB, size, message)
unsafe extern "C" fn cb_ftp_read_blob(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let data_vec = duckdb_struct_vector_get_child(output, 1);
    let size_vec = duckdb_struct_vector_get_child(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let r = ftp::read_blob(url);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = r.success;
        // Write blob data
        duckdb_vector_assign_string_element_len(
            data_vec,
            row,
            r.data.as_ptr() as *const _,
            r.data.len() as idx_t,
        );
        let szd = duckdb_vector_get_data(size_vec) as *mut i64;
        *szd.add(row as usize) = r.size;
        write_varchar(message_vec, row, &r.message);
    }
}

/// sftp_read_blob(url) -> STRUCT(success, data BLOB, size, message)
unsafe extern "C" fn cb_sftp_read_blob(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let data_vec = duckdb_struct_vector_get_child(output, 1);
    let size_vec = duckdb_struct_vector_get_child(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let r = sftp::read_blob(url, None);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = r.success;
        duckdb_vector_assign_string_element_len(
            data_vec,
            row,
            r.data.as_ptr() as *const _,
            r.data.len() as idx_t,
        );
        let szd = duckdb_vector_get_data(size_vec) as *mut i64;
        *szd.add(row as usize) = r.size;
        write_varchar(message_vec, row, &r.message);
    }
}

/// sftp_read_blob(url, key_file) -> STRUCT(success, data BLOB, size, message)
unsafe extern "C" fn cb_sftp_read_blob_key(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let key_reader = VectorReader::new(input, 1);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let data_vec = duckdb_struct_vector_get_child(output, 1);
    let size_vec = duckdb_struct_vector_get_child(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let key_file = key_reader.read_str(row as usize);
        let r = sftp::read_blob(url, Some(key_file));

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = r.success;
        duckdb_vector_assign_string_element_len(
            data_vec,
            row,
            r.data.as_ptr() as *const _,
            r.data.len() as idx_t,
        );
        let szd = duckdb_vector_get_data(size_vec) as *mut i64;
        *szd.add(row as usize) = r.size;
        write_varchar(message_vec, row, &r.message);
    }
}

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
    let url_val = bind.get_parameter(0);
    let url_cstr = duckdb_get_varchar(url_val);
    let url = std::ffi::CStr::from_ptr(url_cstr)
        .to_str()
        .unwrap_or("")
        .to_string();
    duckdb_free(url_cstr as *mut _);
    duckdb_destroy_value(&mut { url_val });

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

unsafe extern "C" fn ftp_list_scan(info: duckdb_function_info, output: duckdb_data_chunk) {
    let bind_data = match FfiBindData::<FtpListBindData>::get_from_function(info) {
        Some(d) => d,
        None => {
            duckdb_data_chunk_set_size(output, 0);
            return;
        }
    };
    let init_data = match FfiInitData::<FtpListInitData>::get_mut(info) {
        Some(d) => d,
        None => {
            duckdb_data_chunk_set_size(output, 0);
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
                duckdb_data_chunk_set_size(output, 0);
                return;
            }
        }
    }

    let name_vec = duckdb_data_chunk_get_vector(output, 0);
    let size_vec = duckdb_data_chunk_get_vector(output, 1);
    let is_dir_vec = duckdb_data_chunk_get_vector(output, 2);

    let mut count: idx_t = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.entries.len() && count < max_chunk {
        let entry = &init_data.entries[init_data.idx];
        write_varchar(name_vec, count, &entry.name);
        let szd = duckdb_vector_get_data(size_vec) as *mut i64;
        *szd.add(count as usize) = entry.size;
        let dd = duckdb_vector_get_data(is_dir_vec) as *mut bool;
        *dd.add(count as usize) = entry.is_dir;
        init_data.idx += 1;
        count += 1;
    }

    duckdb_data_chunk_set_size(output, count);
}

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
    let url_val = bind.get_parameter(0);
    let url_cstr = duckdb_get_varchar(url_val);
    let url = std::ffi::CStr::from_ptr(url_cstr)
        .to_str()
        .unwrap_or("")
        .to_string();
    duckdb_free(url_cstr as *mut _);
    duckdb_destroy_value(&mut { url_val });

    // Try to read optional key_file named parameter
    let key_val = bind.get_named_parameter("key_file");
    let key_file = if key_val.is_null() {
        None
    } else {
        let cstr = duckdb_get_varchar(key_val);
        let s = if cstr.is_null() {
            None
        } else {
            let s = std::ffi::CStr::from_ptr(cstr)
                .to_str()
                .ok()
                .map(|s| s.to_string());
            duckdb_free(cstr as *mut _);
            s
        };
        duckdb_destroy_value(&mut { key_val });
        s
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

unsafe extern "C" fn sftp_list_scan(info: duckdb_function_info, output: duckdb_data_chunk) {
    let bind_data = match FfiBindData::<SftpListBindData>::get_from_function(info) {
        Some(d) => d,
        None => {
            duckdb_data_chunk_set_size(output, 0);
            return;
        }
    };
    let init_data = match FfiInitData::<SftpListInitData>::get_mut(info) {
        Some(d) => d,
        None => {
            duckdb_data_chunk_set_size(output, 0);
            return;
        }
    };

    if init_data.entries.is_empty() && init_data.idx == 0 {
        match sftp::list(&bind_data.url, bind_data.key_file.as_deref()) {
            Ok(entries) => init_data.entries = entries,
            Err(e) => {
                let fi = FunctionInfo::new(info);
                fi.set_error(&e);
                duckdb_data_chunk_set_size(output, 0);
                return;
            }
        }
    }

    let name_vec = duckdb_data_chunk_get_vector(output, 0);
    let size_vec = duckdb_data_chunk_get_vector(output, 1);
    let is_dir_vec = duckdb_data_chunk_get_vector(output, 2);

    let mut count: idx_t = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.entries.len() && count < max_chunk {
        let entry = &init_data.entries[init_data.idx];
        write_varchar(name_vec, count, &entry.name);
        let szd = duckdb_vector_get_data(size_vec) as *mut i64;
        *szd.add(count as usize) = entry.size;
        let dd = duckdb_vector_get_data(is_dir_vec) as *mut bool;
        *dd.add(count as usize) = entry.is_dir;
        init_data.idx += 1;
        count += 1;
    }

    duckdb_data_chunk_set_size(output, count);
}

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
