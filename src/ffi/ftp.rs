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
        .param(v).param(v)
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
                .param(v).param(v)
                .returns_logical(read_result_type())
                .function(cb_sftp_read_key),
        )
        .register(con)?;

    ScalarFunctionBuilder::new("sftp_write")
        .param(v).param(v)
        .returns_logical(write_result_type())
        .function(cb_sftp_write)
        .register(con)?;

    ScalarFunctionBuilder::new("sftp_delete")
        .param(v)
        .returns_logical(delete_result_type())
        .function(cb_sftp_delete)
        .register(con)?;

    Ok(())
}
