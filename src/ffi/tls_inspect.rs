// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::tls_inspect;

use super::dns::write_string_list;
use super::scalars::write_varchar;

fn tls_cert_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("subject", LogicalType::new(TypeId::Varchar)),
        ("issuer", LogicalType::new(TypeId::Varchar)),
        ("not_before", LogicalType::new(TypeId::Varchar)),
        ("not_after", LogicalType::new(TypeId::Varchar)),
        ("serial", LogicalType::new(TypeId::Varchar)),
        (
            "san_names",
            LogicalType::list_from_logical(&LogicalType::new(TypeId::Varchar)),
        ),
        ("key_algorithm", LogicalType::new(TypeId::Varchar)),
        ("signature_algorithm", LogicalType::new(TypeId::Varchar)),
        ("is_expired", LogicalType::new(TypeId::Boolean)),
        ("days_until_expiry", LogicalType::new(TypeId::BigInt)),
        ("version", LogicalType::new(TypeId::Varchar)),
    ])
}

/// tls_inspect(host) -> STRUCT
unsafe extern "C" fn cb_tls_inspect(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let host_reader = VectorReader::new(input, 0);

    let subject_vec = duckdb_struct_vector_get_child(output, 0);
    let issuer_vec = duckdb_struct_vector_get_child(output, 1);
    let not_before_vec = duckdb_struct_vector_get_child(output, 2);
    let not_after_vec = duckdb_struct_vector_get_child(output, 3);
    let serial_vec = duckdb_struct_vector_get_child(output, 4);
    let san_names_vec = duckdb_struct_vector_get_child(output, 5);
    let key_algo_vec = duckdb_struct_vector_get_child(output, 6);
    let sig_algo_vec = duckdb_struct_vector_get_child(output, 7);
    let is_expired_vec = duckdb_struct_vector_get_child(output, 8);
    let days_vec = duckdb_struct_vector_get_child(output, 9);
    let version_vec = duckdb_struct_vector_get_child(output, 10);

    let mut san_list_offset: idx_t = 0;

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        match tls_inspect::inspect(host, 443) {
            Ok(info) => {
                write_varchar(subject_vec, row, &info.subject);
                write_varchar(issuer_vec, row, &info.issuer);
                write_varchar(not_before_vec, row, &info.not_before);
                write_varchar(not_after_vec, row, &info.not_after);
                write_varchar(serial_vec, row, &info.serial);
                write_string_list(san_names_vec, row, &info.san_names, &mut san_list_offset);
                write_varchar(key_algo_vec, row, &info.key_algorithm);
                write_varchar(sig_algo_vec, row, &info.signature_algorithm);
                let exp_data = duckdb_vector_get_data(is_expired_vec) as *mut bool;
                *exp_data.add(row as usize) = info.is_expired;
                let days_data = duckdb_vector_get_data(days_vec) as *mut i64;
                *days_data.add(row as usize) = info.days_until_expiry;
                write_varchar(version_vec, row, &info.version);
            }
            Err(e) => {
                write_varchar(subject_vec, row, &format!("Error: {e}"));
                write_varchar(issuer_vec, row, "");
                write_varchar(not_before_vec, row, "");
                write_varchar(not_after_vec, row, "");
                write_varchar(serial_vec, row, "");
                write_string_list(san_names_vec, row, &[], &mut san_list_offset);
                write_varchar(key_algo_vec, row, "");
                write_varchar(sig_algo_vec, row, "");
                let exp_data = duckdb_vector_get_data(is_expired_vec) as *mut bool;
                *exp_data.add(row as usize) = false;
                let days_data = duckdb_vector_get_data(days_vec) as *mut i64;
                *days_data.add(row as usize) = -1;
                write_varchar(version_vec, row, "");
            }
        }
    }
}

/// tls_inspect(host, port) -> STRUCT
unsafe extern "C" fn cb_tls_inspect_port(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let host_reader = VectorReader::new(input, 0);
    let port_data = duckdb_vector_get_data(duckdb_data_chunk_get_vector(input, 1)) as *const i32;

    let subject_vec = duckdb_struct_vector_get_child(output, 0);
    let issuer_vec = duckdb_struct_vector_get_child(output, 1);
    let not_before_vec = duckdb_struct_vector_get_child(output, 2);
    let not_after_vec = duckdb_struct_vector_get_child(output, 3);
    let serial_vec = duckdb_struct_vector_get_child(output, 4);
    let san_names_vec = duckdb_struct_vector_get_child(output, 5);
    let key_algo_vec = duckdb_struct_vector_get_child(output, 6);
    let sig_algo_vec = duckdb_struct_vector_get_child(output, 7);
    let is_expired_vec = duckdb_struct_vector_get_child(output, 8);
    let days_vec = duckdb_struct_vector_get_child(output, 9);
    let version_vec = duckdb_struct_vector_get_child(output, 10);

    let mut san_list_offset: idx_t = 0;

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let port = *port_data.add(row as usize) as u16;
        match tls_inspect::inspect(host, port) {
            Ok(info) => {
                write_varchar(subject_vec, row, &info.subject);
                write_varchar(issuer_vec, row, &info.issuer);
                write_varchar(not_before_vec, row, &info.not_before);
                write_varchar(not_after_vec, row, &info.not_after);
                write_varchar(serial_vec, row, &info.serial);
                write_string_list(san_names_vec, row, &info.san_names, &mut san_list_offset);
                write_varchar(key_algo_vec, row, &info.key_algorithm);
                write_varchar(sig_algo_vec, row, &info.signature_algorithm);
                let exp_data = duckdb_vector_get_data(is_expired_vec) as *mut bool;
                *exp_data.add(row as usize) = info.is_expired;
                let days_data = duckdb_vector_get_data(days_vec) as *mut i64;
                *days_data.add(row as usize) = info.days_until_expiry;
                write_varchar(version_vec, row, &info.version);
            }
            Err(e) => {
                write_varchar(subject_vec, row, &format!("Error: {e}"));
                write_varchar(issuer_vec, row, "");
                write_varchar(not_before_vec, row, "");
                write_varchar(not_after_vec, row, "");
                write_varchar(serial_vec, row, "");
                write_string_list(san_names_vec, row, &[], &mut san_list_offset);
                write_varchar(key_algo_vec, row, "");
                write_varchar(sig_algo_vec, row, "");
                let exp_data = duckdb_vector_get_data(is_expired_vec) as *mut bool;
                *exp_data.add(row as usize) = false;
                let days_data = duckdb_vector_get_data(days_vec) as *mut i64;
                *days_data.add(row as usize) = -1;
                write_varchar(version_vec, row, "");
            }
        }
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    ScalarFunctionSetBuilder::new("tls_inspect")
        .overload(
            ScalarOverloadBuilder::new()
                .param(TypeId::Varchar)
                .returns_logical(tls_cert_type())
                .function(cb_tls_inspect)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(TypeId::Varchar)
                .param(TypeId::Integer)
                .returns_logical(tls_cert_type())
                .function(cb_tls_inspect_port)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con)?;

    Ok(())
}
