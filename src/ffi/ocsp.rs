// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::ocsp;

use super::scalars::write_varchar;

fn ocsp_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("status", LogicalType::new(TypeId::Varchar)),
        ("revocation_time", LogicalType::new(TypeId::Varchar)),
        ("this_update", LogicalType::new(TypeId::Varchar)),
        ("next_update", LogicalType::new(TypeId::Varchar)),
        ("responder", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

/// ocsp_check(host, port) -> STRUCT
unsafe extern "C" fn cb_ocsp_check(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let host_reader = VectorReader::new(input, 0);
    let port_data = duckdb_vector_get_data(duckdb_data_chunk_get_vector(input, 1)) as *const i32;

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let status_vec = duckdb_struct_vector_get_child(output, 1);
    let revocation_vec = duckdb_struct_vector_get_child(output, 2);
    let this_update_vec = duckdb_struct_vector_get_child(output, 3);
    let next_update_vec = duckdb_struct_vector_get_child(output, 4);
    let responder_vec = duckdb_struct_vector_get_child(output, 5);
    let message_vec = duckdb_struct_vector_get_child(output, 6);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let port = *port_data.add(row as usize) as u16;

        let result = ocsp::check(host, port);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(status_vec, row, &result.status);
        write_varchar(revocation_vec, row, &result.revocation_time);
        write_varchar(this_update_vec, row, &result.this_update);
        write_varchar(next_update_vec, row, &result.next_update);
        write_varchar(responder_vec, row, &result.responder);
        write_varchar(message_vec, row, &result.message);
    }
}

/// ocsp_check(host) -> STRUCT (default port 443)
unsafe extern "C" fn cb_ocsp_check_default(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let host_reader = VectorReader::new(input, 0);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let status_vec = duckdb_struct_vector_get_child(output, 1);
    let revocation_vec = duckdb_struct_vector_get_child(output, 2);
    let this_update_vec = duckdb_struct_vector_get_child(output, 3);
    let next_update_vec = duckdb_struct_vector_get_child(output, 4);
    let responder_vec = duckdb_struct_vector_get_child(output, 5);
    let message_vec = duckdb_struct_vector_get_child(output, 6);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);

        let result = ocsp::check(host, 443);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(status_vec, row, &result.status);
        write_varchar(revocation_vec, row, &result.revocation_time);
        write_varchar(this_update_vec, row, &result.this_update);
        write_varchar(next_update_vec, row, &result.next_update);
        write_varchar(responder_vec, row, &result.responder);
        write_varchar(message_vec, row, &result.message);
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionSetBuilder::new("ocsp_check")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // host
                .returns_logical(ocsp_result_type())
                .function(cb_ocsp_check_default)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // host
                .param(TypeId::Integer) // port
                .returns_logical(ocsp_result_type())
                .function(cb_ocsp_check)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con)?;

    Ok(())
}
