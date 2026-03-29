// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::grpc;

use super::scalars::write_varchar;

fn grpc_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("status_code", LogicalType::new(TypeId::Integer)),
        ("body", LogicalType::new(TypeId::Varchar)),
        ("grpc_status", LogicalType::new(TypeId::Integer)),
        ("grpc_message", LogicalType::new(TypeId::Varchar)),
    ])
}

/// grpc_call(url, service, method, payload) -> STRUCT
unsafe extern "C" fn cb_grpc_call(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let svc_reader = VectorReader::new(input, 1);
    let method_reader = VectorReader::new(input, 2);
    let payload_reader = VectorReader::new(input, 3);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let status_vec = duckdb_struct_vector_get_child(output, 1);
    let body_vec = duckdb_struct_vector_get_child(output, 2);
    let grpc_status_vec = duckdb_struct_vector_get_child(output, 3);
    let grpc_msg_vec = duckdb_struct_vector_get_child(output, 4);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let service = svc_reader.read_str(row as usize);
        let method = method_reader.read_str(row as usize);
        let payload = payload_reader.read_str(row as usize);

        let result = grpc::call(url, service, method, payload);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        let hd = duckdb_vector_get_data(status_vec) as *mut i32;
        *hd.add(row as usize) = result.status_code;
        write_varchar(body_vec, row, &result.body);
        let gd = duckdb_vector_get_data(grpc_status_vec) as *mut i32;
        *gd.add(row as usize) = result.grpc_status;
        write_varchar(grpc_msg_vec, row, &result.grpc_message);
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionBuilder::new("grpc_call")
        .param(v) // url
        .param(v) // service
        .param(v) // method
        .param(v) // json_payload
        .returns_logical(grpc_result_type())
        .function(cb_grpc_call)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
