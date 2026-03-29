// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::grpc;
use crate::grpc_reflect;

use super::dns::write_string_list;
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

fn grpc_reflection_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        (
            "services",
            LogicalType::list_from_logical(&LogicalType::new(TypeId::Varchar)),
        ),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

/// grpc_list_services(url) -> STRUCT
unsafe extern "C" fn cb_grpc_list_services(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);

    let mut success_w = StructVector::field_writer(output, 0);
    let services_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);
    let mut list_offset: usize = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);

        let result = grpc_reflect::list_services(url);

        success_w.write_bool(row as usize, result.success);
        write_string_list(services_vec, row, &result.services, &mut list_offset);
        write_varchar(message_vec, row, &result.message);
    }
}

/// grpc_call(url, service, method, payload) -> STRUCT
unsafe extern "C" fn cb_grpc_call(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let svc_reader = chunk.reader(1);
    let method_reader = chunk.reader(2);
    let payload_reader = chunk.reader(3);

    let mut success_w = StructVector::field_writer(output, 0);
    let mut status_w = StructVector::field_writer(output, 1);
    let body_vec = duckdb_struct_vector_get_child(output, 2);
    let mut grpc_status_w = StructVector::field_writer(output, 3);
    let grpc_msg_vec = duckdb_struct_vector_get_child(output, 4);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let service = svc_reader.read_str(row as usize);
        let method = method_reader.read_str(row as usize);
        let payload = payload_reader.read_str(row as usize);

        let result = grpc::call(url, service, method, payload);

        success_w.write_bool(row as usize, result.success);
        status_w.write_i32(row as usize, result.status_code);
        write_varchar(body_vec, row, &result.body);
        grpc_status_w.write_i32(row as usize, result.grpc_status);
        write_varchar(grpc_msg_vec, row, &result.grpc_message);
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionBuilder::new("grpc_list_services")
        .param(v)
        .returns_logical(grpc_reflection_result_type())
        .function(cb_grpc_list_services)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

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
