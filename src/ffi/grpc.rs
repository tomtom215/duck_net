// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::grpc;
use crate::grpc_reflect;

use super::dns::write_string_list;

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

// grpc_list_services(url) -> STRUCT
quack_rs::scalar_callback!(cb_grpc_list_services, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };

    let mut sw = unsafe { StructWriter::new(output, 3) };
    let services_vec = unsafe { duckdb_struct_vector_get_child(output, 1) };
    let mut list_offset: usize = 0;

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row as usize) };

        let result = grpc_reflect::list_services(url);

        unsafe { sw.write_bool(row as usize, 0, result.success) };
        unsafe { write_string_list(services_vec, row, &result.services, &mut list_offset) };
        unsafe { sw.write_varchar(row as usize, 2, &result.message) };
    }
});

// grpc_call(url, service, method, payload) -> STRUCT
quack_rs::scalar_callback!(cb_grpc_call, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let svc_reader = unsafe { chunk.reader(1) };
    let method_reader = unsafe { chunk.reader(2) };
    let payload_reader = unsafe { chunk.reader(3) };

    let mut sw = unsafe { StructWriter::new(output, 5) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row as usize) };
        let service = unsafe { svc_reader.read_str(row as usize) };
        let method = unsafe { method_reader.read_str(row as usize) };
        let payload = unsafe { payload_reader.read_str(row as usize) };

        let result = grpc::call(url, service, method, payload);

        unsafe { sw.write_bool(row as usize, 0, result.success) };
        unsafe { sw.write_i32(row as usize, 1, result.status_code) };
        unsafe { sw.write_varchar(row as usize, 2, &result.body) };
        unsafe { sw.write_i32(row as usize, 3, result.grpc_status) };
        unsafe { sw.write_varchar(row as usize, 4, &result.grpc_message) };
    }
});

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
