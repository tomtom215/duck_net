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
    let services_vec = sw.child_vector(1);
    let mut list_offset: usize = 0;

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };

        let result = grpc_reflect::list_services(url);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { write_string_list(services_vec, row, &result.services, &mut list_offset) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
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
        let url = unsafe { url_reader.read_str(row) };
        let service = unsafe { svc_reader.read_str(row) };
        let method = unsafe { method_reader.read_str(row) };
        let payload = unsafe { payload_reader.read_str(row) };

        let result = grpc::call(url, service, method, payload);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_i32(row, 1, result.status_code) };
        unsafe { sw.write_varchar(row, 2, &result.body) };
        unsafe { sw.write_i32(row, 3, result.grpc_status) };
        unsafe { sw.write_varchar(row, 4, &result.grpc_message) };
    }
});

// ===== grpc_stream table function =====

struct GrpcStreamBindData {
    url: String,
    service: String,
    method: String,
    payload: String,
}

struct GrpcStreamInitData {
    messages: Vec<String>,
    idx: usize,
    fetched: bool,
    grpc_status: i32,
    grpc_message: String,
}

unsafe extern "C" fn grpc_stream_bind(info: duckdb_bind_info) {
    let bind = BindInfo::new(info);
    let url = bind.get_parameter_value(0).as_str().unwrap_or_default();
    let service = bind.get_parameter_value(1).as_str().unwrap_or_default();
    let method = bind.get_parameter_value(2).as_str().unwrap_or_default();
    let payload = bind.get_parameter_value(3).as_str().unwrap_or_default();

    bind.add_result_column("index", TypeId::BigInt);
    bind.add_result_column("body", TypeId::Varchar);
    bind.add_result_column("grpc_status", TypeId::Integer);
    bind.add_result_column("grpc_message", TypeId::Varchar);

    FfiBindData::<GrpcStreamBindData>::set(
        info,
        GrpcStreamBindData {
            url,
            service,
            method,
            payload,
        },
    );
}

unsafe extern "C" fn grpc_stream_init(info: duckdb_init_info) {
    FfiInitData::<GrpcStreamInitData>::set(
        info,
        GrpcStreamInitData {
            messages: vec![],
            idx: 0,
            fetched: false,
            grpc_status: -1,
            grpc_message: String::new(),
        },
    );
}

quack_rs::table_scan_callback!(grpc_stream_scan, |info, output| {
    let bind_data = match unsafe { FfiBindData::<GrpcStreamBindData>::get_from_function(info) } {
        Some(d) => d,
        None => {
            unsafe { DataChunk::from_raw(output).set_size(0) };
            return;
        }
    };
    let init_data = match unsafe { FfiInitData::<GrpcStreamInitData>::get_mut(info) } {
        Some(d) => d,
        None => {
            unsafe { DataChunk::from_raw(output).set_size(0) };
            return;
        }
    };

    if !init_data.fetched {
        init_data.fetched = true;
        let result =
            grpc::call_stream(&bind_data.url, &bind_data.service, &bind_data.method, &bind_data.payload);
        if !result.success && result.messages.is_empty() {
            let fi = FunctionInfo::new(info);
            fi.set_error(&result.grpc_message);
            unsafe { DataChunk::from_raw(output).set_size(0) };
            return;
        }
        init_data.grpc_status = result.grpc_status;
        init_data.grpc_message = result.grpc_message;
        init_data.messages = result.messages;
    }

    let out_chunk = unsafe { DataChunk::from_raw(output) };
    let mut idx_w = unsafe { out_chunk.writer(0) };
    let mut body_w = unsafe { out_chunk.writer(1) };
    let mut status_w = unsafe { out_chunk.writer(2) };
    let mut msg_w = unsafe { out_chunk.writer(3) };

    let mut count: idx_t = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.messages.len() && count < max_chunk {
        let body = &init_data.messages[init_data.idx];
        let row = count as usize;
        unsafe { idx_w.write_i64(row, init_data.idx as i64) };
        unsafe { body_w.write_varchar(row, body) };
        unsafe { status_w.write_i32(row, init_data.grpc_status) };
        unsafe { msg_w.write_varchar(row, &init_data.grpc_message) };
        init_data.idx += 1;
        count += 1;
    }

    unsafe { out_chunk.set_size(count as usize) };
});

pub unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionBuilder::new("grpc_list_services")
        .param(v)
        .returns_logical(grpc_reflection_result_type())
        .function(cb_grpc_list_services)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    ScalarFunctionBuilder::new("grpc_call")
        .param(v) // url
        .param(v) // service
        .param(v) // method
        .param(v) // json_payload
        .returns_logical(grpc_result_type())
        .function(cb_grpc_call)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // grpc_stream(url, service, method, payload) -> TABLE(index, body, grpc_status, grpc_message)
    TableFunctionBuilder::new("grpc_stream")
        .param(v) // url
        .param(v) // service
        .param(v) // method
        .param(v) // json_payload
        .bind(grpc_stream_bind)
        .init(grpc_stream_init)
        .scan(grpc_stream_scan)
        .register(con.as_raw_connection())?;

    Ok(())
}
