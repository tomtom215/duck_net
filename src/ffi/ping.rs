// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::ffi::CStr;

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::ping as ping_mod;

use super::scalars::write_varchar;

fn ping_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("alive", LogicalType::new(TypeId::Boolean)),
        ("latency_ms", LogicalType::new(TypeId::Double)),
        ("ttl", LogicalType::new(TypeId::Integer)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

/// ping(host) -> STRUCT(alive, latency_ms, ttl, message)
unsafe extern "C" fn cb_ping(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let host_reader = chunk.reader(0);

    let mut alive_w = StructVector::field_writer(output, 0);
    let mut latency_w = StructVector::field_writer(output, 1);
    let mut ttl_w = StructVector::field_writer(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let result = ping_mod::ping(host, 5);

        alive_w.write_bool(row as usize, result.alive);
        latency_w.write_f64(row as usize, result.latency_ms);
        ttl_w.write_i32(row as usize, result.ttl);
        write_varchar(message_vec, row, &result.message);
    }
}

/// ping(host, timeout_secs) -> STRUCT
unsafe extern "C" fn cb_ping_timeout(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let host_reader = chunk.reader(0);
    let timeout_reader = chunk.reader(1);

    let mut alive_w = StructVector::field_writer(output, 0);
    let mut latency_w = StructVector::field_writer(output, 1);
    let mut ttl_w = StructVector::field_writer(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let timeout = timeout_reader.read_i32(row as usize) as u32;
        let result = ping_mod::ping(host, timeout);

        alive_w.write_bool(row as usize, result.alive);
        latency_w.write_f64(row as usize, result.latency_ms);
        ttl_w.write_i32(row as usize, result.ttl);
        write_varchar(message_vec, row, &result.message);
    }
}

// ===== traceroute table function =====

struct TracerouteBindData {
    host: String,
    max_hops: u32,
}

struct TracerouteInitData {
    hops: Vec<ping_mod::TracerouteHop>,
    idx: usize,
    fetched: bool,
}

unsafe extern "C" fn traceroute_bind(info: duckdb_bind_info) {
    let bind = BindInfo::new(info);
    let val = bind.get_parameter(0);
    let cstr = duckdb_get_varchar(val);
    let host = CStr::from_ptr(cstr).to_str().unwrap_or("").to_string();
    duckdb_free(cstr as *mut _);
    duckdb_destroy_value(&mut { val });

    let max_val = bind.get_named_parameter("max_hops");
    let max_hops = if max_val.is_null() {
        30
    } else {
        let n = duckdb_get_int64(max_val) as u32;
        duckdb_destroy_value(&mut { max_val });
        n
    };

    bind.add_result_column("hop", TypeId::Integer);
    bind.add_result_column("ip", TypeId::Varchar);
    bind.add_result_column("hostname", TypeId::Varchar);
    bind.add_result_column("latency_ms", TypeId::Double);

    FfiBindData::<TracerouteBindData>::set(info, TracerouteBindData { host, max_hops });
}

unsafe extern "C" fn traceroute_init(info: duckdb_init_info) {
    FfiInitData::<TracerouteInitData>::set(
        info,
        TracerouteInitData {
            hops: vec![],
            idx: 0,
            fetched: false,
        },
    );
}

unsafe extern "C" fn traceroute_scan(info: duckdb_function_info, output: duckdb_data_chunk) {
    let bind_data = match FfiBindData::<TracerouteBindData>::get_from_function(info) {
        Some(d) => d,
        None => {
            duckdb_data_chunk_set_size(output, 0);
            return;
        }
    };
    let init_data = match FfiInitData::<TracerouteInitData>::get_mut(info) {
        Some(d) => d,
        None => {
            duckdb_data_chunk_set_size(output, 0);
            return;
        }
    };

    if !init_data.fetched {
        init_data.fetched = true;
        match ping_mod::traceroute(&bind_data.host, bind_data.max_hops) {
            Ok(hops) => init_data.hops = hops,
            Err(e) => {
                let fi = FunctionInfo::new(info);
                fi.set_error(&e);
                duckdb_data_chunk_set_size(output, 0);
                return;
            }
        }
    }

    let out_chunk = DataChunk::from_raw(output);
    let mut hop_w = out_chunk.writer(0);
    let mut ip_w = out_chunk.writer(1);
    let mut host_w = out_chunk.writer(2);
    let mut lat_w = out_chunk.writer(3);

    let mut count: idx_t = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.hops.len() && count < max_chunk {
        let h = &init_data.hops[init_data.idx];
        hop_w.write_i32(count as usize, h.hop);
        ip_w.write_varchar(count as usize, &h.ip);
        host_w.write_varchar(count as usize, &h.hostname);
        lat_w.write_f64(count as usize, h.latency_ms);
        init_data.idx += 1;
        count += 1;
    }

    out_chunk.set_size(count as usize);
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionSetBuilder::new("ping")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .returns_logical(ping_result_type())
                .function(cb_ping)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .param(TypeId::Integer)
                .returns_logical(ping_result_type())
                .function(cb_ping_timeout)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con)?;

    TableFunctionBuilder::new("traceroute")
        .param(v)
        .named_param("max_hops", TypeId::BigInt)
        .bind(traceroute_bind)
        .init(traceroute_init)
        .scan(traceroute_scan)
        .register(con)?;

    Ok(())
}
