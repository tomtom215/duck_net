// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::ping as ping_mod;

fn ping_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("alive", LogicalType::new(TypeId::Boolean)),
        ("latency_ms", LogicalType::new(TypeId::Double)),
        ("ttl", LogicalType::new(TypeId::Integer)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// ping(host) -> STRUCT(alive, latency_ms, ttl, message)
quack_rs::scalar_callback!(cb_ping, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row) };
        let result = ping_mod::ping(host, 5);

        unsafe { sw.write_bool(row, 0, result.alive) };
        unsafe { sw.write_f64(row, 1, result.latency_ms) };
        unsafe { sw.write_i32(row, 2, result.ttl) };
        unsafe { sw.write_varchar(row, 3, &result.message) };
    }
});

// ping(host, timeout_secs) -> STRUCT
quack_rs::scalar_callback!(cb_ping_timeout, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let timeout_reader = unsafe { chunk.reader(1) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row) };
        let timeout = unsafe { timeout_reader.read_i32(row) } as u32;
        let result = ping_mod::ping(host, timeout);

        unsafe { sw.write_bool(row, 0, result.alive) };
        unsafe { sw.write_f64(row, 1, result.latency_ms) };
        unsafe { sw.write_i32(row, 2, result.ttl) };
        unsafe { sw.write_varchar(row, 3, &result.message) };
    }
});

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
    let host = bind.get_parameter_value(0).as_str_or_default();

    let max_val = bind.get_named_parameter_value("max_hops");
    let max_hops = if max_val.is_null() {
        30u32
    } else {
        max_val.as_i64() as u32
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

// traceroute table scan callback
quack_rs::table_scan_callback!(traceroute_scan, |info, output| {
    let bind_data = match unsafe { FfiBindData::<TracerouteBindData>::get_from_function(info) } {
        Some(d) => d,
        None => {
            unsafe { DataChunk::from_raw(output).set_size(0) };
            return;
        }
    };
    let init_data = match unsafe { FfiInitData::<TracerouteInitData>::get_mut(info) } {
        Some(d) => d,
        None => {
            unsafe { DataChunk::from_raw(output).set_size(0) };
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
                unsafe { DataChunk::from_raw(output).set_size(0) };
                return;
            }
        }
    }

    let out_chunk = unsafe { DataChunk::from_raw(output) };
    let mut hop_w = unsafe { out_chunk.writer(0) };
    let mut ip_w = unsafe { out_chunk.writer(1) };
    let mut host_w = unsafe { out_chunk.writer(2) };
    let mut lat_w = unsafe { out_chunk.writer(3) };

    let mut count: idx_t = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.hops.len() && count < max_chunk {
        let h = &init_data.hops[init_data.idx];
        unsafe { hop_w.write_i32(count as usize, h.hop) };
        unsafe { ip_w.write_varchar(count as usize, &h.ip) };
        unsafe { host_w.write_varchar(count as usize, &h.hostname) };
        unsafe { lat_w.write_f64(count as usize, h.latency_ms) };
        init_data.idx += 1;
        count += 1;
    }

    unsafe { out_chunk.set_size(count as usize) };
});

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
