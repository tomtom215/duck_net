// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::ffi::CStr;

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::mdns;

use super::dns::write_string_list;

// ===== mdns_discover table function =====

struct MdnsBindData {
    service_type: String,
    timeout_secs: u32,
}

struct MdnsInitData {
    services: Vec<mdns::MdnsService>,
    idx: usize,
    fetched: bool,
}

unsafe extern "C" fn mdns_bind(info: duckdb_bind_info) {
    let bind = BindInfo::new(info);
    let val = bind.get_parameter(0);
    let cstr = duckdb_get_varchar(val);
    let service_type = CStr::from_ptr(cstr).to_str().unwrap_or("").to_string();
    duckdb_free(cstr as *mut _);
    duckdb_destroy_value(&mut { val });

    let timeout_val = bind.get_named_parameter("timeout");
    let timeout_secs = if timeout_val.is_null() {
        3
    } else {
        let n = duckdb_get_int64(timeout_val) as u32;
        duckdb_destroy_value(&mut { timeout_val });
        n
    };

    bind.add_result_column("instance_name", TypeId::Varchar);
    bind.add_result_column("hostname", TypeId::Varchar);
    bind.add_result_column("port", TypeId::Integer);
    bind.add_result_column_with_type(
        "ips",
        &LogicalType::list_from_logical(&LogicalType::new(TypeId::Varchar)),
    );
    bind.add_result_column_with_type(
        "txt",
        &LogicalType::list_from_logical(&LogicalType::new(TypeId::Varchar)),
    );

    FfiBindData::<MdnsBindData>::set(
        info,
        MdnsBindData {
            service_type,
            timeout_secs,
        },
    );
}

unsafe extern "C" fn mdns_init(info: duckdb_init_info) {
    FfiInitData::<MdnsInitData>::set(
        info,
        MdnsInitData {
            services: vec![],
            idx: 0,
            fetched: false,
        },
    );
}

// mdns_scan table scan callback
quack_rs::table_scan_callback!(mdns_scan, |info, output| {
    let bind_data = match unsafe { FfiBindData::<MdnsBindData>::get_from_function(info) } {
        Some(d) => d,
        None => {
            unsafe { duckdb_data_chunk_set_size(output, 0) };
            return;
        }
    };
    let init_data = match unsafe { FfiInitData::<MdnsInitData>::get_mut(info) } {
        Some(d) => d,
        None => {
            unsafe { duckdb_data_chunk_set_size(output, 0) };
            return;
        }
    };

    if !init_data.fetched {
        init_data.fetched = true;
        match mdns::discover(&bind_data.service_type, bind_data.timeout_secs) {
            Ok(svcs) => init_data.services = svcs,
            Err(e) => {
                let fi = unsafe { FunctionInfo::new(info) };
                fi.set_error(&e);
                unsafe { duckdb_data_chunk_set_size(output, 0) };
                return;
            }
        }
    }

    let out_chunk = unsafe { DataChunk::from_raw(output) };
    let mut name_w = unsafe { out_chunk.writer(0) };
    let mut host_w = unsafe { out_chunk.writer(1) };
    let mut port_w = unsafe { out_chunk.writer(2) };
    let ips_vec = unsafe { duckdb_data_chunk_get_vector(output, 3) };
    let txt_vec = unsafe { duckdb_data_chunk_get_vector(output, 4) };

    let mut count: usize = 0;
    let max_chunk = 2048;
    let mut ips_list_offset: usize = 0;
    let mut txt_list_offset: usize = 0;

    while init_data.idx < init_data.services.len() && count < max_chunk {
        let svc = &init_data.services[init_data.idx];

        unsafe { name_w.write_varchar(count, &svc.instance_name) };
        unsafe { host_w.write_varchar(count, &svc.hostname) };
        unsafe { port_w.write_i32(count, svc.port as i32) };

        unsafe { write_string_list(ips_vec, count, &svc.ips, &mut ips_list_offset) };
        unsafe { write_string_list(txt_vec, count, &svc.txt, &mut txt_list_offset) };

        init_data.idx += 1;
        count += 1;
    }

    unsafe { duckdb_data_chunk_set_size(output, count as idx_t) };
});

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    TableFunctionBuilder::new("mdns_discover")
        .param(TypeId::Varchar) // service_type
        .named_param("timeout", TypeId::BigInt)
        .bind(mdns_bind)
        .init(mdns_init)
        .scan(mdns_scan)
        .register(con)?;

    Ok(())
}
