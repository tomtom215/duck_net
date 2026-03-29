// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::ffi::CStr;

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::mdns;

use super::dns::write_string_list;
use super::scalars::write_varchar;

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

unsafe extern "C" fn mdns_scan(info: duckdb_function_info, output: duckdb_data_chunk) {
    let bind_data = match FfiBindData::<MdnsBindData>::get_from_function(info) {
        Some(d) => d,
        None => {
            duckdb_data_chunk_set_size(output, 0);
            return;
        }
    };
    let init_data = match FfiInitData::<MdnsInitData>::get_mut(info) {
        Some(d) => d,
        None => {
            duckdb_data_chunk_set_size(output, 0);
            return;
        }
    };

    if !init_data.fetched {
        init_data.fetched = true;
        match mdns::discover(&bind_data.service_type, bind_data.timeout_secs) {
            Ok(svcs) => init_data.services = svcs,
            Err(e) => {
                let fi = FunctionInfo::new(info);
                fi.set_error(&e);
                duckdb_data_chunk_set_size(output, 0);
                return;
            }
        }
    }

    let name_vec = duckdb_data_chunk_get_vector(output, 0);
    let host_vec = duckdb_data_chunk_get_vector(output, 1);
    let port_vec = duckdb_data_chunk_get_vector(output, 2);
    let ips_vec = duckdb_data_chunk_get_vector(output, 3);
    let txt_vec = duckdb_data_chunk_get_vector(output, 4);

    let mut count: idx_t = 0;
    let max_chunk = 2048;
    let mut ips_list_offset: idx_t = 0;
    let mut txt_list_offset: idx_t = 0;

    while init_data.idx < init_data.services.len() && count < max_chunk {
        let svc = &init_data.services[init_data.idx];

        write_varchar(name_vec, count, &svc.instance_name);
        write_varchar(host_vec, count, &svc.hostname);

        let pd = duckdb_vector_get_data(port_vec) as *mut i32;
        *pd.add(count as usize) = svc.port as i32;

        write_string_list(ips_vec, count, &svc.ips, &mut ips_list_offset);
        write_string_list(txt_vec, count, &svc.txt, &mut txt_list_offset);

        init_data.idx += 1;
        count += 1;
    }

    duckdb_data_chunk_set_size(output, count);
}

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
