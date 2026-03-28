use std::ffi::CStr;

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::pagination::{self, PaginateConfig, PaginateState, PaginationStrategy};

use super::scalars::{map_varchar_varchar, write_varchar};

// ===== Bind/Init/Scan Data =====

struct PaginateBindData {
    config: PaginateConfig,
}

struct PaginateInitData {
    state: PaginateState,
}

// ===== Bind Callback =====

unsafe extern "C" fn paginate_bind(info: duckdb_bind_info) {
    let bind = BindInfo::new(info);

    // Read positional parameter: url (VARCHAR)
    let url_val = bind.get_parameter(0);
    let url_cstr = duckdb_get_varchar(url_val);
    let url = CStr::from_ptr(url_cstr).to_str().unwrap_or("").to_string();
    duckdb_free(url_cstr as *mut _);
    duckdb_destroy_value(&mut { url_val });

    // Read named parameters
    let page_param = read_named_varchar(info, "page_param");
    let next_url_path = read_named_varchar(info, "next_url_path");
    let max_pages = read_named_bigint(info, "max_pages").unwrap_or(100);
    let start_page = read_named_bigint(info, "start_page").unwrap_or(1);

    // Determine pagination strategy
    let strategy = if let Some(path) = next_url_path {
        PaginationStrategy::NextUrl {
            json_path: Some(path),
            use_link_header: true,
        }
    } else {
        let param_name = page_param.unwrap_or_else(|| "page".to_string());
        PaginationStrategy::PageNumber {
            param_name,
            start: start_page,
            increment: 1,
        }
    };

    let config = PaginateConfig {
        base_url: url,
        strategy,
        max_pages,
        headers: vec![],
    };

    // Declare output columns
    bind.add_result_column("page", TypeId::Integer);
    bind.add_result_column("status", TypeId::Integer);
    bind.add_result_column_with_type("headers", &map_varchar_varchar());
    bind.add_result_column("body", TypeId::Varchar);

    FfiBindData::<PaginateBindData>::set(info, PaginateBindData { config });
}

unsafe fn read_named_varchar(info: duckdb_bind_info, name: &str) -> Option<String> {
    let bind = BindInfo::new(info);
    let val = bind.get_named_parameter(name);
    if val.is_null() {
        return None;
    }
    let cstr = duckdb_get_varchar(val);
    if cstr.is_null() {
        duckdb_destroy_value(&mut { val });
        return None;
    }
    let s = CStr::from_ptr(cstr).to_str().ok().map(|s| s.to_string());
    duckdb_free(cstr as *mut _);
    duckdb_destroy_value(&mut { val });
    s
}

unsafe fn read_named_bigint(info: duckdb_bind_info, name: &str) -> Option<i64> {
    let bind = BindInfo::new(info);
    let val = bind.get_named_parameter(name);
    if val.is_null() {
        return None;
    }
    let n = duckdb_get_int64(val);
    duckdb_destroy_value(&mut { val });
    Some(n)
}

// ===== Init Callback =====

unsafe extern "C" fn paginate_init(info: duckdb_init_info) {
    FfiInitData::<PaginateInitData>::set(
        info,
        PaginateInitData {
            state: PaginateState::empty(),
        },
    );
}

// ===== Scan Callback =====

unsafe extern "C" fn paginate_scan(info: duckdb_function_info, output: duckdb_data_chunk) {
    let bind_data = match FfiBindData::<PaginateBindData>::get_from_function(info) {
        Some(d) => d,
        None => {
            duckdb_data_chunk_set_size(output, 0);
            return;
        }
    };
    let init_data = match FfiInitData::<PaginateInitData>::get_mut(info) {
        Some(d) => d,
        None => {
            duckdb_data_chunk_set_size(output, 0);
            return;
        }
    };

    // Initialize state on first scan
    if init_data.state.next_url.is_none() && init_data.state.current_page == 0 && !init_data.state.done {
        init_data.state = PaginateState::new(&bind_data.config);
    }

    match pagination::fetch_next(&bind_data.config, &mut init_data.state) {
        Some((page_num, resp)) => {
            let page_vec = duckdb_data_chunk_get_vector(output, 0);
            let status_vec = duckdb_data_chunk_get_vector(output, 1);
            let headers_vec = duckdb_data_chunk_get_vector(output, 2);
            let body_vec = duckdb_data_chunk_get_vector(output, 3);

            // page (INTEGER)
            let page_data = duckdb_vector_get_data(page_vec) as *mut i32;
            *page_data = page_num as i32;

            // status (INTEGER)
            let status_data = duckdb_vector_get_data(status_vec) as *mut i32;
            *status_data = resp.status as i32;

            // headers (MAP)
            let n = resp.headers.len() as idx_t;
            MapVector::reserve(headers_vec, n as usize);
            let keys = MapVector::keys(headers_vec);
            let vals = MapVector::values(headers_vec);
            for (i, (k, v)) in resp.headers.iter().enumerate() {
                write_varchar(keys, i as idx_t, k);
                write_varchar(vals, i as idx_t, v);
            }
            MapVector::set_entry(headers_vec, 0, 0, n);
            MapVector::set_size(headers_vec, n as usize);

            // body (VARCHAR)
            write_varchar(body_vec, 0, &resp.body);

            duckdb_data_chunk_set_size(output, 1);
        }
        None => {
            duckdb_data_chunk_set_size(output, 0);
        }
    }
}

// ===== Registration =====

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    TableFunctionBuilder::new("http_paginate")
        .param(TypeId::Varchar)
        .named_param("page_param", TypeId::Varchar)
        .named_param("start_page", TypeId::BigInt)
        .named_param("max_pages", TypeId::BigInt)
        .named_param("next_url_path", TypeId::Varchar)
        .bind(paginate_bind)
        .init(paginate_init)
        .scan(paginate_scan)
        .register(con)?;

    Ok(())
}
