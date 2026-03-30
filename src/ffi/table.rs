// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::pagination::{self, PaginateConfig, PaginateState, PaginationStrategy};

use super::scalars::map_varchar_varchar;

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
    let url = bind
        .get_parameter_value(0)
        .as_str()
        .unwrap_or_default();

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
    let val = bind.get_named_parameter_value(name);
    if val.is_null() {
        return None;
    }
    val.as_str().ok()
}

unsafe fn read_named_bigint(info: duckdb_bind_info, name: &str) -> Option<i64> {
    let bind = BindInfo::new(info);
    let val = bind.get_named_parameter_value(name);
    if val.is_null() {
        return None;
    }
    Some(val.as_i64())
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

// paginate_scan table scan callback
quack_rs::table_scan_callback!(paginate_scan, |info, output| {
    let bind_data = match unsafe { FfiBindData::<PaginateBindData>::get_from_function(info) } {
        Some(d) => d,
        None => {
            unsafe { duckdb_data_chunk_set_size(output, 0) };
            return;
        }
    };
    let init_data = match unsafe { FfiInitData::<PaginateInitData>::get_mut(info) } {
        Some(d) => d,
        None => {
            unsafe { duckdb_data_chunk_set_size(output, 0) };
            return;
        }
    };

    // Initialize state on first scan
    if init_data.state.next_url.is_none()
        && init_data.state.current_page == 0
        && !init_data.state.done
    {
        init_data.state = PaginateState::new(&bind_data.config);
    }

    match pagination::fetch_next(&bind_data.config, &mut init_data.state) {
        Some((page_num, resp)) => {
            let chunk = unsafe { DataChunk::from_raw(output) };

            // page (INTEGER)
            let mut page_w = unsafe { chunk.writer(0) };
            unsafe { page_w.write_i32(0, page_num as i32) };

            // status (INTEGER)
            let mut status_w = unsafe { chunk.writer(1) };
            unsafe { status_w.write_i32(0, resp.status as i32) };

            // headers (MAP)
            let headers_vec = unsafe { chunk.vector(2) };
            let n = resp.headers.len() as idx_t;
            unsafe { MapVector::reserve(headers_vec, n as usize) };
            let mut key_w = unsafe { MapVector::key_writer(headers_vec) };
            let mut val_w = unsafe { MapVector::value_writer(headers_vec) };
            for (i, (k, v)) in resp.headers.iter().enumerate() {
                unsafe { key_w.write_varchar(i, k) };
                unsafe { val_w.write_varchar(i, v) };
            }
            unsafe { MapVector::set_entry(headers_vec, 0, 0, n) };
            unsafe { MapVector::set_size(headers_vec, n as usize) };

            // body (VARCHAR)
            let mut body_w = unsafe { chunk.writer(3) };
            unsafe { body_w.write_varchar(0, &resp.body) };

            unsafe { chunk.set_size(1) };
        }
        None => {
            unsafe { duckdb_data_chunk_set_size(output, 0) };
        }
    }
});

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
