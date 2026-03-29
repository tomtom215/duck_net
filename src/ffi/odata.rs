use std::ffi::CStr;

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::odata;

use super::scalars::{map_varchar_varchar, read_headers_map, response_type, write_response, write_varchar};

// ===== odata_query scalar function =====

/// odata_query(url, headers MAP) -> STRUCT (HTTP response)
unsafe extern "C" fn cb_odata_query(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let mut map_offset: idx_t = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let headers = read_headers_map(input, 1, row as usize);
        let resp = odata::query(url, None, None, None, None, None, None, &headers);
        write_response(output, row, &resp, &mut map_offset);
    }
}

// ===== odata_paginate table function =====

struct ODataPaginateBindData {
    base_url: String,
    filter: Option<String>,
    select: Option<String>,
    top: Option<i64>,
    orderby: Option<String>,
    expand: Option<String>,
    headers: Vec<(String, String)>,
    max_pages: i64,
}

struct ODataPaginateInitData {
    state: odata::ODataPaginateState,
}

unsafe extern "C" fn odata_paginate_bind(info: duckdb_bind_info) {
    let bind = BindInfo::new(info);

    let url_val = bind.get_parameter(0);
    let url_cstr = duckdb_get_varchar(url_val);
    let url = CStr::from_ptr(url_cstr).to_str().unwrap_or("").to_string();
    duckdb_free(url_cstr as *mut _);
    duckdb_destroy_value(&mut { url_val });

    let filter = read_named_varchar_odata(info, "filter");
    let select = read_named_varchar_odata(info, "select");
    let orderby = read_named_varchar_odata(info, "orderby");
    let expand = read_named_varchar_odata(info, "expand");
    let top = read_named_bigint_odata(info, "top");
    let max_pages = read_named_bigint_odata(info, "max_pages").unwrap_or(100);

    bind.add_result_column("page", TypeId::Integer);
    bind.add_result_column("status", TypeId::Integer);
    bind.add_result_column_with_type("headers", &map_varchar_varchar());
    bind.add_result_column("body", TypeId::Varchar);

    FfiBindData::<ODataPaginateBindData>::set(
        info,
        ODataPaginateBindData {
            base_url: url,
            filter,
            select,
            top,
            orderby,
            expand,
            headers: vec![],
            max_pages,
        },
    );
}

unsafe fn read_named_varchar_odata(info: duckdb_bind_info, name: &str) -> Option<String> {
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

unsafe fn read_named_bigint_odata(info: duckdb_bind_info, name: &str) -> Option<i64> {
    let bind = BindInfo::new(info);
    let val = bind.get_named_parameter(name);
    if val.is_null() {
        return None;
    }
    let n = duckdb_get_int64(val);
    duckdb_destroy_value(&mut { val });
    Some(n)
}

unsafe extern "C" fn odata_paginate_init(info: duckdb_init_info) {
    FfiInitData::<ODataPaginateInitData>::set(
        info,
        ODataPaginateInitData {
            state: odata::ODataPaginateState::new(),
        },
    );
}

unsafe extern "C" fn odata_paginate_scan(info: duckdb_function_info, output: duckdb_data_chunk) {
    let bind_data = match FfiBindData::<ODataPaginateBindData>::get_from_function(info) {
        Some(d) => d,
        None => { duckdb_data_chunk_set_size(output, 0); return; }
    };
    let init_data = match FfiInitData::<ODataPaginateInitData>::get_mut(info) {
        Some(d) => d,
        None => { duckdb_data_chunk_set_size(output, 0); return; }
    };

    match odata::fetch_next_page(
        &bind_data.base_url,
        bind_data.filter.as_deref(),
        bind_data.select.as_deref(),
        bind_data.top,
        bind_data.orderby.as_deref(),
        bind_data.expand.as_deref(),
        &bind_data.headers,
        &mut init_data.state,
        bind_data.max_pages,
    ) {
        Some((page_num, resp)) => {
            let page_vec = duckdb_data_chunk_get_vector(output, 0);
            let status_vec = duckdb_data_chunk_get_vector(output, 1);
            let headers_vec = duckdb_data_chunk_get_vector(output, 2);
            let body_vec = duckdb_data_chunk_get_vector(output, 3);

            let page_data = duckdb_vector_get_data(page_vec) as *mut i32;
            *page_data = page_num as i32;

            let status_data = duckdb_vector_get_data(status_vec) as *mut i32;
            *status_data = resp.status as i32;

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

            write_varchar(body_vec, 0, &resp.body);
            duckdb_data_chunk_set_size(output, 1);
        }
        None => {
            duckdb_data_chunk_set_size(output, 0);
        }
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    // odata_query(url, headers MAP) -> STRUCT
    ScalarFunctionBuilder::new("odata_query")
        .param(v)
        .param_logical(map_varchar_varchar())
        .returns_logical(response_type())
        .function(cb_odata_query)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // odata_paginate table function
    TableFunctionBuilder::new("odata_paginate")
        .param(v)
        .named_param("filter", v)
        .named_param("select", v)
        .named_param("orderby", v)
        .named_param("expand", v)
        .named_param("top", TypeId::BigInt)
        .named_param("max_pages", TypeId::BigInt)
        .bind(odata_paginate_bind)
        .init(odata_paginate_init)
        .scan(odata_paginate_scan)
        .register(con)?;

    Ok(())
}
