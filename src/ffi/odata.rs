// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::odata;

use super::scalars::{
    map_varchar_varchar, read_headers_map, response_type, write_response, write_varchar,
};

// ===== odata_query scalar function =====

/// odata_query(url, headers MAP) -> STRUCT (HTTP response)
unsafe extern "C" fn cb_odata_query(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row);
        let headers = read_headers_map(input, 1, row);
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

    let url = bind.get_parameter_value(0).as_str().unwrap_or_default();

    let filter_val = bind.get_named_parameter_value("filter");
    let filter = if filter_val.is_null() { None } else { filter_val.as_str().ok() };

    let select_val = bind.get_named_parameter_value("select");
    let select = if select_val.is_null() { None } else { select_val.as_str().ok() };

    let orderby_val = bind.get_named_parameter_value("orderby");
    let orderby = if orderby_val.is_null() { None } else { orderby_val.as_str().ok() };

    let expand_val = bind.get_named_parameter_value("expand");
    let expand = if expand_val.is_null() { None } else { expand_val.as_str().ok() };

    let top_val = bind.get_named_parameter_value("top");
    let top = if top_val.is_null() { None } else { Some(top_val.as_i64()) };

    let max_pages_val = bind.get_named_parameter_value("max_pages");
    let max_pages = if max_pages_val.is_null() { 100 } else { max_pages_val.as_i64() };

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
        None => {
            duckdb_data_chunk_set_size(output, 0);
            return;
        }
    };
    let init_data = match FfiInitData::<ODataPaginateInitData>::get_mut(info) {
        Some(d) => d,
        None => {
            duckdb_data_chunk_set_size(output, 0);
            return;
        }
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
            let out_chunk = DataChunk::from_raw(output);
            let mut page_w = out_chunk.writer(0);
            let mut status_w = out_chunk.writer(1);
            let headers_vec = duckdb_data_chunk_get_vector(output, 2);
            let mut body_w = out_chunk.writer(3);

            page_w.write_i32(0, page_num as i32);
            status_w.write_i32(0, resp.status as i32);

            let n = resp.headers.len() as idx_t;
            MapVector::reserve(headers_vec, n as usize);
            let keys = MapVector::keys(headers_vec);
            let vals = MapVector::values(headers_vec);
            for (i, (k, v)) in resp.headers.iter().enumerate() {
                write_varchar(keys, i, k);
                write_varchar(vals, i, v);
            }
            MapVector::set_entry(headers_vec, 0, 0, n);
            MapVector::set_size(headers_vec, n as usize);

            body_w.write_varchar(0, &resp.body);
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
