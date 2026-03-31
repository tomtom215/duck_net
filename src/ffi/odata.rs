// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::metadata;
use crate::odata;

use super::scalars::{map_varchar_varchar, read_headers_map, response_type, write_response};

// ===== odata_query scalar function =====

// odata_query(url, headers MAP) -> STRUCT (HTTP response)
quack_rs::scalar_callback!(cb_odata_query, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let headers = unsafe { read_headers_map(&chunk, 1, row) };
        let resp = odata::query(url, None, None, None, None, None, None, &headers);
        unsafe { write_response(output, row, &resp, &mut map_offset) };
    }
});

// ===== odata_extract_count scalar =====

// odata_extract_count(body VARCHAR) -> BIGINT
// Returns the server-reported total count from @odata.count (v4) or __count (v2 JSON).
// Returns NULL when the field is absent (query did not include $count=true / $inlinecount=allpages).
quack_rs::scalar_callback!(cb_odata_extract_count, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let body_reader = unsafe { chunk.reader(0) };
    let mut out_w = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let body = unsafe { body_reader.read_str(row) };
        match odata::extract_total_count(body) {
            Some(n) => unsafe { out_w.write_i64(row, n) },
            None => unsafe { out_w.set_null(row) },
        }
    }
});

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
    let filter = if filter_val.is_null() {
        None
    } else {
        filter_val.as_str().ok()
    };

    let select_val = bind.get_named_parameter_value("select");
    let select = if select_val.is_null() {
        None
    } else {
        select_val.as_str().ok()
    };

    let orderby_val = bind.get_named_parameter_value("orderby");
    let orderby = if orderby_val.is_null() {
        None
    } else {
        orderby_val.as_str().ok()
    };

    let expand_val = bind.get_named_parameter_value("expand");
    let expand = if expand_val.is_null() {
        None
    } else {
        expand_val.as_str().ok()
    };

    let top_val = bind.get_named_parameter_value("top");
    let top = if top_val.is_null() {
        None
    } else {
        Some(top_val.as_i64())
    };

    let max_pages_val = bind.get_named_parameter_value("max_pages");
    let max_pages = if max_pages_val.is_null() {
        100
    } else {
        max_pages_val.as_i64()
    };

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

// odata_paginate_scan table scan callback
quack_rs::table_scan_callback!(odata_paginate_scan, |info, output| {
    let bind_data = match unsafe { FfiBindData::<ODataPaginateBindData>::get_from_function(info) } {
        Some(d) => d,
        None => {
            unsafe { DataChunk::from_raw(output).set_size(0) };
            return;
        }
    };
    let init_data = match unsafe { FfiInitData::<ODataPaginateInitData>::get_mut(info) } {
        Some(d) => d,
        None => {
            unsafe { DataChunk::from_raw(output).set_size(0) };
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
            let out_chunk = unsafe { DataChunk::from_raw(output) };
            let mut page_w = unsafe { out_chunk.writer(0) };
            let mut status_w = unsafe { out_chunk.writer(1) };
            let headers_vec = unsafe { out_chunk.vector(2) };
            let mut body_w = unsafe { out_chunk.writer(3) };

            unsafe { page_w.write_i32(0, page_num as i32) };
            unsafe { status_w.write_i32(0, resp.status as i32) };

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

            unsafe { body_w.write_varchar(0, &resp.body) };
            unsafe { out_chunk.set_size(1) };
        }
        None => {
            unsafe { DataChunk::from_raw(output).set_size(0) };
        }
    }
});

// ===== odata_metadata table function =====

struct ODataMetadataBindData {
    url: String,
    authorization: Option<String>,
}

struct ODataMetadataInitData {
    rows: Vec<metadata::MetadataRow>,
    idx: usize,
}

unsafe extern "C" fn odata_metadata_bind(info: duckdb_bind_info) {
    let bind = BindInfo::new(info);

    let url = bind.get_parameter_value(0).as_str().unwrap_or_default();

    let auth_val = bind.get_named_parameter_value("authorization");
    let authorization = if auth_val.is_null() {
        None
    } else {
        auth_val.as_str().ok()
    };

    bind.add_result_column("entity_set", TypeId::Varchar);
    bind.add_result_column("entity_type", TypeId::Varchar);
    bind.add_result_column("property_name", TypeId::Varchar);
    bind.add_result_column("property_type", TypeId::Varchar);
    bind.add_result_column("nullable", TypeId::Boolean);
    bind.add_result_column("is_key", TypeId::Boolean);
    bind.add_result_column("is_navigation", TypeId::Boolean);

    FfiBindData::<ODataMetadataBindData>::set(info, ODataMetadataBindData { url, authorization });
}

unsafe extern "C" fn odata_metadata_init(info: duckdb_init_info) {
    let bind_data = match unsafe { FfiBindData::<ODataMetadataBindData>::get_from_init(info) } {
        Some(d) => d,
        None => {
            FfiInitData::<ODataMetadataInitData>::set(
                info,
                ODataMetadataInitData {
                    rows: vec![],
                    idx: 0,
                },
            );
            return;
        }
    };

    let mut headers: Vec<(String, String)> = Vec::new();
    if let Some(auth) = &bind_data.authorization {
        headers.push(("Authorization".into(), auth.clone()));
    }

    let rows = match metadata::fetch_metadata(&bind_data.url, &headers) {
        Ok(r) => r,
        Err(e) => {
            let init = InitInfo::new(info);
            init.set_error(&e);
            vec![]
        }
    };

    FfiInitData::<ODataMetadataInitData>::set(info, ODataMetadataInitData { rows, idx: 0 });
}

quack_rs::table_scan_callback!(odata_metadata_scan, |info, output| {
    let init_data = match unsafe { FfiInitData::<ODataMetadataInitData>::get_mut(info) } {
        Some(d) => d,
        None => {
            unsafe { DataChunk::from_raw(output).set_size(0) };
            return;
        }
    };

    let out_chunk = unsafe { DataChunk::from_raw(output) };
    let mut set_w = unsafe { out_chunk.writer(0) };
    let mut type_w = unsafe { out_chunk.writer(1) };
    let mut prop_w = unsafe { out_chunk.writer(2) };
    let mut ptype_w = unsafe { out_chunk.writer(3) };
    let mut null_w = unsafe { out_chunk.writer(4) };
    let mut key_w = unsafe { out_chunk.writer(5) };
    let mut nav_w = unsafe { out_chunk.writer(6) };

    let max_chunk: usize = 2048;
    let mut count: usize = 0;

    while init_data.idx < init_data.rows.len() && count < max_chunk {
        let row = &init_data.rows[init_data.idx];
        if let Some(ref es) = row.entity_set {
            unsafe { set_w.write_varchar(count, es) };
        } else {
            unsafe { set_w.set_null(count) };
        }
        unsafe { type_w.write_varchar(count, &row.entity_type) };
        unsafe { prop_w.write_varchar(count, &row.property_name) };
        unsafe { ptype_w.write_varchar(count, &row.property_type) };
        unsafe { null_w.write_bool(count, row.nullable) };
        unsafe { key_w.write_bool(count, row.is_key) };
        unsafe { nav_w.write_bool(count, row.is_navigation) };

        init_data.idx += 1;
        count += 1;
    }

    unsafe { out_chunk.set_size(count) };
});

pub unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    // odata_extract_count(body VARCHAR) -> BIGINT
    // Returns server-reported total count from @odata.count (v4) or __count (v2 JSON).
    // Returns NULL when the field is absent.
    ScalarFunctionBuilder::new("odata_extract_count")
        .param(v)
        .returns(TypeId::BigInt)
        .function(cb_odata_extract_count)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // odata_query(url, headers MAP) -> STRUCT
    ScalarFunctionBuilder::new("odata_query")
        .param(v)
        .param_logical(map_varchar_varchar())
        .returns_logical(response_type())
        .function(cb_odata_query)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // odata_metadata(url, authorization :=) -> TABLE
    TableFunctionBuilder::new("odata_metadata")
        .param(v)
        .named_param("authorization", v)
        .bind(odata_metadata_bind)
        .init(odata_metadata_init)
        .scan(odata_metadata_scan)
        .register(con.as_raw_connection())?;

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
        .register(con.as_raw_connection())?;

    Ok(())
}
